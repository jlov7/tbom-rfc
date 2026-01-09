#!/usr/bin/env python3
"""
tbomctl.py — Minimal reference tooling for the MCP Tool Bill of Materials (TBOM) v1.0.2.

This script provides:
- RFC8785-like JSON canonicalization (sufficient for the typical TBOM data model: objects/arrays/strings/ints)
- Tool definition digest computation (definitionDigest)
- TBOM schema validation + internal consistency checks
- JWS (detached payload) signing and verification for Ed25519 / ECDSA P-256 / ECDSA P-384

Notes:
- This is a reference implementation intended for testing and interoperability.
- It does NOT fetch key documents from the network (use --keys to provide a local keys document).
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ImportError as e:
    raise SystemExit(
        "Missing dependency 'jsonschema'. Install with: python3 -m pip install -r requirements.txt"
    ) from e

try:
    import jcs
except ImportError as e:
    raise SystemExit(
        "Missing dependency 'jcs'. Install with: python3 -m pip install -r requirements.txt"
    ) from e

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
except ImportError as e:
    raise SystemExit(
        "Missing dependency 'cryptography'. Install with: python3 -m pip install -r requirements.txt"
    ) from e


# ---------------------------
# Utilities
# ---------------------------

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def now_rfc3339() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def strip_null_object_keys(obj: Any) -> Any:
    """
    Remove dict keys whose value is None, recursively.
    (This implements TBOM's pre-canonicalization normalization rule for null-valued keys.)
    """
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            if v is None:
                continue
            out[k] = strip_null_object_keys(v)
        return out
    if isinstance(obj, list):
        return [strip_null_object_keys(v) for v in obj]
    return obj


def jcs_canonicalize(obj: Any) -> str:
    """
    RFC 8785 (JCS) canonicalization via the 'jcs' library.
    """
    canonical = jcs.canonicalize(obj)
    if isinstance(canonical, bytes):
        return canonical.decode("utf-8")
    return canonical


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise SystemExit(f"Invalid JSON in {path}: {e}") from e


def dump_json(obj: Any, *, pretty: bool = True) -> str:
    if pretty:
        return json.dumps(obj, indent=2, ensure_ascii=False, sort_keys=False) + "\n"
    return json.dumps(obj, ensure_ascii=False) + "\n"


# ---------------------------
# Tool definition digest
# ---------------------------

DIGEST_FIELDS = ["name", "description", "inputSchema", "outputSchema", "annotations"]


def tool_digest_input(tool: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build the digest input object for a tool definition, per TBOM v1.0.2:
      { name, description, inputSchema, (outputSchema?), (annotations?) }
    Optional fields are included only if present and non-null after normalization.
    """
    required = ["name", "description", "inputSchema"]
    for r in required:
        if r not in tool:
            raise ValueError(f"Tool definition missing required field: {r}")

    digest_obj: Dict[str, Any] = {
        "name": tool["name"],
        "description": tool["description"],
        "inputSchema": tool["inputSchema"],
    }

    if "outputSchema" in tool and tool["outputSchema"] is not None:
        digest_obj["outputSchema"] = tool["outputSchema"]
    if "annotations" in tool and tool["annotations"] is not None:
        digest_obj["annotations"] = tool["annotations"]

    return strip_null_object_keys(digest_obj)


def compute_tool_digest(tool: Dict[str, Any]) -> Tuple[str, str]:
    """
    Returns (canonical_json, digest_value) where digest_value is "sha256:<hex>".
    """
    digest_obj = tool_digest_input(tool)
    canonical = jcs_canonicalize(digest_obj)
    digest_value = "sha256:" + sha256_hex(canonical.encode("utf-8"))
    return canonical, digest_value


def definition_digest_covers(tool: Dict[str, Any]) -> str:
    """
    Return the definitionDigest.covers string for the tool digest input.
    """
    digest_obj = tool_digest_input(tool)
    fields = [f for f in DIGEST_FIELDS if f in digest_obj]
    return "{" + ",".join(fields) + "}"


# ---------------------------
# JWS (detached payload) signing / verification
# ---------------------------

def tbom_payload_for_signing(tbom: Dict[str, Any]) -> Dict[str, Any]:
    """
    The signed payload is the TBOM object with the 'signatures' field removed.
    """
    payload = {k: v for k, v in tbom.items() if k != "signatures"}
    return strip_null_object_keys(payload)


def jws_alg_for_tbom_algorithm(tbom_algorithm: str) -> str:
    """
    Informative mapping in TBOM:
      Ed25519 -> EdDSA
      ECDSA-P256 -> ES256
      ECDSA-P384 -> ES384
    """
    mapping = {
        "Ed25519": "EdDSA",
        "ECDSA-P256": "ES256",
        "ECDSA-P384": "ES384",
    }
    try:
        return mapping[tbom_algorithm]
    except KeyError as e:
        raise ValueError(f"Unsupported TBOM signature algorithm: {tbom_algorithm}") from e


def load_private_key_from_jwk(jwk: Dict[str, Any]):
    """
    Supports:
    - OKP Ed25519 with 'd' (raw 32-byte private key)
    - EC P-256 / P-384 with 'd', 'x', 'y' (base64url)
    """
    kty = jwk.get("kty")
    if kty == "OKP":
        if jwk.get("crv") != "Ed25519":
            raise ValueError("Only OKP/Ed25519 is supported for OKP keys")
        d = jwk.get("d")
        if not isinstance(d, str):
            raise ValueError("Ed25519 private JWK must include 'd'")
        priv_bytes = b64url_decode(d)
        if len(priv_bytes) != 32:
            raise ValueError("Ed25519 private key must be 32 bytes (raw)")
        return ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)

    if kty == "EC":
        crv = jwk.get("crv")
        if crv == "P-256":
            curve = ec.SECP256R1()
        elif crv == "P-384":
            curve = ec.SECP384R1()
        else:
            raise ValueError("Only EC/P-256 and EC/P-384 are supported")
        for f in ("d", "x", "y"):
            if f not in jwk or not isinstance(jwk[f], str):
                raise ValueError(f"EC private JWK must include '{f}'")

        d_int = int.from_bytes(b64url_decode(jwk["d"]), "big")
        x_int = int.from_bytes(b64url_decode(jwk["x"]), "big")
        y_int = int.from_bytes(b64url_decode(jwk["y"]), "big")
        pub = ec.EllipticCurvePublicNumbers(x_int, y_int, curve)
        priv = ec.EllipticCurvePrivateNumbers(d_int, pub)
        return priv.private_key()

    raise ValueError(f"Unsupported JWK kty: {kty}")


def load_public_key_from_jwk(jwk: Dict[str, Any]):
    kty = jwk.get("kty")
    if kty == "OKP":
        if jwk.get("crv") != "Ed25519":
            raise ValueError("Only OKP/Ed25519 is supported")
        x = jwk.get("x")
        if not isinstance(x, str):
            raise ValueError("Ed25519 public JWK must include 'x'")
        pub_bytes = b64url_decode(x)
        if len(pub_bytes) != 32:
            raise ValueError("Ed25519 public key must be 32 bytes (raw)")
        return ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)

    if kty == "EC":
        crv = jwk.get("crv")
        if crv == "P-256":
            curve = ec.SECP256R1()
            size = 32
        elif crv == "P-384":
            curve = ec.SECP384R1()
            size = 48
        else:
            raise ValueError("Only EC/P-256 and EC/P-384 are supported")
        x = jwk.get("x")
        y = jwk.get("y")
        if not isinstance(x, str) or not isinstance(y, str):
            raise ValueError("EC public JWK must include 'x' and 'y'")
        x_int = int.from_bytes(b64url_decode(x), "big")
        y_int = int.from_bytes(b64url_decode(y), "big")
        return ec.EllipticCurvePublicNumbers(x_int, y_int, curve).public_key(), size

    raise ValueError(f"Unsupported JWK kty: {kty}")


def ecdsa_raw_signature_from_der(der_sig: bytes, size: int) -> bytes:
    r, s = decode_dss_signature(der_sig)
    return r.to_bytes(size, "big") + s.to_bytes(size, "big")


def ecdsa_der_signature_from_raw(raw_sig: bytes, size: int) -> bytes:
    if len(raw_sig) != 2 * size:
        raise ValueError("Invalid ECDSA raw signature length for curve")
    r = int.from_bytes(raw_sig[:size], "big")
    s = int.from_bytes(raw_sig[size:], "big")
    return encode_dss_signature(r, s)


def sign_tbom_jws_detached(
    tbom: Dict[str, Any],
    *,
    tbom_algorithm: str,
    key_id: str,
    private_jwk: Dict[str, Any],
    typ: str = "JWS",
) -> str:
    """
    Return JWS Compact Serialization with detached payload: "<protected>..<signature>"
    """
    payload_obj = tbom_payload_for_signing(tbom)
    payload_canon = jcs_canonicalize(payload_obj).encode("utf-8")
    protected_header = {"alg": jws_alg_for_tbom_algorithm(tbom_algorithm), "kid": key_id, "typ": typ}

    protected_b64 = b64url_encode(json.dumps(protected_header, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    payload_b64 = b64url_encode(payload_canon)
    signing_input = (protected_b64 + "." + payload_b64).encode("ascii")

    priv = load_private_key_from_jwk(private_jwk)
    if isinstance(priv, ed25519.Ed25519PrivateKey):
        sig = priv.sign(signing_input)
        sig_b64 = b64url_encode(sig)
        return protected_b64 + ".." + sig_b64

    # ECDSA case
    if isinstance(priv, ec.EllipticCurvePrivateKey):
        crv = private_jwk.get("crv")
        if crv == "P-256":
            size = 32
            h = hashes.SHA256()
        elif crv == "P-384":
            size = 48
            h = hashes.SHA384()
        else:
            raise ValueError("Unsupported EC curve for signing")
        der = priv.sign(signing_input, ec.ECDSA(h))
        raw = ecdsa_raw_signature_from_der(der, size)
        return protected_b64 + ".." + b64url_encode(raw)

    raise ValueError("Unsupported private key type")


def resolve_kid_from_key_id(key_id: str) -> Tuple[str, Optional[str]]:
    """
    Return (base_url, fragment_kid)
    """
    if "#" in key_id:
        base, frag = key_id.split("#", 1)
        frag = frag or None
        return base, frag
    return key_id, None


def load_key_from_keys_doc(keys_doc: Dict[str, Any], kid: str) -> Dict[str, Any]:
    keys = keys_doc.get("keys")
    if not isinstance(keys, list):
        raise ValueError("Invalid keys doc: missing 'keys' array")
    for k in keys:
        if isinstance(k, dict) and k.get("kid") == kid:
            return k
    raise ValueError(f"Key with kid='{kid}' not found in keys document")


def verify_tbom_jws_detached(
    tbom: Dict[str, Any],
    signature_entry: Dict[str, Any],
    keys_doc: Dict[str, Any],
) -> None:
    """
    Verify a TBOM signature entry of type 'jws' (detached payload).
    Raises ValueError on failure.
    """
    jws = signature_entry.get("value")
    if not isinstance(jws, str) or jws.count(".") != 2:
        raise ValueError("Invalid JWS compact serialization")
    protected_b64, payload_b64_in_jws, sig_b64 = jws.split(".", 2)
    if payload_b64_in_jws != "":
        raise ValueError("Expected detached payload (empty middle segment)")

    protected = json.loads(b64url_decode(protected_b64).decode("utf-8"))
    alg = protected.get("alg")
    header_kid = protected.get("kid")

    key_id = signature_entry.get("keyId")
    if not isinstance(key_id, str):
        raise ValueError("Signature entry missing 'keyId'")

    tbom_algorithm = signature_entry.get("algorithm")
    if not isinstance(tbom_algorithm, str):
        raise ValueError("Signature entry missing 'algorithm'")
    expected_alg = jws_alg_for_tbom_algorithm(tbom_algorithm)
    if alg != expected_alg:
        raise ValueError(f"JWS alg '{alg}' does not match TBOM algorithm '{tbom_algorithm}'")

    _, frag_kid = resolve_kid_from_key_id(key_id)
    resolved_kid: Optional[str] = frag_kid
    if resolved_kid is None:
        if isinstance(header_kid, str):
            # If header kid is a URL, extract fragment, otherwise treat as kid
            _, hk = resolve_kid_from_key_id(header_kid)
            resolved_kid = hk or header_kid
    elif isinstance(header_kid, str):
        _, hk = resolve_kid_from_key_id(header_kid)
        header_resolved = hk or header_kid
        if header_resolved != resolved_kid:
            raise ValueError("JWS header kid does not match signature keyId fragment")
    if resolved_kid is None:
        raise ValueError("Unable to resolve kid (use keyId with #fragment or JWS header kid)")

    jwk = load_key_from_keys_doc(keys_doc, resolved_kid)
    kty = jwk.get("kty")
    crv = jwk.get("crv")
    if tbom_algorithm == "Ed25519" and (kty != "OKP" or crv != "Ed25519"):
        raise ValueError("TBOM algorithm Ed25519 requires OKP/Ed25519 JWK")
    if tbom_algorithm == "ECDSA-P256" and (kty != "EC" or crv != "P-256"):
        raise ValueError("TBOM algorithm ECDSA-P256 requires EC/P-256 JWK")
    if tbom_algorithm == "ECDSA-P384" and (kty != "EC" or crv != "P-384"):
        raise ValueError("TBOM algorithm ECDSA-P384 requires EC/P-384 JWK")

    payload_obj = tbom_payload_for_signing(tbom)
    payload_canon = jcs_canonicalize(payload_obj).encode("utf-8")
    payload_b64 = b64url_encode(payload_canon)
    signing_input = (protected_b64 + "." + payload_b64).encode("ascii")
    sig_bytes = b64url_decode(sig_b64)

    # EdDSA
    if alg == "EdDSA":
        pub = load_public_key_from_jwk(jwk)
        if isinstance(pub, ed25519.Ed25519PublicKey):
            pub.verify(sig_bytes, signing_input)
            return
        raise ValueError("Resolved key is not an Ed25519 public key")

    # ECDSA
    if alg in ("ES256", "ES384"):
        pub_key, size = load_public_key_from_jwk(jwk)
        if not isinstance(pub_key, ec.EllipticCurvePublicKey):
            raise ValueError("Resolved key is not an EC public key")
        if alg == "ES256":
            h = hashes.SHA256()
        else:
            h = hashes.SHA384()
        der = ecdsa_der_signature_from_raw(sig_bytes, size)
        pub_key.verify(der, signing_input, ec.ECDSA(h))
        return

    raise ValueError(f"Unsupported JWS alg: {alg}")


# ---------------------------
# Commands
# ---------------------------

def cmd_canon(args: argparse.Namespace) -> int:
    obj = load_json(Path(args.input))
    print(jcs_canonicalize(obj))
    return 0


def cmd_digest_tool(args: argparse.Namespace) -> int:
    tool = load_json(Path(args.input))
    if not isinstance(tool, dict):
        raise SystemExit("Tool definition must be a JSON object")
    canonical, digest = compute_tool_digest(tool)
    if args.show_canonical:
        print(canonical)
    print(digest)
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    tbom = load_json(Path(args.tbom))
    if not isinstance(tbom, dict):
        raise SystemExit("TBOM must be a JSON object")

    schema = load_json(Path(args.schema))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(tbom), key=lambda e: e.path)
    if errors:
        for err in errors:
            path = ".".join(str(p) for p in err.path) or "<root>"
            print(f"[SCHEMA] {path}: {err.message}", file=sys.stderr)
        return 2

    # verify tool digests
    tools = tbom.get("tools")
    if not isinstance(tools, list):
        raise SystemExit("TBOM tools must be an array")
    ok = True
    for i, t in enumerate(tools):
        if not isinstance(t, dict):
            print(f"[FAIL] tools[{i}] is not an object", file=sys.stderr)
            ok = False
            continue
        dd = t.get("definitionDigest")
        if not isinstance(dd, dict):
            print(f"[FAIL] tools[{i}] missing definitionDigest", file=sys.stderr)
            ok = False
            continue
        expected = dd.get("value")
        canonical, computed = compute_tool_digest(t)
        if expected != computed:
            print(f"[FAIL] tools[{i}] {t.get('name')}: definitionDigest mismatch", file=sys.stderr)
            print(f"  expected: {expected}", file=sys.stderr)
            print(f"  computed: {computed}", file=sys.stderr)
            if args.debug:
                print(f"  canonical: {canonical}", file=sys.stderr)
            ok = False
        covers = dd.get("covers")
        if covers is not None:
            try:
                expected_covers = definition_digest_covers(t)
            except ValueError as e:
                print(f"[FAIL] tools[{i}] {t.get('name')}: {e}", file=sys.stderr)
                ok = False
            else:
                if covers != expected_covers:
                    print(f"[FAIL] tools[{i}] {t.get('name')}: definitionDigest.covers mismatch", file=sys.stderr)
                    print(f"  expected: {expected_covers}", file=sys.stderr)
                    print(f"  found: {covers}", file=sys.stderr)
                    ok = False

    # optional: verify signatures with local keys doc
    if args.keys_schema and not args.keys:
        raise SystemExit("--keys-schema requires --keys")

    if args.keys:
        keys_doc = load_json(Path(args.keys))
        if args.keys_schema:
            keys_schema = load_json(Path(args.keys_schema))
            key_validator = Draft202012Validator(keys_schema, format_checker=FormatChecker())
            key_errors = sorted(key_validator.iter_errors(keys_doc), key=lambda e: e.path)
            if key_errors:
                for err in key_errors:
                    path = ".".join(str(p) for p in err.path) or "<root>"
                    print(f"[KEYS SCHEMA] {path}: {err.message}", file=sys.stderr)
                return 2
        sigs = tbom.get("signatures")
        if isinstance(sigs, list):
            for j, s in enumerate(sigs):
                if not isinstance(s, dict):
                    continue
                if s.get("type") != "jws":
                    continue
                try:
                    verify_tbom_jws_detached(tbom, s, keys_doc)
                except Exception as e:
                    ok = False
                    print(f"[FAIL] signatures[{j}] ({s.get('role')}): JWS verification failed: {e}", file=sys.stderr)

    if ok:
        print("OK")
        return 0
    return 2


def cmd_generate(args: argparse.Namespace) -> int:
    subject = load_json(Path(args.subject))
    if not isinstance(subject, dict):
        raise SystemExit("subject must be a JSON object")

    tools_list_obj = load_json(Path(args.tools_list))
    tools: Any
    if isinstance(tools_list_obj, dict) and "tools" in tools_list_obj:
        tools = tools_list_obj["tools"]
    else:
        tools = tools_list_obj
    if not isinstance(tools, list):
        raise SystemExit("tools-list must be a JSON array or an object with a 'tools' array")

    tbom: Dict[str, Any] = {
        "tbomVersion": "1.0.2",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "createdAt": now_rfc3339(),
        "subject": subject,
        "tools": [],
        "signatures": [
            {
                "role": "supplier",
                "type": "jws",
                "algorithm": "Ed25519",
                "keyId": "https://example.com/.well-known/tbom-keys.json#CHANGE-ME",
                "signedAt": now_rfc3339(),
                "coverage": "tbomPayload",
                "value": "<detached-jws-compact-serialization>"
            }
        ],
    }

    for t in tools:
        if not isinstance(t, dict):
            continue
        # Copy fields we care about
        tool_entry: Dict[str, Any] = {
            k: v for k, v in t.items()
            if k in ("toolId", "name", "description", "inputSchema", "outputSchema", "annotations")
        }
        canonical, digest = compute_tool_digest(tool_entry)
        tool_entry["definitionDigest"] = {
            "algorithm": "sha256",
            "value": digest,
            "canonicalization": "rfc8785",
            "covers": definition_digest_covers(tool_entry),
        }
        tbom["tools"].append(tool_entry)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(dump_json(tbom, pretty=True), encoding="utf-8")
    print(args.output)
    return 0


def cmd_sign_jws(args: argparse.Namespace) -> int:
    tbom = load_json(Path(args.input))
    if not isinstance(tbom, dict):
        raise SystemExit("TBOM must be a JSON object")
    private_jwk = load_json(Path(args.key))
    if not isinstance(private_jwk, dict):
        raise SystemExit("Private key must be a JSON object (JWK)")

    tbom_algorithm = args.algorithm
    key_id = args.kid
    jws = sign_tbom_jws_detached(
        tbom,
        tbom_algorithm=tbom_algorithm,
        key_id=key_id,
        private_jwk=private_jwk,
        typ=args.typ,
    )

    sig_entry = {
        "role": args.role,
        "type": "jws",
        "algorithm": tbom_algorithm,
        "keyId": key_id,
        "signedAt": now_rfc3339(),
        "coverage": "tbomPayload",
        "value": jws,
    }

    # Replace or append signature
    sigs = tbom.get("signatures")
    if not isinstance(sigs, list):
        tbom["signatures"] = [sig_entry]
    else:
        sigs.append(sig_entry)

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(dump_json(tbom, pretty=True), encoding="utf-8")
    print(args.output)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tbomctl.py")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_canon = sub.add_parser("canon", help="Print canonical JSON (RFC8785-like)")
    p_canon.add_argument("input")
    p_canon.set_defaults(func=cmd_canon)

    p_dt = sub.add_parser("digest-tool", help="Compute ToolDefinition definitionDigest value")
    p_dt.add_argument("input")
    p_dt.add_argument("--show-canonical", action="store_true", help="Print canonical digest input JSON first")
    p_dt.set_defaults(func=cmd_digest_tool)

    p_chk = sub.add_parser("check", help="Validate TBOM against schema and verify internal digests")
    p_chk.add_argument("--schema", required=True, help="Path to tbom schema JSON")
    p_chk.add_argument("--keys", help="Optional: path to local tbom-keys.json for verifying JWS signatures")
    p_chk.add_argument("--keys-schema", help="Optional: path to tbom-keys schema JSON for validating keys document")
    p_chk.add_argument("--debug", action="store_true", help="Print canonical digest inputs on mismatch")
    p_chk.add_argument("tbom")
    p_chk.set_defaults(func=cmd_check)

    p_gen = sub.add_parser("generate", help="Generate a TBOM skeleton from subject.json + tools/list JSON")
    p_gen.add_argument("--subject", required=True, help="Path to subject.json")
    p_gen.add_argument("--tools-list", required=True, help="Path to tools/list JSON (array or {tools:[...]})")
    p_gen.add_argument("--output", required=True, help="Path to write TBOM JSON")
    p_gen.set_defaults(func=cmd_generate)

    p_sign = sub.add_parser("sign-jws", help="Add a supplier/registry/enterprise JWS signature to an unsigned TBOM")
    p_sign.add_argument("--key", required=True, help="Path to private key JWK (Ed25519 or EC)")
    p_sign.add_argument("--kid", required=True, help="Key ID URI (recommended: keys doc URL with #fragment)")
    p_sign.add_argument("--algorithm", required=True, choices=["Ed25519", "ECDSA-P256", "ECDSA-P384"])
    p_sign.add_argument("--role", default="supplier", choices=["supplier", "registry", "enterprise"])
    p_sign.add_argument("--typ", default="JWS", help="JWS 'typ' header value")
    p_sign.add_argument("--input", required=True, help="Path to TBOM JSON (unsigned or partially signed)")
    p_sign.add_argument("--output", required=True, help="Path to write signed TBOM JSON")
    p_sign.set_defaults(func=cmd_sign_jws)

    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
