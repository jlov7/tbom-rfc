import builtins
import json
import runpy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

import tbomctl


def _make_ed25519_pair(kid: str = "kid-ed25519") -> dict[str, object]:
    priv = ed25519.Ed25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "key_id": f"https://example.com/keys.json#{kid}",
        "private": {"kty": "OKP", "crv": "Ed25519", "d": tbomctl.b64url_encode(priv_bytes)},
        "public": {"kty": "OKP", "crv": "Ed25519", "x": tbomctl.b64url_encode(pub_bytes), "kid": kid},
    }


def _make_ec_pair(curve: ec.EllipticCurve, crv: str, kid: str) -> dict[str, object]:
    priv = ec.generate_private_key(curve)
    numbers = priv.private_numbers()
    size = (curve.key_size + 7) // 8
    return {
        "key_id": f"https://example.com/keys.json#{kid}",
        "size": size,
        "private": {
            "kty": "EC",
            "crv": crv,
            "d": tbomctl.b64url_encode(numbers.private_value.to_bytes(size, "big")),
            "x": tbomctl.b64url_encode(numbers.public_numbers.x.to_bytes(size, "big")),
            "y": tbomctl.b64url_encode(numbers.public_numbers.y.to_bytes(size, "big")),
        },
        "public": {
            "kty": "EC",
            "crv": crv,
            "x": tbomctl.b64url_encode(numbers.public_numbers.x.to_bytes(size, "big")),
            "y": tbomctl.b64url_encode(numbers.public_numbers.y.to_bytes(size, "big")),
            "kid": kid,
        },
    }


def _minimal_tbom() -> dict[str, object]:
    return {"tbomVersion": "1.0.2", "subject": {"name": "example"}, "tools": [], "signatures": []}


def test_import_errors_for_dependencies(monkeypatch):
    tbomctl_path = Path(tbomctl.__file__)

    real_import = builtins.__import__

    def import_jsonschema(name, *args, **kwargs):
        if name == "jsonschema":
            raise ImportError("missing")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", import_jsonschema)
    with pytest.raises(SystemExit) as excinfo:
        runpy.run_path(str(tbomctl_path), run_name="__main__")
    assert "jsonschema" in str(excinfo.value)

    def import_jcs(name, *args, **kwargs):
        if name == "jcs":
            raise ImportError("missing")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", import_jcs)
    with pytest.raises(SystemExit) as excinfo:
        runpy.run_path(str(tbomctl_path), run_name="__main__")
    assert "jcs" in str(excinfo.value)

    def import_crypto(name, *args, **kwargs):
        if name.startswith("cryptography"):
            raise ImportError("missing")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", import_crypto)
    with pytest.raises(SystemExit) as excinfo:
        runpy.run_path(str(tbomctl_path), run_name="__main__")
    assert "cryptography" in str(excinfo.value)


def test_jcs_canonicalize_str_return(monkeypatch):
    monkeypatch.setattr(tbomctl.jcs, "canonicalize", lambda obj: '{"a":1}')
    assert tbomctl.jcs_canonicalize({"a": 1}) == '{"a":1}'


def test_dump_json_compact():
    assert tbomctl.dump_json({"a": 1}, pretty=False).strip() == '{"a": 1}'


def test_resource_digest_input_without_mime_type():
    resource = {"uri": "tbom://x", "description": "res", "mimeType": None}
    digest_input = tbomctl.resource_digest_input(resource)
    assert "mimeType" not in digest_input


def test_prompt_digest_input_without_arguments():
    prompt = {"name": "p", "description": "d", "arguments": None}
    digest_input = tbomctl.prompt_digest_input(prompt)
    assert "arguments" not in digest_input


def test_load_private_key_ed25519_bad_length():
    jwk = {"kty": "OKP", "crv": "Ed25519", "d": tbomctl.b64url_encode(b"short")}
    with pytest.raises(ValueError):
        tbomctl.load_private_key_from_jwk(jwk)


def test_load_private_key_success_ed25519_and_ec():
    ed_pair = _make_ed25519_pair()
    assert tbomctl.load_private_key_from_jwk(ed_pair["private"])

    p256 = _make_ec_pair(ec.SECP256R1(), "P-256", "kid-p256")
    assert tbomctl.load_private_key_from_jwk(p256["private"])

    p384 = _make_ec_pair(ec.SECP384R1(), "P-384", "kid-p384")
    assert tbomctl.load_private_key_from_jwk(p384["private"])


def test_load_private_key_unsupported_kty():
    with pytest.raises(ValueError):
        tbomctl.load_private_key_from_jwk({"kty": "RSA"})


def test_load_public_key_errors():
    with pytest.raises(ValueError):
        tbomctl.load_public_key_from_jwk({"kty": "OKP", "crv": "Ed25519"})
    with pytest.raises(ValueError):
        tbomctl.load_public_key_from_jwk({"kty": "OKP", "crv": "Ed25519", "x": tbomctl.b64url_encode(b"bad")})


def test_load_public_key_ec_missing_xy_and_unsupported_kty():
    with pytest.raises(ValueError):
        tbomctl.load_public_key_from_jwk({"kty": "EC", "crv": "P-256", "x": tbomctl.b64url_encode(b"x")})
    with pytest.raises(ValueError):
        tbomctl.load_public_key_from_jwk({"kty": "RSA"})


def test_load_public_key_success_ec():
    p256 = _make_ec_pair(ec.SECP256R1(), "P-256", "kid-p256")
    pub, size = tbomctl.load_public_key_from_jwk(p256["public"])
    assert size == 32
    assert isinstance(pub, ec.EllipticCurvePublicKey)

    p384 = _make_ec_pair(ec.SECP384R1(), "P-384", "kid-p384")
    pub, size = tbomctl.load_public_key_from_jwk(p384["public"])
    assert size == 48
    assert isinstance(pub, ec.EllipticCurvePublicKey)


def test_ecdsa_signature_roundtrip():
    key = ec.generate_private_key(ec.SECP256R1())
    data = b"hello"
    der = key.sign(data, ec.ECDSA(hashes.SHA256()))
    raw = tbomctl.ecdsa_raw_signature_from_der(der, 32)
    der_roundtrip = tbomctl.ecdsa_der_signature_from_raw(raw, 32)
    key.public_key().verify(der_roundtrip, data, ec.ECDSA(hashes.SHA256()))


def test_sign_tbom_jws_detached_success_and_mismatch():
    tbom = _minimal_tbom()
    ed_pair = _make_ed25519_pair()
    jws = tbomctl.sign_tbom_jws_detached(
        tbom,
        tbom_algorithm="Ed25519",
        key_id=ed_pair["key_id"],
        private_jwk=ed_pair["private"],
    )
    assert ".." in jws

    p256 = _make_ec_pair(ec.SECP256R1(), "P-256", "kid-p256")
    jws_ec = tbomctl.sign_tbom_jws_detached(
        tbom,
        tbom_algorithm="ECDSA-P256",
        key_id=p256["key_id"],
        private_jwk=p256["private"],
    )
    assert ".." in jws_ec

    p384 = _make_ec_pair(ec.SECP384R1(), "P-384", "kid-p384")
    jws_ec2 = tbomctl.sign_tbom_jws_detached(
        tbom,
        tbom_algorithm="ECDSA-P384",
        key_id=p384["key_id"],
        private_jwk=p384["private"],
    )
    assert ".." in jws_ec2

    with pytest.raises(ValueError):
        tbomctl.sign_tbom_jws_detached(
            tbom,
            tbom_algorithm="Ed25519",
            key_id=p256["key_id"],
            private_jwk=p256["private"],
        )
    with pytest.raises(ValueError):
        tbomctl.sign_tbom_jws_detached(
            tbom,
            tbom_algorithm="ECDSA-P384",
            key_id=p256["key_id"],
            private_jwk=p256["private"],
        )


def test_sign_tbom_jws_detached_unsupported_cases(monkeypatch):
    tbom = _minimal_tbom()
    ec_priv = ec.generate_private_key(ec.SECP256R1())

    monkeypatch.setattr(tbomctl, "load_private_key_from_jwk", lambda _jwk: ec_priv)
    monkeypatch.setattr(tbomctl, "jws_alg_for_tbom_algorithm", lambda _a: "ES256")
    with pytest.raises(ValueError):
        tbomctl.sign_tbom_jws_detached(
            tbom,
            tbom_algorithm="UNKNOWN",
            key_id="kid",
            private_jwk={"crv": "P-521"},
        )

    monkeypatch.setattr(tbomctl, "load_private_key_from_jwk", lambda _jwk: object())
    monkeypatch.setattr(tbomctl, "jws_alg_for_tbom_algorithm", lambda _a: "none")
    with pytest.raises(ValueError):
        tbomctl.sign_tbom_jws_detached(
            tbom,
            tbom_algorithm="UNKNOWN",
            key_id="kid",
            private_jwk={},
        )


def test_load_key_from_keys_doc_success():
    key_doc = {"keys": [{"kid": "kid1", "kty": "OKP"}]}
    key = tbomctl.load_key_from_keys_doc(key_doc, "kid1")
    assert key["kid"] == "kid1"


def test_load_key_from_keys_doc_skips_non_matching():
    key_doc = {"keys": ["bad", {"kid": "other"}, {"kid": "match"}]}
    key = tbomctl.load_key_from_keys_doc(key_doc, "match")
    assert key["kid"] == "match"


def test_verify_tbom_jws_detached_success_paths():
    tbom = _minimal_tbom()
    ed_pair = _make_ed25519_pair()
    jws = tbomctl.sign_tbom_jws_detached(
        tbom,
        tbom_algorithm="Ed25519",
        key_id=ed_pair["key_id"],
        private_jwk=ed_pair["private"],
    )
    tbomctl.verify_tbom_jws_detached(
        tbom,
        {"type": "jws", "value": jws, "keyId": ed_pair["key_id"], "algorithm": "Ed25519"},
        {"keys": [ed_pair["public"]]},
    )

    p256 = _make_ec_pair(ec.SECP256R1(), "P-256", "kid-p256")
    jws_ec = tbomctl.sign_tbom_jws_detached(
        tbom,
        tbom_algorithm="ECDSA-P256",
        key_id=p256["key_id"],
        private_jwk=p256["private"],
    )
    tbomctl.verify_tbom_jws_detached(
        tbom,
        {"type": "jws", "value": jws_ec, "keyId": p256["key_id"], "algorithm": "ECDSA-P256"},
        {"keys": [p256["public"]]},
    )


def test_verify_tbom_jws_detached_error_branches(monkeypatch):
    tbom = _minimal_tbom()
    ed_pair = _make_ed25519_pair()
    protected = {"alg": "EdDSA", "kid": "kid-x"}
    protected_b64 = tbomctl.b64url_encode(json.dumps(protected).encode("utf-8"))
    bad_jws = f"{protected_b64}.AA.BB"
    with pytest.raises(ValueError):
        tbomctl.verify_tbom_jws_detached(
            tbom,
            {"type": "jws", "value": bad_jws, "keyId": ed_pair["key_id"], "algorithm": "Ed25519"},
            {"keys": [ed_pair["public"]]},
        )

    detached_jws = f"{protected_b64}..AA"
    with pytest.raises(ValueError):
        tbomctl.verify_tbom_jws_detached(
            tbom, {"type": "jws", "value": detached_jws, "algorithm": "Ed25519"}, {"keys": []}
        )
    with pytest.raises(ValueError):
        tbomctl.verify_tbom_jws_detached(tbom, {"type": "jws", "value": detached_jws, "keyId": "kid"}, {"keys": []})

    bad_alg_header = tbomctl.b64url_encode(json.dumps({"alg": "ES256", "kid": "kid-x"}).encode("utf-8"))
    bad_alg_jws = f"{bad_alg_header}..AA"
    with pytest.raises(ValueError):
        tbomctl.verify_tbom_jws_detached(
            tbom,
            {"type": "jws", "value": bad_alg_jws, "keyId": "kid-x", "algorithm": "Ed25519"},
            {"keys": [{"kid": "kid-x", "kty": "OKP", "crv": "Ed25519", "x": ed_pair["public"]["x"]}]},
        )

    mismatch_header = tbomctl.b64url_encode(json.dumps({"alg": "EdDSA", "kid": "kid-other"}).encode("utf-8"))
    mismatch_jws = f"{mismatch_header}..AA"
    with pytest.raises(ValueError):
        tbomctl.verify_tbom_jws_detached(
            tbom,
            {
                "type": "jws",
                "value": mismatch_jws,
                "keyId": "https://example.com/keys.json#kid-x",
                "algorithm": "Ed25519",
            },
            {"keys": [{"kid": "kid-x", "kty": "OKP", "crv": "Ed25519", "x": ed_pair["public"]["x"]}]},
        )

    no_kid_header = tbomctl.b64url_encode(json.dumps({"alg": "EdDSA"}).encode("utf-8"))
    no_kid_jws = f"{no_kid_header}..AA"
    with pytest.raises(ValueError):
        tbomctl.verify_tbom_jws_detached(
            tbom,
            {"type": "jws", "value": no_kid_jws, "keyId": "https://example.com/keys.json", "algorithm": "Ed25519"},
            {"keys": []},
        )

    match_header = tbomctl.b64url_encode(json.dumps({"alg": "EdDSA", "kid": "kid-ed25519"}).encode("utf-8"))
    with pytest.raises(ValueError):
        tbomctl.verify_tbom_jws_detached(
            tbom,
            {"type": "jws", "value": f"{match_header}..AA", "keyId": ed_pair["key_id"], "algorithm": "Ed25519"},
            {"keys": [{"kid": "kid-ed25519", "kty": "EC", "crv": "P-256"}]},
        )
    match_header_es256 = tbomctl.b64url_encode(json.dumps({"alg": "ES256", "kid": "kid-ed25519"}).encode("utf-8"))
    with pytest.raises(ValueError):
        tbomctl.verify_tbom_jws_detached(
            tbom,
            {
                "type": "jws",
                "value": f"{match_header_es256}..AA",
                "keyId": ed_pair["key_id"],
                "algorithm": "ECDSA-P256",
            },
            {"keys": [{"kid": "kid-ed25519", "kty": "OKP", "crv": "Ed25519"}]},
        )
    match_header_es384 = tbomctl.b64url_encode(json.dumps({"alg": "ES384", "kid": "kid-ed25519"}).encode("utf-8"))
    with pytest.raises(ValueError):
        tbomctl.verify_tbom_jws_detached(
            tbom,
            {
                "type": "jws",
                "value": f"{match_header_es384}..AA",
                "keyId": ed_pair["key_id"],
                "algorithm": "ECDSA-P384",
            },
            {"keys": [{"kid": "kid-ed25519", "kty": "EC", "crv": "P-256"}]},
        )

    monkeypatch.setattr(tbomctl, "load_public_key_from_jwk", lambda _jwk: object())
    with pytest.raises(ValueError):
        tbomctl.verify_tbom_jws_detached(
            tbom,
            {"type": "jws", "value": f"{match_header}..AA", "keyId": ed_pair["key_id"], "algorithm": "Ed25519"},
            {"keys": [{"kid": "kid-ed25519", "kty": "OKP", "crv": "Ed25519", "x": ed_pair["public"]["x"]}]},
        )

    p256 = _make_ec_pair(ec.SECP256R1(), "P-256", "kid-p256")
    match_header_ec = tbomctl.b64url_encode(json.dumps({"alg": "ES256", "kid": "kid-p256"}).encode("utf-8"))

    def fake_pub(_jwk):
        return ed25519.Ed25519PrivateKey.generate().public_key()

    monkeypatch.setattr(tbomctl, "load_public_key_from_jwk", fake_pub)
    with pytest.raises(ValueError):
        tbomctl.verify_tbom_jws_detached(
            tbom,
            {
                "type": "jws",
                "value": f"{match_header_ec}..AA",
                "keyId": p256["key_id"],
                "algorithm": "ECDSA-P256",
            },
            {"keys": [p256["public"]]},
        )

    monkeypatch.setattr(tbomctl, "load_public_key_from_jwk", lambda _jwk: (object(), 32))
    with pytest.raises(ValueError):
        tbomctl.verify_tbom_jws_detached(
            tbom,
            {"type": "jws", "value": f"{match_header_ec}..AA", "keyId": p256["key_id"], "algorithm": "ECDSA-P256"},
            {"keys": [p256["public"]]},
        )

    monkeypatch.setattr(tbomctl, "jws_alg_for_tbom_algorithm", lambda _a: "none")
    unsupported_header = tbomctl.b64url_encode(json.dumps({"alg": "none", "kid": "kid-x"}).encode("utf-8"))
    with pytest.raises(ValueError):
        tbomctl.verify_tbom_jws_detached(
            tbom,
            {"type": "jws", "value": f"{unsupported_header}..AA", "keyId": "kid-x", "algorithm": "Ed25519"},
            {"keys": [{"kid": "kid-x", "kty": "OKP", "crv": "Ed25519", "x": ed_pair["public"]["x"]}]},
        )


def test_verify_tbom_jws_detached_header_kid_from_url():
    tbom = _minimal_tbom()
    ed_pair = _make_ed25519_pair(kid="kid-url")
    jws = tbomctl.sign_tbom_jws_detached(
        tbom,
        tbom_algorithm="Ed25519",
        key_id="https://example.com/keys.json",
        private_jwk=ed_pair["private"],
    )
    public_key = dict(ed_pair["public"])
    public_key["kid"] = "https://example.com/keys.json"
    tbomctl.verify_tbom_jws_detached(
        tbom,
        {"type": "jws", "value": jws, "keyId": "https://example.com/keys.json", "algorithm": "Ed25519"},
        {"keys": [public_key]},
    )


def test_verify_tbom_jws_detached_header_kid_mismatch():
    tbom = _minimal_tbom()
    header = tbomctl.b64url_encode(json.dumps({"alg": "EdDSA", "kid": "kid-other"}).encode("utf-8"))
    jws = f"{header}..AA"
    with pytest.raises(ValueError) as excinfo:
        tbomctl.verify_tbom_jws_detached(
            tbom,
            {"type": "jws", "value": jws, "keyId": "https://example.com/keys.json#kid-x", "algorithm": "Ed25519"},
            {"keys": [{"kid": "kid-x", "kty": "OKP", "crv": "Ed25519", "x": "AA"}]},
        )
    assert "header kid" in str(excinfo.value)


def test_verify_tbom_jws_detached_header_kid_missing_with_fragment():
    tbom = _minimal_tbom()
    pair = _make_ed25519_pair()
    payload = tbomctl.tbom_payload_for_signing(tbom)
    payload_canon = tbomctl.jcs_canonicalize(payload).encode("utf-8")
    protected = {"alg": "EdDSA", "typ": "JWS"}
    protected_b64 = tbomctl.b64url_encode(json.dumps(protected, separators=(",", ":")).encode("utf-8"))
    payload_b64 = tbomctl.b64url_encode(payload_canon)
    signing_input = (protected_b64 + "." + payload_b64).encode("ascii")
    priv = tbomctl.load_private_key_from_jwk(pair["private"])
    sig = priv.sign(signing_input)
    jws = protected_b64 + ".." + tbomctl.b64url_encode(sig)
    tbomctl.verify_tbom_jws_detached(
        tbom,
        {"type": "jws", "value": jws, "keyId": pair["key_id"], "algorithm": "Ed25519"},
        {"keys": [pair["public"]]},
    )


def _write_json(tmp_path: Path, name: str, data: object) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_cmd_digest_tool_requires_object(tmp_path):
    input_path = _write_json(tmp_path, "tool.json", ["not", "object"])

    class Args:
        input = str(input_path)
        show_canonical = False

    with pytest.raises(SystemExit):
        tbomctl.cmd_digest_tool(Args())


def test_cmd_check_schema_errors(tmp_path, capsys):
    schema_path = Path("tbom-schema-v1.0.2.json")
    tbom_path = _write_json(tmp_path, "bad.json", {})

    class Args:
        tbom = str(tbom_path)
        schema = str(schema_path)
        keys = None
        keys_schema = None
        debug = False

    assert tbomctl.cmd_check(Args()) == 2
    assert "[SCHEMA]" in capsys.readouterr().err


def test_cmd_check_tbom_not_object(tmp_path):
    schema_path = _write_json(tmp_path, "schema.json", {"type": "object"})
    tbom_path = _write_json(tmp_path, "tbom.json", ["bad"])

    class Args:
        tbom = str(tbom_path)
        schema = str(schema_path)
        keys = None
        keys_schema = None
        debug = False

    with pytest.raises(SystemExit):
        tbomctl.cmd_check(Args())


def test_cmd_check_tools_not_list(tmp_path):
    schema_path = _write_json(tmp_path, "schema.json", {"type": "object"})
    tbom_path = _write_json(tmp_path, "tbom.json", {"tools": {"not": "list"}})

    class Args:
        tbom = str(tbom_path)
        schema = str(schema_path)
        keys = None
        keys_schema = None
        debug = False

    with pytest.raises(SystemExit):
        tbomctl.cmd_check(Args())


def test_cmd_check_definition_digest_failures(tmp_path, capsys):
    schema_path = _write_json(tmp_path, "schema.json", {"type": "object"})
    valid_tool = {"name": "ok", "description": "d", "inputSchema": {}}
    _, digest = tbomctl.compute_tool_digest(valid_tool)
    tbom = {
        "tools": [
            "not-a-dict",
            {"name": "missing-dd", "description": "d", "inputSchema": {}},
            {"name": "bad", "inputSchema": {}, "definitionDigest": {"value": "sha256:bad"}},
            {
                "name": "mismatch",
                "description": "d",
                "inputSchema": {},
                "definitionDigest": {"value": "sha256:bad", "covers": "{name}"},
            },
            {"name": "ok", "description": "d", "inputSchema": {}, "definitionDigest": {"value": digest}},
        ]
    }
    tbom_path = _write_json(tmp_path, "tbom.json", tbom)

    class Args:
        tbom = str(tbom_path)
        schema = str(schema_path)
        keys = None
        keys_schema = None
        debug = True

    assert tbomctl.cmd_check(Args()) == 2
    assert "[FAIL]" in capsys.readouterr().err


def test_cmd_check_covers_error_and_mismatch(tmp_path, monkeypatch, capsys):
    schema_path = _write_json(tmp_path, "schema.json", {"type": "object"})
    tbom = {
        "tools": [],
        "resources": [
            {
                "uri": "tbom://r",
                "description": "res",
                "definitionDigest": {"value": "sha256:bad", "covers": "{uri}"},
            }
        ],
        "prompts": [
            {
                "name": "p",
                "description": "d",
                "definitionDigest": {"value": "sha256:bad", "covers": "{name}"},
            }
        ],
    }
    tbom_path = _write_json(tmp_path, "tbom.json", tbom)

    monkeypatch.setattr(tbomctl, "resource_digest_covers", lambda _r: (_ for _ in ()).throw(ValueError("nope")))

    class Args:
        tbom = str(tbom_path)
        schema = str(schema_path)
        keys = None
        keys_schema = None
        debug = False

    assert tbomctl.cmd_check(Args()) == 2
    assert "covers" in capsys.readouterr().err


def test_cmd_check_keys_schema_requires_keys(tmp_path):
    schema_path = _write_json(tmp_path, "schema.json", {"type": "object"})
    tbom_path = _write_json(tmp_path, "tbom.json", {"tools": []})

    class Args:
        tbom = str(tbom_path)
        schema = str(schema_path)
        keys = None
        keys_schema = str(schema_path)
        debug = False

    with pytest.raises(SystemExit):
        tbomctl.cmd_check(Args())


def test_cmd_check_keys_schema_errors(tmp_path, capsys):
    schema_path = _write_json(tmp_path, "schema.json", {"type": "object"})
    keys_schema_path = _write_json(tmp_path, "keys-schema.json", {"type": "object", "required": ["keys"]})
    tbom_path = _write_json(tmp_path, "tbom.json", {"tools": [], "signatures": []})
    keys_path = _write_json(tmp_path, "keys.json", {})

    class Args:
        tbom = str(tbom_path)
        schema = str(schema_path)
        keys = str(keys_path)
        keys_schema = str(keys_schema_path)
        debug = False

    assert tbomctl.cmd_check(Args()) == 2
    assert "[KEYS SCHEMA]" in capsys.readouterr().err


def test_cmd_check_keys_schema_valid_and_signature_skip(tmp_path, capsys):
    schema_path = _write_json(tmp_path, "schema.json", {"type": "object"})
    keys_schema_path = _write_json(tmp_path, "keys-schema.json", {"type": "object", "required": ["keys"]})
    tbom_path = _write_json(tmp_path, "tbom.json", {"tools": [], "signatures": "skip"})
    keys_path = _write_json(tmp_path, "keys.json", {"keys": []})

    class Args:
        tbom = str(tbom_path)
        schema = str(schema_path)
        keys = str(keys_path)
        keys_schema = str(keys_schema_path)
        debug = False

    assert tbomctl.cmd_check(Args()) == 0
    assert "OK" in capsys.readouterr().out


def test_cmd_check_signature_failure(tmp_path, monkeypatch, capsys):
    schema_path = _write_json(tmp_path, "schema.json", {"type": "object"})
    tbom_path = _write_json(
        tmp_path,
        "tbom.json",
        {
            "tools": [],
            "signatures": ["bad", {"type": "other"}, {"type": "jws", "value": "a..b"}],
        },
    )
    keys_path = _write_json(tmp_path, "keys.json", {"keys": []})

    monkeypatch.setattr(tbomctl, "verify_tbom_jws_detached", lambda *_a, **_k: (_ for _ in ()).throw(ValueError("bad")))

    class Args:
        tbom = str(tbom_path)
        schema = str(schema_path)
        keys = str(keys_path)
        keys_schema = None
        debug = False

    assert tbomctl.cmd_check(Args()) == 2
    assert "JWS verification failed" in capsys.readouterr().err


def test_cmd_check_ok(tmp_path, capsys):
    schema_path = Path("tbom-schema-v1.0.2.json")
    tbom_path = Path("tbom-example-full-v1.0.2.json")

    class Args:
        tbom = str(tbom_path)
        schema = str(schema_path)
        keys = None
        keys_schema = None
        debug = False

    assert tbomctl.cmd_check(Args()) == 0
    assert "OK" in capsys.readouterr().out


def test_cmd_generate_invalid_inputs(tmp_path):
    subject_path = _write_json(tmp_path, "subject.json", ["bad"])
    tools_path = _write_json(tmp_path, "tools.json", [])

    class Args:
        subject = str(subject_path)
        tools_list = str(tools_path)
        output = str(tmp_path / "out.json")

    with pytest.raises(SystemExit):
        tbomctl.cmd_generate(Args())

    subject_path = _write_json(tmp_path, "subject.json", {"name": "x"})
    tools_path = _write_json(tmp_path, "tools.json", {"no": "list"})

    Args.subject = str(subject_path)
    Args.tools_list = str(tools_path)
    with pytest.raises(SystemExit):
        tbomctl.cmd_generate(Args())


def test_cmd_generate_tools_list_object(tmp_path):
    subject_path = _write_json(tmp_path, "subject.json", {"name": "x"})
    tools_path = _write_json(
        tmp_path,
        "tools.json",
        {"tools": [{"name": "t1", "description": "d", "inputSchema": {}}, "skip"]},
    )

    class Args:
        subject = str(subject_path)
        tools_list = str(tools_path)
        output = str(tmp_path / "out.json")

    assert tbomctl.cmd_generate(Args()) == 0
    out = json.loads(Path(Args.output).read_text(encoding="utf-8"))
    assert len(out["tools"]) == 1
    assert out["tools"][0]["definitionDigest"]["value"].startswith("sha256:")


def test_cmd_generate_tools_list_array(tmp_path):
    subject_path = _write_json(tmp_path, "subject.json", {"name": "x"})
    tools_path = _write_json(
        tmp_path,
        "tools.json",
        [{"name": "t1", "description": "d", "inputSchema": {}}],
    )

    class Args:
        subject = str(subject_path)
        tools_list = str(tools_path)
        output = str(tmp_path / "out.json")

    assert tbomctl.cmd_generate(Args()) == 0


def test_cmd_sign_jws_invalid_inputs(tmp_path):
    tbom_path = _write_json(tmp_path, "tbom.json", ["bad"])
    key_path = _write_json(tmp_path, "key.json", {"kty": "OKP"})

    class Args:
        input = str(tbom_path)
        key = str(key_path)
        kid = "https://example.com/keys#kid"
        algorithm = "Ed25519"
        role = "supplier"
        typ = "JWS"
        output = str(tmp_path / "out.json")

    with pytest.raises(SystemExit):
        tbomctl.cmd_sign_jws(Args())

    tbom_path = _write_json(tmp_path, "tbom.json", {"tbomVersion": "1.0.2", "subject": {"name": "x"}, "tools": []})
    key_path = _write_json(tmp_path, "key.json", ["bad"])
    Args.input = str(tbom_path)
    Args.key = str(key_path)
    with pytest.raises(SystemExit):
        tbomctl.cmd_sign_jws(Args())


def test_cmd_sign_jws_signature_handling(tmp_path):
    key_path = Path("tbom-testvector-private-ed25519.jwk.json")
    tbom_path = _write_json(
        tmp_path,
        "tbom.json",
        {
            "tbomVersion": "1.0.2",
            "subject": {"name": "x"},
            "tools": [],
            "signatures": "not-a-list",
        },
    )

    class Args:
        input = str(tbom_path)
        key = str(key_path)
        kid = "https://example.com/keys#kid"
        algorithm = "Ed25519"
        role = "supplier"
        typ = "JWS"
        output = str(tmp_path / "out.json")

    assert tbomctl.cmd_sign_jws(Args()) == 0

    tbom_path = _write_json(
        tmp_path,
        "tbom2.json",
        {
            "tbomVersion": "1.0.2",
            "subject": {"name": "x"},
            "tools": [],
            "signatures": [{"value": "keep-me"}],
        },
    )
    Args.input = str(tbom_path)
    Args.output = str(tmp_path / "out2.json")
    assert tbomctl.cmd_sign_jws(Args()) == 0
    out = json.loads(Path(Args.output).read_text(encoding="utf-8"))
    assert len(out["signatures"]) == 2


def test_cmd_verify_drift_invalid_inputs(tmp_path):
    tbom_path = _write_json(tmp_path, "tbom.json", ["bad"])
    tools_path = _write_json(tmp_path, "tools.json", [])

    class Args:
        tbom = str(tbom_path)
        tools_list = str(tools_path)
        verbose = False

    with pytest.raises(SystemExit):
        tbomctl.cmd_verify_drift(Args())

    tbom_path = _write_json(tmp_path, "tbom.json", {"tools": []})
    tools_path = _write_json(tmp_path, "tools.json", {"not": "list"})
    Args.tbom = str(tbom_path)
    Args.tools_list = str(tools_path)
    with pytest.raises(SystemExit):
        tbomctl.cmd_verify_drift(Args())

    tbom_path = _write_json(tmp_path, "tbom.json", {"tools": "bad"})
    tools_path = _write_json(tmp_path, "tools.json", [])
    Args.tbom = str(tbom_path)
    Args.tools_list = str(tools_path)
    with pytest.raises(SystemExit):
        tbomctl.cmd_verify_drift(Args())


def test_cmd_verify_drift_branches(tmp_path, capsys):
    tool_ok = {"toolId": "id-ok", "name": "ok", "description": "d", "inputSchema": {}}
    _, digest_ok = tbomctl.compute_tool_digest(tool_ok)
    tbom = {
        "tools": [
            {
                "toolId": "dup",
                "name": "a",
                "description": "d",
                "inputSchema": {},
                "definitionDigest": {"value": digest_ok},
            },
            {
                "toolId": "dup",
                "name": "b",
                "description": "d",
                "inputSchema": {},
                "definitionDigest": {"value": digest_ok},
            },
            {
                "name": "ambig",
                "description": "d",
                "inputSchema": {},
                "definitionDigest": {"value": digest_ok},
            },
            {
                "name": "ambig",
                "description": "d",
                "inputSchema": {},
                "definitionDigest": {"value": digest_ok},
            },
        ]
    }
    live_tools = [{"name": "ambig", "description": "d", "inputSchema": {}}]
    tbom_path = _write_json(tmp_path, "tbom.json", tbom)
    tools_path = _write_json(tmp_path, "tools.json", live_tools)

    class Args:
        tbom = str(tbom_path)
        tools_list = str(tools_path)
        verbose = False

    assert tbomctl.cmd_verify_drift(Args()) == 1
    assert "DRIFT DETECTED" in capsys.readouterr().out


def test_cmd_verify_drift_drift_and_verbose(tmp_path, capsys):
    tool1 = {"toolId": "id1", "name": "t1", "description": "d1", "inputSchema": {}}
    _, digest1 = tbomctl.compute_tool_digest(tool1)
    tool3 = {"toolId": "id3", "name": "t3", "description": "d3", "inputSchema": {}}
    tool4 = {"toolId": "id4", "name": "t4", "description": "d4", "inputSchema": {}}
    _, digest4 = tbomctl.compute_tool_digest(tool4)
    tbom = {
        "tools": [
            {**tool1, "definitionDigest": {"value": digest1}},
            {"toolId": "id2", "name": "t2", "description": "d2", "inputSchema": {}},
            {**tool3, "definitionDigest": {"value": "sha256:bad"}},
            {**tool4, "definitionDigest": {"value": digest4}},
            {
                "toolId": "id5",
                "name": "t5",
                "description": "d5",
                "inputSchema": {},
                "definitionDigest": {"value": digest1},
            },
            {
                "toolId": "id-missing",
                "name": "t-missing",
                "description": "d",
                "inputSchema": {},
                "definitionDigest": {"value": digest1},
            },
        ]
    }
    live_tools = [
        {**tool1},
        {"toolId": "id2", "name": "t2", "description": "d2", "inputSchema": {}},
        {**tool3},
        {**tool4},
        {"toolId": "id5", "name": "t5", "inputSchema": {}},
        {"toolId": "id-live", "name": "live", "description": "d", "inputSchema": {}},
    ]
    tbom_path = _write_json(tmp_path, "tbom.json", tbom)
    tools_path = _write_json(tmp_path, "tools.json", live_tools)

    class Args:
        tbom = str(tbom_path)
        tools_list = str(tools_path)
        verbose = True

    assert tbomctl.cmd_verify_drift(Args()) == 1
    err = capsys.readouterr().err
    assert "DRIFT" in err


def test_cmd_verify_drift_ok(tmp_path, capsys):
    tool = {"toolId": "id-ok", "name": "ok", "description": "d", "inputSchema": {}}
    _, digest = tbomctl.compute_tool_digest(tool)
    tbom = {"tools": [{**tool, "definitionDigest": {"value": digest}}]}
    tbom_path = _write_json(tmp_path, "tbom.json", tbom)
    tools_path = _write_json(tmp_path, "tools.json", [tool])

    class Args:
        tbom = str(tbom_path)
        tools_list = str(tools_path)
        verbose = False

    assert tbomctl.cmd_verify_drift(Args()) == 0
    assert "No drift" in capsys.readouterr().out


def test_cmd_verify_drift_additional_branches(tmp_path, capsys):
    tool = {"toolId": "id1", "name": "t1", "description": "d1", "inputSchema": {}}
    _, digest = tbomctl.compute_tool_digest(tool)
    name_only = {"name": "name-only", "description": "d", "inputSchema": {}}
    _, name_digest = tbomctl.compute_tool_digest(name_only)
    tbom = {
        "tools": [
            "skip",
            {**tool, "definitionDigest": {"value": "sha256:bad"}},
            {**name_only, "definitionDigest": {"value": name_digest}},
            {
                "toolId": "id-no-name",
                "name": None,
                "description": "d",
                "inputSchema": {},
                "definitionDigest": {"value": digest},
            },
        ]
    }
    live_tools = {
        "tools": [
            "skip-live",
            {},
            {**name_only},
            {**tool},
        ]
    }
    tbom_path = _write_json(tmp_path, "tbom.json", tbom)
    tools_path = _write_json(tmp_path, "tools.json", live_tools)

    class Args:
        tbom = str(tbom_path)
        tools_list = str(tools_path)
        verbose = True

    assert tbomctl.cmd_verify_drift(Args()) == 1
    assert "[WARN]" in capsys.readouterr().err


def test_cmd_verify_drift_verbose_canonical(tmp_path, capsys):
    tool = {"toolId": "id1", "name": "t1", "description": "d1", "inputSchema": {}}
    tbom = {"tools": [{**tool, "definitionDigest": {"value": "sha256:bad"}}]}
    tbom_path = _write_json(tmp_path, "tbom.json", tbom)
    tools_path = _write_json(tmp_path, "tools.json", [tool])

    class Args:
        tbom = str(tbom_path)
        tools_list = str(tools_path)
        verbose = True

    assert tbomctl.cmd_verify_drift(Args()) == 1
    assert "Live canonical" in capsys.readouterr().err


def test_cmd_verify_drift_mismatch_non_verbose(tmp_path, capsys):
    tool = {"toolId": "id1", "name": "t1", "description": "d1", "inputSchema": {}}
    tbom = {"tools": [{**tool, "definitionDigest": {"value": "sha256:bad"}}]}
    tbom_path = _write_json(tmp_path, "tbom.json", tbom)
    tools_path = _write_json(tmp_path, "tools.json", [tool])

    class Args:
        tbom = str(tbom_path)
        tools_list = str(tools_path)
        verbose = False

    assert tbomctl.cmd_verify_drift(Args()) == 1
    assert "[DRIFT]" in capsys.readouterr().err
