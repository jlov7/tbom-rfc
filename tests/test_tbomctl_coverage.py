import json
import runpy
from pathlib import Path

import pytest

import tbomctl


def test_b64url_roundtrip():
    raw = b"hello"
    enc = tbomctl.b64url_encode(raw)
    assert tbomctl.b64url_decode(enc) == raw


def test_now_rfc3339_format():
    ts = tbomctl.now_rfc3339()
    assert ts.endswith("Z")
    assert "T" in ts


def test_strip_null_object_keys_nested():
    obj = {"a": None, "b": {"c": None, "d": 1}, "e": [None, {"f": None, "g": 2}]}
    assert tbomctl.strip_null_object_keys(obj) == {"b": {"d": 1}, "e": [None, {"g": 2}]}


def test_jws_alg_for_tbom_algorithm_invalid():
    with pytest.raises(ValueError):
        tbomctl.jws_alg_for_tbom_algorithm("RSA")


def test_load_json_invalid(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json}")
    with pytest.raises(SystemExit):
        tbomctl.load_json(p)


def test_tool_digest_input_missing_field():
    with pytest.raises(ValueError):
        tbomctl.tool_digest_input({"name": "x"})


def test_resource_digest_input_missing_field():
    with pytest.raises(ValueError):
        tbomctl.resource_digest_input({"uri": "x"})


def test_prompt_digest_input_missing_field():
    with pytest.raises(ValueError):
        tbomctl.prompt_digest_input({"name": "x"})


def test_load_private_key_invalid_cases():
    with pytest.raises(ValueError):
        tbomctl.load_private_key_from_jwk({"kty": "OKP", "crv": "X25519"})
    with pytest.raises(ValueError):
        tbomctl.load_private_key_from_jwk({"kty": "OKP", "crv": "Ed25519"})
    with pytest.raises(ValueError):
        tbomctl.load_private_key_from_jwk({"kty": "EC", "crv": "P-521"})
    with pytest.raises(ValueError):
        tbomctl.load_private_key_from_jwk({"kty": "EC", "crv": "P-256", "d": "AA"})


def test_load_public_key_invalid_cases():
    with pytest.raises(ValueError):
        tbomctl.load_public_key_from_jwk({"kty": "OKP", "crv": "X25519"})
    with pytest.raises(ValueError):
        tbomctl.load_public_key_from_jwk({"kty": "EC", "crv": "P-521"})


def test_ecdsa_der_signature_from_raw_invalid():
    with pytest.raises(ValueError):
        tbomctl.ecdsa_der_signature_from_raw(b"short", 32)


def test_resolve_kid_from_key_id():
    base, frag = tbomctl.resolve_kid_from_key_id("https://x#y")
    assert base == "https://x" and frag == "y"
    base2, frag2 = tbomctl.resolve_kid_from_key_id("https://x")
    assert frag2 is None


def test_load_key_from_keys_doc_errors():
    with pytest.raises(ValueError):
        tbomctl.load_key_from_keys_doc({}, "kid")
    with pytest.raises(ValueError):
        tbomctl.load_key_from_keys_doc({"keys": []}, "kid")


def test_verify_tbom_jws_detached_invalid_formats():
    tbom = {"tbomVersion": "1.0.2", "subject": {"name": "x"}, "tools": [], "signatures": []}
    keys = {"keys": []}
    with pytest.raises(ValueError):
        tbomctl.verify_tbom_jws_detached(tbom, {"value": "abc"}, keys)


def test_cmd_canon(tmp_path, capsys):
    p = tmp_path / "x.json"
    p.write_text(json.dumps({"b": 1, "a": 2}))

    class Args:
        input = str(p)

    assert tbomctl.cmd_canon(Args()) == 0
    assert capsys.readouterr().out.strip() == '{"a":2,"b":1}'


def test_cmd_digest_tool(tmp_path, capsys):
    p = tmp_path / "tool.json"
    p.write_text(json.dumps({"name": "x", "description": "y", "inputSchema": {}}))

    class Args:
        input = str(p)
        show_canonical = True

    assert tbomctl.cmd_digest_tool(Args()) == 0
    out = capsys.readouterr().out.strip().splitlines()
    assert out[0].startswith("{")
    assert out[-1].startswith("sha256:")


def test_main_entrypoint(tmp_path, monkeypatch):
    p = tmp_path / "tool.json"
    p.write_text(json.dumps({"name": "x", "description": "y", "inputSchema": {}}))
    monkeypatch.setattr("sys.argv", ["tbomctl.py", "digest-tool", str(p)])
    with pytest.raises(SystemExit) as excinfo:
        runpy.run_module("tbomctl", run_name="__main__")
    assert excinfo.value.code == 0
