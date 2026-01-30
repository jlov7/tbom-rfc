import json
from pathlib import Path

import tbom_mcp_server


def test_get_own_tbom_missing(monkeypatch):
    monkeypatch.setattr(tbom_mcp_server, "TBOM_PATH", Path("/missing.json"))
    data = json.loads(tbom_mcp_server.get_own_tbom())
    assert "error" in data


def test_get_own_tbom_present(tmp_path, monkeypatch):
    p = tmp_path / "tbom.json"
    p.write_text("{}")
    monkeypatch.setattr(tbom_mcp_server, "TBOM_PATH", p)
    assert tbom_mcp_server.get_own_tbom() == "{}"


def test_verify_tbom_schema_missing(monkeypatch):
    monkeypatch.setattr(tbom_mcp_server, "SCHEMA_PATH", Path("/missing.json"))
    assert tbom_mcp_server.verify_tbom("{}") == "Error: TBOM schema not found on server."


def test_verify_tbom_invalid_json():
    assert "Error during verification" in tbom_mcp_server.verify_tbom("{")


def test_get_tool_digest_invalid_schema():
    assert "Error" in tbom_mcp_server.get_tool_digest("n", "d", "not json")
