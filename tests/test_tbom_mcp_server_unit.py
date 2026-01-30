import json
import runpy
import tempfile
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


def test_get_tool_digest_success():
    digest = tbom_mcp_server.get_tool_digest("n", "d", '{"type":"object"}')
    assert digest.startswith("sha256:")


def test_verify_tbom_success_and_cleanup(tmp_path, monkeypatch):
    tbom_json = Path("tbom-example-full-v1.0.2.json").read_text(encoding="utf-8")
    created = {"path": None}
    real_mkstemp = tempfile.mkstemp

    def fake_mkstemp(*_args, **kwargs):
        fd, name = real_mkstemp(dir=tmp_path, suffix=kwargs.get("suffix", ""), text=kwargs.get("text", True))
        created["path"] = Path(name)
        return fd, name

    monkeypatch.setattr(tbom_mcp_server.tempfile, "mkstemp", fake_mkstemp)
    result = tbom_mcp_server.verify_tbom(tbom_json)
    assert "VALID" in result
    assert created["path"] is not None
    assert not created["path"].exists()


def test_verify_tbom_invalid_with_details():
    result = tbom_mcp_server.verify_tbom("{}")
    assert result.startswith("TBOM is INVALID.")


def test_verify_tbom_invalid_no_details(monkeypatch):
    monkeypatch.setattr(tbom_mcp_server.tbomctl, "cmd_check", lambda _args: 2)
    result = tbom_mcp_server.verify_tbom("{}")
    assert result == "TBOM is INVALID."


def test_main_runs(monkeypatch):
    called = {"ok": False}

    def fake_run():
        called["ok"] = True

    monkeypatch.setattr(tbom_mcp_server.mcp, "run", fake_run)
    tbom_mcp_server.main()
    assert called["ok"] is True


def test_main_guard_runs(monkeypatch):
    from mcp.server.fastmcp import FastMCP

    monkeypatch.setattr(FastMCP, "run", lambda _self: None)
    runpy.run_module("tbom_mcp_server", run_name="__main__")
