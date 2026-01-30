import runpy


def test_run_tbomctl_as_main(tmp_path, monkeypatch):
    (tmp_path / "tool.json").write_text('{"name": "x", "description": "y", "inputSchema": {}}')
    monkeypatch.setattr("sys.argv", ["tbomctl.py", "digest-tool", str(tmp_path / "tool.json")])
    with __import__("pytest").raises(SystemExit) as excinfo:
        runpy.run_module("tbomctl", run_name="__main__")
    assert excinfo.value.code == 0


def test_run_generate_provenance_as_main(tmp_path, monkeypatch):
    zip_path = tmp_path / "bundle.zip"
    zip_path.write_bytes(b"x")
    out = tmp_path / "prov.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "generate_provenance.py",
            "--zip",
            str(zip_path),
            "--output",
            str(out),
            "--version",
            "1.0.2",
        ],
    )
    with __import__("pytest").raises(SystemExit) as excinfo:
        runpy.run_module("scripts.generate_provenance", run_name="__main__")
    assert excinfo.value.code == 0
