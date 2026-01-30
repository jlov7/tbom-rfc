import runpy
import shutil
import subprocess
from pathlib import Path


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


def test_run_build_binaries_as_main(monkeypatch):
    class Result:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: Result())
    monkeypatch.setattr("platform.system", lambda: "linux")
    monkeypatch.setattr("platform.machine", lambda: "x86_64")
    monkeypatch.setattr("os.chdir", lambda *_a, **_k: None)
    repo_root = Path(__file__).resolve().parents[1]
    with __import__("pytest").raises(SystemExit) as excinfo:
        runpy.run_module("scripts.build_binaries", run_name="__main__")
    assert excinfo.value.code == 0
    shutil.rmtree(repo_root / "dist", ignore_errors=True)


def test_run_mutation_test_as_main(monkeypatch):
    class Result:
        returncode = 1
        stdout = "fail"
        stderr = ""

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: Result())
    monkeypatch.setattr("sys.argv", ["mutation_test.py"])
    with __import__("pytest").raises(SystemExit) as excinfo:
        runpy.run_module("scripts.mutation_test", run_name="__main__")
    assert excinfo.value.code == 0


def test_run_render_demo_gif_as_main(tmp_path, monkeypatch):
    class Result:
        returncode = 0
        stderr = ""

    input_path = tmp_path / "demo.mp4"
    input_path.write_text("x")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: Result())
    monkeypatch.setattr(
        "sys.argv",
        [
            "render_demo_gif.py",
            "--input",
            str(input_path),
            "--output",
            str(tmp_path / "out.gif"),
        ],
    )
    with __import__("pytest").raises(SystemExit) as excinfo:
        runpy.run_module("scripts.render_demo_gif", run_name="__main__")
    assert excinfo.value.code == 0


def test_run_render_demo_video_as_main(tmp_path, monkeypatch):
    class Result:
        returncode = 0
        stdout = "1"

    showcase_dir = tmp_path / "showcase"
    showcase_dir.mkdir()
    (showcase_dir / "demo.log").write_text("== Verify TBOM ==\nOK\n", encoding="utf-8")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: Result())
    monkeypatch.setattr(
        "sys.argv",
        [
            "render_demo_video.py",
            "--showcase-dir",
            str(showcase_dir),
            "--voiceover",
            "off",
            "--output",
            str(tmp_path / "out.mp4"),
        ],
    )
    with __import__("pytest").raises(SystemExit) as excinfo:
        runpy.run_module("scripts.render_demo_video", run_name="__main__")
    assert excinfo.value.code == 0


def test_run_showcase_as_main(tmp_path, monkeypatch):
    def fake_run(cmd, **_kwargs):
        cmd_str = " ".join(cmd)
        if "verify-drift" in cmd_str and "--verbose" in cmd:
            return type("R", (), {"returncode": 1, "stdout": "DRIFT", "stderr": ""})()
        return type("R", (), {"returncode": 0, "stdout": "OK", "stderr": ""})()

    monkeypatch.setattr(subprocess, "run", fake_run)
    out_dir = tmp_path / "showcase"
    monkeypatch.setattr("sys.argv", ["showcase.py", "--output-dir", str(out_dir)])
    with __import__("pytest").raises(SystemExit) as excinfo:
        runpy.run_module("scripts.showcase", run_name="__main__")
    assert excinfo.value.code == 0
