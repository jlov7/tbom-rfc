import json
from pathlib import Path

import pytest

import scripts.ai_eval as ai_eval
import scripts.build_binaries as build_binaries
import scripts.generate_provenance as generate_provenance
import scripts.mutation_test as mutation_test
import scripts.showcase as showcase


def test_ai_eval_missing_files(monkeypatch, tmp_path):
    monkeypatch.setattr(ai_eval, "REPO_ROOT", tmp_path)
    report = ai_eval.run_evals()
    assert report["summary"]["failed"] >= 1


def test_ai_eval_success():
    report = ai_eval.run_evals()
    assert report["summary"]["failed"] == 0


def test_generate_provenance(tmp_path):
    zip_path = tmp_path / "bundle.zip"
    zip_path.write_bytes(b"data")
    out = tmp_path / "prov.json"
    assert (
        generate_provenance.main(
            [
                "--zip",
                str(zip_path),
                "--output",
                str(out),
                "--version",
                "1.0.2",
            ]
        )
        == 0
    )
    data = json.loads(out.read_text())
    assert data["subject"][0]["digest"]["sha256"]


def test_mutation_apply_mutation_error():
    with pytest.raises(ValueError):
        mutation_test.apply_mutation("abc", "needle", "x")


def test_mutation_main_pass(monkeypatch, tmp_path):
    monkeypatch.setattr(mutation_test, "run_pytest", lambda env, cwd, test_path: (1, "fail"))
    assert mutation_test.main(["--output", str(tmp_path / "m.json"), "--min-score", "0.5"]) == 0


def test_mutation_main_fail(monkeypatch, tmp_path):
    monkeypatch.setattr(mutation_test, "run_pytest", lambda env, cwd, test_path: (0, "ok"))
    assert mutation_test.main(["--output", str(tmp_path / "m.json"), "--min-score", "1.0"]) == 1


def test_run_command_success(monkeypatch):
    class Result:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(build_binaries.subprocess, "run", lambda *a, **k: Result())
    assert build_binaries.run_command("echo ok") is True


def test_run_command_failure(monkeypatch):
    class Result:
        returncode = 1
        stdout = "out"
        stderr = "err"

    monkeypatch.setattr(build_binaries.subprocess, "run", lambda *a, **k: Result())
    assert build_binaries.run_command("echo bad") is False


def test_run_command_exception(monkeypatch):
    def boom(*_args, **_kwargs):
        raise RuntimeError("nope")

    monkeypatch.setattr(build_binaries.subprocess, "run", boom)
    assert build_binaries.run_command("echo fail") is False


def test_build_binary_success(monkeypatch, tmp_path):
    class Result:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(build_binaries.subprocess, "run", lambda *a, **k: Result())
    assert build_binaries.build_binary(str(tmp_path / "tbomctl.py"), "tbomctl", str(tmp_path)) is True


def test_build_binary_failure(monkeypatch, tmp_path):
    class Result:
        returncode = 1
        stdout = "out"
        stderr = "err"

    monkeypatch.setattr(build_binaries.subprocess, "run", lambda *a, **k: Result())
    assert build_binaries.build_binary(str(tmp_path / "tbomctl.py"), "tbomctl", str(tmp_path)) is False


def test_build_binary_exception(monkeypatch, tmp_path):
    def boom(*_args, **_kwargs):
        raise RuntimeError("bad")

    monkeypatch.setattr(build_binaries.subprocess, "run", boom)
    assert build_binaries.build_binary(str(tmp_path / "tbomctl.py"), "tbomctl", str(tmp_path)) is False


def test_build_binaries_missing_script(monkeypatch, tmp_path):
    fake_file = tmp_path / "scripts" / "build_binaries.py"
    fake_file.parent.mkdir(parents=True, exist_ok=True)
    fake_file.write_text("# stub")
    monkeypatch.setattr(build_binaries, "__file__", str(fake_file))
    monkeypatch.setattr(build_binaries.os, "chdir", lambda *_: None)
    assert build_binaries.main([]) == 1


def test_build_binaries_tbomctl_fail(monkeypatch, tmp_path):
    fake_file = tmp_path / "scripts" / "build_binaries.py"
    fake_file.parent.mkdir(parents=True, exist_ok=True)
    fake_file.write_text("# stub")
    (tmp_path / "tbomctl.py").write_text("# stub")
    monkeypatch.setattr(build_binaries, "__file__", str(fake_file))
    monkeypatch.setattr(build_binaries.os, "chdir", lambda *_: None)
    monkeypatch.setattr(build_binaries, "build_binary", lambda *a, **k: False)
    assert build_binaries.main([]) == 1


def test_build_binaries_mcp_fail(monkeypatch, tmp_path):
    fake_file = tmp_path / "scripts" / "build_binaries.py"
    fake_file.parent.mkdir(parents=True, exist_ok=True)
    fake_file.write_text("# stub")
    (tmp_path / "tbomctl.py").write_text("# stub")
    (tmp_path / "tbom_mcp_server.py").write_text("# stub")
    monkeypatch.setattr(build_binaries, "__file__", str(fake_file))
    monkeypatch.setattr(build_binaries.os, "chdir", lambda *_: None)

    calls = {"count": 0}

    def _fake(*_a, **_k):
        calls["count"] += 1
        return calls["count"] == 1

    monkeypatch.setattr(build_binaries, "build_binary", _fake)
    assert build_binaries.main([]) == 1


def test_build_binaries_success_unknown_platform(monkeypatch, tmp_path):
    fake_file = tmp_path / "scripts" / "build_binaries.py"
    fake_file.parent.mkdir(parents=True, exist_ok=True)
    fake_file.write_text("# stub")
    (tmp_path / "tbomctl.py").write_text("# stub")
    monkeypatch.setattr(build_binaries, "__file__", str(fake_file))
    monkeypatch.setattr(build_binaries.os, "chdir", lambda *_: None)
    monkeypatch.setattr(build_binaries, "build_binary", lambda *a, **k: True)
    monkeypatch.setattr(build_binaries.platform, "system", lambda: "Plan9")
    monkeypatch.setattr(build_binaries.platform, "machine", lambda: "arm64")
    assert build_binaries.main([]) == 0


def test_showcase_format_cmd(monkeypatch):
    cmd = ["/abs/path/python", "/abs/path/tbomctl.py", "check"]
    monkeypatch.setattr(showcase, "REPO_ROOT", Path("/abs/path"))
    out = showcase.format_cmd(cmd)
    assert out.startswith("python ")


def test_showcase_main_ok(monkeypatch, tmp_path):
    out_dir = tmp_path / "showcase"
    out_dir.mkdir()
    (tmp_path / "tbom-example-full-v1.0.2.json").write_text(
        json.dumps({"tbomVersion": "1.0.2", "tools": []})
    )
    ai_eval_path = out_dir / "ai-eval.json"
    ai_eval_path.write_text(json.dumps({"summary": {"total": 1, "passed": 1}}))

    def fake_run_cmd(cmd):
        if "verify-drift" in " ".join(cmd) and "--verbose" in cmd:
            return (1, "DRIFT")
        return (0, "OK")

    monkeypatch.setattr(showcase, "run_cmd", fake_run_cmd)
    monkeypatch.setattr(showcase, "REPO_ROOT", tmp_path)

    assert showcase.main(["--output-dir", str(out_dir)]) == 0


def test_showcase_main_strict_failure(monkeypatch, tmp_path):
    out_dir = tmp_path / "showcase"
    out_dir.mkdir()
    (tmp_path / "tbom-example-full-v1.0.2.json").write_text(
        json.dumps({"tbomVersion": "1.0.2", "tools": []})
    )
    mutation_path = out_dir / "mutation-report.json"
    mutation_path.write_text(json.dumps({"summary": {"score": 1.0}}))
    ai_eval_path = out_dir / "ai-eval.json"
    ai_eval_path.write_text(json.dumps({"summary": {"total": 1, "passed": 0}}))

    def fake_run_cmd(cmd):
        if "verify-drift" in " ".join(cmd):
            return (1, "DRIFT")
        return (1, "FAIL")

    monkeypatch.setattr(showcase, "run_cmd", fake_run_cmd)
    monkeypatch.setattr(showcase, "REPO_ROOT", tmp_path)

    assert showcase.main(["--output-dir", str(out_dir), "--strict"]) == 1
