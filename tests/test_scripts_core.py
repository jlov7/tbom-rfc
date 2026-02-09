import json
import runpy
import sys
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


def test_ai_eval_mismatch_paths(monkeypatch):
    def fake_compute(tool):
        if tool.get("description") == "desc updated":
            return ("{}", "sha256:same")
        if "extraField" in tool:
            return ("{}", "sha256:different")
        return ("{}", "sha256:wrong")

    monkeypatch.setattr(ai_eval.tbomctl, "compute_tool_digest", fake_compute)

    def boom(*_a, **_k):
        raise RuntimeError("bad")

    monkeypatch.setattr(ai_eval.tbomctl, "verify_tbom_jws_detached", boom)
    report = ai_eval.run_evals()
    assert report["summary"]["failed"] >= 1


def test_ai_eval_description_no_change(monkeypatch):
    monkeypatch.setattr(ai_eval.tbomctl, "compute_tool_digest", lambda _tool: ("{}", "sha256:same"))
    report = ai_eval.run_evals()
    assert report["summary"]["failed"] >= 1


def test_ai_eval_skips_non_jws_and_records(monkeypatch, tmp_path):
    monkeypatch.setattr(ai_eval, "REPO_ROOT", tmp_path)
    (tmp_path / "tbom-testvector-signed-v1.0.2.json").write_text(
        json.dumps({"signatures": ["skip", {"type": "other"}]})
    )
    (tmp_path / "tbom-testvector-keys-v1.0.1.json").write_text(json.dumps({"keys": []}))

    def fake_record(results, name, passed, details):
        results.append({"name": name, "passed": passed, "details": details})
        return False if name == "signed_testvector_verification" else passed

    monkeypatch.setattr(ai_eval, "record", fake_record)
    report = ai_eval.run_evals()
    assert report["summary"]["failed"] >= 1


def test_ai_eval_signature_verification_failure(monkeypatch, tmp_path):
    monkeypatch.setattr(ai_eval, "REPO_ROOT", tmp_path)
    (tmp_path / "tbom-testvector-signed-v1.0.2.json").write_text(
        json.dumps(
            {
                "signatures": [
                    {"type": "jws", "value": "a..b", "algorithm": "Ed25519", "keyId": "kid"},
                ]
            }
        )
    )
    (tmp_path / "tbom-testvector-keys-v1.0.1.json").write_text(json.dumps({"keys": []}))
    monkeypatch.setattr(
        ai_eval.tbomctl, "verify_tbom_jws_detached", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("bad"))
    )
    monkeypatch.setattr(ai_eval, "record", lambda results, name, passed, details: results.append({"name": name}))
    report = ai_eval.run_evals()
    assert report["summary"]["failed"] >= 1


def test_ai_eval_signature_exception_branch(monkeypatch, tmp_path):
    monkeypatch.setattr(ai_eval, "REPO_ROOT", tmp_path)
    (tmp_path / "tbom-testvector-signed-v1.0.2.json").write_text(
        json.dumps(
            {
                "signatures": [
                    {"type": "jws", "value": "a..b", "algorithm": "Ed25519", "keyId": "kid"},
                ]
            }
        )
    )
    (tmp_path / "tbom-testvector-keys-v1.0.1.json").write_text(json.dumps({"keys": []}))

    called = {"verify": False, "record": False}

    def fake_verify(*_a, **_k):
        called["verify"] = True
        raise RuntimeError("boom")

    def fake_record(results, name, passed, details):
        if name == "signed_testvector_verification":
            called["record"] = True
        results.append({"name": name, "passed": passed, "details": details})
        return False

    monkeypatch.setattr(ai_eval.tbomctl, "verify_tbom_jws_detached", fake_verify)
    monkeypatch.setattr(ai_eval, "record", fake_record)
    ai_eval.run_evals()
    assert called["verify"] and called["record"]


def test_ai_eval_signature_exception_record_true(monkeypatch, tmp_path):
    monkeypatch.setattr(ai_eval, "REPO_ROOT", tmp_path)
    (tmp_path / "tbom-testvector-signed-v1.0.2.json").write_text(
        json.dumps(
            {
                "signatures": [
                    {"type": "jws", "value": "a..b", "algorithm": "Ed25519", "keyId": "kid"},
                ]
            }
        )
    )
    (tmp_path / "tbom-testvector-keys-v1.0.1.json").write_text(json.dumps({"keys": []}))

    monkeypatch.setattr(
        ai_eval.tbomctl, "verify_tbom_jws_detached", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("bad"))
    )
    monkeypatch.setattr(ai_eval, "record", lambda *_a, **_k: True)
    ai_eval.run_evals()


def test_ai_eval_main_writes_output(tmp_path):
    out = tmp_path / "ai.json"
    assert ai_eval.main(["--output", str(out)]) == 0
    assert out.exists()


def test_ai_eval_main_prints(monkeypatch, capsys):
    monkeypatch.setattr(ai_eval, "run_evals", lambda: {"summary": {"failed": 0}, "results": []})
    assert ai_eval.main([]) == 0
    assert capsys.readouterr().out.strip().startswith("{")


def test_ai_eval_runpath_inserts_sys_path(tmp_path, monkeypatch):
    out = tmp_path / "ai.json"
    repo_root = Path(__file__).resolve().parent.parent
    original_path = list(sys.path)
    try:
        sys.path = [p for p in sys.path if p != str(repo_root)]
        monkeypatch.setattr(sys, "argv", ["ai_eval.py", "--output", str(out)])
        with pytest.raises(SystemExit) as excinfo:
            runpy.run_path(str(repo_root / "scripts" / "ai_eval.py"), run_name="__main__")
        assert excinfo.value.code == 0
        assert str(repo_root) in sys.path
    finally:
        sys.path = original_path


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


def test_mutation_run_pytest(monkeypatch, tmp_path):
    class Result:
        returncode = 0
        stdout = "out"
        stderr = "err"

    monkeypatch.setattr(mutation_test.subprocess, "run", lambda *a, **k: Result())
    rc, output = mutation_test.run_pytest({}, tmp_path, tmp_path / "test.py")
    assert rc == 0
    assert "out" in output and "err" in output


def test_mutation_main_prints(monkeypatch, capsys):
    monkeypatch.setattr(mutation_test, "run_pytest", lambda env, cwd, test_path: (1, "fail"))
    assert mutation_test.main([]) == 0
    assert capsys.readouterr().out.strip().startswith("{")


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


def test_build_binaries_success_linux(monkeypatch, tmp_path):
    fake_file = tmp_path / "scripts" / "build_binaries.py"
    fake_file.parent.mkdir(parents=True, exist_ok=True)
    fake_file.write_text("# stub")
    (tmp_path / "tbomctl.py").write_text("# stub")
    (tmp_path / "tbom_mcp_server.py").write_text("# stub")
    monkeypatch.setattr(build_binaries, "__file__", str(fake_file))
    monkeypatch.setattr(build_binaries.os, "chdir", lambda *_: None)
    monkeypatch.setattr(build_binaries.platform, "system", lambda: "linux")
    monkeypatch.setattr(build_binaries.platform, "machine", lambda: "x86_64")

    def _fake(script_path, output_name, dist_dir):
        Path(dist_dir).mkdir(parents=True, exist_ok=True)
        (Path(dist_dir) / output_name).write_text("bin")
        (Path(dist_dir) / "subdir").mkdir(exist_ok=True)
        return True

    monkeypatch.setattr(build_binaries, "build_binary", _fake)
    assert build_binaries.main([]) == 0


def test_build_binaries_success_windows(monkeypatch, tmp_path):
    fake_file = tmp_path / "scripts" / "build_binaries.py"
    fake_file.parent.mkdir(parents=True, exist_ok=True)
    fake_file.write_text("# stub")
    (tmp_path / "tbomctl.py").write_text("# stub")
    monkeypatch.setattr(build_binaries, "__file__", str(fake_file))
    monkeypatch.setattr(build_binaries.os, "chdir", lambda *_: None)
    monkeypatch.setattr(build_binaries.platform, "system", lambda: "windows")
    monkeypatch.setattr(build_binaries.platform, "machine", lambda: "amd64")
    monkeypatch.setattr(build_binaries, "build_binary", lambda *a, **k: True)
    assert build_binaries.main([]) == 0


@pytest.mark.parametrize(
    ("machine", "expected_tbomctl_name"),
    [
        ("arm64", "tbomctl-macos-arm64"),
        ("x86_64", "tbomctl-macos-x86_64"),
    ],
)
def test_build_binaries_success_macos_variants(monkeypatch, tmp_path, machine, expected_tbomctl_name):
    fake_file = tmp_path / "scripts" / "build_binaries.py"
    fake_file.parent.mkdir(parents=True, exist_ok=True)
    fake_file.write_text("# stub")
    (tmp_path / "tbomctl.py").write_text("# stub")
    (tmp_path / "tbom_mcp_server.py").write_text("# stub")
    monkeypatch.setattr(build_binaries, "__file__", str(fake_file))
    monkeypatch.setattr(build_binaries.os, "chdir", lambda *_: None)
    monkeypatch.setattr(build_binaries.platform, "system", lambda: "darwin")
    monkeypatch.setattr(build_binaries.platform, "machine", lambda: machine)

    called_output_names = []

    def _fake(_script_path, output_name, dist_dir):
        called_output_names.append(output_name)
        Path(dist_dir).mkdir(parents=True, exist_ok=True)
        (Path(dist_dir) / output_name).write_text("bin")
        return True

    monkeypatch.setattr(build_binaries, "build_binary", _fake)
    assert build_binaries.main([]) == 0
    assert called_output_names == [
        expected_tbomctl_name,
        f"tbom-mcp-server-darwin-{machine}",
    ]


def test_showcase_format_cmd(monkeypatch):
    cmd = ["/abs/path/python", "/abs/path/tbomctl.py", "check"]
    monkeypatch.setattr(showcase, "REPO_ROOT", Path("/abs/path"))
    out = showcase.format_cmd(cmd)
    assert out.startswith("python ")


def test_showcase_run_cmd(monkeypatch):
    class Result:
        returncode = 0
        stdout = "out"
        stderr = "err"

    monkeypatch.setattr(showcase.subprocess, "run", lambda *a, **k: Result())
    rc, output = showcase.run_cmd(["echo", "hi"])
    assert rc == 0
    assert "out" in output and "err" in output


def test_showcase_main_ok(monkeypatch, tmp_path):
    out_dir = tmp_path / "showcase"
    out_dir.mkdir()
    (tmp_path / "tbom-example-full-v1.0.2.json").write_text(
        json.dumps(
            {
                "tbomVersion": "1.0.2",
                "tools": [
                    {"name": "t1", "description": None},
                    "not-a-dict",
                ],
            }
        )
    )
    ai_eval_path = out_dir / "ai-eval.json"
    ai_eval_path.write_text(json.dumps({"summary": {"total": 1, "passed": 1}}))
    (out_dir / "tbom-demo.mp4").write_text("video")

    def fake_run_cmd(cmd):
        if "tbomctl.py check" in " ".join(cmd):
            return (0, "")
        if "verify-drift" in " ".join(cmd) and "--verbose" in cmd:
            return (1, "DRIFT")
        return (0, "OK")

    monkeypatch.setattr(showcase, "run_cmd", fake_run_cmd)
    monkeypatch.setattr(showcase, "REPO_ROOT", tmp_path)

    assert showcase.main(["--output-dir", str(out_dir)]) == 0


def test_showcase_main_strict_with_metrics(monkeypatch, tmp_path):
    out_dir = tmp_path / "showcase"
    out_dir.mkdir()
    (tmp_path / "tbom-example-full-v1.0.2.json").write_text(json.dumps({"tbomVersion": "1.0.2", "tools": []}))
    (out_dir / "ai-eval.json").write_text(json.dumps({"summary": {"total": 2, "passed": 2}}))
    (out_dir / "mutation-report.json").write_text(json.dumps({"summary": {"score": 1.0}}))

    def fake_run_cmd(cmd):
        cmd_str = " ".join(cmd)
        if "verify-drift" in cmd_str and "--verbose" in cmd:
            return (1, "DRIFT")
        return (0, "OK")

    monkeypatch.setattr(showcase, "run_cmd", fake_run_cmd)
    monkeypatch.setattr(showcase, "REPO_ROOT", tmp_path)

    assert showcase.main(["--output-dir", str(out_dir), "--strict"]) == 0
    metrics = json.loads((out_dir / "metrics.json").read_text(encoding="utf-8"))
    assert metrics["aiEval"] is not None
    assert metrics["mutation"] is not None


def test_showcase_missing_artifact_skips_zip_entry(monkeypatch, tmp_path):
    out_dir = tmp_path / "showcase"
    out_dir.mkdir()
    (tmp_path / "tbom-example-full-v1.0.2.json").write_text(json.dumps({"tbomVersion": "1.0.2", "tools": []}))

    def fake_run_cmd(cmd):
        cmd_str = " ".join(cmd)
        if "verify-drift" in cmd_str and "--verbose" in cmd:
            return (1, "DRIFT")
        return (0, "OK")

    monkeypatch.setattr(showcase, "run_cmd", fake_run_cmd)
    monkeypatch.setattr(showcase, "REPO_ROOT", tmp_path)

    assert showcase.main(["--output-dir", str(out_dir)]) == 0
    assert (out_dir / "evidence-pack.zip").exists()


def test_showcase_main_strict_failure(monkeypatch, tmp_path):
    out_dir = tmp_path / "showcase"
    out_dir.mkdir()
    (tmp_path / "tbom-example-full-v1.0.2.json").write_text(json.dumps({"tbomVersion": "1.0.2", "tools": []}))
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


def test_showcase_strict_without_mutation_file(monkeypatch, tmp_path):
    out_dir = tmp_path / "showcase"
    out_dir.mkdir()
    (tmp_path / "tbom-example-full-v1.0.2.json").write_text(json.dumps({"tbomVersion": "1.0.2", "tools": []}))

    def fake_run_cmd(cmd):
        cmd_str = " ".join(cmd)
        if "verify-drift" in cmd_str and "--verbose" in cmd:
            return (1, "DRIFT")
        return (0, "OK")

    monkeypatch.setattr(showcase, "run_cmd", fake_run_cmd)
    monkeypatch.setattr(showcase, "REPO_ROOT", tmp_path)

    assert showcase.main(["--output-dir", str(out_dir), "--strict"]) == 0
