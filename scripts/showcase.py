#!/usr/bin/env python3
# Copyright 2026 Jason M. Lovell
# SPDX-License-Identifier: Apache-2.0
"""
Generate a narrated demo + evidence pack for TBOM.
Writes logs and metrics to an output directory.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import shlex
import subprocess
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def run_cmd(cmd: list[str]) -> tuple[int, str]:
    result = subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    output = (result.stdout or "") + (result.stderr or "")
    return result.returncode, output.strip()


def format_cmd(cmd: list[str]) -> str:
    cleaned: list[str] = []
    repo_root = str(REPO_ROOT)
    for part in cmd:
        if part == sys.executable:
            cleaned.append("python")
            continue
        if isinstance(part, str) and part.startswith(repo_root):
            rel = part.replace(repo_root + "/", "")
            cleaned.append(rel)
            continue
        cleaned.append(part)
    return " ".join(shlex.quote(part) for part in cleaned)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate TBOM showcase evidence pack")
    parser.add_argument("--output-dir", default=str(REPO_ROOT / "build" / "showcase"))
    parser.add_argument("--strict", action="store_true", help="Include mutation testing output")
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    demo_log = out_dir / "demo.log"
    ai_eval_path = out_dir / "ai-eval.json"
    mutation_path = out_dir / "mutation-report.json"
    drift_path = out_dir / "live-tools-drift.json"
    metrics_path = out_dir / "metrics.json"
    pack_path = out_dir / "evidence-pack.zip"
    demo_video = out_dir / "tbom-demo.mp4"
    demo_video_light = out_dir / "tbom-demo-light.mp4"
    demo_gif = out_dir / "tbom-demo.gif"
    demo_gif_light = out_dir / "tbom-demo-light.gif"

    log_lines: list[str] = []
    steps: list[dict[str, object]] = []
    ok = True

    def add_section(title: str, cmd: list[str], output: str) -> None:
        log_lines.append(f"== {title} ==")
        log_lines.append(f"$ {format_cmd(cmd)}")
        if output:
            log_lines.append(output)
        else:
            log_lines.append("(no output)")
        log_lines.append("")

    # Step 1: schema + digest verification
    cmd_check = [
        sys.executable,
        str(REPO_ROOT / "tbomctl.py"),
        "check",
        "--schema",
        str(REPO_ROOT / "tbom-schema-v1.0.2.json"),
        str(REPO_ROOT / "tbom-example-full-v1.0.2.json"),
    ]
    rc, output = run_cmd(cmd_check)
    add_section("Verify TBOM", cmd_check, output)
    steps.append({"name": "verify_tbom", "returncode": rc, "expected": 0, "command": format_cmd(cmd_check)})
    ok = ok and rc == 0

    # Step 2: drift check expected OK
    cmd_drift_ok = [
        sys.executable,
        str(REPO_ROOT / "tbomctl.py"),
        "verify-drift",
        "--tbom",
        str(REPO_ROOT / "tbom-example-full-v1.0.2.json"),
        "--tools-list",
        str(REPO_ROOT / "tbom-example-full-v1.0.2.json"),
    ]
    rc, output = run_cmd(cmd_drift_ok)
    add_section("Drift Check (expected OK)", cmd_drift_ok, output)
    steps.append({"name": "drift_ok", "returncode": rc, "expected": 0, "command": format_cmd(cmd_drift_ok)})
    ok = ok and rc == 0

    # Step 3: create a drifted tools list
    tbom = json.loads((REPO_ROOT / "tbom-example-full-v1.0.2.json").read_text(encoding="utf-8"))
    tools = tbom.get("tools", [])
    drifted_tools = []
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        clone = dict(tool)
        desc = clone.get("description")
        clone["description"] = f"{desc} (drifted)" if isinstance(desc, str) else "drifted tool"
        drifted_tools.append(clone)
    drift_path.write_text(json.dumps({"tools": drifted_tools}, indent=2) + "\n", encoding="utf-8")

    # Step 4: drift check expected DRIFT
    cmd_drift = [
        sys.executable,
        str(REPO_ROOT / "tbomctl.py"),
        "verify-drift",
        "--tbom",
        str(REPO_ROOT / "tbom-example-full-v1.0.2.json"),
        "--tools-list",
        str(drift_path),
        "--verbose",
    ]
    rc, output = run_cmd(cmd_drift)
    add_section("Drift Check (expected DRIFT)", cmd_drift, output)
    steps.append({"name": "drift_detected", "returncode": rc, "expected": 1, "command": format_cmd(cmd_drift)})
    ok = ok and rc == 1

    # Step 5: AI-style evals
    cmd_ai = [
        sys.executable,
        str(REPO_ROOT / "scripts" / "ai_eval.py"),
        "--output",
        str(ai_eval_path),
    ]
    rc, output = run_cmd(cmd_ai)
    add_section("AI Eval", cmd_ai, output)
    steps.append({"name": "ai_eval", "returncode": rc, "expected": 0, "command": format_cmd(cmd_ai)})
    ok = ok and rc == 0

    # Step 6: mutation testing (optional)
    mutation_summary: dict[str, object] | None = None
    if args.strict:
        cmd_mutation = [
            sys.executable,
            str(REPO_ROOT / "scripts" / "mutation_test.py"),
            "--output",
            str(mutation_path),
        ]
        rc, output = run_cmd(cmd_mutation)
        add_section("Mutation Testing", cmd_mutation, output)
        steps.append({"name": "mutation_test", "returncode": rc, "expected": 0, "command": format_cmd(cmd_mutation)})
        ok = ok and rc == 0

        if mutation_path.exists():
            mutation_summary = json.loads(mutation_path.read_text(encoding="utf-8")).get("summary")

    # Build metrics snapshot
    ai_summary: dict[str, object] | None = None
    if ai_eval_path.exists():
        ai_summary = json.loads(ai_eval_path.read_text(encoding="utf-8")).get("summary")

    metrics = {
        "generatedAt": now_utc(),
        "tbomVersion": tbom.get("tbomVersion", "unknown"),
        "status": "ok" if ok else "failed",
        "steps": steps,
        "aiEval": ai_summary,
        "mutation": mutation_summary,
    }
    metrics_path.write_text(json.dumps(metrics, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")

    demo_log.write_text("\n".join(log_lines).rstrip() + "\n", encoding="utf-8")

    # Evidence pack zip
    artifacts = [demo_log, metrics_path, ai_eval_path, drift_path]
    if args.strict and mutation_path.exists():
        artifacts.append(mutation_path)
    for artifact in (demo_video, demo_video_light, demo_gif, demo_gif_light):
        if artifact.exists():
            artifacts.append(artifact)

    with zipfile.ZipFile(pack_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for artifact in artifacts:
            if artifact.exists():
                zf.write(artifact, artifact.relative_to(out_dir))

    print(f"Showcase pack written to: {out_dir}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
