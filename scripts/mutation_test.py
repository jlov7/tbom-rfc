#!/usr/bin/env python3
# Copyright 2026 Jason M. Lovell
# SPDX-License-Identifier: Apache-2.0
"""
Minimal mutation testing harness for critical TBOM logic.
Outputs JSON and exits non-zero if mutation score is below threshold.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def run_pytest(env: dict[str, str], cwd: Path, test_path: Path) -> tuple[int, str]:
    result = subprocess.run(
        [sys.executable, "-m", "pytest", str(test_path)],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
    )
    output = (result.stdout or "") + (result.stderr or "")
    return result.returncode, output


def apply_mutation(content: str, needle: str, replacement: str) -> str:
    if needle not in content:
        raise ValueError(f"Mutation needle not found: {needle!r}")
    return content.replace(needle, replacement, 1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run targeted mutation tests")
    parser.add_argument("--output", help="Optional path to write JSON results")
    parser.add_argument("--min-score", type=float, default=1.0, help="Minimum mutation score (0.0-1.0)")
    args = parser.parse_args(argv)

    repo_root = Path(__file__).parent.parent
    target = repo_root / "tbomctl.py"
    test_path = repo_root / "tests" / "test_tbomctl.py"
    original = target.read_text(encoding="utf-8")

    mutations = [
        {
            "name": "digest_algorithm_prefix",
            "needle": 'digest_value = "sha256:" + sha256_hex(canonical.encode("utf-8"))',
            "replacement": 'digest_value = "sha1:" + sha256_hex(canonical.encode("utf-8"))',
        },
        {
            "name": "definition_digest_covers_inversion",
            "needle": "if f in digest_obj",
            "replacement": "if f not in digest_obj",
        },
    ]

    results: list[dict[str, object]] = []
    killed = 0

    for mutation in mutations:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            mutated_content = apply_mutation(original, mutation["needle"], mutation["replacement"])
            (tmp_path / "tbomctl.py").write_text(mutated_content, encoding="utf-8")

            env = os.environ.copy()
            pythonpath = os.pathsep.join([str(tmp_path), str(repo_root), env.get("PYTHONPATH", "")])
            env["PYTHONPATH"] = pythonpath

            returncode, output = run_pytest(env, tmp_path, test_path)
            is_killed = returncode != 0
            if is_killed:
                killed += 1
            results.append(
                {
                    "name": mutation["name"],
                    "killed": is_killed,
                    "returncode": returncode,
                    "output": output[-4000:],
                }
            )

    total = len(mutations)
    score = 0.0 if total == 0 else killed / total
    summary = {"total": total, "killed": killed, "survived": total - killed, "score": score}
    report = {"summary": summary, "results": results}

    output_json = json.dumps(report, indent=2, ensure_ascii=True) + "\n"
    if args.output:
        Path(args.output).write_text(output_json, encoding="utf-8")
    else:
        print(output_json, end="")

    return 0 if score >= args.min_score else 1


if __name__ == "__main__":
    raise SystemExit(main())
