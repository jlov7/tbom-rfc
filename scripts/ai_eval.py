#!/usr/bin/env python3
# Copyright 2026 Jason M. Lovell
# SPDX-License-Identifier: Apache-2.0
"""
Lightweight AI-style evals for TBOM invariants.
Outputs JSON and exits non-zero on failures.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import tbomctl  # noqa: E402


def record(results: list[dict[str, object]], name: str, passed: bool, details: str) -> bool:
    results.append({"name": name, "passed": passed, "details": details})
    return passed


def run_evals() -> dict[str, object]:
    results: list[dict[str, object]] = []
    failures = 0
    repo_root = REPO_ROOT

    # Golden digest check (matches reference example)
    tool_path = repo_root / "tool-create_note.json"
    if tool_path.exists():
        tool = json.loads(tool_path.read_text(encoding="utf-8"))
        _, digest = tbomctl.compute_tool_digest(tool)
        expected = "sha256:c8b0dd1582c61e53295ac07bae66448e67097a3b853ad6f2401025998b82dac7"
        if not record(results, "golden_tool_digest", digest == expected, f"expected {expected}, got {digest}"):
            failures += 1
    else:
        record(results, "golden_tool_digest", False, "tool-create_note.json missing")
        failures += 1

    # Metamorphic: extra fields do not affect tool digest
    tool = {"name": "example", "description": "desc", "inputSchema": {"type": "object"}}
    _, digest_base = tbomctl.compute_tool_digest(tool)
    tool_with_extra = dict(tool)
    tool_with_extra["extraField"] = "ignored"
    _, digest_extra = tbomctl.compute_tool_digest(tool_with_extra)
    if not record(results, "tool_digest_ignores_extras", digest_base == digest_extra, "digest should ignore extras"):
        failures += 1

    # Metamorphic: changing description must change digest
    tool_changed = dict(tool)
    tool_changed["description"] = "desc updated"
    _, digest_changed = tbomctl.compute_tool_digest(tool_changed)
    if not record(
        results,
        "tool_digest_changes_on_description",
        digest_base != digest_changed,
        "digest should change when description changes",
    ):
        failures += 1

    # Signed test vector verification
    tbom_path = repo_root / "tbom-testvector-signed-v1.0.2.json"
    keys_path = repo_root / "tbom-testvector-keys-v1.0.1.json"
    if tbom_path.exists() and keys_path.exists():
        tbom = json.loads(tbom_path.read_text(encoding="utf-8"))
        keys = json.loads(keys_path.read_text(encoding="utf-8"))
        sigs = tbom.get("signatures", [])
        ok = True
        for sig in sigs:
            if not isinstance(sig, dict) or sig.get("type") != "jws":
                continue
            try:
                tbomctl.verify_tbom_jws_detached(tbom, sig, keys)
            except Exception as exc:
                ok = False
                details = f"signature verification failed: {exc}"
                if not record(results, "signed_testvector_verification", False, details):
                    failures += 1
                break
        if ok and not record(results, "signed_testvector_verification", True, "all JWS signatures verified"):
            failures += 1
    else:
        record(results, "signed_testvector_verification", False, "testvector files missing")
        failures += 1

    passed = len(results) - failures
    return {
        "summary": {"total": len(results), "passed": passed, "failed": failures},
        "results": results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run TBOM AI-style evals")
    parser.add_argument("--output", help="Optional path to write JSON results")
    args = parser.parse_args(argv)

    report = run_evals()
    output = json.dumps(report, indent=2, ensure_ascii=True) + "\n"
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        print(output, end="")

    return 0 if report["summary"]["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
