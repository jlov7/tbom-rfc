#!/usr/bin/env python3
# Copyright 2026 Jason M. Lovell
# SPDX-License-Identifier: Apache-2.0
"""
Generate a minimal SLSA-style provenance statement for a release bundle.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import uuid
from pathlib import Path


def sha256_hex(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate SLSA-style provenance JSON")
    parser.add_argument("--zip", required=True, help="Path to the release zip")
    parser.add_argument("--output", required=True, help="Output provenance JSON path")
    parser.add_argument("--version", required=True, help="Release version")
    parser.add_argument(
        "--build-type",
        default="urn:tbom:build:tooling-release:v1",
        help="Build type URI",
    )
    parser.add_argument(
        "--builder-id",
        default="urn:tbom:build:cli",
        help="Builder ID",
    )
    args = parser.parse_args(argv)

    zip_path = Path(args.zip)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    digest = sha256_hex(zip_path)
    timestamp = now_utc()

    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": zip_path.name,
                "digest": {"sha256": digest},
            }
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": args.build_type,
                "externalParameters": {
                    "makeTarget": "release",
                    "version": args.version,
                },
            },
            "runDetails": {
                "builder": {"id": args.builder_id},
                "metadata": {
                    "invocationId": str(uuid.uuid4()),
                    "startedOn": timestamp,
                    "finishedOn": timestamp,
                },
            },
        },
    }

    output_path.write_text(json.dumps(statement, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
