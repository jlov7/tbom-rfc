#!/usr/bin/env bash
# Copyright 2026 Jason M. Lovell
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
if [ -f ".venv/bin/activate" ]; then
  # Use local venv if present to avoid missing Python deps.
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi
make all
