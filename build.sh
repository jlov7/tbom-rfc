#!/usr/bin/env bash
set -euo pipefail
if [ -f ".venv/bin/activate" ]; then
  # Use local venv if present to avoid missing Python deps.
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi
make all
