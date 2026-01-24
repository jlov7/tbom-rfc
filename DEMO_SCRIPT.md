# TBOM 60-Second Demo Script

Goal: show that TBOM proves tool integrity and detects drift in seconds.

## Setup (once)

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.lock
```

## Live demo (copy/paste)

1) Verify a signed TBOM against the schema:

```bash
python tbomctl.py check --schema tbom-schema-v1.0.2.json tbom-example-full-v1.0.2.json
```

2) Verify drift with the exact tools list (expected OK):

```bash
python tbomctl.py verify-drift --tbom tbom-example-full-v1.0.2.json --tools-list tbom-example-full-v1.0.2.json
```

3) Simulate drift by changing a tool description and re-check:

```bash
mkdir -p build
python - <<'PY'
import json
from pathlib import Path

tbom = json.loads(Path("tbom-example-full-v1.0.2.json").read_text(encoding="utf-8"))
tools = tbom["tools"]
drifted = []
for tool in tools:
    clone = dict(tool)
    clone["description"] = f'{clone.get("description", "")} (drifted)'
    drifted.append(clone)

Path("build/demo-live.json").write_text(json.dumps({"tools": drifted}, indent=2), encoding="utf-8")
PY

python tbomctl.py verify-drift --tbom tbom-example-full-v1.0.2.json --tools-list build/demo-live.json --verbose
```

## Talk track (non-technical)

- TBOM is a tamper-evident label for AI tooling.
- If any tool metadata changes after release, the drift check flags it.
- This gives procurement, security, and engineering a shared proof of integrity.

## Optional: full showcase pack

```bash
make showcase
```

Artifacts land in `build/showcase/` (demo log, metrics, evidence pack zip).
