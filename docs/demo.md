# 60-second demo

Goal: show that TBOM proves tool integrity and detects drift in seconds.

## Step 1: verify a TBOM

```bash
python tbomctl.py check --schema tbom-schema-v1.0.2.json tbom-example-full-v1.0.2.json
```

Expected output: `OK`.

If you installed the CLI (`make install-cli`), you can use `tbomctl` instead of `python tbomctl.py`.

## Step 2: verify drift (expected OK)

```bash
python tbomctl.py verify-drift --tbom tbom-example-full-v1.0.2.json --tools-list tbom-example-full-v1.0.2.json
```

Expected output: `OK: no drift detected`.

## Step 3: simulate drift

```bash
mkdir -p build
python - <<'PY'
import json
from pathlib import Path

tbom = json.loads(Path("tbom-example-full-v1.0.2.json").read_text(encoding="utf-8"))
drifted = []
for tool in tbom["tools"]:
    clone = dict(tool)
    clone["description"] = f'{clone.get("description", "")} (drifted)'
    drifted.append(clone)

Path("build/demo-live.json").write_text(json.dumps({"tools": drifted}, indent=2), encoding="utf-8")
PY
```

## Step 4: detect drift

```bash
python tbomctl.py verify-drift --tbom tbom-example-full-v1.0.2.json --tools-list build/demo-live.json --verbose
```

Expected output: `DRIFT detected`.

## Optional: narrated evidence pack

```bash
make showcase
```

Artifacts land in `build/showcase/` (demo log, metrics, evidence pack zip).
