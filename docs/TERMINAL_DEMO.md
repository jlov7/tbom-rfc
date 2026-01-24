# Terminal Demo

Minimal verification:

```bash
$ python tbomctl.py check --schema tbom-schema-v1.0.2.json tbom-example-full-v1.0.2.json
OK
```

Drift detection:

```bash
$ python tbomctl.py verify-drift --tbom tbom-example-full-v1.0.2.json --tools-list tbom-example-full-v1.0.2.json

Drift detection summary:
  Tools checked: 1
  Drifted: 0
  Ambiguous: 0
  Missing in TBOM: 0
  Missing in live: 0

OK: no drift detected
```
