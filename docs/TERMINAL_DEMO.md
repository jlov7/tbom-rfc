# Visual Demo

## Non-technical view

Think of TBOM as a tamper-evident label for AI tooling:

```
Release build
  |
  v
TBOM manifest  --signed-->  Proof of what shipped
  |
  v
Runtime check  --------->   Block changes, alert on drift
```

If anything changes after release, the check flips from OK to DRIFT.

## Technical view (copy/paste)

Minimal verification:

```bash
$ python tbomctl.py check --schema tbom-schema-v1.0.2.json tbom-example-full-v1.0.2.json
OK
```

If you installed the CLI (`make install-cli`), you can use `tbomctl` instead of `python tbomctl.py`.

Drift detection:

```bash
$ python tbomctl.py verify-drift --tbom tbom-example-full-v1.0.2.json --tools-list tbom-example-full-v1.0.2.json

Drift detection summary:
  Tools checked: 3
  Drifted: 0
  Ambiguous: 0
  Missing in TBOM: 0
  Missing in live: 0

No drift detected
```

Note: the final line is prefixed with a checkmark on terminals that support it.

## Visual trace (what the verifier is doing)

```
[tools/list] -> [canonicalize] -> [digest] -> [compare] -> [OK | DRIFT]
```

## Drift example (illustrative)

```
Drift detection summary:
  Tools checked: 3
  Drifted: 3
  Ambiguous: 0
  Missing in TBOM: 0
  Missing in live: 0

DRIFT DETECTED - tool metadata has changed since TBOM was signed
```

Note: the final line is prefixed with a cross icon on terminals that support it.

## Tell me it worked

If the output ends with `OK`, the TBOM is valid and matches the tool list.

For a narrated live demo, see `demo.md` or `DEMO_SCRIPT.md`.
