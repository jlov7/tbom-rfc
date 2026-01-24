# TBOM Showcase Pack

This folder describes the "showcase mode" used for live demos and reviews.

## 60-second story (non-technical)

TBOM is a tamper-evident label for AI tools:
- It proves who shipped the tool metadata.
- It detects silent changes in seconds.
- It gives security and engineering the same ground truth.

## Generate a demo + evidence pack

```bash
make showcase
```

For a stricter run (includes mutation testing):

```bash
make showcase-strict
```

Generate a video from the showcase log:

```bash
make demo-video
```

## What you get

Artifacts are written to `build/showcase/`:
- `demo.log` - narrated, copy/paste-friendly output
- `metrics.json` - summary counts for evals and mutation results
- `ai-eval.json` - AI-style invariant checks
- `mutation-report.json` - mutation results (strict mode only)
- `live-tools-drift.json` - drifted tools list used in the demo
- `evidence-pack.zip` - all of the above in one bundle
- `tbom-demo.mp4` - auto-generated demo video

## Sample excerpt

```
== Verify TBOM ==
$ python tbomctl.py check --schema tbom-schema-v1.0.2.json tbom-example-full-v1.0.2.json
OK

== Drift Check (expected OK) ==
$ python tbomctl.py verify-drift --tbom tbom-example-full-v1.0.2.json --tools-list tbom-example-full-v1.0.2.json
```

## Live demo path (copy/paste)

See `../demo.md` for a 60-second script.
