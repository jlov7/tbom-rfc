# Testing

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.lock
```

## Verify (recommended)

```bash
make verify
```

`make verify` runs:
- schema validation on examples,
- signed test vector verification,
- linting (`ruff`) and type checks (`mypy`),
- unit tests (`pytest`),
- integration tests (skipped if `mcp` is not installed),
- AI-style evals (`scripts/ai_eval.py`, output in `build/ai-eval.json`).

## Verify (strict)

```bash
make verify-strict
```

Adds targeted mutation tests (`scripts/mutation_test.py`, output in `build/mutation-report.json`).
The mutation score must meet the default threshold (100% killed).

## Individual commands

```bash
make test
make integration-test
make ai-eval
make mutation-test
```

## Showcase pack (optional)

```bash
make showcase
make showcase-strict
make demo-video
make demo-video-strict
```

## Docs site (optional)

```bash
python -m pip install -r docs/requirements.txt
mkdocs build
```
