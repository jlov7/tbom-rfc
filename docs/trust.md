# Trust signals

TBOM is designed to be verifiable. This repo publishes signals that make audits
and reviews straightforward:

## Automated checks

- **CI verify** runs schema validation, signatures, linting, tests, and AI evals.
- **Mutation tests** run in strict mode to harden critical logic.

## Security scanning

- **CodeQL** scans the Python codebase.
- **OpenSSF Scorecard** provides supply-chain risk scoring.

## Release artifacts

- **SBOM** (`sbom.spdx.json`) is generated for each release.
- **Provenance** is emitted via the in-toto statement.
- **Evidence pack** bundles logs, metrics, and demo outputs.

## Where to find everything

```text
dist/            release bundle + SBOM + provenance
build/showcase/  evidence pack + metrics (local runs)
```
