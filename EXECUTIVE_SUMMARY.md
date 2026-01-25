# TBOM Executive Summary (v1.0.2)

## Overview

TBOM (Tool Bill of Materials) is a standard for the Model Context Protocol (MCP). It defines a signed, machine-readable manifest that binds a tool's published description and schema to the exact release that shipped. This makes metadata drift or tampering detectable.

## Why it matters

- AI agents choose tools based on text descriptions. If those descriptions change, behavior can change without any code changes.
- Enterprises need clear provenance and auditability for AI tools.
- Traditional SBOM formats cover software components, not the semantic layer of AI tools.

## What TBOM provides

- Cryptographic signatures for publisher identity
- Deterministic digests of tool definitions
- Artifact digests for package integrity
- Links to SBOMs, advisories, and attestations
- Machine-readable policy fields for registry and enterprise controls

## What this release includes

- JSON schemas, examples, and reproducible test vectors
- Reference CLI (`tbomctl.py`) for validation and verification
- Reference MCP server showing how to publish and verify TBOMs
- Reproducible build workflow and signed release bundle with provenance

## How to explain it (non-technical)

"TBOM is a tamper-evident label for AI tools. It tells you who shipped the tool, what it claims to do, and lets you prove that description has not been silently changed."

## The STAMP model

- **Signed**: provenance is cryptographically verifiable
- **Tamper-evident**: any metadata change flips to DRIFT
- **Auditable**: re-check releases months later
- **Machine-checkable**: policy engines can block drift automatically
- **Provenance**: labels are tied to release bundles

## Value at a glance

- **Trust**: confirm the publisher and signed metadata
- **Integrity**: detect silent changes to tool descriptions or schemas
- **Accountability**: create auditable trails for tool releases
- **Risk reduction**: faster incident response and safer rollbacks

## Demo in 60 seconds

Use `DEMO_SCRIPT.md` for a copy/paste live demo, and `ARCHITECTURE.md` for the visual system overview.
