# TBOM FAQ

## What is TBOM?

TBOM (Tool Bill of Materials) is a proposed standard for the Model Context Protocol (MCP). It is a signed, machine-readable manifest that ties a tool's published description and schema to a specific release.

## What problem does it solve?

AI agents choose tools based on their descriptions. If those descriptions are changed, the agent's behavior can change without any code changes. TBOM makes those changes detectable and auditable.

## How is this different from an SBOM?

SBOMs describe software components (libraries, packages, containers). TBOM focuses on the semantic layer that AI agents read: tool names, descriptions, schemas, and behavioral annotations.

## Does TBOM guarantee a tool is safe?

No. TBOM verifies integrity and provenance of metadata. It does not prove that a tool behaves safely or honestly at runtime. It is one layer in a broader security strategy.

## Who should use TBOM?

Tool publishers, MCP registries, and enterprises that want stronger provenance and verification for AI tools.

## Is TBOM an official MCP standard?

Not yet. This is a community RFC intended for public review and adoption.

## How does verification work?

The TBOM includes cryptographic signatures and deterministic digests of tool definitions. A verifier can recompute those digests and check signatures to detect changes.

## What happens if a signing key is compromised?

TBOM cannot detect a compromised key on its own. Key management, revocation, and transparency logs are required for that scenario.

## Do I need to change my MCP server?

No immediate changes are required. TBOM is designed to be added alongside existing MCP servers and registries.

## How do I get started?

Start by generating a TBOM for your server release and signing it. Use `tbomctl.py` to validate and verify the output, and publish it alongside your release artifacts.
