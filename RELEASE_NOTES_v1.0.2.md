# TBOM RFC v1.0.2 Release Notes

## Summary

This release packages the TBOM RFC and reference implementation as a verifiable, signed bundle. It includes the specification, schemas, test vectors, tooling, and a reproducible build pipeline.

## Highlights

- RFC v1.0.2 with clarified signature and digest semantics
- Schemas, examples, and test vectors aligned and validated
- Reference CLI (`tbomctl.py`) for validation and verification
- Reference MCP server (`tbom_mcp_server.py`) demonstrating TBOM publication
- Signed release bundle with checksums and provenance
- CI workflow for tagged release verification

## Artifacts

- `dist/tbom-whitepaper-rfc-v1.0.2.zip`
- `dist/SHA256SUMS.txt` and `dist/SHA256SUMS.txt.sig`
- `dist/provenance.json` and `dist/provenance.json.sig`
- `dist/RELEASE_SIGNING_KEY.pub`

## Verify the release

```bash
make verify-release
```

## Quick validation

```bash
python tbomctl.py check --schema tbom-schema-v1.0.2.json tbom-example-full-v1.0.2.json
python tbomctl.py check --schema tbom-schema-v1.0.2.json --keys tbom-testvector-keys-v1.0.1.json tbom-testvector-signed-v1.0.2.json
```

## Security status

No third-party security audit has been completed yet. See `SECURITY_AUDIT.md` for current status and recommended scope.
