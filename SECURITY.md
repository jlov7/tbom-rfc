# Security Policy

**Security Audit Status**: See [SECURITY_AUDIT.md](SECURITY_AUDIT.md) for current audit status and recommendations.

## Reporting a Vulnerability

If you discover a security vulnerability in the TBOM specification, reference implementation, or test vectors, please report it responsibly.

### For Specification Vulnerabilities

If you find a weakness in the TBOM specification that could lead to security issues when implemented:

1. **Do not open a public issue**
2. Email the maintainer directly at: **jase.lovell@me.com**
3. Include:
   - Description of the vulnerability
   - Attack scenario or proof of concept
   - Suggested mitigation (if any)
   - Whether you'd like to be credited

### For Implementation Vulnerabilities

If you find a bug in `tbomctl.py` or the build tooling that could cause security issues:

1. For **critical issues** (e.g., signature bypass): Email privately first
2. For **low-severity issues**: Open a GitHub issue

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 7 days
- **Fix timeline**: Depends on severity; critical issues prioritized

## Scope

### In Scope

- TBOM specification weaknesses
- `tbomctl.py` signature verification bugs
- Canonicalization implementation errors
- Build/release signing process issues
- Test vector correctness

### Out of Scope

- Vulnerabilities in dependencies (report to upstream)
- Issues in MCP itself (report to MCP maintainers)
- Theoretical attacks already documented in §5 (Threat Model)
- Social engineering or phishing

## Security Design Principles

The TBOM specification is designed with these security principles:

1. **Defense in depth**: TBOM is one layer; it does not replace sandboxing, code review, or runtime controls
2. **Fail-safe defaults**: Missing signatures or mismatched digests should cause rejection
3. **Minimal trust**: Descriptions are untrusted unless verified
4. **Cryptographic agility**: Support for multiple algorithms, with clear deprecation path

## Self-Assessment and Assurance

This reference implementation follows rigorous engineering practices to ensure correctness and security:

### 1. Static Analysis
- **Linting**: Enforced via `ruff` (PEP 8, flake8, isort) to prevent common coding errors.
- **Type Safety**: Enforced via `mypy` (strict mode) to prevent type-related bugs.

### 2. Cryptographic Verification
- **Test Vectors**: The test suite exercises the normative test vectors in the specification using `pytest`.
- **Library Selection**: Uses `cryptography` (Python) and `jcs` (RFC 8785), which are standard, widely-reviewed libraries. We do not implement custom crypto primitives.

### 3. Supply Chain Security
- **Release Signing**: Release bundles produced via `make release` are signed; official releases should use a dedicated key or HSM-backed signing.
- **Provenance**: The release workflow generates SLSA-style provenance for release artifacts.
- **Dependency Pinning**: Dependencies are pinned in `requirements.lock` to support reproducibility.

## Known Limitations

The following are **documented limitations**, not vulnerabilities:

- **Key compromise**: If a signing key is compromised, TBOM cannot detect malicious-but-signed packages (§12.1)
- **Semantic gap**: TBOM verifies metadata integrity, not behavioral correctness (§12.1)
- **TOCTOU**: Time-of-check-to-time-of-use gaps between verification and invocation (§15)

## Security Updates

Security-relevant updates will be:

1. Tagged with `[SECURITY]` in commit messages
2. Mentioned in release notes
3. Accompanied by updated test vectors where applicable

## Acknowledgments

We thank security researchers who responsibly disclose vulnerabilities. Contributors will be credited in release notes unless they prefer anonymity.
