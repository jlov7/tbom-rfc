# TBOM Specification Development History

## Version Evolution: v1.0.1 → v1.0.2

**Author:** Jason M. Lovell
**Period:** January 2026
**Purpose:** Documentation of iterative refinement for EB-1A/NIW petition materials

---

## Summary

Version 1.0.2 represents a significant maturation from proposal document to reference implementation package, incorporating expert review feedback and adding verifiable cryptographic test vectors.

Note: v1.0.1 artifacts are not included in this repository; the table below focuses on verifiable v1.0.2 outcomes and describes deltas qualitatively.

| Area | v1.0.2 outcome | Notes |
|------|----------------|-------|
| Document length | 2,290 lines | Expanded from the v1.0.1 draft |
| Schema version | 1.0.2 | Keys schema remains v1.0.1 |
| Test vectors | Verifiable Ed25519 signatures | Reproducible, byte-for-byte |
| Build tooling | Makefile + tbomctl.py + build.sh | Operational toolchain |
| Release signing | Implemented | Signed bundle + verification key |

---

## Detailed Changes

### 1. Document Structure Improvements

**Added: "Status of This Memo" section**
- Explicit RFC-style disclaimer clarifying community proposal status
- Aligns with IETF document conventions

**Enhanced: Table of Contents**
- Improved anchor linking for HTML/PDF generation
- Consistent section numbering

### 2. Statistical Accuracy (Critical for Credibility)

**Changed: mcp-remote download count**

| Version | Claim | Source |
|---------|-------|--------|
| v1.0.1 | "over 400,000 times" | Third-party estimate |
| v1.0.2 | "233,023 downloads" | npm Downloads API (July 2025) |

**Rationale:** Direct API query provides a verifiable, defensible figure. This is a precision correction that prioritizes accuracy over magnitude.

**Changed: Ecosystem scale claims**
- v1.0.1: Led with "97 million monthly SDK downloads"
- v1.0.2: Leads with "more than 10,000 published MCP servers" (and removes the SDK downloads figure)

**Rationale:** Server count is the more directly relevant metric for TBOM (which addresses server provenance). The SDK downloads figure was removed to prioritize verifiable, primary-source metrics.

### 3. Test Vectors (Major Enhancement)

**v1.0.1 test vectors:**
```
sha256:7b9f3f4b2e8a1c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d
```
- Placeholder/example digests
- Not independently verifiable
- Signature values were illustrative only

**v1.0.2 test vectors:**
```
sha256:c8b0dd1582c61e53295ac07bae66448e67097a3b853ad6f2401025998b82dac7
```
- **Real Ed25519 keypair** with actual cryptographic material
- **Verifiable JWS signatures** (detached payload format)
- **Reproducible** - implementers can verify byte-for-byte
- Private key included (clearly marked NOT FOR PRODUCTION) for reproducibility

**Files added:**
- `tbom-testvector-signed-v1.0.2.json` - Complete signed TBOM
- `tbom-testvector-keys-v1.0.1.json` - Public key document
- `tbom-testvector-private-ed25519.jwk.json` - Test private key
- `tool-create_note.json` - Tool definition input
- `tbom-test-artifact.txt` - Test artifact for digest verification

**Impact:** Transforms specification from theoretical proposal to implementable standard. Standards reviewers specifically look for working test vectors.

### 4. Reference Tooling (New)

**Added: tbomctl.py**
- Schema validation against JSON Schema
- Signature verification (Ed25519/JWS)
- Canonical JSON generation (RFC 8785)
- Digest computation and verification
- `definitionDigest.covers` generation and validation aligned with digest input
- Uses a strict RFC 8785 canonicalization library (`jcs`)

**Added: Build system**
- `Makefile` with targets: check, html, pdf, versions, lock, dist, keygen, sign, verify-release, release
- `build.sh` wrapper with virtualenv support
- `requirements.txt` for Python dependencies
- `requirements.lock` for pinned dependency versions
- `build-versions.txt` for toolchain version capture
- `.github/workflows/release.yml` for tagged CI release verification (ephemeral key)

**Commands:**
```bash
make check        # Schema + signature verification
make html         # Generate HTML from markdown
make pdf          # Generate PDF (requires LaTeX)
make keygen       # Generate release signing key
make verify-release  # Verify release signatures + checksums
make release      # Build signed distribution bundle
```

### 5. Release Signing Workflow (New)

**Implemented:** The signing workflow TBOM recommends for MCP servers

```
dist/
├── tbom-whitepaper-rfc-v1.0.2.zip
├── SHA256SUMS.txt
├── SHA256SUMS.txt.sig      # RSA-3072 signature
├── provenance.json          # SLSA-style provenance statement
├── provenance.json.sig      # Signature over provenance.json
└── RELEASE_SIGNING_KEY.pub  # Verification key
```

**Verification command:**
```bash
openssl dgst -sha256 -verify dist/RELEASE_SIGNING_KEY.pub \
  -signature dist/SHA256SUMS.txt.sig dist/SHA256SUMS.txt
```

**Impact:** Demonstrates "practicing what you preach" - the specification author applies the same supply chain security practices being proposed.

**Automation:** Tagged CI builds run the same release and verification steps with an ephemeral signing key. Official releases should use a dedicated signing host or injected long-term key.

### 6. Schema Refinements

**Version bump:** 1.0.1 → 1.0.2

**Key changes:**
- `tbomVersion` const updated to "1.0.2"
- Examples updated to reference v1.0.2 schema
- `definitionDigest.covers` format defined and schema pattern tightened
- Keys schema remains v1.0.1 (no changes needed)

**Spec clarifications:**
- `covers` string format defined and validated
- Pre-canonicalization `undefined` handling clarified
- `downloadUrl` guidance updated to recommend `https://`
- `tools-list.json` input format documented for reference tooling

**Consistency verified:**
- Schema, conformance text, and examples now fully aligned
- All example files validate against schema
- Signed test vector verifies against public key

### 7. Incident Description Refinement

**CVE-2025-6514 description:**
- v1.0.1: "accumulated significant download volume before disclosure"
- v1.0.2: "the npm Downloads API reports 233,023 downloads for July 2025"

**Supabase/Cursor incident:**
- Added Simon Willison attribution for "lethal trifecta" term
- Added reference [25] for proper citation

### 8. Documentation Improvements

**README.md enhancements:**
- Quick start instructions with virtualenv
- Build requirements clearly listed
- Python 3.9+ version noted
- Release bundle structure documented
- **Explicit warning** about test private key
- Release verification instructions and reproducibility notes

**Appendix organization:**
- Appendix D (Test Vectors) expanded significantly
- Includes both tool definition digest and full JWS signature vectors
- Canonical payload digest provided for verification

---

## Development Process Evidence

### Review Cycle

1. **v1.0.0** (Initial draft) - Core specification structure
2. **v1.0.1** (First revision) - Addressed internal consistency issues:
   - Aligned schema, conformance text, and examples
   - Added BCP 14 (RFC 2119) boilerplate
   - Added Related Work section
   - Added signature roles
   - Added TBOM Keys Document schema
   - Corrected incident language (exposed vs. compromised)

3. **v1.0.2** (Current) - Reference implementation package:
   - Real cryptographic test vectors
   - Working verification tooling
   - Signed release workflow
   - Verified statistics from primary sources

### Expert Review Incorporation

Changes between versions reflect feedback on:
- **Internal consistency** - Schema/conformance/example alignment
- **Verifiability** - Real test vectors vs. placeholders
- **Credibility** - Primary source citations vs. secondary estimates
- **Implementability** - Reference tooling vs. specification-only
- **Professionalism** - RFC conventions, signed releases

---

## Artifact Inventory

### Specification Documents
| File | Version | Lines | Purpose |
|------|---------|-------|---------|
| tbom-whitepaper-rfc-v1.0.2.md | 1.0.2 | 2,290 | Primary specification |
| tbom-whitepaper-rfc-v1.0.2.html | 1.0.2 | Generated | Web distribution |
| tbom-whitepaper-rfc-v1.0.2.pdf | 1.0.2 | Generated | Print/archive |

### Process Documentation
| File | Purpose |
|------|---------|
| tbom-development-history.md | Development history and change log |

### Schema Files
| File | Version | Purpose |
|------|---------|---------|
| tbom-schema-v1.0.2.json | 1.0.2 | TBOM document validation |
| tbom-keys-schema-v1.0.1.json | 1.0.1 | Keys document validation |

### Examples and Test Vectors
| File | Purpose |
|------|---------|
| tbom-example-minimal-v1.0.2.json | Minimal conformant example |
| tbom-example-full-v1.0.2.json | Full-featured example |
| tbom-testvector-signed-v1.0.2.json | Verifiable signed TBOM |
| tbom-testvector-keys-v1.0.1.json | Test public key |
| tbom-testvector-private-ed25519.jwk.json | Test private key (NOT FOR PRODUCTION) |
| tool-create_note.json | Tool definition test input |
| tbom-test-artifact.txt | Artifact digest test input |

### Tooling
| File | Purpose |
|------|---------|
| tbomctl.py | Reference CLI tool |
| Makefile | Build automation |
| build.sh | Build wrapper |
| requirements.txt | Python dependencies |
| requirements.lock | Pinned Python dependencies |
| build-versions.txt | Toolchain version record |
| scripts/generate_provenance.py | SLSA-style provenance generator |
| .github/workflows/release.yml | CI release build + verification |

---

## Significance for Immigration Petition

### Original Contribution Evidence

1. **Novel technical contribution** - TBOM addresses a gap not covered by existing SBOM standards (tool semantics vs. code dependencies)

2. **Implementable specification** - Working test vectors and reference tooling demonstrate practical viability

3. **Standards-quality work** - RFC conventions, BCP 14 compliance, JSON Schema validation

4. **Iterative refinement** - Development history shows responsiveness to expert review

5. **Supply chain security expertise** - Author applies same practices being proposed (signed releases)

### Potential Citation/Adoption Indicators

- MCP community discussion engagement
- Registry operator interest (Smithery, mcp.run, etc.)
- Enterprise security team evaluations
- Integration into MCP tooling or specification

---

*Document generated: January 2026*
*For use in EB-1A/NIW petition supporting materials*
