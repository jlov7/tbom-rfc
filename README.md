# TBOM White Paper (RFC v1.0.2)

This repo contains the TBOM white paper, schemas, examples, test vectors, and a reference toolchain for validation and signing checks.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
# or for pinned versions:
# python -m pip install -r requirements.lock
./build.sh
```

`./build.sh` runs `make all`, which:
- validates JSON examples against the schema,
- verifies the signed test vector,
- builds HTML and PDF outputs from the markdown.

## Build requirements

- Python 3.9+
- `pandoc`
- `latexmk` with `xelatex` (Tex Live / MacTeX provides both)
- `openssl` (for release signing)

## Useful commands

```bash
make check        # schema + signature verification
make html         # regenerate HTML
make pdf          # regenerate PDF
make versions     # record tool versions to build-versions.txt
make lock         # pin Python dependencies to requirements.lock
make dist         # build release zip + checksums
make keygen       # generate a local release signing key
make sign         # sign SHA256SUMS.txt (requires key)
make release      # dist + sign
make verify-release  # verify release signatures + checksums
make clean        # remove generated HTML/PDF
```

## Release bundle

The release bundle is written to `dist/`:
- `dist/tbom-whitepaper-rfc-v1.0.2.zip`
- `dist/SHA256SUMS.txt`
- `dist/SHA256SUMS.txt.sig`
- `dist/provenance.json`
- `dist/provenance.json.sig`
- `dist/RELEASE_SIGNING_KEY.pub`

Signing uses a local key stored at `~/.tbom-release-keys/tbom-release.pem`.
Generate the key with `make keygen`, then run `make release`.

### Production signing (recommended)

For a long-term release key, use a dedicated signing host or an HSM-backed key.
Set the key paths explicitly and run `make release` on the signing host:

```bash
SIGNING_KEY=/path/to/release-key.pem \
SIGNING_PUB=/path/to/release-key.pub \
make release
```

Avoid `make keygen` for production releases; it is intended for local or CI-only testing.

Verify the signed manifest:

```bash
openssl dgst -sha256 -verify dist/RELEASE_SIGNING_KEY.pub \
  -signature dist/SHA256SUMS.txt.sig dist/SHA256SUMS.txt
```

Verify the provenance attestation:

```bash
openssl dgst -sha256 -verify dist/RELEASE_SIGNING_KEY.pub \
  -signature dist/provenance.json.sig dist/provenance.json
```

## Reproducibility notes

- `requirements.lock` captures exact Python dependency versions (`make lock`).
- `build-versions.txt` records toolchain versions used for the release (`make versions`).

## CI verification

The workflow in `.github/workflows/release.yml` runs `make release` and
`make verify-release` on tagged builds using an ephemeral signing key.
For official releases, run the release step on your dedicated signing host
or inject a long-term key via CI secrets and set `SIGNING_KEY`/`SIGNING_PUB`.

## Key artifacts

- `tbom-whitepaper-rfc-v1.0.2.md` (source)
- `tbom-whitepaper-rfc-v1.0.2.html`
- `tbom-whitepaper-rfc-v1.0.2.pdf`
- `tbom-schema-v1.0.2.json`
- `tbom-keys-schema-v1.0.1.json`
- `tbom-example-minimal-v1.0.2.json`
- `tbom-example-full-v1.0.2.json`
- `tbom-testvector-signed-v1.0.2.json`
- `tbomctl.py`
- `tbom-development-history.md`
- `requirements.lock`
- `build-versions.txt`

Test-only key material:
- `tbom-testvector-private-ed25519.jwk.json` is included solely to reproduce the test vector signatures; it is labeled **NOT FOR PRODUCTION**.
