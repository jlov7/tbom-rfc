# Copyright 2026 Jason M. Lovell
# SPDX-License-Identifier: Apache-2.0

OPENSSL ?= openssl
PYTHON ?= python3
DIST_DIR := dist
DIST_ZIP := $(DIST_DIR)/tbom-tooling-v1.0.2.zip
KEY_DIR ?= $(HOME)/.tbom-release-keys
SIGNING_KEY ?= $(KEY_DIR)/tbom-release.pem
SIGNING_PUB ?= $(KEY_DIR)/tbom-release.pub
DIST_SIG := $(DIST_DIR)/SHA256SUMS.txt.sig
DIST_PUB := $(DIST_DIR)/RELEASE_SIGNING_KEY.pub
BUILD_VERSIONS := build-versions.txt
LOCK_FILE := requirements.lock
PROVENANCE := $(DIST_DIR)/provenance.json
PROVENANCE_SIG := $(DIST_DIR)/provenance.json.sig
PROVENANCE_SCRIPT := scripts/generate_provenance.py
SHOWCASE_DIR ?= build/showcase
DEMO_VIDEO ?= $(SHOWCASE_DIR)/tbom-demo.mp4
DEMO_VIDEO_LIGHT ?= $(SHOWCASE_DIR)/tbom-demo-light.mp4
DEMO_GIF ?= $(SHOWCASE_DIR)/tbom-demo.gif
DEMO_GIF_LIGHT ?= $(SHOWCASE_DIR)/tbom-demo-light.gif

SCHEMA := tbom-schema-v1.0.2.json
KEYS_SCHEMA := tbom-keys-schema-v1.0.1.json
EXAMPLES := tbom-example-minimal-v1.0.2.json tbom-example-full-v1.0.2.json
SIGNED := tbom-testvector-signed-v1.0.2.json
KEYS := tbom-testvector-keys-v1.0.1.json
PRIVATE_KEY := tbom-testvector-private-ed25519.jwk.json
TOOL_DEF := tool-create_note.json
TEST_ARTIFACT := tbom-test-artifact.txt

DIST_FILES := $(SCHEMA) $(KEYS_SCHEMA) $(EXAMPLES) \
	$(SIGNED) $(KEYS) $(PRIVATE_KEY) $(TOOL_DEF) $(TEST_ARTIFACT) \
	tbomctl.py tbom_mcp_server.py py.typed Makefile build.sh requirements.txt $(LOCK_FILE) $(BUILD_VERSIONS) \
	pyproject.toml README.md tbom-development-history.md $(PROVENANCE_SCRIPT) scripts/build_binaries.py scripts/ai_eval.py scripts/mutation_test.py scripts/showcase.py scripts/render_demo_video.py scripts/render_demo_gif.py \
	tests/test_tbomctl.py tests/test_mcp_integration.py TESTING.md \
	EXECUTIVE_SUMMARY.md DEMO_SCRIPT.md ARCHITECTURE.md FAQ.md RELEASE_NOTES_v1.0.2.md docs/TERMINAL_DEMO.md docs/showcase/index.md \
	docs/index.md docs/demo.md docs/explainer.md docs/architecture.md docs/trust.md docs/requirements.txt docs/stylesheets/extra.css \
	docs/assets/tbom-sigil.svg docs/assets/tbom-explainer.svg docs/assets/tbom-demo-still.png docs/assets/tbom-demo.gif mkdocs.yml \
	LICENSE CONTRIBUTING.md SECURITY.md SECURITY_AUDIT.md PERFORMANCE.md CODE_OF_CONDUCT.md
ifneq ($(wildcard .venv/bin/python),)
PYTHON := .venv/bin/python
endif

.PHONY: all check check-python validate-examples verify-testvector versions lock dist binaries keygen sign release verify-release clean lint test integration-test verify verify-strict coverage ai-eval mutation-test showcase showcase-strict demo-video demo-video-strict demo-video-light demo-video-light-strict demo-gif demo-gif-strict demo-gif-light install-cli

all: verify

check: validate-examples verify-testvector lint test

verify: check integration-test ai-eval

verify-strict: verify mutation-test coverage

check-python:
	@[ -x "$(PYTHON)" ] || { echo "python3 is required"; exit 1; }
	@$(PYTHON) -c "import jsonschema, cryptography, jcs; print(\"python deps OK\")"

install-cli: check-python
	@$(PYTHON) -m pip install -e .

validate-examples: check-python
	@for f in $(EXAMPLES); do \
		$(PYTHON) tbomctl.py check --schema $(SCHEMA) $$f; \
	done

verify-testvector: check-python
	@$(PYTHON) tbomctl.py check --schema $(SCHEMA) --keys $(KEYS) --keys-schema $(KEYS_SCHEMA) $(SIGNED)

lint: check-python
	@$(PYTHON) -m ruff check .
	@$(PYTHON) -m ruff format --check .
	@$(PYTHON) -m mypy tbomctl.py scripts/generate_provenance.py

test: check-python
	@$(PYTHON) -m pytest tests/ -m "not integration"

integration-test: check-python
	@$(PYTHON) -m pytest tests/ -m "integration"

ai-eval: check-python
	@mkdir -p build
	@$(PYTHON) scripts/ai_eval.py --output build/ai-eval.json

coverage: check-python
	@$(PYTHON) -m pytest --cov=tbomctl --cov=tbom_mcp_server --cov=scripts --cov-branch --cov-report=term-missing --cov-fail-under=100

mutation-test: check-python
	@mkdir -p build
	@$(PYTHON) scripts/mutation_test.py --output build/mutation-report.json

showcase: check-python
	@$(PYTHON) scripts/showcase.py --output-dir $(SHOWCASE_DIR)

showcase-strict: check-python
	@$(PYTHON) scripts/showcase.py --output-dir $(SHOWCASE_DIR) --strict

demo-video: check-python
	@$(PYTHON) scripts/render_demo_video.py --output $(DEMO_VIDEO) --showcase-dir $(SHOWCASE_DIR) --theme dark

demo-video-strict: check-python
	@$(PYTHON) scripts/render_demo_video.py --output $(DEMO_VIDEO) --showcase-dir $(SHOWCASE_DIR) --strict --theme dark

demo-video-light: check-python
	@$(PYTHON) scripts/render_demo_video.py --output $(DEMO_VIDEO_LIGHT) --showcase-dir $(SHOWCASE_DIR) --theme light

demo-video-light-strict: check-python
	@$(PYTHON) scripts/render_demo_video.py --output $(DEMO_VIDEO_LIGHT) --showcase-dir $(SHOWCASE_DIR) --strict --theme light

demo-gif: demo-video
	@$(PYTHON) scripts/render_demo_gif.py --input $(DEMO_VIDEO) --output $(DEMO_GIF)

demo-gif-strict: demo-video-strict
	@$(PYTHON) scripts/render_demo_gif.py --input $(DEMO_VIDEO) --output $(DEMO_GIF)

demo-gif-light: demo-video-light
	@$(PYTHON) scripts/render_demo_gif.py --input $(DEMO_VIDEO_LIGHT) --output $(DEMO_GIF_LIGHT)

versions:
	@{ \
		echo "generated_utc: $$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
		echo "python: $$($(PYTHON) --version 2>&1)"; \
		if command -v $(OPENSSL) >/dev/null; then $(OPENSSL) version; else echo "openssl: not found"; fi; \
	} > $(BUILD_VERSIONS)

lock: check-python
	@$(PYTHON) -m pip freeze > $(LOCK_FILE)

dist: all versions lock
	@command -v zip >/dev/null || { echo "zip is required for dist bundle"; exit 1; }
	@mkdir -p $(DIST_DIR)
	@rm -f $(DIST_ZIP)
	@zip -q -r $(DIST_ZIP) $(DIST_FILES)
	@$(PYTHON) $(PROVENANCE_SCRIPT) --zip $(DIST_ZIP) --output $(PROVENANCE) --version 1.0.2
	@shasum -a 256 $(DIST_ZIP) $(DIST_FILES) $(PROVENANCE) > $(DIST_DIR)/SHA256SUMS.txt

binaries: check-python
	@command -v pyinstaller >/dev/null || { echo "pyinstaller is required for binaries (pip install pyinstaller)"; exit 1; }
	@$(PYTHON) scripts/build_binaries.py
keygen:
	@command -v $(OPENSSL) >/dev/null || { echo \"openssl is required for release signing\"; exit 1; }
	@mkdir -p $(KEY_DIR)
	@if [ -f "$(SIGNING_KEY)" ]; then \
		echo \"Signing key already exists: $(SIGNING_KEY)\"; \
	else \
		$(OPENSSL) genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out $(SIGNING_KEY); \
		$(OPENSSL) pkey -in $(SIGNING_KEY) -pubout -out $(SIGNING_PUB); \
		chmod 600 $(SIGNING_KEY); \
		echo \"Generated signing key: $(SIGNING_KEY)\"; \
	fi

sign: dist
	@command -v $(OPENSSL) >/dev/null || { echo \"openssl is required for release signing\"; exit 1; }
	@[ -f "$(SIGNING_KEY)" ] || { echo \"Signing key not found. Run 'make keygen' or set SIGNING_KEY/SIGNING_PUB\"; exit 1; }
	@$(OPENSSL) pkey -in $(SIGNING_KEY) -pubout -out $(SIGNING_PUB)
	@$(OPENSSL) dgst -sha256 -sign $(SIGNING_KEY) -out $(DIST_SIG) $(DIST_DIR)/SHA256SUMS.txt
	@$(OPENSSL) dgst -sha256 -sign $(SIGNING_KEY) -out $(PROVENANCE_SIG) $(PROVENANCE)
	@cp $(SIGNING_PUB) $(DIST_PUB)

release: sign

verify-release:
	@command -v $(OPENSSL) >/dev/null || { echo \"openssl is required for release verification\"; exit 1; }
	@command -v shasum >/dev/null || { echo \"shasum is required for release verification\"; exit 1; }
	@$(OPENSSL) dgst -sha256 -verify $(DIST_PUB) -signature $(DIST_SIG) $(DIST_DIR)/SHA256SUMS.txt
	@$(OPENSSL) dgst -sha256 -verify $(DIST_PUB) -signature $(PROVENANCE_SIG) $(PROVENANCE)
	@shasum -a 256 -c $(DIST_DIR)/SHA256SUMS.txt

clean:
	@rm -rf build
