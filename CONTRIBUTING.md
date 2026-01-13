# Contributing to TBOM

Thank you for your interest in contributing to the Tool Bill of Materials (TBOM) specification!

## Ways to Contribute

### 1. Specification Feedback

The TBOM specification is currently in **Draft for MCP Community Review** status. We welcome feedback on:

- **Clarity**: Are any sections unclear or ambiguous?
- **Completeness**: Are there gaps in the threat model or use cases?
- **Implementability**: Are there barriers to implementing TBOM in your environment?
- **Interoperability**: Are there conflicts with existing standards or tooling?

To provide feedback:
1. Open an issue describing your concern or suggestion
2. Reference the specific section(s) of the specification
3. If proposing a change, explain the rationale and any trade-offs

### 2. Reference Tooling

The `tbomctl.py` reference implementation is designed to be minimal and correct, not feature-complete. Contributions that improve:

- **Correctness**: Bug fixes for canonicalization, signature verification, or schema validation
- **Test coverage**: Additional test vectors or edge cases
- **Documentation**: Usage examples or API documentation

### 3. Test Vectors

Additional test vectors are valuable for interoperability. When contributing test vectors:

- Ensure all cryptographic values are reproducible
- Include both the input data and expected outputs
- Mark any test keys as **NOT FOR PRODUCTION**
- Document the test scenario being covered

## Contribution Process

### For Minor Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b fix/typo-in-section-5`)
3. Make your changes
4. Run validation (`make check`)
5. Submit a pull request with a clear description

### For Specification Changes

Specification changes require more discussion:

1. **Open an issue first** describing the proposed change
2. Wait for maintainer feedback before investing in implementation
3. If approved, follow the minor changes process above
4. Specification PRs should update:
   - The markdown source (`tbom-whitepaper-rfc-v1.0.2.md`)
   - The JSON schema if normative fields change
   - Examples if affected
   - Test vectors if verification logic changes

### Commit Messages

Follow conventional commit style:
- `fix:` for bug fixes
- `feat:` for new features
- `docs:` for documentation changes
- `chore:` for maintenance tasks

Example: `fix: correct RFC 8785 canonicalization for empty arrays`

## Code Style

### Python (`tbomctl.py`)

- Python 3.9+ compatibility
- Type hints for function signatures
- Docstrings for public functions
- No external dependencies beyond `requirements.txt`

### JSON Schemas

- Use JSON Schema Draft 2020-12
- Include `description` for all properties
- Use `additionalProperties: false` for strict validation
- Keep examples in sync with schema changes

## Testing

Before submitting:

```bash
# Set up environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run all checks
make check

# Verify release bundle (if changing dist files)
make release
make verify-release
```

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). By participating, you agree to uphold this code.

## Questions?

- Open an issue for questions about the specification
- Contact the maintainer at jase.lovell@me.com for sensitive matters

## License

By contributing, you agree that your contributions will be licensed under the same terms as the project (Apache 2.0 for code, CC BY 4.0 for specification content).
