# Contributing to Validibot Validators

Thank you for your interest in contributing! This document covers the process
for contributing to `validibot-validator-backends`.

## License Agreement

By submitting a pull request, you agree that your contributions are licensed
under the [MIT License](LICENSE), the same license that covers this project.
You confirm that you have the right to grant this license for your contributions.

## Getting Started

1. Fork the repository
2. Clone your fork and create a feature branch
3. Install dependencies: `uv sync --extra dev`
4. Make your changes
5. Run checks: `just check` (runs linter + tests)
6. Submit a pull request

## Development Setup

```bash
# Install dependencies
uv sync --extra dev

# Run all tests
just test

# Run linter
just lint

# Run type checker
just typecheck

# Run all checks (lint + test)
just check
```

## Pull Request Guidelines

- Keep changes focused — one feature or fix per PR
- Include tests for new functionality
- Ensure `just check` passes before submitting
- Write a clear PR description explaining the "why" behind the change

## Security Property Tests

Hypothesis complements the repository's fixed hostile-input fixtures at the
runtime boundaries where generated variation adds value: attempt scratch
confinement, immutable streamed input verification, and SHACL SPARQL policy
checks. Shared envelope semantics remain tested in `validibot-shared` rather
than being duplicated here.

CI selects a bounded `ci` profile (75 examples per property with a 500 ms
per-example deadline). To reproduce it locally:

```bash
HYPOTHESIS_PROFILE=ci just test \
  validator_backends/core/tests/test_storage_properties.py \
  validator_backends/shacl/tests/test_sparql_security_properties.py
```

Documented rejections such as `FileVerificationError`, `StorageConflictError`,
and `SparqlScrubError` are expected outcomes. Unexpected exceptions, hangs,
resource exhaustion, path escape, partial-file commits, or policy bypasses are
bugs. Add every minimized genuine finding as a named regression test.

## Creating a New Validator

See the [Creating a Custom Validator](README.md#creating-a-custom-validator)
section in the README for a step-by-step guide.

## Code Style

This project uses [Ruff](https://docs.astral.sh/ruff/) for linting and
formatting. Configuration is in [pyproject.toml](pyproject.toml). Run
`just lint-fix` to auto-fix issues and `just format` to format code.

## Reporting Issues

- **Bugs and feature requests:** [GitHub Issues](https://github.com/mcquilleninteractive/validibot-validator-backends/issues)
- **Security vulnerabilities:** See [SECURITY.md](SECURITY.md) — do not open a public issue

## Code of Conduct

Be respectful and constructive. We reserve the right to remove comments or
block contributors who engage in harassment, abuse, or other harmful behavior.
