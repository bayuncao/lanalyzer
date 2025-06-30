# Development Guide

This document describes the development workflow for lanalyzer, including building, testing, and publishing.

## Prerequisites

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) package manager

## Setup Development Environment

1. Clone the repository:
```bash
git clone <repository-url>
cd lanalyzer
```

2. Install dependencies:
```bash
# Install basic dependencies
make install

# Install with development dependencies
make install-dev

# Install with MCP support
make install-mcp

# Install everything (dev + MCP)
make install-all
```

This will install all dependencies including development tools like black, isort, flake8, mypy, pytest, build, and twine. Use `make install-mcp` or `make install-all` if you need MCP server functionality.

## Development Workflow

### Code Quality

Format code:
```bash
make format
```

Run linting:
```bash
make lint
```

Run all quality checks:
```bash
make quality
```

### Testing

Run tests:
```bash
make test
```

Run tests with coverage:
```bash
make test-cov
```

### Building

Clean build artifacts:
```bash
make clean
```

Build package:
```bash
make build
```

This creates both source distribution (.tar.gz) and wheel (.whl) files in the `dist/` directory.

## MCP Server Development

The project includes MCP (Model Context Protocol) server functionality for integration with AI assistants.

### Starting MCP Server

```bash
# Start MCP server on port 8001
make mcp-server

# Start MCP server with debug mode
make mcp-server-debug

# Test MCP CLI
make mcp-test
```

### MCP Server Features

- **Code Analysis**: Analyze Python files for vulnerabilities
- **Configuration Management**: Create and validate analysis configurations
- **Vulnerability Explanation**: Get detailed explanations of found vulnerabilities
- **File Analysis**: Analyze individual files or entire directories

### MCP Client Connection

When connecting to the MCP server with a Python client:

1. Create your ClientSession normally
2. Call `await session.initialize()` BEFORE any tool calls
3. Wait for initialization to complete before making requests

Example connection URL: `http://127.0.0.1:8001`

## Publishing to PyPI

### Method 1: Using Makefile (Simple)

For basic publishing without version management:

```bash
# Publish to test PyPI
make test-publish

# Publish to main PyPI
make publish
```

### Method 2: Using Publishing Script (Recommended)

The publishing script provides better version management and safety checks:

#### Dry Run (Test without publishing)
```bash
make publish-dry-run
```

#### Publish with Version Bump
```bash
# Bump patch version (0.1.1 -> 0.1.2) and publish
make publish-patch

# Bump minor version (0.1.1 -> 0.2.0) and publish
make publish-minor

# Bump major version (0.1.1 -> 1.0.0) and publish
make publish-major
```

#### Publish with Version Bump (Skip Tests)
```bash
# Bump patch version and publish (skip tests)
make publish-patch-no-test

# Bump minor version and publish (skip tests)
make publish-minor-no-test

# Bump major version and publish (skip tests)
make publish-major-no-test

# Publish without version bump (skip tests)
make publish-no-test
```

#### Publish to Test PyPI
```bash
make publish-test
```

#### Manual Version Bump
```bash
# Bump patch version only
make version-patch

# Bump minor version only
make version-minor

# Bump major version only
make version-major
```

### Publishing Script Options

The publishing script (`scripts/publish.py`) supports various options:

```bash
# Basic usage
uv run python scripts/publish.py

# With version bump
uv run python scripts/publish.py --version-bump patch

# Publish to test PyPI
uv run python scripts/publish.py --test-pypi

# Skip various checks (for CI/CD)
uv run python scripts/publish.py --skip-tests --skip-quality --skip-git-check

# Dry run (test without publishing)
uv run python scripts/publish.py --dry-run
```

## PyPI Credentials

Before publishing, ensure you have PyPI credentials configured:

1. Create accounts on [PyPI](https://pypi.org) and [Test PyPI](https://test.pypi.org)
2. Generate API tokens for both services
3. Configure credentials using one of these methods:

### Option 1: Using keyring (Recommended)
```bash
# For main PyPI
uv run python -m keyring set https://upload.pypi.org/legacy/ __token__

# For test PyPI
uv run python -m keyring set https://test.pypi.org/legacy/ __token__
```

### Option 2: Using .pypirc file
Create `~/.pypirc`:
```ini
[distutils]
index-servers =
    pypi
    testpypi

[pypi]
username = __token__
password = pypi-your-api-token-here

[testpypi]
repository = https://test.pypi.org/legacy/
username = __token__
password = pypi-your-test-api-token-here
```

## Migration from Poetry to uv

This project has been migrated from Poetry to uv. Key changes:

1. **Dependency management**: Use `uv add/remove` instead of `poetry add/remove`
2. **Virtual environment**: Managed automatically by uv
3. **Scripts**: Use `uv run` instead of `poetry run`
4. **Lock file**: `uv.lock` instead of `poetry.lock`
5. **Configuration**: Dependencies defined in `pyproject.toml` under `[dependency-groups]`

## Available Make Commands

Run `make help` to see all available commands:

```bash
make help
```

This will show:
- `format` - Format code with black and isort
- `lint` - Run linting with flake8 and mypy
- `check` - Run format and lint
- `quality` - Run format, lint, and pre-commit
- `test` - Run tests
- `test-cov` - Run tests with coverage
- `clean` - Clean build artifacts
- `build` - Build package
- `test-publish` - Publish to test PyPI
- `publish` - Publish to PyPI
- `publish-patch` - Bump patch version and publish
- `publish-minor` - Bump minor version and publish
- `publish-major` - Bump major version and publish
- `publish-patch-no-test` - Bump patch version and publish (skip tests)
- `publish-minor-no-test` - Bump minor version and publish (skip tests)
- `publish-major-no-test` - Bump major version and publish (skip tests)
- `publish-no-test` - Publish without version bump (skip tests)
- `publish-test` - Publish to test PyPI with checks
- `publish-dry-run` - Test publishing process without uploading
- `install` - Install dependencies
- `install-dev` - Install dev dependencies
- `install-mcp` - Install with MCP support
- `install-all` - Install dev dependencies and MCP support
- `mcp-server` - Start MCP server on port 8001
- `mcp-server-debug` - Start MCP server with debug mode
- `mcp-test` - Test MCP CLI
- `version-patch` - Bump patch version
- `version-minor` - Bump minor version
- `version-major` - Bump major version

## Troubleshooting

### Build Issues
- Ensure all dependencies are installed: `make install-dev`
- Clean build artifacts: `make clean`
- Check for syntax errors: `make lint`

### Publishing Issues
- Verify PyPI credentials are configured
- Test with test PyPI first: `make publish-test`
- Use dry run to test the process: `make publish-dry-run`

### Quality Check Failures
- Run `make format` to fix formatting issues
- Fix linting errors shown by `make lint`
- Update imports and remove unused variables
