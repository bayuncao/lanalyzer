# Development commands
format:
	uv run black .
	uv run isort .

lint:
	uv run flake8 .
	# Skip mypy for now due to existing type issues
	# uv run mypy .

check: format lint

pre-commit:
	uv run pre-commit run --all-files

quality: format lint pre-commit

# Testing commands
test:
	uv run pytest

test-cov:
	uv run pytest --cov=lanalyzer --cov-report=html --cov-report=term

# Build and publish commands
clean:
	rm -rf dist/ build/ *.egg-info/ .pytest_cache/ htmlcov/ .coverage

install-build-deps:
	uv add --group dev build twine

build: clean
	uv build

test-publish: build
	uv run twine upload --repository-url https://test.pypi.org/legacy/ dist/*

publish: build
	uv run twine upload dist/*

# Publishing with version management
publish-patch:
	uv run python scripts/publish.py --version-bump patch

publish-minor:
	uv run python scripts/publish.py --version-bump minor

publish-major:
	uv run python scripts/publish.py --version-bump major

publish-test:
	uv run python scripts/publish.py --test-pypi

publish-dry-run:
	uv run python scripts/publish.py --dry-run

publish-patch-no-test:
	uv run python scripts/publish.py --version-bump patch --skip-tests

publish-minor-no-test:
	uv run python scripts/publish.py --version-bump minor --skip-tests

publish-major-no-test:
	uv run python scripts/publish.py --version-bump major --skip-tests

publish-no-test:
	uv run python scripts/publish.py --skip-tests

# Development setup
install:
	uv sync

install-dev:
	uv sync --group dev

install-mcp:
	uv sync --extra mcp

install-all:
	uv sync --group dev --extra mcp

# MCP server commands
mcp-server:
	uv run python -m lanalyzer.mcp run --port 8001

mcp-server-debug:
	uv run python -m lanalyzer.mcp run --port 8001 --debug

mcp-test:
	uv run python -m lanalyzer.mcp --help

# Version management
version-patch:
	uv run python -c "import re; content = open('pyproject.toml').read(); version = re.search(r'version = \"([^\"]+)\"', content).group(1); parts = version.split('.'); parts[2] = str(int(parts[2]) + 1); new_version = '.'.join(parts); open('pyproject.toml', 'w').write(re.sub(r'version = \"[^\"]+\"', f'version = \"{new_version}\"', content)); print(f'Version updated to {new_version}')"

version-minor:
	uv run python -c "import re; content = open('pyproject.toml').read(); version = re.search(r'version = \"([^\"]+)\"', content).group(1); parts = version.split('.'); parts[1] = str(int(parts[1]) + 1); parts[2] = '0'; new_version = '.'.join(parts); open('pyproject.toml', 'w').write(re.sub(r'version = \"[^\"]+\"', f'version = \"{new_version}\"', content)); print(f'Version updated to {new_version}')"

version-major:
	uv run python -c "import re; content = open('pyproject.toml').read(); version = re.search(r'version = \"([^\"]+)\"', content).group(1); parts = version.split('.'); parts[0] = str(int(parts[0]) + 1); parts[1] = '0'; parts[2] = '0'; new_version = '.'.join(parts); open('pyproject.toml', 'w').write(re.sub(r'version = \"[^\"]+\"', f'version = \"{new_version}\"', content)); print(f'Version updated to {new_version}')"

# Help
help:
	@echo "Available commands:"
	@echo "  format        - Format code with black and isort"
	@echo "  lint          - Run linting with flake8 and mypy"
	@echo "  check         - Run format and lint"
	@echo "  pre-commit    - Run pre-commit hooks"
	@echo "  quality       - Run format, lint, and pre-commit"
	@echo "  test          - Run tests"
	@echo "  test-cov      - Run tests with coverage"
	@echo "  clean         - Clean build artifacts"
	@echo "  build         - Build package"
	@echo "  test-publish  - Publish to test PyPI"
	@echo "  publish       - Publish to PyPI"
	@echo "  publish-patch - Bump patch version and publish"
	@echo "  publish-minor - Bump minor version and publish"
	@echo "  publish-major - Bump major version and publish"
	@echo "  publish-patch-no-test - Bump patch version and publish (skip tests)"
	@echo "  publish-minor-no-test - Bump minor version and publish (skip tests)"
	@echo "  publish-major-no-test - Bump major version and publish (skip tests)"
	@echo "  publish-no-test - Publish without version bump (skip tests)"
	@echo "  publish-test  - Publish to test PyPI with checks"
	@echo "  publish-dry-run - Test publishing process without uploading"
	@echo "  install       - Install dependencies"
	@echo "  install-dev   - Install dev dependencies"
	@echo "  install-mcp   - Install with MCP support"
	@echo "  install-all   - Install dev dependencies and MCP support"
	@echo "  mcp-server    - Start MCP server on port 8001"
	@echo "  mcp-server-debug - Start MCP server with debug mode"
	@echo "  mcp-test      - Test MCP CLI"
	@echo "  version-patch - Bump patch version"
	@echo "  version-minor - Bump minor version"
	@echo "  version-major - Bump major version"

.PHONY: format lint check pre-commit quality test test-cov clean build test-publish publish publish-patch publish-minor publish-major publish-patch-no-test publish-minor-no-test publish-major-no-test publish-no-test publish-test publish-dry-run install install-dev install-mcp install-all mcp-server mcp-server-debug mcp-test version-patch version-minor version-major help
