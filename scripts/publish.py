#!/usr/bin/env python3
"""
PyPI Publishing Script for lanalyzer

This script helps manage the publishing process to PyPI with proper version management
and safety checks.
"""

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path


def run_command(cmd, check=True):
    """Run a shell command and return the result."""
    print(f"Running: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and result.returncode != 0:
        print(f"Error running command: {cmd}")
        print(f"stdout: {result.stdout}")
        print(f"stderr: {result.stderr}")
        sys.exit(1)
    return result


def get_current_version():
    """Get the current version from pyproject.toml."""
    pyproject_path = Path("pyproject.toml")
    if not pyproject_path.exists():
        print("Error: pyproject.toml not found")
        sys.exit(1)

    content = pyproject_path.read_text()
    match = re.search(r'version = "([^"]+)"', content)
    if not match:
        print("Error: Could not find version in pyproject.toml")
        sys.exit(1)

    return match.group(1)


def update_version(version_type):
    """Update version in pyproject.toml."""
    current_version = get_current_version()
    parts = current_version.split(".")

    if version_type == "patch":
        parts[2] = str(int(parts[2]) + 1)
    elif version_type == "minor":
        parts[1] = str(int(parts[1]) + 1)
        parts[2] = "0"
    elif version_type == "major":
        parts[0] = str(int(parts[0]) + 1)
        parts[1] = "0"
        parts[2] = "0"
    else:
        print(f"Error: Invalid version type: {version_type}")
        sys.exit(1)

    new_version = ".".join(parts)

    # Update pyproject.toml
    pyproject_path = Path("pyproject.toml")
    content = pyproject_path.read_text()
    new_content = re.sub(r'version = "[^"]+"', f'version = "{new_version}"', content)
    pyproject_path.write_text(new_content)

    print(f"Version updated from {current_version} to {new_version}")
    return new_version


def check_git_status():
    """Check if git working directory is clean."""
    result = run_command("git status --porcelain", check=False)
    if result.stdout.strip():
        print("Warning: Git working directory is not clean")
        print("Uncommitted changes:")
        print(result.stdout)
        response = input("Continue anyway? (y/N): ")
        if response.lower() != "y":
            sys.exit(1)


def run_tests():
    """Run tests before publishing."""
    print("Running tests...")
    run_command("uv run pytest")
    print("Tests passed!")


def run_quality_checks():
    """Run code quality checks."""
    print("Running quality checks...")
    run_command("make quality")
    print("Quality checks passed!")


def build_package():
    """Build the package."""
    print("Building package...")
    run_command("make build")
    print("Package built successfully!")


def publish_to_test_pypi():
    """Publish to test PyPI."""
    print("Publishing to test PyPI...")
    run_command(
        "uv run twine upload --repository-url https://test.pypi.org/legacy/ dist/*"
    )
    print("Published to test PyPI successfully!")


def publish_to_pypi():
    """Publish to PyPI."""
    print("Publishing to PyPI...")
    run_command("uv run twine upload dist/*")
    print("Published to PyPI successfully!")


def main():
    parser = argparse.ArgumentParser(description="Publish lanalyzer to PyPI")
    parser.add_argument(
        "--version-bump",
        choices=["patch", "minor", "major"],
        help="Bump version before publishing",
    )
    parser.add_argument(
        "--test-pypi",
        action="store_true",
        help="Publish to test PyPI instead of main PyPI",
    )
    parser.add_argument("--skip-tests", action="store_true", help="Skip running tests")
    parser.add_argument(
        "--skip-quality", action="store_true", help="Skip quality checks"
    )
    parser.add_argument(
        "--skip-git-check", action="store_true", help="Skip git status check"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Perform all steps except actual publishing",
    )

    args = parser.parse_args()

    # Change to project root
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    os.chdir(project_root)

    print(f"Publishing lanalyzer from {project_root}")

    # Check git status
    if not args.skip_git_check:
        check_git_status()

    # Bump version if requested
    if args.version_bump:
        new_version = update_version(args.version_bump)
        print(f"Version bumped to {new_version}")

    current_version = get_current_version()
    print(f"Current version: {current_version}")

    # Run quality checks
    if not args.skip_quality:
        run_quality_checks()

    # Run tests
    if not args.skip_tests:
        run_tests()

    # Build package
    build_package()

    if args.dry_run:
        print("Dry run completed. Package is ready for publishing.")
        print("To publish, run:")
        if args.test_pypi:
            print("  make test-publish")
        else:
            print("  make publish")
        return

    # Publish
    if args.test_pypi:
        publish_to_test_pypi()
    else:
        # Confirm before publishing to main PyPI
        response = input(
            f"Are you sure you want to publish version {current_version} to PyPI? (y/N): "
        )
        if response.lower() == "y":
            publish_to_pypi()
        else:
            print("Publishing cancelled.")
            sys.exit(1)

    print("Publishing completed successfully!")


if __name__ == "__main__":
    main()
