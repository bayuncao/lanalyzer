#!/usr/bin/env python3
"""
Version Update Script for lanalyzer

This script updates version numbers in both pyproject.toml and lanalyzer/__version__.py
to ensure they stay synchronized.
"""

import argparse
import re
import sys
from pathlib import Path


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
    """Update version in both pyproject.toml and lanalyzer/__version__.py."""
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

    # Update lanalyzer/__version__.py
    version_file_path = Path("lanalyzer/__version__.py")
    if version_file_path.exists():
        version_content = version_file_path.read_text()
        new_version_content = re.sub(
            r'__version__ = "[^"]+"', f'__version__ = "{new_version}"', version_content
        )
        version_file_path.write_text(new_version_content)
        print(f"✅ Updated lanalyzer/__version__.py to {new_version}")
    else:
        print("⚠️  Warning: lanalyzer/__version__.py not found")

    print(f"✅ Updated pyproject.toml to {new_version}")
    print(f"🎉 Version updated from {current_version} to {new_version}")
    return new_version


def main():
    parser = argparse.ArgumentParser(description="Update version numbers in lanalyzer")
    parser.add_argument(
        "version_type",
        choices=["patch", "minor", "major"],
        help="Type of version bump to perform",
    )

    args = parser.parse_args()

    # Change to project root
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    import os

    os.chdir(project_root)

    update_version(args.version_type)


if __name__ == "__main__":
    main()
