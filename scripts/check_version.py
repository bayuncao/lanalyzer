#!/usr/bin/env python3
"""
Version Check Script for lanalyzer

This script checks if version numbers in pyproject.toml and lanalyzer/__version__.py
are synchronized.
"""

import re
import sys
from pathlib import Path


def main():
    """Check version synchronization between files."""
    # Change to project root
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    import os

    os.chdir(project_root)

    # Check pyproject.toml version
    pyproject = Path("pyproject.toml")
    if not pyproject.exists():
        print("❌ pyproject.toml 文件不存在")
        sys.exit(1)

    content = pyproject.read_text()
    pyproject_match = re.search(r'version = "([^"]+)"', content)
    if not pyproject_match:
        print("❌ 无法在 pyproject.toml 中找到版本")
        sys.exit(1)

    pyproject_version = pyproject_match.group(1)
    print(f"📄 pyproject.toml version: {pyproject_version}")

    # Check __version__.py version
    version_file = Path("lanalyzer/__version__.py")
    if not version_file.exists():
        print("❌ lanalyzer/__version__.py 文件不存在")
        sys.exit(1)

    version_content = version_file.read_text()
    version_match = re.search(r'__version__ = "([^"]+)"', version_content)
    if not version_match:
        print("❌ 无法在 lanalyzer/__version__.py 中找到版本")
        sys.exit(1)

    file_version = version_match.group(1)
    print(f"🐍 lanalyzer/__version__.py version: {file_version}")

    # Compare versions
    if pyproject_version == file_version:
        print("✅ 版本同步正常")
        sys.exit(0)
    else:
        print("❌ 版本不同步")
        print(f"   pyproject.toml: {pyproject_version}")
        print(f"   __version__.py: {file_version}")
        print("💡 运行 make version-patch/minor/major 来同步版本")
        sys.exit(1)


if __name__ == "__main__":
    main()
