"""
File utilities for LanaLyzer.

Provides common file and path operations used by the taint analysis engine.
"""

import os
from pathlib import Path
from typing import List, Optional


def is_python_file(file_path: str) -> bool:
    """
    Check if a file is a Python file.

    Args:
        file_path: Path to the file

    Returns:
        True if the file has a .py extension, False otherwise
    """
    return file_path.lower().endswith(".py")


def get_python_files_in_directory(
    directory: str, recursive: bool = True, exclude_dirs: List[str] = None
) -> List[str]:
    """
    Get all Python files in a directory.

    Args:
        directory: Directory to search for Python files
        recursive: Whether to search recursively in subdirectories
        exclude_dirs: List of directory names to exclude (e.g., ["venv", "__pycache__"])

    Returns:
        List of paths to Python files
    """
    exclude_dirs = exclude_dirs or ["__pycache__", "venv", ".git", ".github"]
    python_files = []

    # Handle the case where the input is a file, not a directory
    if os.path.isfile(directory):
        if is_python_file(directory):
            return [directory]
        return []

    if recursive:
        for root, dirs, files in os.walk(directory):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in exclude_dirs]

            for file in files:
                if is_python_file(file):
                    python_files.append(os.path.join(root, file))
    else:
        # Non-recursive search
        for item in os.listdir(directory):
            item_path = os.path.join(directory, item)
            if os.path.isfile(item_path) and is_python_file(item_path):
                python_files.append(item_path)

    return python_files


def ensure_directory_exists(directory_path: str) -> None:
    """
    Ensure a directory exists, creating it if necessary.

    Args:
        directory_path: Path to the directory
    """
    Path(directory_path).mkdir(parents=True, exist_ok=True)


def get_relative_path(base_path: str, full_path: str) -> str:
    """
    Convert an absolute path to a path relative to the base path.

    Args:
        base_path: Base directory path
        full_path: Full path to convert to relative

    Returns:
        Path relative to the base path
    """
    try:
        return os.path.relpath(full_path, base_path)
    except ValueError:
        # Handle case where paths are on different drives (Windows)
        return full_path


def get_absolute_path(path: str, relative_to: Optional[str] = None) -> str:
    """
    Convert a relative path to an absolute path.

    Args:
        path: Path to convert to absolute
        relative_to: Base directory for relative paths (default: current working directory)

    Returns:
        Absolute path
    """
    if os.path.isabs(path):
        return path

    base_dir = relative_to or os.getcwd()
    return os.path.normpath(os.path.join(base_dir, path))
