"""
File system utility module providing file and path operations for LanaLyzer.

This module provides common file and path operations used by the taint analysis engine.
"""

import os
from pathlib import Path
from typing import List, Optional


def is_python_file(file_path: str) -> bool:
    """
    Checks if a file is a Python file.

    Args:
        file_path: The path to the file.

    Returns:
        True if the file extension is .py, False otherwise.
    """
    return file_path.lower().endswith(".py")


def get_python_files_in_directory(
    directory: str, recursive: bool = True, exclude_dirs: List[str] = None
) -> List[str]:
    """
    Gets all Python files in a directory.

    Args:
        directory: The directory to search for Python files.
        recursive: Whether to search subdirectories recursively.
        exclude_dirs: A list of directory names to exclude (e.g., ["venv", "__pycache__"]).

    Returns:
        A list of Python file paths.
    """
    exclude_dirs = exclude_dirs or [
        # Compilation cache
        "__pycache__",
        # Virtual environments
        "venv",
        ".env",
        ".venv",
        "env",
        # Version control
        ".git",
        ".github",
        ".gitignore",
        ".svn",
        # Testing and coverage
        ".pytest_cache",
        ".coverage",
        "htmlcov",
        ".tox",
        # Type checking and linting caches
        ".mypy_cache",
        ".ruff_cache",
        ".pytype",
        # Build and distribution
        "dist",
        "build",
        "*.egg-info",
        ".eggs",
        "__pypackages__",
        # IDE configurations
        ".idea",
        ".vscode",
        ".vs",
        # Others
        ".ipynb_checkpoints",
        "node_modules",
        ".DS_Store",
    ]
    python_files = []

    # Handle cases where the input is a file, not a directory
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
    Ensures a directory exists, creating it if necessary.

    Args:
        directory_path: The path to the directory.
    """
    Path(directory_path).mkdir(parents=True, exist_ok=True)


def get_relative_path(base_path: str, full_path: str) -> str:
    """
    Converts an absolute path to a path relative to a base path.

    Args:
        base_path: The base directory path.
        full_path: The full path to convert to a relative path.

    Returns:
        The path relative to the base path.
    """
    try:
        return os.path.relpath(full_path, base_path)
    except ValueError:
        # Handle cases where paths are on different drives (Windows)
        return full_path


def get_absolute_path(path: str, relative_to: Optional[str] = None) -> str:
    """
    Converts a relative path to an absolute path.

    Args:
        path: The path to convert to an absolute path.
        relative_to: The base directory for the relative path (default: current working directory).

    Returns:
        The absolute path.
    """
    if os.path.isabs(path):
        return path

    base_dir = relative_to or os.getcwd()
    return os.path.normpath(os.path.join(base_dir, path))
