"""
Utility function package, providing general utility functions required by LanaLyzer.

This package contains various utility functions to support the core functionalities of the LanaLyzer tool.
"""

# AST analysis utilities
from lanalyzer.utils.ast_utils import (
    contains_sink_patterns,
    extract_call_targets,
    extract_function_calls,
    parse_file,
)

# File utilities
from lanalyzer.utils.fs_utils import (
    ensure_directory_exists,
    get_absolute_path,
    get_python_files_in_directory,
    get_relative_path,
    is_python_file,
)

__all__ = [
    # File utilities
    "is_python_file",
    "get_python_files_in_directory",
    "ensure_directory_exists",
    "get_relative_path",
    "get_absolute_path",
    # AST analysis utilities
    "parse_file",
    "extract_call_targets",
    "extract_function_calls",
    "contains_sink_patterns",
]
