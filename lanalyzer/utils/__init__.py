"""
Utility functions for LAnaLyzer.

This package provides common utility functions used throughout the LAnaLyzer tool.
"""

# AST utilities
from lanalyzer.utils.ast_utils import (
    find_function_calls,
    find_source_locations,
    get_assignment_targets,
    get_call_names,
    get_class_definitions,
    get_function_calls_with_args,
    get_function_definitions,
    get_function_local_variables,
    get_function_parameters,
    get_import_names,
    get_node_source_code,
    parse_file,
)

# Decorator utilities
from lanalyzer.utils.decorators import debug_calls, deprecated, retry, timing_decorator

# File utilities
from lanalyzer.utils.file import (
    ensure_directory_exists,
    get_absolute_path,
    get_python_files_in_directory,
    get_relative_path,
    is_python_file,
)

# Logging utilities
from lanalyzer.utils.logging import (
    configure_logger,
    critical,
    debug,
    error,
    get_logger,
    info,
    warning,
)

__all__ = [
    # File utilities
    "is_python_file",
    "get_python_files_in_directory",
    "ensure_directory_exists",
    "get_relative_path",
    "get_absolute_path",
    # Logging utilities
    "get_logger",
    "configure_logger",
    "debug",
    "info",
    "warning",
    "error",
    "critical",
    # Decorator utilities
    "timing_decorator",
    "deprecated",
    "debug_calls",
    "retry",
    # AST utilities
    "parse_file",
    "get_function_definitions",
    "get_class_definitions",
    "get_call_names",
    "get_function_parameters",
    "get_function_local_variables",
    "find_function_calls",
    "get_assignment_targets",
    "get_import_names",
    "get_function_calls_with_args",
    "find_source_locations",
    "get_node_source_code",
]
