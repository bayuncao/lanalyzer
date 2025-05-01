"""
工具函数包，提供 LanaLyzer 所需的通用工具函数。

此包中包含各种实用函数，用于支持 LanaLyzer 工具的核心功能。
"""

# 文件实用工具
from lanalyzer.utils.fs_utils import (
    ensure_directory_exists,
    get_absolute_path,
    get_python_files_in_directory,
    get_relative_path,
    is_python_file,
)

# AST 分析实用工具
from lanalyzer.utils.ast_utils import (
    parse_file,
    contains_sink_patterns,
    extract_call_targets,
    extract_function_calls,
)

__all__ = [
    # 文件实用工具
    "is_python_file",
    "get_python_files_in_directory",
    "ensure_directory_exists",
    "get_relative_path",
    "get_absolute_path",
    # AST 分析实用工具
    "parse_file",
    "extract_call_targets",
    "extract_function_calls",
    "contains_sink_patterns",
]
