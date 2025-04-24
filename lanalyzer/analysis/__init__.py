"""
Taint analysis module for LAnaLyzer.

This package provides advanced taint analysis with the following capabilities:

1. Enhanced analysis - advanced analysis with detailed call chains and propagation
2. Comprehensive vulnerability detection
3. Support for various sources and sinks

The analysis APIs are designed to be simple to use while providing detailed results.
"""

# Common components
from lanalyzer.analysis.base import BaseAnalyzer

# Enhanced analysis exports
from lanalyzer.analysis.enhanced import enhanced_analyze_file
from lanalyzer.analysis.enhanced.tracker import EnhancedTaintTracker

# 从utils包导入我们已经迁移的函数
from lanalyzer.utils.ast_utils import (
    contains_sink_patterns,
    extract_call_targets,
    extract_function_calls,
)
from lanalyzer.utils.ast_utils import parse_file as parse_ast
from lanalyzer.utils.file import get_python_files_in_directory as get_python_files

# Exports for external use
__all__ = [
    # Enhanced analysis
    "enhanced_analyze_file",
    "EnhancedTaintTracker",
    # Common components
    "BaseAnalyzer",
    "parse_ast",
    "get_python_files",
    "extract_call_targets",
    "extract_function_calls",
    "contains_sink_patterns",
]
