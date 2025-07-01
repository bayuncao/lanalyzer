"""
Lanalyzer - Static Taint Analysis Tool for Python Projects

Provides static taint analysis for Python code to help detect security vulnerabilities.
"""

from lanalyzer.__version__ import __version__

# Set package information
__title__ = "lanalyzer"
__description__ = "Python taint analysis tool for security vulnerability detection"
__url__ = "https://github.com/bayuncao/lanalyzer"
__author__ = "bayuncao"
__author_email__ = "8533596@gmail.com"
__license__ = "AGPL-3.0"

# Export main interface
from lanalyzer.analysis import BaseAnalyzer, EnhancedTaintTracker, analyze_file

# Export logging tools
from lanalyzer.logger import (  # Core logging functions; Logging decorators; Configuration utilities
    conditional_log,
    configure_logger,
    critical,
    debug,
    error,
    get_logger,
    info,
    log_analysis_file,
    log_function,
    log_result,
    log_vulnerabilities,
    setup_application_logging,
    setup_console_logging,
    setup_file_logging,
    warning,
)

__all__ = [
    "analyze_file",
    "BaseAnalyzer",
    "EnhancedTaintTracker",
    "__version__",
    # Logging exports
    "configure_logger",
    "get_logger",
    "debug",
    "info",
    "warning",
    "error",
    "critical",
    "log_function",
    "log_analysis_file",
    "log_result",
    "conditional_log",
    "log_vulnerabilities",
    "setup_file_logging",
    "setup_console_logging",
    "setup_application_logging",
]
