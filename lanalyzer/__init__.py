"""
LanaLyzer - Static Taint Analysis Tool for Python Projects

Provides static taint analysis for Python code to help detect security vulnerabilities.
"""

from lanalyzer.__version__ import __version__

# Set package information
__title__ = "lanalyzer"
__description__ = "Python taint analysis tool for security vulnerability detection"
__url__ = "https://github.com/mxcrafts/lanalyzer"
__author__ = "mxcrafts"
__author_email__ = "mx@crafts.com"
__license__ = "MIT"

# Export main interface
from lanalyzer.analysis import analyze_file, BaseAnalyzer, EnhancedTaintTracker

# Export logging tools
from lanalyzer.logger import (
    # Core logging functions
    configure_logger,
    get_logger,
    debug,
    info,
    warning,
    error,
    critical,
    # Logging decorators
    log_function,
    log_analysis_file,
    log_result,
    conditional_log,
    log_vulnerabilities,
    # Configuration utilities
    setup_file_logging,
    setup_console_logging,
    setup_application_logging,
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
