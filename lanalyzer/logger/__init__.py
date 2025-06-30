"""
LanaLyzer Logging Module

This module provides logging tools for the entire application.
"""

from lanalyzer.logger.config import (
    setup_application_logging,
    setup_console_logging,
    setup_file_logging,
)
from lanalyzer.logger.core import (
    LogTee,
    configure_logger,
    critical,
    debug,
    error,
    get_logger,
    get_timestamp,
    info,
    warning,
)
from lanalyzer.logger.decorators import (
    conditional_log,
    log_analysis_file,
    log_function,
    log_result,
    log_vulnerabilities,
)

__all__ = [
    # Core logging functions
    "configure_logger",
    "get_logger",
    "debug",
    "info",
    "warning",
    "error",
    "critical",
    # Logging decorators
    "log_function",
    "log_analysis_file",
    "log_result",
    "conditional_log",
    "log_vulnerabilities",
    # Configuration utilities
    "setup_file_logging",
    "setup_console_logging",
    "setup_application_logging",
    # Output redirection tools
    "LogTee",
    "get_timestamp",
]
