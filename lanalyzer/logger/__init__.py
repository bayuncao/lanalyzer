"""
LanaLyzer Logging Module

This module provides logging tools for the entire application.
"""

from lanalyzer.logger.core import (
    configure_logger,
    get_logger,
    debug,
    info,
    warning,
    error,
    critical,
    LogTee,
    get_timestamp,
)

from lanalyzer.logger.decorators import (
    log_function,
    log_analysis_file,
    log_result,
    conditional_log,
    log_vulnerabilities,
)

from lanalyzer.logger.config import (
    setup_file_logging,
    setup_console_logging,
    setup_application_logging,
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
