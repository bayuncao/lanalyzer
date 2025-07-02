"""
Lanalyzer Logging Module

A comprehensive logging system providing structured, configurable logging
capabilities for the entire application.

Features:
    - Structured logging with consistent formatting
    - Multiple output destinations (console, file)
    - Decorators for automatic function logging
    - Specialized analysis logging utilities
    - Thread-safe logging operations
    - Configurable log levels and formats

Example:
    Basic usage:
        >>> from lanalyzer.logger import info, debug, setup_application_logging
        >>> setup_application_logging(debug=True)
        >>> info("Application started")
        >>> debug("Debug information")

    Using decorators:
        >>> from lanalyzer.logger import log_function, log_analysis_file
        >>> @log_function()
        ... def my_function():
        ...     pass

        >>> @log_analysis_file
        ... def analyze_file(file_path):
        ...     pass

    Advanced configuration:
        >>> from lanalyzer.logger import setup_file_logging, get_logger
        >>> setup_file_logging("/var/log/lanalyzer.log")
        >>> logger = get_logger("my_module")
"""

# Configuration utilities
from lanalyzer.logger.config import (
    setup_application_logging,
    setup_console_logging,
    setup_file_logging,
)

# Core logging functionality
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

# Specialized decorators
from lanalyzer.logger.decorators import (
    conditional_log,
    log_analysis_file,
    log_function,
    log_result,
    log_vulnerabilities,
)

# Version information for logging compatibility
__version__ = "1.0.0"

# Public API - organized by functionality
__all__ = [
    # === Core Logging Functions ===
    "get_logger",  # Get a logger instance for a module
    "configure_logger",  # Configure global logger settings
    # === Logging Level Functions ===
    "debug",  # Log debug messages
    "info",  # Log informational messages
    "warning",  # Log warning messages
    "error",  # Log error messages
    "critical",  # Log critical messages
    # === Configuration Utilities ===
    "setup_application_logging",  # Complete application logging setup
    "setup_console_logging",  # Console-only logging setup
    "setup_file_logging",  # File-based logging setup
    # === Specialized Decorators ===
    "log_function",  # Automatic function execution logging
    "log_analysis_file",  # File analysis logging decorator
    "log_result",  # Function result logging decorator
    "conditional_log",  # Conditional logging decorator
    "log_vulnerabilities",  # Vulnerability analysis logging
    # === Utility Classes ===
    "LogTee",  # Dual-output logging utility
    "get_timestamp",  # Timestamp generation utility
]

# === Convenience Functions ===


def get_module_logger(name: str = None):
    """
    Get a logger for the calling module with automatic name detection.

    Args:
        name: Optional logger name. If None, automatically detects the calling module's name.

    Returns:
        Logger instance configured for the module.

    Example:
        >>> # In module 'myapp.analysis'
        >>> logger = get_module_logger()  # Creates logger named 'myapp.analysis'
        >>> logger.info("Module initialized")

        >>> # Or with explicit name
        >>> logger = get_module_logger("custom.logger")
        >>> logger.info("Custom logger message")
    """
    if name is None:
        import inspect

        frame = inspect.currentframe().f_back
        name = frame.f_globals.get("__name__", "unknown")
    return get_logger(name)


def quick_setup(debug: bool = False, log_file: str = None):
    """
    Quick logging setup for simple use cases and rapid prototyping.

    This is a convenience function that sets up logging with sensible defaults.
    For production use, consider using setup_application_logging directly.

    Args:
        debug: Enable debug logging (sets level to DEBUG)
        log_file: Optional log file path for persistent logging

    Example:
        >>> # Simple console logging
        >>> quick_setup()

        >>> # Debug mode with file logging
        >>> quick_setup(debug=True, log_file="debug.log")

        >>> # Production setup
        >>> quick_setup(log_file="/var/log/lanalyzer.log")
    """
    setup_application_logging(log_file=log_file, debug=debug)
