"""
Logging utilities for LAnaLyzer.

Provides a consistent logging interface for the entire application.
"""

import logging
import sys
from typing import Optional

# Configure default logger
logger = logging.getLogger("lanalyzer")
logger.setLevel(logging.INFO)

# Default formatter
DEFAULT_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
formatter = logging.Formatter(DEFAULT_FORMAT)

# Console handler
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)


def get_logger(name: str = "lanalyzer") -> logging.Logger:
    """
    Get a logger instance with the specified name.

    Args:
        name: Name of the logger (default: "lanalyzer")

    Returns:
        Logger instance
    """
    return logging.getLogger(name)


def configure_logger(
    level: int = logging.INFO,
    log_format: str = DEFAULT_FORMAT,
    log_file: Optional[str] = None,
    verbose: bool = False,
    debug: bool = False,
) -> None:
    """
    Configure the global logger settings.

    Args:
        level: Logging level (default: INFO)
        log_format: Log message format (default: standard format with timestamp)
        log_file: Path to log file (default: None, logs to console only)
        verbose: Whether to enable verbose logging (sets level to INFO)
        debug: Whether to enable debug logging (sets level to DEBUG)
    """
    # Set log level based on debug/verbose flags
    if debug:
        level = logging.DEBUG
    elif verbose and level > logging.INFO:
        level = logging.INFO

    # Set logger level
    logger.setLevel(level)

    # Update console handler formatter
    formatter = logging.Formatter(log_format)
    for handler in logger.handlers:
        handler.setFormatter(formatter)

    # Add file handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)


def debug(message: str, *args, **kwargs) -> None:
    """
    Log a debug message.

    Args:
        message: Message to log
        *args: Additional arguments to pass to logger.debug
        **kwargs: Additional keyword arguments to pass to logger.debug
    """
    logger.debug(message, *args, **kwargs)


def info(message: str, *args, **kwargs) -> None:
    """
    Log an info message.

    Args:
        message: Message to log
        *args: Additional arguments to pass to logger.info
        **kwargs: Additional keyword arguments to pass to logger.info
    """
    logger.info(message, *args, **kwargs)


def warning(message: str, *args, **kwargs) -> None:
    """
    Log a warning message.

    Args:
        message: Message to log
        *args: Additional arguments to pass to logger.warning
        **kwargs: Additional keyword arguments to pass to logger.warning
    """
    logger.warning(message, *args, **kwargs)


def error(message: str, *args, **kwargs) -> None:
    """
    Log an error message.

    Args:
        message: Message to log
        *args: Additional arguments to pass to logger.error
        **kwargs: Additional keyword arguments to pass to logger.error
    """
    logger.error(message, *args, **kwargs)


def critical(message: str, *args, **kwargs) -> None:
    """
    Log a critical message.

    Args:
        message: Message to log
        *args: Additional arguments to pass to logger.critical
        **kwargs: Additional keyword arguments to pass to logger.critical
    """
    logger.critical(message, *args, **kwargs)
