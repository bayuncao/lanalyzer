"""
Logging configuration utilities

Provides functions to configure the application's logging behavior.
"""

import logging
import os
import sys
from typing import Optional

from lanalyzer.logger.core import configure_logger


def setup_file_logging(log_file: str, level: int = logging.INFO) -> None:
    """
    Configure logging to a file.

    Args:
        log_file: Log file path
        level: Log level (default: INFO)
    """
    # Ensure log directory exists
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)

    configure_logger(level=level, log_file=log_file)


def setup_console_logging(level: int = logging.INFO, detailed: bool = False) -> None:
    """
    Configure console logging output.

    Args:
        level: Log level (default: INFO)
        detailed: Use detailed format (default: False)
    """
    log_format = (
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        if detailed
        else "%(levelname)s: %(message)s"
    )

    configure_logger(level=level, log_format=log_format)


def setup_application_logging(
    log_file: Optional[str] = None,
    debug: bool = False,
) -> logging.Logger:
    """
    Configure application logging.

    Args:
        log_file: Log file path (default: None)
        debug: Enable debug logging (default: False)

    Returns:
        The logger instance
    """
    # Determine log level
    level = logging.DEBUG if debug else logging.INFO

    # Configure log format
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    # Create and configure logger
    logger = logging.getLogger("lanalyzer")
    logger.setLevel(level)

    # Clear existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter(log_format))
    logger.addHandler(console_handler)

    # File handler if log file is specified
    if log_file:
        # Ensure log directory exists
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)

        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(log_format))
        logger.addHandler(file_handler)

    # Output initial log message
    logger.info(f"Logging configured - Level: {logging.getLevelName(level)}")
    if log_file:
        logger.info(f"Log file: {log_file}")

    return logger
