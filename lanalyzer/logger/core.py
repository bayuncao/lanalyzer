"""
Core logging utilities

Provides a consistent logging interface for the entire application.
"""

import logging
import sys
import datetime
from typing import Optional, TextIO, Union, Any

# Configure default logger
logger = logging.getLogger("lanalyzer")
logger.setLevel(logging.INFO)

# Default format
DEFAULT_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
formatter = logging.Formatter(DEFAULT_FORMAT)

# Console handler
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)


class LogTee:
    """Send output to two destinations simultaneously.

    Supports both file-like objects and logger instances.
    """

    def __init__(
        self, file1: TextIO, file2: Union[TextIO, logging.Logger], prefix: str = ""
    ):
        self.file1 = file1
        self.file2 = file2
        self.prefix = prefix
        self.is_logger = isinstance(file2, logging.Logger)

    def write(self, data: str) -> None:
        # Add prefix if specified and data is not just whitespace
        if self.prefix and data.strip():
            data = f"{self.prefix} {data}"

        self.file1.write(data)

        if self.is_logger:
            # For logger objects, log non-empty lines
            if data.strip():
                self.file2.info(data.strip())
        else:
            # For file-like objects, write directly
            self.file2.write(data)
            self.file2.flush()

        self.file1.flush()  # Ensure real-time output

    def flush(self) -> None:
        self.file1.flush()
        if not self.is_logger:
            self.file2.flush()

    def __getattr__(self, name: str) -> Any:
        """Forward any other attributes to file1"""
        return getattr(self.file1, name)


def get_timestamp() -> str:
    """Return the current formatted timestamp"""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_logger(name: str = "lanalyzer") -> logging.Logger:
    """
    Get a logger instance with the specified name.

    Args:
        name: Logger name (default: "lanalyzer")

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
    Configure global logger settings.

    Args:
        level: Log level (default: INFO)
        log_format: Log message format (default: standard format with timestamp)
        log_file: Log file path (default: None, only output to console)
        verbose: Enable verbose logging (set level to INFO)
        debug: Enable debug logging (set level to DEBUG)
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

    # Add file handler if log file is specified
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
    Log a critical error message.

    Args:
        message: Message to log
        *args: Additional arguments to pass to logger.critical
        **kwargs: Additional keyword arguments to pass to logger.critical
    """
    logger.critical(message, *args, **kwargs)
