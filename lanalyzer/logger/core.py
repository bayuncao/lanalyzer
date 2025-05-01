"""
Core logging utilities

Provides a consistent logging interface for the entire application.
"""

import logging
import sys
import datetime
from typing import Optional, TextIO

# 配置默认日志器
logger = logging.getLogger("lanalyzer")
logger.setLevel(logging.INFO)

# 默认格式
DEFAULT_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
formatter = logging.Formatter(DEFAULT_FORMAT)

# 控制台处理器
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)


class LogTee:
    """Send output to two file objects simultaneously"""

    def __init__(self, file1: TextIO, file2: TextIO):
        self.file1 = file1
        self.file2 = file2

    def write(self, data: str) -> None:
        self.file1.write(data)
        self.file2.write(data)
        self.file1.flush()  # Ensure real-time output
        self.file2.flush()

    def flush(self) -> None:
        self.file1.flush()
        self.file2.flush()


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
    # 根据调试/详细标志设置日志级别
    if debug:
        level = logging.DEBUG
    elif verbose and level > logging.INFO:
        level = logging.INFO

    # 设置日志器级别
    logger.setLevel(level)

    # 更新控制台处理器格式化器
    formatter = logging.Formatter(log_format)
    for handler in logger.handlers:
        handler.setFormatter(formatter)

    # 如果指定了日志文件，添加文件处理器
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
