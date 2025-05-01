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
    # 确保日志目录存在
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
    app_name: str = "lanalyzer",
    level: int = logging.INFO,
    log_file: Optional[str] = None,
    verbose: bool = False,
    debug: bool = False,
    console: bool = True,
) -> None:
    """
    Configure application logging.

    Args:
        app_name: Application name (default: "lanalyzer")
        level: Log level (default: INFO)
        log_file: Log file path (default: None)
        verbose: Enable verbose logging (default: False)
        debug: Enable debug logging (default: False)
        console: Output to console (default: True)
    """
    # 确定日志级别
    if debug:
        level = logging.DEBUG
    elif verbose and level > logging.INFO:
        level = logging.INFO

    # 配置日志格式
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    # 应用配置
    configure_logger(
        level=level,
        log_format=log_format,
        log_file=log_file,
        verbose=verbose,
        debug=debug,
    )

    # 输出初始日志消息
    logger = logging.getLogger(app_name)
    logger.info(f"{app_name} logging configured - Level: {logging.getLevelName(level)}")
    if log_file:
        logger.info(f"Log file: {log_file}")
