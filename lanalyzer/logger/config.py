"""
日志配置工具

提供函数来配置应用程序的日志行为。
"""

import logging
import os
import sys
from typing import Optional

from lanalyzer.logger.core import configure_logger


def setup_file_logging(log_file: str, level: int = logging.INFO) -> None:
    """
    配置将日志记录到文件。

    参数:
        log_file: 日志文件路径
        level: 日志级别 (默认: INFO)
    """
    # 确保日志目录存在
    log_dir = os.path.dirname(log_file)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)

    configure_logger(level=level, log_file=log_file)


def setup_console_logging(level: int = logging.INFO, detailed: bool = False) -> None:
    """
    配置控制台日志输出。

    参数:
        level: 日志级别 (默认: INFO)
        detailed: 是否使用详细格式 (默认: False)
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
    配置应用程序日志。

    参数:
        app_name: 应用程序名称 (默认: "lanalyzer")
        level: 日志级别 (默认: INFO)
        log_file: 日志文件路径 (默认: None)
        verbose: 是否启用详细日志 (默认: False)
        debug: 是否启用调试日志 (默认: False)
        console: 是否输出到控制台 (默认: True)
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
    logger.info(f"{app_name} 日志已配置 - 级别: {logging.getLevelName(level)}")
    if log_file:
        logger.info(f"日志文件: {log_file}")
