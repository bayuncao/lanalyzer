"""
LanaLyzer 日志模块

此模块提供整个应用程序的日志记录工具。
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
    # 核心日志函数
    "configure_logger",
    "get_logger",
    "debug",
    "info",
    "warning",
    "error",
    "critical",
    # 日志装饰器
    "log_function",
    "log_analysis_file",
    "log_result",
    "conditional_log",
    "log_vulnerabilities",
    # 配置工具
    "setup_file_logging",
    "setup_console_logging",
    "setup_application_logging",
    # 输出重定向工具
    "LogTee",
    "get_timestamp",
]
