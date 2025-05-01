"""
核心日志工具

提供整个应用程序的一致日志接口。
"""

import logging
import sys
from typing import Optional

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


def get_logger(name: str = "lanalyzer") -> logging.Logger:
    """
    获取指定名称的日志器实例。

    参数:
        name: 日志器名称 (默认: "lanalyzer")

    返回:
        日志器实例
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
    配置全局日志器设置。

    参数:
        level: 日志级别 (默认: INFO)
        log_format: 日志消息格式 (默认: 带时间戳的标准格式)
        log_file: 日志文件路径 (默认: None，仅输出到控制台)
        verbose: 是否启用详细日志 (设置级别为 INFO)
        debug: 是否启用调试日志 (设置级别为 DEBUG)
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
    记录调试消息。

    参数:
        message: 要记录的消息
        *args: 要传递给 logger.debug 的附加参数
        **kwargs: 要传递给 logger.debug 的附加关键字参数
    """
    logger.debug(message, *args, **kwargs)


def info(message: str, *args, **kwargs) -> None:
    """
    记录信息消息。

    参数:
        message: 要记录的消息
        *args: 要传递给 logger.info 的附加参数
        **kwargs: 要传递给 logger.info 的附加关键字参数
    """
    logger.info(message, *args, **kwargs)


def warning(message: str, *args, **kwargs) -> None:
    """
    记录警告消息。

    参数:
        message: 要记录的消息
        *args: 要传递给 logger.warning 的附加参数
        **kwargs: 要传递给 logger.warning 的附加关键字参数
    """
    logger.warning(message, *args, **kwargs)


def error(message: str, *args, **kwargs) -> None:
    """
    记录错误消息。

    参数:
        message: 要记录的消息
        *args: 要传递给 logger.error 的附加参数
        **kwargs: 要传递给 logger.error 的附加关键字参数
    """
    logger.error(message, *args, **kwargs)


def critical(message: str, *args, **kwargs) -> None:
    """
    记录严重错误消息。

    参数:
        message: 要记录的消息
        *args: 要传递给 logger.critical 的附加参数
        **kwargs: 要传递给 logger.critical 的附加关键字参数
    """
    logger.critical(message, *args, **kwargs)
