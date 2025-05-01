"""
LanaLyzer - 适用于 Python 项目的静态污点分析工具

为 Python 代码提供静态污点分析，帮助检测安全漏洞。
"""

from lanalyzer.__version__ import __version__

# 设置版本信息
__title__ = "lanalyzer"
__description__ = "Python taint analysis tool for security vulnerability detection"
__url__ = "https://github.com/mxcrafts/lanalyzer"
__author__ = "mxcrafts"
__author_email__ = "mx@crafts.com"
__license__ = "MIT"

# 导出主要接口
from lanalyzer.analysis import analyze_file, BaseAnalyzer, EnhancedTaintTracker

# 导出日志工具
from lanalyzer.logger import (
    # 核心日志函数
    configure_logger,
    get_logger,
    debug,
    info,
    warning,
    error,
    critical,
    # 日志装饰器
    log_function,
    log_analysis_file,
    log_result,
    conditional_log,
    log_vulnerabilities,
    # 配置工具
    setup_file_logging,
    setup_console_logging,
    setup_application_logging,
)

__all__ = [
    "analyze_file",
    "BaseAnalyzer",
    "EnhancedTaintTracker",
    "__version__",
    # 日志导出
    "configure_logger",
    "get_logger",
    "debug",
    "info",
    "warning",
    "error",
    "critical",
    "log_function",
    "log_analysis_file",
    "log_result",
    "conditional_log",
    "log_vulnerabilities",
    "setup_file_logging",
    "setup_console_logging",
    "setup_application_logging",
]
