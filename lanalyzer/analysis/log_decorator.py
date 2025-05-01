"""
此模块已弃用。请使用 lanalyzer.logger 代替。

为了向后兼容，我们从新模块导入所有内容。
"""

import warnings

warnings.warn(
    "lanalyzer.analysis.log_decorator 已弃用，请使用 lanalyzer.logger 代替",
    DeprecationWarning,
    stacklevel=2,
)

from lanalyzer.logger import (
    log_function,
    log_analysis_file,
    log_result,
    conditional_log,
    log_vulnerabilities,
)
