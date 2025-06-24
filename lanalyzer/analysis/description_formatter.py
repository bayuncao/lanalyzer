"""description_formatter.py
统一封装调用链节点描述信息的生成逻辑。
"""
from typing import List, Optional

__all__ = [
    "format_source_description",
    "format_sink_description",
]


def format_source_description(source_name: str, source_line: int) -> str:
    """生成源节点描述。"""
    return f"Contains source {source_name} at line {source_line}"


def format_sink_description(
    sink_name: str,
    sink_line: int,
    arg_expressions: Optional[List[str]] = None,
    vulnerability_type: Optional[str] = None,
) -> str:
    """生成汇节点（sink）描述。

    参数:
        sink_name: 汇名称
        sink_line: 行号
        arg_expressions: 解析出的参数表达式（若有）
        vulnerability_type: 漏洞类型描述（若有）
    """
    base = f"Contains sink {sink_name} at line {sink_line}"
    if vulnerability_type:
        base = f"Unsafe {sink_name} operation, potentially leading to {vulnerability_type}"
    if arg_expressions:
        base += f". Processing data from: {', '.join(arg_expressions)}"
    return base
