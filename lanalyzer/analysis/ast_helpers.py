"""ast_helpers.py
封装与 AST 源码行相关的公共帮助函数，供分析过程中复用。
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from lanalyzer.logger import debug


def get_statement_at_line(
    source_lines: List[str],
    line: int,
    *,
    context_lines: int = 0,
) -> Dict[str, Any]:
    """提取指定行及其前后上下文的代码片段。

    参数:
        source_lines: 文件源码按行组成的列表
        line: 目标行号（1 基）
        context_lines: 需要附带的上下文行数
    返回:
        包含 statement 文本、上下文行范围等信息的字典。
    """
    if line <= 0 or line > len(source_lines):
        return {"statement": "", "context_start": line, "context_end": line}

    statement = source_lines[line - 1].strip()

    start_line = max(1, line - context_lines)
    end_line = min(len(source_lines), line + context_lines)

    context: Optional[List[str]] = None
    if context_lines > 0:
        context = [
            f"{i}: {source_lines[i - 1].rstrip()}"
            for i in range(start_line, end_line + 1)
        ]

    return {
        "statement": statement,
        "context_lines": context,
        "context_start": start_line,
        "context_end": end_line,
    }


def extract_operation_at_line(
    source_lines: List[str],
    line: int,
    *,
    debug_enabled: bool = False,
    dangerous_patterns: Optional[Dict[str, List[str]]] = None,
) -> Optional[str]:
    """尝试解析指定行的"操作"字符串，用于匹配危险调用等。

    - 若行号超界或源码不可用，则返回 ``None``。
    - 会根据 ``dangerous_patterns`` 判断是否返回匹配的 sink 字符串。
    """
    if line <= 0 or line > len(source_lines):
        if debug_enabled:
            debug(f"[ast_helpers] Line {line} out of range.")
        return None

    line_content = source_lines[line - 1].strip()

    # 提取右侧表达式或整行
    operation = line_content.split("=", 1)[1].strip() if "=" in line_content else line_content

    # 清理注释/分号
    import re as _re

    operation = _re.sub(r"[;].*$", "", operation)
    operation = _re.sub(r"#.*$", "", operation).strip()

    if dangerous_patterns is None:
        dangerous_patterns = {}

    for sink_name, patterns in dangerous_patterns.items():
        for pattern in patterns:
            if pattern in operation:
                return operation

    return operation or None 