"""data_flow_helpers.py
封装数据流相关辅助函数，供 TaintAnalysisUtils 等调用。
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Set, Tuple

from lanalyzer.logger import debug
from lanalyzer.analysis import ast_helpers
from lanalyzer.analysis.visitor import EnhancedTaintAnalysisVisitor

__all__ = [
    "find_tainted_vars_in_sink",
    "find_potential_sources",
]


def find_tainted_vars_in_sink(visitor: EnhancedTaintAnalysisVisitor, sink_line: int) -> List[str]:
    """查找在 sink 语句中被使用的 tainted 变量名。"""
    tainted_vars: List[str] = []
    if not getattr(visitor, "source_lines", None):
        return tainted_vars

    sink_line_src = visitor.source_lines[sink_line - 1].strip() if 0 < sink_line <= len(visitor.source_lines) else ""

    for var, source_info in getattr(visitor, "tainted", {}).items():
        if var in sink_line_src:
            tainted_vars.append(var)
    return tainted_vars


def _search_all_potential_sources(
    visitor: EnhancedTaintAnalysisVisitor,
    sink_function_range,
    sink_line: int,
    added_sources: Set[str],
    same_function_sources: List[Dict[str, Any]],
    other_sources: List[Dict[str, Any]],
    parser_sources: List[Dict[str, Any]],
    sources_config: List[Dict[str, Any]],
    debug_enabled: bool = False,
):
    """在整个文件中搜索潜在的 taint 来源。"""

    source_type_patterns: Dict[str, str] = {}
    for source_cfg in sources_config:
        src_name = source_cfg.get("name", "UnknownSource")
        for pattern in source_cfg.get("patterns", []):
            source_type_patterns[pattern] = src_name

    potential_sources: List[Dict[str, Any]] = []
    for var_name, assign_info in getattr(visitor, "var_assignments", {}).items():
        line_no = assign_info.get("line")
        if not line_no:
            continue
        if any(src["line"] == line_no for src in same_function_sources + other_sources):
            continue
        stmt = ast_helpers.get_statement_at_line(visitor.source_lines, line_no)["statement"]
        matched_source_type = None
        matched_pattern = None
        for pattern, src_type in source_type_patterns.items():
            if "*" in pattern:
                regex = pattern.replace(".", "\\.").replace("*", ".*")
                if re.search(regex, stmt):
                    matched_source_type = src_type
                    matched_pattern = pattern
                    break
            elif pattern in stmt:
                matched_source_type = src_type
                matched_pattern = pattern
                break
        if matched_source_type:
            in_same_func = sink_function_range and sink_function_range[0] <= line_no <= sink_function_range[1]
            is_cli = "CommandLineArgs" in matched_source_type
            potential_sources.append({
                "var": var_name,
                "line": line_no,
                "statement": stmt,
                "in_same_function": in_same_func,
                "is_parser": is_cli,
                "source_name": matched_source_type,
                "pattern": matched_pattern,
            })
    # 排序：同函数优先，其次距离 sink 近
    potential_sources.sort(key=lambda x: (not x["in_same_function"], abs(x["line"] - sink_line)))
    for src in potential_sources:
        key = f"{src['line']}:{src['statement']}"
        if key in added_sources:
            continue
        added_sources.add(key)
        src_stmt = {
            "function": f"{src['var']} = {src['statement'].split('=')[1].strip()}" if "=" in src["statement"] else src["statement"],
            "file": visitor.file_path,
            "line": src["line"],
            "statement": src["statement"],
            "context_lines": [src["line"] - 1, src["line"] + 1],
            "type": "source",
            "description": f"Source of tainted data ({src.get('source_name', 'Unknown')}) assigned to variable {src['var']}",
        }
        if src.get("in_same_function"):
            same_function_sources.append(src_stmt)
        else:
            target_list = parser_sources if src.get("is_parser") else other_sources
            target_list.append(src_stmt)
        if debug_enabled:
            debug(f"[data_flow_helpers] Matched potential source pattern '{src['pattern']}' at line {src['line']}")


def find_potential_sources(
    visitor: EnhancedTaintAnalysisVisitor,
    sink_function_node,
    sink_line: int,
    sink_stmt_info: Dict[str, Any],
    sink_function_range,
    same_function_sources: List[Dict[str, Any]],
    other_sources: List[Dict[str, Any]],
    parser_sources: List[Dict[str, Any]],
    added_sources: Set[str],
    sources_config: List[Dict[str, Any]],
    debug_enabled: bool = False,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """高层包装：在 sink 周围与全局查找潜在源。

    返回同函数、其他函数、parser 源三类列表。
    """
    found_source_in_function = False
    potential_sources: List[Dict[str, Any]] = []

    # 步骤：先在同一函数内扫描
    if sink_function_node and getattr(visitor, "source_lines", None):
        start = getattr(sink_function_node, "line_no", 0)
        end = getattr(sink_function_node, "end_line_no", 0)
        all_patterns = []
        for src in sources_config:
            src_name = src.get("name", "Unknown")
            for pat in src.get("patterns", []):
                all_patterns.append((pat, src_name))
        all_patterns.sort(key=lambda x: len(x[0]))

        for line_idx in range(start, min(sink_line, end)):
            line_src = visitor.source_lines[line_idx - 1].strip()
            for pat, src_name in all_patterns:
                matches = False
                if "*" in pat:
                    regex = pat.replace(".", "\\.").replace("*", ".*")
                    matches = bool(re.search(regex, line_src))
                else:
                    matches = pat in line_src
                if matches:
                    if "=" in line_src and line_src.index("=") < line_src.find(pat):
                        var_name = line_src.split("=")[0].strip()
                        if var_name in sink_stmt_info["statement"]:
                            potential_sources.append({
                                "line": line_idx,
                                "statement": line_src,
                                "var": var_name,
                                "in_same_function": True,
                                "source_name": src_name,
                                "pattern": pat,
                            })
                            break
        potential_sources.sort(key=lambda x: sink_line - x["line"] if x["line"] < sink_line else float("inf"))
        for src in potential_sources:
            if src["line"] < sink_line:
                key = f"{src['line']}:{src['statement']}"
                if key not in added_sources:
                    added_sources.add(key)
                    same_function_sources.append({
                        "function": f"{src['var']} = {src['statement'].split('=')[1].strip()}" if "=" in src["statement"] else src["statement"],
                        "file": visitor.file_path,
                        "line": src["line"],
                        "statement": src["statement"],
                        "context_lines": [src["line"] - 1, src["line"] + 1],
                        "type": "source",
                        "description": f"Source of tainted data ({src['source_name']}) assigned to variable {src['var']}",
                    })
                    found_source_in_function = True
    # 若同函数未找到则全局搜索
    if not found_source_in_function:
        _search_all_potential_sources(
            visitor,
            sink_function_range,
            sink_line,
            added_sources,
            same_function_sources,
            other_sources,
            parser_sources,
            sources_config,
            debug_enabled,
        )
    return same_function_sources, other_sources, parser_sources 