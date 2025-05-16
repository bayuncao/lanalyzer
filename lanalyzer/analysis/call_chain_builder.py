"""
Call chain builder for taint analysis.
This module provides functionality for building function call chains.
"""

import re
from typing import Any, Dict, List, Set, Optional, Tuple

from lanalyzer.analysis.visitor import EnhancedTaintAnalysisVisitor
from lanalyzer.analysis.data_flow_analyzer import DataFlowAnalyzer
from lanalyzer.analysis.control_flow_analyzer import ControlFlowAnalyzer
from lanalyzer.analysis.chain_utils import ChainUtils


class CallChainBuilder:
    """
    Builds detailed call chains between taint sources and sinks.
    """

    def __init__(self, tracker):
        """
        Initialize the call chain builder.

        Args:
            tracker: The parent tracker instance
        """
        self.tracker = tracker
        self.debug = tracker.debug
        self.data_flow = DataFlowAnalyzer(self)
        self.control_flow = ControlFlowAnalyzer(self)
        self.utils = ChainUtils(self)

    def get_detailed_call_chain(
        self,
        visitor: EnhancedTaintAnalysisVisitor,
        sink: Dict[str, Any],
        source_info: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Get the detailed function call chain from source to sink.
        优化：递归查找 callee 路径，优先 is_self_method_call，利用 self_method_call_map，所有传播规则基于配置。
        """
        call_chain = []
        source_line = source_info.get("line", 0)
        sink_line = sink.get("line", 0)
        source_name = source_info.get("name", "Unknown")
        sink_name = sink.get("name", "Unknown")

        if self.debug:
            print(
                f"[DEBUG] Building call chain from source '{source_name}' (line {source_line}) to sink '{sink_name}' (line {sink_line})"
            )

        source_func = None
        for func_name, func_node in visitor.functions.items():
            if func_node.line_no <= source_line <= func_node.end_line_no:
                source_func = func_node
                break

        sink_func = None
        for func_name, func_node in visitor.functions.items():
            if func_node.line_no <= sink_line <= func_node.end_line_no:
                sink_func = func_node
                break

        if self.debug:
            if source_func:
                print(
                    f"[DEBUG] Found source function: {source_func.name} (lines {source_func.line_no}-{source_func.end_line_no})"
                )
            else:
                print(
                    f"[DEBUG] Could not find function containing source (line {source_line})"
                )

            if sink_func:
                print(
                    f"[DEBUG] Found sink function: {sink_func.name} (lines {sink_func.line_no}-{sink_func.end_line_no})"
                )
            else:
                print(
                    f"[DEBUG] Could not find function containing sink (line {sink_line})"
                )

        source_stmt_info = self.tracker.utils.get_statement_at_line(
            visitor, source_line, context_lines=1
        )
        sink_stmt_info = self.tracker.utils.get_statement_at_line(
            visitor, sink_line, context_lines=1
        )

        # 先创建source和sink语句节点
        source_operation = self.tracker.utils.extract_operation_at_line(
            visitor, source_line
        )
        if source_operation:
            source_stmt = {
                "function": source_operation,
                "file": visitor.file_path,
                "line": source_line,
                "statement": source_stmt_info["statement"],
                "context_lines": [source_line - 1, source_line + 1],
                "type": "source",
                "description": f"Source of tainted data ({source_name}) assigned to variable {self._extract_var_name_from_stmt(source_stmt_info['statement'])}",
            }
            call_chain.append(source_stmt)

        sink_operation = self.tracker.utils.extract_operation_at_line(
            visitor, sink_line
        )
        if sink_operation:
            # 提取可能的sink参数表达式
            sink_arg_expressions = []
            if (
                hasattr(visitor, "source_lines")
                and visitor.source_lines
                and sink_line > 0
                and sink_line <= len(visitor.source_lines)
            ):
                sink_code = visitor.source_lines[sink_line - 1].strip()
                # 使用基于配置的提取方法
                sink_arg_expressions = self.utils.extract_sink_parameters(sink_code)

            sink_desc = f"Unsafe {sink_name} operation, potentially leading to {sink.get('vulnerability_type', 'vulnerability')}"
            # 如果提取到参数表达式，增加到描述中
            if sink_arg_expressions:
                sink_desc += (
                    f". Processing data from: {', '.join(sink_arg_expressions)}"
                )

            sink_stmt = {
                "function": sink_operation,
                "file": visitor.file_path,
                "line": sink_line,
                "statement": sink_stmt_info["statement"],
                "context_lines": [sink_line - 1, sink_line + 1],
                "type": "sink",
                "description": sink_desc,
            }
            call_chain.append(sink_stmt)

        # 处理源和汇聚点在同一函数的情况
        if source_func and sink_func and source_func.name == sink_func.name:
            func_info = {
                "function": source_func.name,
                "file": source_func.file_path,
                "line": source_func.line_no,
                "statement": f"function {source_func.name}",
                "context_lines": [source_func.line_no, source_func.end_line_no],
                "type": "source+sink",
                "description": f"Contains both source {source_name}(line {source_line}) and sink {sink_name}(line {sink_line})",
            }
            call_chain.append(func_info)
            return self.utils.reorder_call_chain_by_data_flow(call_chain)

        # 递归查找 source_func 到 sink_func 的所有路径，优先 is_self_method_call，传播规则基于配置
        def dfs(current_func, target_func, path, depth):
            if self.debug:
                print(
                    f"[DEBUG][DFS] At {current_func.name} -> {target_func.name}, depth={depth}, path={[f.name for f in path]}"
                )
            if current_func == target_func:
                return path + [current_func]
            if depth > 20:
                if self.debug:
                    print(f"[DEBUG][DFS] Max depth reached at {current_func.name}")
                return None
            for callee in getattr(current_func, "callees", []):
                if callee in path:
                    continue
                result = dfs(callee, target_func, path + [current_func], depth + 1)
                if result:
                    return result
            return None

        found_paths = []
        if source_func and sink_func:
            found_paths = dfs(source_func, sink_func, [], 0)
            if self.debug:
                print(
                    f"[DEBUG] Found {len(found_paths)} path(s) from {source_func.name} to {sink_func.name}"
                )

        # 如果 visitor 有 self_method_call_map，尝试补全链路
        if not found_paths and hasattr(visitor, "self_method_call_map"):
            if self.debug:
                print("[DEBUG] 尝试用 self_method_call_map 补全链路")
            for key, lines in visitor.self_method_call_map.items():
                if (
                    source_func
                    and sink_func
                    and source_func.name in key
                    and sink_func.name in key
                ):
                    # 构造一条简单链路
                    found_paths = [[source_func, sink_func]]
                    break

        # 生成调用链节点
        if found_paths:
            # 只取最短路径
            path = min(found_paths, key=len)
            for i, func in enumerate(path):
                node_type = "intermediate"
                description = "Intermediate function in the call chain"
                if i == 0:
                    node_type = "source"
                    description = f"Contains source {source_name} at line {source_line}"
                elif i == len(path) - 1:
                    node_type = "sink"
                    description = f"Contains sink {sink_name} at line {sink_line}"
                line_num = func.line_no
                call_statement = ""
                if i > 0:
                    prev_func = path[i - 1]
                    call_info = self._get_function_call_info(visitor, prev_func, func)
                    if call_info:
                        call_statement = call_info.get("statement", "")
                        line_num = call_info.get("line", func.line_no)
                func_info = {
                    "function": func.name,
                    "file": func.file_path,
                    "line": line_num,
                    "statement": call_statement
                    if call_statement
                    else f"function {func.name}",
                    "context_lines": [func.line_no, func.end_line_no],
                    "type": node_type,
                    "description": description,
                }
                call_chain.append(func_info)
            if self.debug:
                print(f"[DEBUG] 最终调用链节点数: {len(call_chain)}")
            return self.utils.reorder_call_chain_by_data_flow(call_chain)

        # 如果找不到路径，尝试共同调用者
        if self.debug:
            print("[DEBUG] No direct path found, trying to find common callers...")
        # 复用原有共同调用者逻辑
        return self._build_common_callers_path(
            visitor,
            source_func,
            sink_func,
            source_name,
            sink_name,
            source_line,
            sink_line,
            source_stmt_info,
            sink_stmt_info,
        )

    def _build_common_callers_path(
        self,
        visitor: EnhancedTaintAnalysisVisitor,
        source_func,
        sink_func,
        source_name,
        sink_name,
        source_line,
        sink_line,
        source_stmt_info,
        sink_stmt_info,
    ) -> List[Dict[str, Any]]:
        """
        Build path when source and sink are called by a common caller.

        Args:
            visitor: Visitor instance
            source_func: Function containing source
            sink_func: Function containing sink
            source_name: Name of source
            sink_name: Name of sink
            source_line: Line number of source
            sink_line: Line number of sink
            source_stmt_info: Source statement info
            sink_stmt_info: Sink statement info

        Returns:
            Call chain via common caller
        """
        reverse_call_graph = {}
        for func_name, func_node in visitor.functions.items():
            reverse_call_graph[func_name] = []

        for func_name, func_node in visitor.functions.items():
            for callee in func_node.callees:
                if callee.name not in reverse_call_graph:
                    reverse_call_graph[callee.name] = []
                reverse_call_graph[callee.name].append(func_name)

        source_callers = self.utils.find_callers(
            source_func.name, reverse_call_graph, 20
        )
        sink_callers = self.utils.find_callers(sink_func.name, reverse_call_graph, 20)

        common_callers = source_callers.intersection(sink_callers)

        if common_callers and self.debug:
            print(f"Found common callers: {common_callers}")

        if common_callers:
            common_caller = next(iter(common_callers))
            common_caller_node = None

            for func_name, func_node in visitor.functions.items():
                if func_name == common_caller:
                    common_caller_node = func_node
                    break

            if common_caller_node:
                source_call_stmt = ""
                sink_call_stmt = ""
                source_call_line = 0
                sink_call_line = 0

                # 查找更详细的调用信息
                for callee in common_caller_node.callees:
                    if callee.name == source_func.name and hasattr(callee, "call_line"):
                        source_call_line = callee.call_line
                        source_call_stmt = self.tracker.utils.get_statement_at_line(
                            visitor, callee.call_line
                        )["statement"]
                    elif callee.name == sink_func.name and hasattr(callee, "call_line"):
                        sink_call_line = callee.call_line
                        sink_call_stmt = self.tracker.utils.get_statement_at_line(
                            visitor, callee.call_line
                        )["statement"]

                # 提取可能的sink参数表达式，以增强描述
                sink_arg_expressions = []
                if (
                    hasattr(visitor, "source_lines")
                    and visitor.source_lines
                    and sink_line > 0
                    and sink_line <= len(visitor.source_lines)
                ):
                    sink_code = visitor.source_lines[sink_line - 1].strip()
                    # 使用基于配置的提取方法
                    sink_arg_expressions = self.utils.extract_sink_parameters(sink_code)

                    # 尝试提取索引访问信息
                    if "[" in sink_code and "]" in sink_code:
                        array_var_match = re.match(
                            r"([a-zA-Z_][a-zA-Z0-9_]*)\s*\[", sink_code
                        )
                        if array_var_match:
                            array_var = array_var_match.group(1)
                            index_info = self.data_flow.extract_index_access_info(
                                sink_code, array_var
                            )

                # 构建包含共同调用者的调用链
                sink_desc = f"Contains sink {sink_name} at line {sink_line}"
                if sink_arg_expressions:
                    sink_desc += (
                        f" processing data from: {', '.join(sink_arg_expressions)}"
                    )

                source_desc = f"Contains source {source_name} at line {source_line}"

                # 按数据流顺序构建调用链：源 -> 源函数 -> 公共调用者 -> 目标函数 -> 目标
                call_chain = [
                    # 1. 源节点
                    {
                        "function": source_func.name,
                        "file": source_func.file_path,
                        "line": source_func.line_no,
                        "statement": source_stmt_info["statement"],
                        "context_lines": [
                            source_func.line_no,
                            source_func.end_line_no,
                        ],
                        "type": "source",
                        "description": source_desc,
                    },
                    # 2. 公共调用者节点
                    {
                        "function": common_caller_node.name,
                        "file": common_caller_node.file_path,
                        "line": common_caller_node.line_no,
                        "statement": f"function {common_caller_node.name}()",
                        "context_lines": [
                            common_caller_node.line_no,
                            common_caller_node.end_line_no,
                        ],
                        "type": "intermediate",
                        "description": "Common caller of source and sink functions",
                        "calls": [
                            {
                                "function": source_func.name,
                                "statement": source_call_stmt,
                                "line": source_call_line,
                            },
                            {
                                "function": sink_func.name,
                                "statement": sink_call_stmt,
                                "line": sink_call_line,
                            },
                        ],
                    },
                    # 3. 汇聚点节点
                    {
                        "function": sink_func.name,
                        "file": sink_func.file_path,
                        "line": sink_func.line_no,
                        "statement": sink_stmt_info["statement"],
                        "context_lines": [sink_func.line_no, sink_func.end_line_no],
                        "type": "sink",
                        "description": sink_desc,
                    },
                ]

                # 使用数据流排序方法确保调用链顺序正确
                return self.utils.reorder_call_chain_by_data_flow(call_chain)

        return []

    def build_partial_call_chain_for_sink(
        self, visitor: EnhancedTaintAnalysisVisitor, sink_info: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Build a more complete call chain, providing rich calling context even without an explicit source.
        This is used for auto-detected vulnerabilities where the full data source path cannot be determined.

        Args:
            visitor: Visitor instance containing analysis results
            sink_info: Sink information dictionary

        Returns:
            List of dictionaries representing the call chain
        """
        call_chain = []
        added_sources = set()

        sink_line = sink_info.get("line", 0)
        sink_name = sink_info.get("name", "Unknown Sink")
        vulnerability_type = sink_info.get(
            "vulnerability_type", f"{sink_name} Vulnerability"
        )
        # 获取可能存在的污点变量名
        tainted_var = sink_info.get("tainted_variable", "Unknown")

        if self.debug:
            print(
                f"[DEBUG] Building call chain for sink '{sink_name}' (line {sink_line})"
            )

        if not sink_line:
            if self.debug:
                print("[DEBUG] Sink line number is 0 or missing")
            return []

        sink_stmt_info = self.tracker.utils.get_statement_at_line(
            visitor, sink_line, context_lines=2
        )

        # 为了提取sink语句中的实际参数表达式，增加对sink语句分析
        sink_code = ""
        sink_arg_expressions = []
        if (
            hasattr(visitor, "source_lines")
            and visitor.source_lines
            and sink_line > 0
            and sink_line <= len(visitor.source_lines)
        ):
            sink_code = visitor.source_lines[sink_line - 1].strip()
            # 使用基于配置的提取方法
            sink_arg_expressions = self.utils.extract_sink_parameters(sink_code)

            # 处理赋值情况下的参数提取
            if "=" in sink_code and sink_arg_expressions:
                var_name = sink_code.split("=")[0].strip()
                sink_info["tainted_variable"] = var_name

        sink_operation = self.tracker.utils.extract_operation_at_line(
            visitor, sink_line
        )
        sink_entry = None
        if sink_operation:
            # 增强sink描述信息
            sink_desc = f"Unsafe {sink_name} operation, potentially leading to {vulnerability_type}"
            # 如果提取到参数表达式，增加到描述中
            if sink_arg_expressions:
                sink_desc += (
                    f". Processing data from: {', '.join(sink_arg_expressions)}"
                )

            sink_entry = {
                "function": sink_operation,
                "file": visitor.file_path,
                "line": sink_line,
                "statement": sink_stmt_info["statement"],
                "context_lines": [sink_line - 2, sink_line + 2]
                if sink_line > 2
                else [1, sink_line + 2],
                "type": "sink",
                "description": sink_desc,
            }

        sink_function_node = self.tracker.utils.find_function_containing_line(
            visitor, sink_line
        )

        sink_function_range = None
        if sink_function_node:
            sink_function_range = (
                sink_function_node.line_no,
                sink_function_node.end_line_no,
            )

        sink_container_entry = None
        if sink_function_node:
            file_path = getattr(sink_function_node, "file_path", visitor.file_path)
            func_def_start = sink_function_node.line_no
            func_def_end = getattr(
                sink_function_node, "end_line_no", func_def_start + 1
            )
            func_def_stmt = ""
            if (
                hasattr(visitor, "source_lines")
                and visitor.source_lines
                and func_def_start > 0
                and func_def_start <= len(visitor.source_lines)
            ):
                func_def_stmt = visitor.source_lines[func_def_start - 1].strip()

            sink_container_entry = {
                "function": sink_function_node.name,
                "file": file_path,
                "line": sink_function_node.line_no,
                "statement": func_def_stmt
                if func_def_stmt
                else f"function {sink_function_node.name}",
                "context_lines": [func_def_start, func_def_end],
                "type": "sink_container",
                "description": f"Function containing sink {sink_name}, at line {sink_line}",
            }

            # 查找从入口点函数到sink函数的调用链
            # 从配置中读取入口点函数模式
            entry_point_patterns = []
            config = self.tracker.config
            if isinstance(config, dict) and "control_flow" in config:
                control_flow_config = config["control_flow"]
                if "entry_points" in control_flow_config and isinstance(
                    control_flow_config["entry_points"], list
                ):
                    for entry_config in control_flow_config["entry_points"]:
                        if "patterns" in entry_config and isinstance(
                            entry_config["patterns"], list
                        ):
                            entry_point_patterns.extend(entry_config["patterns"])

            # 如果配置中没有指定，使用默认入口点模式
            if not entry_point_patterns:
                entry_point_patterns = ["main", "run", "__main__"]

            if self.debug:
                print(f"[DEBUG] Using entry point patterns: {entry_point_patterns}")

            # 查找匹配配置的入口点函数
            for func_name, func_node in visitor.functions.items():
                # 检查函数名是否匹配任何入口点模式
                is_entry_point = False
                for pattern in entry_point_patterns:
                    if pattern == func_name or (
                        "*" in pattern
                        and re.search(pattern.replace("*", ".*"), func_name)
                    ):
                        is_entry_point = True
                        break

                if is_entry_point:
                    # 查找从入口点到sink函数的调用路径
                    func_calls = self._find_function_calls_between(
                        visitor, func_node, sink_function_node
                    )
                    for call in func_calls:
                        if call not in call_chain:
                            call_chain.append(call)
                            if self.debug:
                                print(
                                    f"[DEBUG] Added call from entry point {func_name} to sink function"
                                )

        # 获取sink中的变量，包括索引访问中的基础变量
        # 例如，对于expression message[1]，要识别出message是被污点的基础变量
        tainted_vars_in_sink = self.tracker.utils.find_tainted_vars_in_sink(
            visitor, sink_line
        )

        # 增加对数组索引访问的识别
        if sink_arg_expressions:
            for expr in sink_arg_expressions:
                # 提取数组索引访问中的基础变量
                # 如message[1]中的message
                array_var_match = re.match(r"([a-zA-Z_][a-zA-Z0-9_]*)\s*\[", expr)
                if array_var_match:
                    array_var = array_var_match.group(1)
                    if array_var not in tainted_vars_in_sink:
                        tainted_vars_in_sink.append(array_var)
                        if self.debug:
                            print(
                                f"[DEBUG] Identified array base variable: {array_var} from expression {expr}"
                            )

        same_function_sources = []
        other_sources = []
        parser_sources = []

        # 查找可能的数据流路径
        data_flow_path = []

        if (
            tainted_vars_in_sink
            and hasattr(visitor, "tainted")
            and hasattr(visitor, "source_statements")
        ):
            for var_name in tainted_vars_in_sink:
                if var_name in visitor.tainted:
                    source_info = visitor.tainted.get(var_name)
                    if source_info and "line" in source_info:
                        source_line = source_info.get("line", 0)
                        source_name = source_info.get("name", "Unknown")
                        if source_line > 0:
                            source_stmt_info = self.tracker.utils.get_statement_at_line(
                                visitor, source_line, context_lines=1
                            )
                            source_operation = (
                                self.tracker.utils.extract_operation_at_line(
                                    visitor, source_line
                                )
                            )

                            # 改进source描述中的变量信息
                            var_desc = f"variable {var_name}"
                            if sink_arg_expressions:
                                # 如果在sink参数中发现索引访问，补充说明
                                for expr in sink_arg_expressions:
                                    if var_name in expr and "[" in expr:
                                        var_desc = f"expression {expr} (base variable: {var_name})"
                                        break

                            source_stmt = {
                                "function": source_operation or f"Source of {var_name}",
                                "file": visitor.file_path,
                                "line": source_line,
                                "statement": source_info.get(
                                    "statement", source_stmt_info["statement"]
                                ),
                                "context_lines": [source_line - 1, source_line + 1],
                                "type": "source",
                                "description": f"Source of tainted data ({source_name}) assigned to {var_desc}",
                            }
                            source_key = f"{source_line}:{source_stmt['statement']}"
                            if source_key not in added_sources:
                                added_sources.add(source_key)
                                if (
                                    sink_function_range
                                    and sink_function_range[0]
                                    <= source_line
                                    <= sink_function_range[1]
                                ):
                                    same_function_sources.append(source_stmt)
                                else:
                                    other_sources.append(source_stmt)
                            if self.debug:
                                print(
                                    f"[DEBUG] Added source statement for var {var_name} at line {source_line}"
                                )

                            # 查找源变量和sink之间的数据流
                            # 检查变量赋值和变量转换操作
                            if hasattr(visitor, "var_assignments"):
                                self.data_flow.find_data_flow_steps(
                                    visitor,
                                    var_name,
                                    source_line,
                                    sink_line,
                                    sink_arg_expressions,
                                    data_flow_path,
                                    added_sources,
                                )

        (
            same_function_sources,
            other_sources,
            parser_sources,
        ) = self.tracker.utils.find_potential_sources(
            visitor,
            sink_function_node,
            sink_line,
            sink_stmt_info,
            sink_function_range,
            same_function_sources,
            other_sources,
            parser_sources,
            added_sources,
        )

        # 整合最终调用链
        final_call_chain = []

        # 1. 首先添加同一函数中找到的污点源（按照与sink的距离排序）
        for entry in same_function_sources:
            final_call_chain.append(entry)

        # 2. 如果有数据流路径，添加到调用链中
        for entry in data_flow_path:
            source_key = f"{entry['line']}:{entry['statement']}"
            if source_key not in added_sources:
                added_sources.add(source_key)
                final_call_chain.append(entry)

        # 3. 添加解析器类型的污点源
        for entry in parser_sources:
            final_call_chain.append(entry)

        # 4. 如果同一函数中没有找到污点源，添加其他函数中的污点源
        if not same_function_sources:
            for entry in other_sources:
                final_call_chain.append(entry)

        # 5. 添加包含sink的函数
        if sink_container_entry:
            final_call_chain.append(sink_container_entry)

        # 6. 添加sink
        if sink_entry:
            final_call_chain.append(sink_entry)

        # 如果同一函数中有多个污点源，按照与sink的距离对它们排序
        if len(same_function_sources) > 1:
            same_function_sources_sorted = sorted(
                same_function_sources, key=lambda x: abs(x["line"] - sink_line)
            )
            final_call_chain = [
                e for e in final_call_chain if e not in same_function_sources
            ]
            for entry in reversed(same_function_sources_sorted):
                final_call_chain.insert(0, entry)

        # 根据数据流依赖关系重新排序调用链
        final_call_chain = self.utils.reorder_call_chain_by_data_flow(final_call_chain)

        if self.debug:
            print(f"[DEBUG] Built call chain with {len(final_call_chain)} nodes")
            source_count = len([e for e in final_call_chain if e["type"] == "source"])
            print(f"[DEBUG] Sources in call chain: {source_count}")
            data_flow_count = len(data_flow_path)
            print(f"[DEBUG] Data flow steps in call chain: {data_flow_count}")

        return final_call_chain

    def build_call_chain_for_entrypoint(
        self, visitor: EnhancedTaintAnalysisVisitor, sink_info: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Build call chain from entry point to sink.
        This is used when we need to understand which HTTP endpoints may lead to the sink.

        Args:
            visitor: Visitor instance containing analysis results
            sink_info: Sink information dictionary

        Returns:
            List representing the call chain from entrypoint to sink
        """
        # 首先，获取对汇聚点的控制流调用链
        control_flow_chain = self.control_flow.build_control_flow_chain(
            visitor, sink_info
        )

        # 然后，获取数据流详情（即使没有明确的污点源）
        data_flow_chain = self.build_partial_call_chain_for_sink(visitor, sink_info)

        # 合并两条链路，优先保留控制流链中的入口点信息
        entrypoints = [
            node for node in control_flow_chain if node.get("type") == "entrypoint"
        ]
        non_entrypoints = [
            node for node in control_flow_chain if node.get("type") != "entrypoint"
        ]

        # 创建最终调用链，从入口点到汇聚点
        combined_chain = []

        # 添加入口点（如果有）
        for entry in entrypoints:
            combined_chain.append(entry)

        # 添加来自data_flow_chain的污点源（如果还没添加）
        source_nodes = [
            node for node in data_flow_chain if node.get("type") == "source"
        ]
        source_lines = set()

        for node in combined_chain:
            if node.get("line"):
                source_lines.add(node.get("line"))

        for node in source_nodes:
            if node.get("line") not in source_lines:
                combined_chain.append(node)
                source_lines.add(node.get("line"))

        # 添加剩余的控制流节点（如果还没添加）
        added_lines = set(source_lines)
        for node in non_entrypoints:
            if node.get("line") and node.get("line") not in added_lines:
                combined_chain.append(node)
                added_lines.add(node.get("line"))

        # 添加所有其他节点类型（intermediate, sink等）
        for node in data_flow_chain:
            if (
                node.get("type") not in ["source", "entrypoint"]
                and node.get("line") not in added_lines
            ):
                combined_chain.append(node)
                if node.get("line"):
                    added_lines.add(node.get("line"))

        # 确保调用链按照合理的顺序排列：入口点 -> 源 -> 中间节点 -> 汇聚点
        # 首先按类型排序
        type_order = {
            "entrypoint": 0,
            "source": 1,
            "intermediate": 2,
            "sink_container": 3,
            "sink": 4,
        }
        combined_chain.sort(
            key=lambda x: type_order.get(x.get("type", "intermediate"), 2)
        )

        # 然后用数据流方法再次排序，确保链接的连贯性
        combined_chain = self.utils.reorder_call_chain_by_data_flow(combined_chain)

        return combined_chain

    def _find_function_call_points(self, visitor, source_func, sink_func):
        """查找两个函数之间的直接调用点，基于AST和配置文件"""
        call_points = []

        # 如果有源代码可用
        if hasattr(visitor, "source_lines") and visitor.source_lines:
            # 添加源函数
            functions_to_check = [source_func]

            # 从配置中读取入口点函数模式
            entry_point_patterns = []
            config = self.tracker.config
            if isinstance(config, dict) and "control_flow" in config:
                control_flow_config = config["control_flow"]
                if "entry_points" in control_flow_config and isinstance(
                    control_flow_config["entry_points"], list
                ):
                    for entry_config in control_flow_config["entry_points"]:
                        if "patterns" in entry_config and isinstance(
                            entry_config["patterns"], list
                        ):
                            entry_point_patterns.extend(entry_config["patterns"])

            # 如果配置中没有指定，使用默认入口点模式
            if not entry_point_patterns:
                entry_point_patterns = ["main", "run", "__main__"]

            # 添加匹配配置的入口点函数
            for func_name, func_node in visitor.functions.items():
                for pattern in entry_point_patterns:
                    if pattern == func_name or (
                        "*" in pattern
                        and re.search(pattern.replace("*", ".*"), func_name)
                    ):
                        if func_node not in functions_to_check:
                            functions_to_check.append(func_node)
                        break

            for func in functions_to_check:
                start_line = func.line_no
                end_line = func.end_line_no

                for line_num in range(start_line, end_line + 1):
                    if line_num > len(visitor.source_lines):
                        break

                    line = visitor.source_lines[line_num - 1].strip()

                    # 从配置中获取方法调用模式
                    method_call_patterns = []
                    if isinstance(config, dict) and "control_flow" in config:
                        control_flow_config = config["control_flow"]
                        if (
                            "method_call_patterns" in control_flow_config
                            and isinstance(
                                control_flow_config["method_call_patterns"], list
                            )
                        ):
                            method_call_patterns = control_flow_config[
                                "method_call_patterns"
                            ]

                    # 如果配置中没有指定，使用默认模式
                    if not method_call_patterns:
                        method_call_patterns = [
                            r"self\.([a-zA-Z_][a-zA-Z0-9_]*)\(",
                            r"([a-zA-Z_][a-zA-Z0-9_]*)\(",
                        ]

                    # 对每个模式进行检查
                    for pattern in method_call_patterns:
                        matches = re.findall(pattern, line)

                        for match in matches:
                            method_name = match
                            if isinstance(match, tuple):
                                method_name = match[0]  # 处理正则表达式捕获组

                            # 检查是否是sink_func的方法名
                            sink_method_name = sink_func.name
                            if "." in sink_method_name:
                                sink_method_name = sink_method_name.split(".")[-1]

                            if method_name == sink_method_name:
                                call_desc = f"{method_name}()"
                                if "self." in pattern:
                                    call_desc = f"self.{method_name}()"

                                call_point = {
                                    "function": call_desc,
                                    "file": visitor.file_path,
                                    "line": line_num,
                                    "statement": line,
                                    "context_lines": [line_num - 1, line_num + 1],
                                    "type": "function_call",
                                    "description": f"Call to function {method_name} at line {line_num}",
                                }
                                call_points.append(call_point)

        return call_points

    def _get_function_call_info(self, visitor, caller_func, callee_func):
        """获取函数调用的详细信息"""
        if hasattr(visitor, "source_lines") and visitor.source_lines:
            start_line = caller_func.line_no
            end_line = caller_func.end_line_no

            for line_num in range(start_line, end_line + 1):
                if line_num > len(visitor.source_lines):
                    break

                line = visitor.source_lines[line_num - 1].strip()

                # 检查对被调用函数的引用
                if callee_func.name in line and "(" in line:
                    # 确保这是一个函数调用而不仅仅是名称的出现
                    call_pattern = r"(self\.)?" + re.escape(callee_func.name) + r"\s*\("
                    if re.search(call_pattern, line):
                        return {"line": line_num, "statement": line}

        return None

    def _extract_var_name_from_stmt(self, stmt):
        """从赋值语句中提取变量名"""
        if "=" in stmt:
            return stmt.split("=")[0].strip()
        return "unknown"

    def _find_function_calls_between(self, visitor, start_func, end_func):
        """找到从start_func到end_func的调用路径，基于AST分析和配置文件"""
        call_points = []

        # 如果有源代码可用
        if hasattr(visitor, "source_lines") and visitor.source_lines:
            start_line = start_func.line_no
            end_line = start_func.end_line_no

            # 从配置中获取方法调用模式
            method_call_patterns = []
            config = self.tracker.config
            if isinstance(config, dict) and "control_flow" in config:
                control_flow_config = config["control_flow"]
                if "method_call_patterns" in control_flow_config and isinstance(
                    control_flow_config["method_call_patterns"], list
                ):
                    method_call_patterns = control_flow_config["method_call_patterns"]

            # 如果配置中没有指定，使用默认模式
            if not method_call_patterns:
                # 提取目标函数名称
                target_method_name = end_func.name
                if "." in target_method_name:
                    target_method_name = target_method_name.split(".")[-1]

                # 默认模式包括self.method()和直接函数调用
                method_call_patterns = [
                    r"self\.([a-zA-Z_][a-zA-Z0-9_]*)\s*\(",
                    r"([a-zA-Z_][a-zA-Z0-9_]*)\s*\(",
                ]

            # 在源函数体内查找对目标函数的调用
            for line_num in range(start_line, end_line + 1):
                if line_num > len(visitor.source_lines):
                    break

                line = visitor.source_lines[line_num - 1].strip()

                # 提取目标函数名称
                target_method_name = end_func.name
                if "." in target_method_name:
                    target_method_name = target_method_name.split(".")[-1]

                # 检查行中是否包含目标函数名和函数调用标记
                if target_method_name in line and "(" in line:
                    # 使用不同的模式检查
                    for pattern in method_call_patterns:
                        matches = re.findall(pattern, line)

                        for match in matches:
                            method_name = match
                            if isinstance(match, tuple):
                                method_name = match[0]  # 处理正则表达式捕获组

                            if method_name == target_method_name:
                                call_point = {
                                    "function": f"{start_func.name}() -> {end_func.name}()",
                                    "file": visitor.file_path,
                                    "line": line_num,
                                    "statement": line,
                                    "context_lines": [line_num - 1, line_num + 1],
                                    "type": "function_call",
                                    "description": f"Call from {start_func.name} to {end_func.name} at line {line_num}",
                                }
                                call_points.append(call_point)
                                break

            # 检查通过AST分析收集的调用点信息
            if hasattr(end_func, "call_points") and end_func.call_points:
                for call_point in end_func.call_points:
                    if call_point.get("caller") == start_func.name:
                        cp = {
                            "function": f"{start_func.name}() -> {end_func.name}()",
                            "file": visitor.file_path,
                            "line": call_point.get("line"),
                            "statement": call_point.get("statement", ""),
                            "context_lines": [
                                call_point.get("line") - 1,
                                call_point.get("line") + 1,
                            ],
                            "type": "function_call",
                            "description": f"Call from {start_func.name} to {end_func.name} at line {call_point.get('line')}",
                        }
                        call_points.append(cp)

        return call_points
