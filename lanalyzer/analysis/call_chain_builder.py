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

        Args:
            visitor: EnhancedTaintAnalysisVisitor instance
            sink: Sink dictionary
            source_info: Source information dictionary

        Returns:
            List of dictionaries containing detailed function call chain information
        """
        call_chain = []
        source_line = source_info.get("line", 0)
        sink_line = sink.get("line", 0)
        source_name = source_info.get("name", "Unknown")
        sink_name = sink.get("name", "Unknown")

        if self.debug:
            print(
                f"Building call chain from source {source_name}(line {source_line}) to sink {sink_name}(line {sink_line})"
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
                    f"Found source function: {source_func.name} (lines {source_func.line_no}-{source_func.end_line_no})"
                )
            else:
                print(f"Could not find function containing source (line {source_line})")

            if sink_func:
                print(
                    f"Found sink function: {sink_func.name} (lines {sink_func.line_no}-{sink_func.end_line_no})"
                )
            else:
                print(f"Could not find function containing sink (line {sink_line})")

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
                "description": f"Source of tainted data ({source_name})",
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

            sink_desc = (
                f"Unsafe {sink_name} operation, potentially leading to vulnerability"
            )
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
            # 确保调用链按数据流方向排序
            return self.utils.reorder_call_chain_by_data_flow(call_chain)

        # 处理源和汇聚点在不同函数的情况
        if source_func and sink_func:
            queue = [(source_func, [source_func])]
            visited = {source_func.name}
            max_depth = 20
            found_path = None

            while queue and not found_path:
                current, path = queue.pop(0)

                for callee in current.callees:
                    if callee.name == sink_func.name:
                        found_path = path + [sink_func]
                        break

                    if callee.name not in visited and len(path) < max_depth:
                        visited.add(callee.name)
                        queue.append((callee, path + [callee]))

            if found_path:
                for i, func in enumerate(found_path):
                    node_type = "intermediate"
                    description = "Intermediate function in the call chain"

                    if i == 0:
                        node_type = "source"
                        description = (
                            f"Contains source {source_name} at line {source_line}"
                        )
                    elif i == len(found_path) - 1:
                        node_type = "sink"
                        description = f"Contains sink {sink_name} at line {sink_line}"

                    line_num = func.line_no
                    call_statement = ""

                    if i > 0 and i < len(found_path) - 1:
                        prev_func = found_path[i - 1]
                        for callee in prev_func.callees:
                            if callee.name == func.name and hasattr(
                                callee, "call_line"
                            ):
                                line_num = callee.call_line
                                call_statement = (
                                    self.tracker.utils.get_statement_at_line(
                                        visitor, line_num
                                    )["statement"]
                                )
                                break

                    func_info = {
                        "function": func.name,
                        "file": func.file_path,
                        "line": line_num,
                        "statement": call_statement
                        if call_statement
                        else f"function {func.name}()",
                        "context_lines": [func.line_no, func.end_line_no],
                        "type": node_type,
                        "description": description,
                    }
                    call_chain.append(func_info)

                # 确保调用链按数据流方向排序
                return self.utils.reorder_call_chain_by_data_flow(call_chain)

            if not found_path and self.debug:
                print("No direct path found, trying to find common callers...")

            # 尝试查找共同调用者
            common_callers_path = self._build_common_callers_path(
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

            if common_callers_path:
                # 确保调用链按数据流方向排序
                return self.utils.reorder_call_chain_by_data_flow(common_callers_path)
            else:
                return []

        # 处理只找到源函数或者只找到汇聚点函数的情况
        if source_func:
            source_func_info = {
                "function": source_func.name,
                "file": source_func.file_path,
                "line": source_func.line_no,
                "statement": source_stmt_info["statement"],
                "context_lines": [source_func.line_no, source_func.end_line_no],
                "type": "source",
                "description": f"Contains source {source_name} at line {source_line}",
            }
            call_chain.append(source_func_info)

        if sink_func:
            sink_func_info = {
                "function": sink_func.name,
                "file": sink_func.file_path,
                "line": sink_func.line_no,
                "statement": sink_stmt_info["statement"],
                "context_lines": [sink_func.line_no, sink_func.end_line_no],
                "type": "sink",
                "description": f"Contains sink {sink_name} at line {sink_line}",
            }
            call_chain.append(sink_func_info)

        # 确保调用链按数据流方向排序
        return self.utils.reorder_call_chain_by_data_flow(call_chain)

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
