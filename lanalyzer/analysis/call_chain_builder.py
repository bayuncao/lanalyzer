"""
Call chain builder for taint analysis.
This module provides functionality for building function call chains.
"""

import re
from typing import Any, Dict, List

from lanalyzer.analysis.data_flow_analyzer import DataFlowAnalyzer
from lanalyzer.analysis.control_flow_analyzer import ControlFlowAnalyzer
from lanalyzer.analysis.chain_utils import ChainUtils
from lanalyzer.analysis.visitor import EnhancedTaintAnalysisVisitor


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
        Optimization: Recursively find callee paths, prioritizing self method calls.
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

        # Create source and sink statement nodes first
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
            # Extract possible sink parameter expressions
            sink_arg_expressions = []
            if (
                hasattr(visitor, "source_lines")
                and visitor.source_lines
                and sink_line > 0
                and sink_line <= len(visitor.source_lines)
            ):
                sink_code = visitor.source_lines[sink_line - 1].strip()
                # Use configuration-based extraction method
                sink_arg_expressions = self.utils.extract_sink_parameters(sink_code)

            sink_desc = f"Unsafe {sink_name} operation, potentially leading to {sink.get('vulnerability_type', 'vulnerability')}"
            # If parameter expressions are extracted, add them to the description
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

        # Handle the case where source and sink are in the same function
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

        # Recursively find all paths from source_func to sink_func
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
                    f"[DEBUG] Found {len(found_paths) if found_paths else 0} path(s) from {source_func.name} to {sink_func.name}"
                )

        # If visitor has self_method_call_map, try to complete the chain
        if not found_paths and hasattr(visitor, "self_method_call_map"):
            if self.debug:
                print("[DEBUG] Trying to complete chain using self_method_call_map")
            for key, lines in visitor.self_method_call_map.items():
                if (
                    source_func
                    and sink_func
                    and source_func.name in key
                    and sink_func.name in key
                ):
                    # Construct a simple chain
                    found_paths = [[source_func, sink_func]]
                    break

        # Generate call chain nodes
        if found_paths:
            # Take only the shortest path
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
                print(f"[DEBUG] Final call chain node count: {len(call_chain)}")
            return self.utils.reorder_call_chain_by_data_flow(call_chain)

        # If no path is found, try common callers
        if self.debug:
            print("[DEBUG] No direct path found, trying to find common callers...")
        # Reuse existing common callers logic
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

                # Find more detailed call information
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

                # Extract possible sink parameter expressions to enhance description
                sink_arg_expressions = []
                if (
                    hasattr(visitor, "source_lines")
                    and visitor.source_lines
                    and sink_line > 0
                    and sink_line <= len(visitor.source_lines)
                ):
                    sink_code = visitor.source_lines[sink_line - 1].strip()
                    # Use configuration-based extraction method
                    sink_arg_expressions = self.utils.extract_sink_parameters(sink_code)

                # Build call chain including common caller
                sink_desc = f"Contains sink {sink_name} at line {sink_line}"
                if sink_arg_expressions:
                    sink_desc += (
                        f" processing data from: {', '.join(sink_arg_expressions)}"
                    )

                source_desc = f"Contains source {source_name} at line {source_line}"

                # Build call chain in data flow order: source -> source func -> common caller -> sink func -> sink
                call_chain = [
                    # 1. Source node
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
                    # 2. Common caller node
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
                    # 3. Sink node
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

                # Use data flow sorting method to ensure correct call chain order
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

        sink_code = ""
        sink_arg_expressions = []
        if (
            hasattr(visitor, "source_lines")
            and visitor.source_lines
            and sink_line > 0
            and sink_line <= len(visitor.source_lines)
        ):
            sink_code = visitor.source_lines[sink_line - 1].strip()
            sink_arg_expressions = self.utils.extract_sink_parameters(sink_code)

            if "=" in sink_code and sink_arg_expressions:
                var_name = sink_code.split("=")[0].strip()
                sink_info["tainted_variable"] = var_name

        sink_operation = self.tracker.utils.extract_operation_at_line(
            visitor, sink_line
        )
        sink_entry = None
        if sink_operation:
            sink_desc = f"Unsafe {sink_name} operation, potentially leading to {vulnerability_type}"
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

            # Find call chain from entry point function to sink function
            # Read entry point function patterns from configuration
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

            # If not specified in configuration, use empty list
            if not entry_point_patterns:
                entry_point_patterns = []

            if self.debug:
                print(f"[DEBUG] Using entry point patterns: {entry_point_patterns}")

            # Find entry point functions matching configuration
            for func_name, func_node in visitor.functions.items():
                # Check if function name matches any entry point pattern
                is_entry_point = False
                for pattern in entry_point_patterns:
                    if pattern == func_name or (
                        "*" in pattern
                        and re.search(pattern.replace("*", ".*"), func_name)
                    ):
                        is_entry_point = True
                        break

                if is_entry_point:
                    # Find call path from entry point to sink function
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

        # Get variables in sink, including base variables in index access
        # For example, for expression message[1], identify message as the tainted base variable
        tainted_vars_in_sink = self.tracker.utils.find_tainted_vars_in_sink(
            visitor, sink_line
        )

        # Enhance identification of array index access
        if sink_arg_expressions:
            for expr in sink_arg_expressions:
                # Extract base variables in array index access
                # Like message in message[1]
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

        # Find possible data flow paths
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

                            # Improve variable information in source description
                            var_desc = f"variable {var_name}"
                            if sink_arg_expressions:
                                # If index access is found in sink parameters, add explanation
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

                            # Find data flow between source variable and sink
                            # Check variable assignments and variable transformation operations
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

        # Integrate the final call chain
        final_call_chain = []

        # 1. First add taint sources found in the same function (sorted by distance to sink)
        for entry in same_function_sources:
            final_call_chain.append(entry)

        # 2. If there are data flow paths, add them to the call chain
        for entry in data_flow_path:
            source_key = f"{entry['line']}:{entry['statement']}"
            if source_key not in added_sources:
                added_sources.add(source_key)
                final_call_chain.append(entry)

        # 3. Add parser-type taint sources
        for entry in parser_sources:
            final_call_chain.append(entry)

        # 4. If no taint sources are found in the same function, add sources from other functions
        if not same_function_sources:
            for entry in other_sources:
                final_call_chain.append(entry)

        # 5. Add the function containing the sink
        if sink_container_entry:
            final_call_chain.append(sink_container_entry)

        # 6. Add the sink
        if sink_entry:
            final_call_chain.append(sink_entry)

        # If there are multiple taint sources in the same function, sort them by distance to the sink
        if len(same_function_sources) > 1:
            same_function_sources_sorted = sorted(
                same_function_sources, key=lambda x: abs(x["line"] - sink_line)
            )
            final_call_chain = [
                e for e in final_call_chain if e not in same_function_sources
            ] + same_function_sources_sorted

        # 7. Add any additional entry points and call paths
        for entry in call_chain:
            if entry not in final_call_chain:
                final_call_chain.append(entry)

        # Sort the final call chain by the line number, but keep sources before sinks
        def sort_key(entry):
            # Assign priorities to different entry types
            type_priority = {
                "source": 0,
                "intermediate": 1,
                "sink_container": 2,
                "sink": 3,
            }
            entry_type = entry.get("type", "intermediate")
            priority = type_priority.get(entry_type, 1)
            return (priority, entry.get("line", 0))

        # Filter out duplicate entries
        unique_entries = {}
        for entry in final_call_chain:
            key = f"{entry.get('function', '')}:{entry.get('line', 0)}:{entry.get('type', '')}"
            if key not in unique_entries:
                unique_entries[key] = entry

        final_call_chain = list(unique_entries.values())
        final_call_chain.sort(key=sort_key)

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
        control_flow_chain = self.control_flow.build_control_flow_chain(
            visitor, sink_info
        )

        data_flow_chain = self.build_partial_call_chain_for_sink(visitor, sink_info)

        entrypoints = [
            node for node in control_flow_chain if node.get("type") == "entrypoint"
        ]
        non_entrypoints = [
            node for node in control_flow_chain if node.get("type") != "entrypoint"
        ]

        combined_chain = []

        for entry in entrypoints:
            combined_chain.append(entry)

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

        added_lines = set(source_lines)
        for node in non_entrypoints:
            if node.get("line") and node.get("line") not in added_lines:
                combined_chain.append(node)
                added_lines.add(node.get("line"))

        for node in data_flow_chain:
            if (
                node.get("type") not in ["source", "entrypoint"]
                and node.get("line") not in added_lines
            ):
                combined_chain.append(node)
                if node.get("line"):
                    added_lines.add(node.get("line"))

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

        combined_chain = self.utils.reorder_call_chain_by_data_flow(combined_chain)

        return combined_chain

    def _find_function_call_points(self, visitor, source_func, sink_func):
        call_points = []

        if hasattr(visitor, "source_lines") and visitor.source_lines:
            functions_to_check = [source_func]

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

            if not entry_point_patterns:
                entry_point_patterns = []

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

                    # Get method call patterns from configuration or use empty list
                    method_call_patterns = []
                    config = self.tracker.config
                    if (
                        isinstance(config, dict)
                        and "analysis" in config
                        and "method_call_patterns" in config["analysis"]
                    ):
                        method_call_patterns = config["analysis"][
                            "method_call_patterns"
                        ]

                    # If not configured, don't detect any patterns
                    if not method_call_patterns:
                        method_call_patterns = []

                    # Check each pattern
                    for pattern in method_call_patterns:
                        matches = re.findall(pattern, line)

                        for match in matches:
                            method_name = match
                            if isinstance(match, tuple):
                                method_name = match[0]  # Handle regex capture groups

                            # Check if it's the sink_func's method name
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
        """Get detailed information about function call"""
        if hasattr(visitor, "source_lines") and visitor.source_lines:
            start_line = caller_func.line_no
            end_line = caller_func.end_line_no

            for line_num in range(start_line, end_line + 1):
                if line_num > len(visitor.source_lines):
                    break

                line = visitor.source_lines[line_num - 1].strip()

                # Check for references to the called function
                if callee_func.name in line and "(" in line:
                    # Make sure this is a function call and not just an occurrence of the name
                    call_pattern = r"(self\.)?" + re.escape(callee_func.name) + r"\s*\("
                    if re.search(call_pattern, line):
                        return {"line": line_num, "statement": line}

        return None

    def _extract_var_name_from_stmt(self, stmt):
        """Extract variable name from assignment statement"""
        if "=" in stmt:
            return stmt.split("=")[0].strip()
        return "unknown"

    def _find_function_calls_between(self, visitor, start_func, end_func):
        """Find call path from start_func to end_func, based on AST analysis"""
        call_points = []

        # If source code is available
        if hasattr(visitor, "source_lines") and visitor.source_lines:
            start_line = start_func.line_no
            end_line = start_func.end_line_no

            # Get method call patterns from configuration
            method_call_patterns = []
            config = self.tracker.config
            if (
                isinstance(config, dict)
                and "analysis" in config
                and "method_call_patterns" in config["analysis"]
            ):
                method_call_patterns = config["analysis"]["method_call_patterns"]

            # If not configured, don't detect any patterns
            if not method_call_patterns:
                method_call_patterns = []

            # Search for calls to the target function within the source function body
            for line_num in range(start_line, end_line + 1):
                if line_num > len(visitor.source_lines):
                    break

                line = visitor.source_lines[line_num - 1].strip()

                # Extract target function name
                target_method_name = end_func.name
                if "." in target_method_name:
                    target_method_name = target_method_name.split(".")[-1]

                # Check if the line contains the target function name and function call marker
                if target_method_name in line and "(" in line:
                    # Check with different patterns
                    for pattern in method_call_patterns:
                        matches = re.findall(pattern, line)

                        for match in matches:
                            method_name = match
                            if isinstance(match, tuple):
                                method_name = match[0]  # Handle regex capture groups

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

            # Check call points information collected through AST analysis
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
