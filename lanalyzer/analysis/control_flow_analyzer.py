"""
Control flow analysis for taint analysis call chains.

This module analyzes control flow from entry points to taint sinks by:
1. Using AST to build function call graphs
2. Identifying self.method() style method calls
3. Tracing paths from entry points to sink functions
4. Constructing detailed call chains with source code context
"""

import re
from typing import Any, Dict, List

from lanalyzer.analysis.visitor import EnhancedTaintAnalysisVisitor
from lanalyzer.logger import debug


class ControlFlowAnalyzer:
    """Analyze control flow from entry points to taint sinks."""

    def __init__(self, builder):
        """Initialize with reference to parent builder."""
        self.builder = builder
        self.tracker = builder.tracker
        self.debug = builder.debug

    def build_control_flow_chain(
        self, visitor: EnhancedTaintAnalysisVisitor, sink_info: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Build the control flow call stack from entry points to sink

        Args:
            visitor: Visitor instance
            sink_info: Sink information

        Returns:
            Control flow call chain
        """
        sink_line = sink_info.get("line", 0)
        sink_name = sink_info.get("name", "Unknown Sink")

        if self.debug:
            debug(
                f"[DEBUG] Building control flow chain for sink {sink_name} at line {sink_line}"
            )

        # Find the function containing the sink
        sink_func = self.tracker.utils.find_function_containing_line(visitor, sink_line)
        if not sink_func:
            if self.debug:
                debug(
                    f"[DEBUG] Could not find function containing sink at line {sink_line}"
                )
            return []

        # Get sink statement information
        sink_stmt_info = self.tracker.utils.get_statement_at_line(
            visitor, sink_line, context_lines=1
        )

        # Trace call stack upwards
        call_stack = self.trace_call_stack_to_entry(visitor, sink_func)

        # Convert to call chain format
        return self.convert_call_stack_to_chain(
            call_stack, sink_info, visitor, sink_func, sink_stmt_info
        )

    def trace_call_stack_to_entry(
        self, visitor: EnhancedTaintAnalysisVisitor, sink_func
    ) -> List[Any]:
        """
        Trace the call stack from entry point to target function

        Args:
            visitor: Visitor instance
            sink_func: Target function node

        Returns:
            Call stack (list of function nodes)
        """
        if not sink_func:
            return []

        # Build reverse call graph
        reverse_call_graph = {}
        for func_name, func_node in visitor.functions.items():
            reverse_call_graph[func_name] = []

        for func_name, func_node in visitor.functions.items():
            for callee in func_node.callees:
                if callee.name not in reverse_call_graph:
                    reverse_call_graph[callee.name] = []
                reverse_call_graph[callee.name].append(func_node)

        # Get entry point patterns from config
        entry_point_patterns = []
        config = self.tracker.config
        if isinstance(config, dict) and "control_flow" in config:
            control_flow_config = config["control_flow"]
            # Get patterns from entry_points config
            if "entry_points" in control_flow_config and isinstance(
                control_flow_config["entry_points"], list
            ):
                for entry_config in control_flow_config["entry_points"]:
                    if "patterns" in entry_config and isinstance(
                        entry_config["patterns"], list
                    ):
                        entry_point_patterns.extend(entry_config["patterns"])

        if self.debug:
            debug(
                f"[DEBUG] Got {len(entry_point_patterns)} entry point patterns from config"
            )

        # Prioritize entry points defined in configuration
        config_defined_entry_points = []
        if entry_point_patterns:
            for func_name, func_node in visitor.functions.items():
                func_method_name = (
                    func_name.split(".")[-1] if "." in func_name else func_name
                )
                for pattern in entry_point_patterns:
                    # Three matching methods:
                    # 1. Exact match of function name
                    # 2. Exact match of method name part
                    # 3. Regex match (for patterns containing *)
                    if (
                        pattern == func_name
                        or pattern == func_method_name
                        or (
                            "*" in pattern
                            and re.search(pattern.replace("*", ".*"), func_name)
                        )
                    ):
                        config_defined_entry_points.append(func_node)
                        if self.debug:
                            debug(
                                f"[DEBUG] Found config-defined entry point: {func_name} matched pattern {pattern}"
                            )
                        break

        # If config-defined entry points are found, prioritize them
        if config_defined_entry_points:
            # Try to find path from config-defined entry points to sink function
            for entry_point in config_defined_entry_points:
                path = self.find_path_to_function(
                    entry_point, sink_func, visitor.functions
                )
                if path:
                    if self.debug:
                        debug(
                            f"[DEBUG] Found path from config-defined entry point {entry_point.name} to sink function {sink_func.name}"
                        )
                    return path

        # If no config-defined entry points are found or no path from them to sink, use default method
        # Use BFS to find possible entry point functions (functions not called by other functions)
        default_entry_points = []
        for func_name, callers in reverse_call_graph.items():
            if not callers:  # No callers, might be an entry point
                func_node = visitor.functions.get(func_name)
                if func_node:
                    default_entry_points.append(func_node)

        if self.debug:
            debug(
                f"[DEBUG] Found {len(default_entry_points)} default entry points: {[ep.name for ep in default_entry_points]}"
            )

        # For each default entry point, try to find a path to the sink function
        for entry_point in default_entry_points:
            path = self.find_path_to_function(entry_point, sink_func, visitor.functions)
            if path:
                if self.debug:
                    debug(
                        f"[DEBUG] Found path from default entry point {entry_point.name} to sink function {sink_func.name}"
                    )
                return path

        # If no complete path is found, at least return the sink function
        if self.debug:
            debug("[DEBUG] No complete path found, returning just the sink function")
        return [sink_func]

    def find_path_to_function(
        self, start_func, target_func, all_functions, max_depth=None
    ):
        """
        Use BFS to find a path from start function to target function

        Args:
            start_func: Start function
            target_func: Target function
            all_functions: Dictionary of all functions
            max_depth: Maximum search depth, if None get from config

        Returns:
            Function path, None if not found
        """
        if start_func == target_func:
            return [start_func]

        # Get max depth from configuration if not provided
        if max_depth is None:
            config = self.tracker.config
            if (
                isinstance(config, dict)
                and "control_flow" in config
                and "max_call_depth" in config["control_flow"]
                and isinstance(config["control_flow"]["max_call_depth"], int)
            ):
                max_depth = config["control_flow"]["max_call_depth"]
            else:
                max_depth = 10  # Default to 10 if not in config

        if self.debug:
            debug(f"[DEBUG] Using max call depth of {max_depth}")

        # Initialize BFS queue
        queue = [(start_func, [start_func])]  # (current node, path to current node)
        visited = {
            start_func.name
        }  # Use names for visited to avoid object equality issues

        # Perform BFS to find path
        while queue and max_depth > 0:
            max_depth -= 1
            level_size = len(queue)
            for _ in range(level_size):
                cur_func, path = queue.pop(0)

                # Check if target is directly called by current function
                if target_func.name in [callee.name for callee in cur_func.callees]:
                    return path + [target_func]

                # Add all unvisited callees to queue
                for callee in cur_func.callees:
                    if callee.name not in visited:
                        visited.add(callee.name)
                        queue.append((callee, path + [callee]))

            if max_depth <= 0:
                if self.debug:
                    debug("[DEBUG] Reached max call depth limit")
                break

        return None  # No path found

    def convert_call_stack_to_chain(
        self,
        call_stack: List[Any],
        sink_info: Dict[str, Any],
        visitor: EnhancedTaintAnalysisVisitor,
        sink_func,
        sink_stmt_info: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Convert function call stack to detailed call chain

        Args:
            call_stack: List of functions in the call path
            sink_info: Sink information
            visitor: Visitor instance
            sink_func: Sink function node
            sink_stmt_info: Sink statement information

        Returns:
            Detailed call chain with source locations and code
        """
        if not call_stack:
            return []

        call_chain = []

        # Add entry point function (first in call stack)
        entry_func = call_stack[0]
        entry_info = {
            "type": "entry",
            "name": entry_func.name,
            "location": {
                "file": visitor.file_path,
                "line": entry_func.lineno,
                "end_line": entry_func.end_lineno,
            },
            "code": self.tracker.utils.get_function_code(visitor, entry_func),
        }
        call_chain.append(entry_info)

        # Add intermediate functions in call path
        for i in range(1, len(call_stack) - 1):
            func = call_stack[i]
            call_info = {
                "type": "call",
                "name": func.name,
                "location": {
                    "file": visitor.file_path,
                    "line": func.lineno,
                    "end_line": func.end_lineno,
                },
                "code": self.tracker.utils.get_function_code(visitor, func),
            }
            call_chain.append(call_info)

        # Add sink function and sink statement
        sink_func_info = {
            "type": "function",
            "name": sink_func.name,
            "location": {
                "file": visitor.file_path,
                "line": sink_func.lineno,
                "end_line": sink_func.end_lineno,
            },
            "code": self.tracker.utils.get_function_code(visitor, sink_func),
        }
        call_chain.append(sink_func_info)

        # Add sink statement as the final element
        sink_info = {
            "type": "sink",
            "name": sink_info.get("name", "Unknown Sink"),
            "location": {
                "file": visitor.file_path,
                "line": sink_info.get("line", 0),
            },
            "code": sink_stmt_info.get("line_content", ""),
            "context": sink_stmt_info.get("context", ""),
        }
        call_chain.append(sink_info)

        return call_chain
