"""
Unified flow analyzer.

This module consolidates data flow and control flow analysis
into a single, coherent implementation.
"""

from typing import Any, Dict, List, Optional

from lanalyzer.logger import debug

from ..core.visitor import TaintAnalysisVisitor


class FlowAnalyzer:
    """
    Unified analyzer for data flow and control flow analysis.

    This class combines the functionality of DataFlowAnalyzer and
    ControlFlowAnalyzer into a single, more maintainable implementation.
    """

    def __init__(self, tracker, debug_mode: bool = False):
        """
        Initialize the flow analyzer.

        Args:
            tracker: Parent tracker instance
            debug_mode: Whether to enable debug output
        """
        self.tracker = tracker
        self.debug = debug_mode

    def analyze_data_flow(
        self,
        visitor: TaintAnalysisVisitor,
        source_var: str,
        source_line: int,
        sink_line: int,
        sink_args: List[str],
    ) -> List[Dict[str, Any]]:
        """
        Analyze data flow from source variable to sink arguments.

        Args:
            visitor: Visitor instance with analysis results
            source_var: Name of the source variable
            source_line: Line number where source is defined
            sink_line: Line number where sink is called
            sink_args: List of sink argument expressions

        Returns:
            List of data flow steps
        """
        if not hasattr(visitor, "source_lines") or not visitor.source_lines:
            return []

        data_flow_steps = []

        # Build variable usage mapping
        var_usage_map = self._build_variable_usage_map(visitor, source_var)

        # Find relevant assignments between source and sink
        relevant_assignments = self._find_relevant_assignments(
            visitor, source_var, source_line, sink_line, var_usage_map
        )

        # Check if source variable is used directly in sink
        if self._is_variable_used_in_sink(source_var, sink_args):
            data_flow_steps.extend(relevant_assignments)

            # Add direct usage step
            if visitor.source_lines and 1 <= source_line <= len(visitor.source_lines):
                source_stmt = visitor.source_lines[source_line - 1].strip()
                direct_usage_step = {
                    "function": "Data flow: Direct use of source variable",
                    "file": visitor.file_path,
                    "line": source_line,
                    "statement": source_stmt,
                    "context_lines": [source_line - 1, source_line + 1],
                    "type": "data_flow",
                    "description": f"Source variable {source_var} used directly in sink",
                }
                data_flow_steps.append(direct_usage_step)

        return sorted(data_flow_steps, key=lambda x: x["line"])

    def analyze_control_flow(
        self,
        visitor: TaintAnalysisVisitor,
        sink_info: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Analyze control flow from entry points to sink.

        Args:
            visitor: Visitor instance with analysis results
            sink_info: Information about the sink

        Returns:
            List of control flow steps
        """
        sink_line = sink_info.get("line", 0)
        sink_name = sink_info.get("name", "Unknown Sink")

        if self.debug:
            debug(
                f"[FlowAnalyzer] Building control flow for sink {sink_name} at line {sink_line}"
            )

        # Find the function containing the sink
        sink_func = self._find_function_containing_line(visitor, sink_line)
        if not sink_func:
            if self.debug:
                debug(
                    f"[FlowAnalyzer] Could not find function containing sink at line {sink_line}"
                )
            return []

        control_flow_steps = []

        # Add entry point if sink is in a function
        if sink_func["name"] != "__main__":
            entry_step = {
                "function": f"Entry point: {sink_func['name']}()",
                "file": visitor.file_path,
                "line": sink_func["line"],
                "statement": f"def {sink_func['name']}({', '.join(sink_func.get('args', []))}):",
                "type": "entry_point",
                "description": f"Function {sink_func['name']} contains the sink",
            }
            control_flow_steps.append(entry_step)

        # Add function calls within the sink function
        function_calls = self._find_function_calls_in_range(
            visitor, sink_func["line"], sink_line
        )

        for call in function_calls:
            if call["line"] < sink_line:  # Only calls before the sink
                call_step = {
                    "function": f"Function call: {call['name']}()",
                    "file": visitor.file_path,
                    "line": call["line"],
                    "statement": call.get("statement", ""),
                    "type": "function_call",
                    "description": f"Call to {call['name']} before sink",
                }
                control_flow_steps.append(call_step)

        return sorted(control_flow_steps, key=lambda x: x["line"])

    def _build_variable_usage_map(
        self, visitor: TaintAnalysisVisitor, var_name: str
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Build a mapping of variable usage throughout the code."""
        usage_map = {}

        if hasattr(visitor, "var_assignments") and var_name in visitor.var_assignments:
            usage_map[var_name] = visitor.var_assignments[var_name]

        return usage_map

    def _find_relevant_assignments(
        self,
        visitor: TaintAnalysisVisitor,
        var_name: str,
        source_line: int,
        sink_line: int,
        usage_map: Dict[str, List[Dict[str, Any]]],
    ) -> List[Dict[str, Any]]:
        """Find variable assignments relevant to the data flow."""
        relevant_assignments = []

        if var_name in usage_map:
            for assignment in usage_map[var_name]:
                assign_line = assignment.get("line", 0)

                # Only consider assignments between source and sink
                if source_line < assign_line < sink_line:
                    flow_step = {
                        "function": f"Data flow: {assignment['statement']}",
                        "file": visitor.file_path,
                        "line": assign_line,
                        "statement": assignment["statement"],
                        "context_lines": [assign_line - 1, assign_line + 1],
                        "type": "data_flow",
                        "description": f"Variable {var_name} modified at line {assign_line}",
                    }
                    relevant_assignments.append(flow_step)

        return relevant_assignments

    def _is_variable_used_in_sink(self, var_name: str, sink_args: List[str]) -> bool:
        """Check if variable is used in sink arguments."""
        for arg in sink_args:
            if var_name in arg:
                return True
        return False

    def _find_function_containing_line(
        self, visitor: TaintAnalysisVisitor, line: int
    ) -> Optional[Dict[str, Any]]:
        """Find the function that contains the given line number."""
        for func_name, func_info in visitor.functions.items():
            func_line = func_info.get("line", 0)

            # Simple heuristic: if the line is after the function definition,
            # assume it's in that function (this could be improved with proper AST analysis)
            if func_line <= line:
                return func_info

        # If no function found, assume it's in global scope
        return {"name": "__main__", "line": 1, "args": []}

    def _find_function_calls_in_range(
        self,
        visitor: TaintAnalysisVisitor,
        start_line: int,
        end_line: int,
    ) -> List[Dict[str, Any]]:
        """Find function calls within a line range."""
        calls_in_range = []

        for call in visitor.call_locations:
            call_line = call.get("line", 0)
            if start_line <= call_line <= end_line:
                # Get statement text
                statement = ""
                if visitor.source_lines and 1 <= call_line <= len(visitor.source_lines):
                    statement = visitor.source_lines[call_line - 1].strip()

                call_info = {
                    "name": call.get("name", "unknown"),
                    "line": call_line,
                    "statement": statement,
                }
                calls_in_range.append(call_info)

        return calls_in_range
