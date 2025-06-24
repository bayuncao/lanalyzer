"""
Utility functions for taint analysis.
"""

import re
from typing import Any, Dict, List, Set, Tuple, Optional

from lanalyzer.analysis.visitor import EnhancedTaintAnalysisVisitor
from lanalyzer.logger import debug
from lanalyzer.analysis import ast_helpers
from lanalyzer.analysis import data_flow_helpers


class TaintAnalysisUtils:
    """
    Utility methods for taint analysis.
    """

    def __init__(self, tracker):
        """
        Initialize the utilities.

        Args:
            tracker: The parent tracker instance
        """
        self.tracker = tracker
        self.debug = tracker.debug
        self.sources = tracker.sources

    def get_statement_at_line(
        self, visitor: EnhancedTaintAnalysisVisitor, line: int, context_lines: int = 0
    ) -> Dict[str, Any]:
        """包装 ast_helpers.get_statement_at_line"""
        if not hasattr(visitor, "source_lines") or not visitor.source_lines:
            return {"statement": "", "context_start": line, "context_end": line}
        return ast_helpers.get_statement_at_line(
            visitor.source_lines, line, context_lines=context_lines
        )

    def extract_operation_at_line(
        self, visitor: EnhancedTaintAnalysisVisitor, line: int
    ) -> Optional[str]:
        """包装 ast_helpers.extract_operation_at_line"""
        if not hasattr(visitor, "source_lines") or not visitor.source_lines:
            return None

        dangerous_patterns = {}
        if hasattr(self.tracker, "config") and isinstance(self.tracker.config, dict):
            dangerous_patterns = self.tracker.config.get("dangerous_patterns", {})

        return ast_helpers.extract_operation_at_line(
            visitor.source_lines,
            line,
            debug_enabled=self.debug,
            dangerous_patterns=dangerous_patterns,
        )

    def find_function_containing_line(
        self, visitor: EnhancedTaintAnalysisVisitor, line: int
    ) -> Optional[Any]:
        """
        Find the function node containing the specified line.

        Args:
            visitor: Visitor instance
            line: Line number

        Returns:
            The function node containing the line, or None if not found
        """
        for func_name, func_node in visitor.functions.items():
            # Ensure the node has necessary attributes
            if not hasattr(func_node, "line_no") or not hasattr(
                func_node, "end_line_no"
            ):
                continue

            # Check if the line number is valid
            if not isinstance(func_node.line_no, int) or not isinstance(
                func_node.end_line_no, int
            ):
                continue

            # Check if the line is within the function's range
            if func_node.line_no <= line <= func_node.end_line_no:
                return func_node

        return None

    def find_tainted_vars_in_sink(
        self, visitor: EnhancedTaintAnalysisVisitor, sink_line: int
    ) -> List[str]:
        """包装 data_flow_helpers.find_tainted_vars_in_sink"""
        return data_flow_helpers.find_tainted_vars_in_sink(visitor, sink_line)

    def find_potential_sources(
        self,
        visitor: EnhancedTaintAnalysisVisitor,
        sink_function_node,
        sink_line: int,
        sink_stmt_info: Dict[str, Any],
        sink_function_range,
        same_function_sources: List[Dict[str, Any]],
        other_sources: List[Dict[str, Any]],
        parser_sources: List[Dict[str, Any]],
        added_sources: Set[str],
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
        """包装 data_flow_helpers.find_potential_sources"""
        return data_flow_helpers.find_potential_sources(
            visitor,
            sink_function_node,
            sink_line,
            sink_stmt_info,
            sink_function_range,
            same_function_sources,
            other_sources,
            parser_sources,
            added_sources,
            self.sources,
            debug_enabled=self.debug,
        )

    def find_related_functions(
        self, visitor: EnhancedTaintAnalysisVisitor, sink_name: str
    ) -> List[Any]:
        """
        Find functions related to the given sink.

        Args:
            visitor: Visitor instance
            sink_name: Sink name

        Returns:
            List of related function nodes
        """
        related_functions = []

        # 1. Use sink definitions from the config file to find related function patterns
        related_patterns = []

        # Find patterns related to sink_name in the config file
        sinks = self.tracker.sinks
        for sink in sinks:
            if sink.get("name") == sink_name:
                # First check if there are specific related_patterns
                if "related_patterns" in sink:
                    related_patterns.extend(sink.get("related_patterns", []))
                    if self.debug:
                        debug(
                            f"Found related_patterns in config for {sink_name}: {related_patterns}"
                        )

                # Otherwise, extract keywords from patterns
                for pattern in sink.get("patterns", []):
                    # Extract the base function name part from the pattern
                    if "." in pattern:
                        func_part = pattern.split(".")[-1]
                        related_patterns.append(func_part)
                    elif "(" in pattern:
                        func_part = pattern.split("(")[0]
                        related_patterns.append(func_part)
                    else:
                        related_patterns.append(pattern)
                break

        # If no related patterns found in config, use the sink name itself as a basis
        if not related_patterns:
            # Use words from sink_name as search patterns
            words = re.findall(r"[A-Za-z]+", sink_name)
            for word in words:
                if (
                    len(word) > 3
                ):  # Only use longer words to avoid mismatches from short words
                    related_patterns.append(word.lower())

            if self.debug:
                debug(
                    f"No patterns found in config for {sink_name}, using words: {related_patterns}"
                )

        # 2. Find similar functions through AST analysis
        # First, find functions similar to the pattern names
        for func_name, func_node in visitor.functions.items():
            for pattern in related_patterns:
                # Check if function name contains pattern (case-insensitive)
                if pattern.lower() in func_name.lower():
                    if self.debug:
                        debug(
                            f"Found related function {func_name} matching pattern {pattern}"
                        )
                    related_functions.append(func_node)
                    break

        # 3. Find functions that call similar functions
        call_related_functions = []
        for func_node in list(
            related_functions
        ):  # Use a copy to avoid modifying while iterating
            # Find other functions that call the current function
            for caller in func_node.callers:
                if (
                    caller not in related_functions
                    and caller not in call_related_functions
                ):
                    call_related_functions.append(caller)

        # Merge directly related functions and call-relation related functions
        related_functions.extend(call_related_functions)

        # 4. Limit the number of returned results to avoid excessive length
        return related_functions[:5]
