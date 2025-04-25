"""
Call chain builder for taint analysis.
This module provides functionality for building function call chains.
"""

import re
from typing import Any, Dict, List, Set, Optional

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

    def get_detailed_call_chain(
        self,
        sink: Dict[str, Any],
        visitor: EnhancedTaintAnalysisVisitor,
        source_info: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Get the detailed function call chain from source to sink.

        Args:
            sink: Sink dictionary
            visitor: EnhancedTaintAnalysisVisitor instance
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

        # 1. Find function containing the source
        source_func = None
        for func_name, func_node in visitor.functions.items():
            if func_node.line_no <= source_line <= func_node.end_line_no:
                source_func = func_node
                break

        # 2. Find function containing the sink
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

        # 3. First add the specific sink statement with detailed information
        sink_operation = self.tracker.utils.extract_operation_at_line(
            visitor, sink_line
        )
        if sink_operation:
            sink_stmt = {
                "function": sink_operation,
                "file": visitor.file_path,
                "line": sink_line,
                "statement": sink_stmt_info["statement"],
                "context_lines": [sink_line - 1, sink_line + 1],
                "type": "sink",
                "description": f"Unsafe {sink_name} operation, potentially leading to vulnerability",
            }
            call_chain.append(sink_stmt)

        # 4. Next add the specific source statement with detailed information
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

        # 5. If source and sink are in the same function, return detailed info
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
            return call_chain

        # 6. Build the complete call chain from source to sink
        if source_func and sink_func:
            # Use Breadth-First Search (BFS) to find the path from source function to sink function
            queue = [(source_func, [source_func])]  # (current_node, path)
            visited = {source_func.name}
            max_depth = 20  # Prevent overly deep search
            found_path = None

            while queue and not found_path:
                current, path = queue.pop(0)

                # Check callees of the current node
                for callee in current.callees:
                    if callee.name == sink_func.name:
                        # Path found
                        found_path = path + [sink_func]
                        break

                    if callee.name not in visited and len(path) < max_depth:
                        visited.add(callee.name)
                        queue.append((callee, path + [callee]))

            # If path found, build the call chain with function and statement info
            if found_path:
                for i, func in enumerate(found_path):
                    # Determine node type
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

                    # Find a representative line number for this function where it's called
                    line_num = func.line_no

                    # Try to find the actual call statement if this is an intermediate function
                    call_statement = ""

                    if i > 0 and i < len(found_path) - 1:
                        # This is an intermediate function - try to find where it's called
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

                return call_chain

            # If direct path not found, try finding common callers...
            if not found_path and self.debug:
                print("No direct path found, trying to find common callers...")

            # Try to find common callers path
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

        # 7. If full call chain cannot be built, but source or sink function exists, add them
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

        return call_chain

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
        # Build reverse call graph (from callee to caller)
        reverse_call_graph = {}
        for func_name, func_node in visitor.functions.items():
            reverse_call_graph[func_name] = []

        for func_name, func_node in visitor.functions.items():
            for callee in func_node.callees:
                if callee.name not in reverse_call_graph:
                    reverse_call_graph[callee.name] = []
                reverse_call_graph[callee.name].append(func_name)

        # Use BFS to find common callers of source and sink functions
        source_callers = self._find_callers(source_func.name, reverse_call_graph, 20)
        sink_callers = self._find_callers(sink_func.name, reverse_call_graph, 20)

        common_callers = source_callers.intersection(sink_callers)

        if common_callers and self.debug:
            print(f"Found common callers: {common_callers}")

        # If common callers found, build path
        if common_callers:
            # Select a common caller
            common_caller = next(iter(common_callers))
            common_caller_node = None

            for func_name, func_node in visitor.functions.items():
                if func_name == common_caller:
                    common_caller_node = func_node
                    break

            if common_caller_node:
                # Try to extract call statements for both source and sink functions
                source_call_stmt = ""
                sink_call_stmt = ""

                for callee in common_caller_node.callees:
                    if callee.name == source_func.name and hasattr(callee, "call_line"):
                        source_call_stmt = self.tracker.utils.get_statement_at_line(
                            visitor, callee.call_line
                        )["statement"]
                    elif callee.name == sink_func.name and hasattr(callee, "call_line"):
                        sink_call_stmt = self.tracker.utils.get_statement_at_line(
                            visitor, callee.call_line
                        )["statement"]

                # Source function -> Common caller -> Sink function
                call_chain = [
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
                        "description": f"Contains source {source_name} at line {source_line}",
                    },
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
                            },
                            {
                                "function": sink_func.name,
                                "statement": sink_call_stmt,
                            },
                        ],
                    },
                    {
                        "function": sink_func.name,
                        "file": sink_func.file_path,
                        "line": sink_func.line_no,
                        "statement": sink_stmt_info["statement"],
                        "context_lines": [sink_func.line_no, sink_func.end_line_no],
                        "type": "sink",
                        "description": f"Contains sink {sink_name} at line {sink_line}",
                    },
                ]
                return call_chain

        return []

    def _find_callers(
        self, func_name: str, reverse_call_graph: Dict[str, List[str]], max_depth: int
    ) -> Set[str]:
        """
        Use BFS to find all functions that call the specified function.

        Args:
            func_name: Name of the function to find callers for
            reverse_call_graph: Reverse call graph
            max_depth: Maximum search depth

        Returns:
            Set of function names that call this function
        """
        callers = set()
        visited = {func_name}
        queue = [(func_name, 0)]  # (function_name, depth)

        while queue:
            current, depth = queue.pop(0)

            if depth >= max_depth:
                continue

            # Get all callers of the current function
            current_callers = reverse_call_graph.get(current, [])

            for caller in current_callers:
                callers.add(caller)

                if caller not in visited:
                    visited.add(caller)
                    queue.append((caller, depth + 1))

        return callers

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
        # Set for deduplication
        added_sources = (
            set()
        )  # Tracks already added sources, format is "line:statement"

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

        # Step 1: Get the exact statement at the sink line
        sink_stmt_info = self.tracker.utils.get_statement_at_line(
            visitor, sink_line, context_lines=2
        )

        # Step 2: Find the direct sink operation (the actual dangerous call)
        sink_operation = self.tracker.utils.extract_operation_at_line(
            visitor, sink_line
        )
        sink_entry = None
        if sink_operation:
            # If direct operation is found, create sink entry (but don't add to chain yet)
            sink_entry = {
                "function": sink_operation,
                "file": visitor.file_path,
                "line": sink_line,
                "statement": sink_stmt_info["statement"],
                "context_lines": [sink_line - 2, sink_line + 2]
                if sink_line > 2
                else [1, sink_line + 2],
                "type": "sink",
                "description": f"Unsafe {sink_name} operation, potentially leading to {vulnerability_type}",
            }

        # Step 3: Find function containing the sink
        sink_function_node = self.tracker.utils.find_function_containing_line(
            visitor, sink_line
        )

        # Record function range where sink is located for prioritizing sources within same function
        sink_function_range = None
        if sink_function_node:
            sink_function_range = (
                sink_function_node.line_no,
                sink_function_node.end_line_no,
            )

        # Create container function info, but don't add to chain yet
        sink_container_entry = None
        if sink_function_node:
            file_path = getattr(sink_function_node, "file_path", visitor.file_path)

            # Find where this function is defined (to provide context)
            func_def_start = sink_function_node.line_no
            func_def_end = getattr(
                sink_function_node, "end_line_no", func_def_start + 1
            )

            # Try to get the function definition statement
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

        # Step 4: Try to find tainted variables used in the sink
        tainted_vars_in_sink = self.tracker.utils.find_tainted_vars_in_sink(
            visitor, sink_line
        )

        # Categorize sources by location
        same_function_sources = []  # Sources in the same function
        other_sources = []  # Sources in other functions
        parser_sources = []  # Command line argument sources

        # Step 5: If we found tainted variables, try to find their source statements
        if (
            tainted_vars_in_sink
            and hasattr(visitor, "tainted")
            and hasattr(visitor, "source_statements")
        ):
            for var_name in tainted_vars_in_sink:
                # Check if variable is tainted and has source info
                if var_name in visitor.tainted:
                    source_info = visitor.tainted.get(var_name)
                    if source_info and "line" in source_info:
                        source_line = source_info.get("line", 0)
                        source_name = source_info.get("name", "Unknown")

                        # Get detailed source statement information
                        if source_line > 0:
                            source_stmt_info = self.tracker.utils.get_statement_at_line(
                                visitor, source_line, context_lines=1
                            )
                            source_operation = (
                                self.tracker.utils.extract_operation_at_line(
                                    visitor, source_line
                                )
                            )

                            # Create source statement info
                            source_stmt = {
                                "function": source_operation or f"Source of {var_name}",
                                "file": visitor.file_path,
                                "line": source_line,
                                "statement": source_info.get(
                                    "statement", source_stmt_info["statement"]
                                ),
                                "context_lines": [source_line - 1, source_line + 1],
                                "type": "source",
                                "description": f"Source of tainted data ({source_name}) assigned to variable {var_name}",
                            }

                            # Deduplication
                            source_key = f"{source_line}:{source_stmt['statement']}"
                            if source_key not in added_sources:
                                added_sources.add(source_key)

                                # Determine if source is in the same function as sink
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

        # Step 6: Search for possible source statements within function, prioritize same function
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

        # Build final call chain in priority order
        final_call_chain = []

        # 1. Sources within same function (highest priority)
        for entry in same_function_sources:
            final_call_chain.append(entry)

        # 2. Command line argument sources
        for entry in parser_sources:
            final_call_chain.append(entry)

        # 3. Sources from other functions (only if no sources in same function)
        if not same_function_sources:
            for entry in other_sources:
                final_call_chain.append(entry)

        # 4. Container function
        if sink_container_entry:
            final_call_chain.append(sink_container_entry)

        # 5. Sink
        if sink_entry:
            final_call_chain.append(sink_entry)

        # For source entries of same type, sort by line number
        if len(same_function_sources) > 1:
            # Sort in-function sources by distance to sink (near→far)
            same_function_sources_sorted = sorted(
                same_function_sources, key=lambda x: abs(x["line"] - sink_line)
            )

            # Remove previously added same function sources
            final_call_chain = [
                e for e in final_call_chain if e not in same_function_sources
            ]

            # Insert sorted same function sources at beginning of call chain
            for entry in reversed(same_function_sources_sorted):
                final_call_chain.insert(0, entry)

        if self.debug:
            print(f"[DEBUG] Built call chain with {len(final_call_chain)} nodes")
            source_count = len([e for e in final_call_chain if e["type"] == "source"])
            print(f"[DEBUG] Sources in call chain: {source_count}")

        return final_call_chain
