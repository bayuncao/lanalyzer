"""
Utility functions for taint analysis.
"""

import re
from typing import Any, Dict, List, Set, Tuple, Optional

from lanalyzer.analysis.visitor import EnhancedTaintAnalysisVisitor
from lanalyzer.logger import debug


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
        """
        Extract the statement at the given line with optional context lines.

        Args:
            visitor: The visitor instance
            line: The line number to extract
            context_lines: Number of lines of context to include before and after

        Returns:
            Dictionary with statement text and context information
        """
        if not hasattr(visitor, "source_lines") or not visitor.source_lines:
            return {"statement": "", "context_start": line, "context_end": line}

        if line <= 0 or line > len(visitor.source_lines):
            return {"statement": "", "context_start": line, "context_end": line}

        # Extract main statement
        statement = visitor.source_lines[line - 1].strip()

        # Determine context range
        start_line = max(1, line - context_lines)
        end_line = min(len(visitor.source_lines), line + context_lines)

        # Extract context if requested
        context = []
        if context_lines > 0:
            for i in range(start_line, end_line + 1):
                if i == line:
                    # Mark the actual statement line (could be used for highlighting)
                    context.append(f"{i}: {visitor.source_lines[i-1].rstrip()}")
                else:
                    context.append(f"{i}: {visitor.source_lines[i-1].rstrip()}")

        return {
            "statement": statement,
            "context_lines": context if context_lines > 0 else None,
            "context_start": start_line,
            "context_end": end_line,
        }

    def extract_operation_at_line(
        self, visitor: EnhancedTaintAnalysisVisitor, line: int
    ) -> Optional[str]:
        """
        Attempt to extract the actual operation name for the specified line.

        Args:
            visitor: Visitor instance
            line: Line number

        Returns:
            Operation name, or None if not found
        """
        # Check if raw source code is available
        if not hasattr(visitor, "source_lines") or not visitor.source_lines:
            if self.debug:
                debug(
                    f"[Warning] Visitor lacks source_lines attribute or it is empty, cannot extract operation for line {line}"
                )
            return None

        # Ensure line number is within valid range
        if line <= 0 or line > len(visitor.source_lines):
            if self.debug:
                debug(
                    f"[Warning] Line number {line} is out of range (1-{len(visitor.source_lines)})"
                )
            return None

        # Get line content
        line_content = visitor.source_lines[line - 1].strip()

        # More detailed extraction of the operation by checking full statement
        if "=" in line_content:
            # Handle assignment cases: extract the right side of the assignment
            operation = line_content.split("=", 1)[1].strip()
        else:
            # For non-assignment statements, use the full statement
            operation = line_content

        # Clean up the operation string
        # Remove trailing semicolons, comments, etc.
        operation = re.sub(r"[;].*$", "", operation)
        operation = re.sub(r"#.*$", "", operation)
        operation = operation.strip()

        # Get dangerous patterns from config or use defaults
        dangerous_patterns = {}

        # Try to get from the tracker's config
        if hasattr(self.tracker, "config") and isinstance(self.tracker.config, dict):
            if "dangerous_patterns" in self.tracker.config:
                dangerous_patterns = self.tracker.config["dangerous_patterns"]

        # Attempt to find matching dangerous patterns
        sink_type = None
        matched_pattern = None

        for sink_name, patterns in dangerous_patterns.items():
            for pattern in patterns:
                if pattern in operation:
                    sink_type = sink_name
                    matched_pattern = pattern
                    break
            if sink_type:
                break

        if sink_type and matched_pattern:
            # Return the exact operation instead of just the pattern
            return operation

        # If no dangerous pattern found but operation is not empty, return the operation
        if operation:
            return operation

        return None

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
        """
        Find tainted variables used in the sink statement.

        Args:
            visitor: Visitor instance
            sink_line: Sink statement line number

        Returns:
            List of tainted variable names used in the sink
        """
        tainted_vars = []

        # Check if visitor has source code lines
        if not hasattr(visitor, "source_lines") or not visitor.source_lines:
            return tainted_vars

        # Get sink line source code
        if sink_line <= 0 or sink_line > len(visitor.source_lines):
            return tainted_vars

        sink_code = visitor.source_lines[sink_line - 1]

        # Extract variable names
        if hasattr(visitor, "tainted"):
            # Check each tainted variable if used in sink code
            for var_name in visitor.tainted:
                # Variable name must have non-alphanumeric char or be at start/end,
                # to avoid partial matching (e.g. avoid matching "a" in "abc")
                pattern = r"(^|[^\w])" + re.escape(var_name) + r"([^\w]|$)"
                if re.search(pattern, sink_code):
                    tainted_vars.append(var_name)
                    if self.debug:
                        debug(
                            f"[DEBUG] Found tainted variable {var_name} used in sink at line {sink_line}"
                        )

        return tainted_vars

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
        """
        Find potential source statements for a sink.

        Args:
            visitor: Visitor instance
            sink_function_node: Function node containing the sink
            sink_line: Line number of the sink
            sink_stmt_info: Information about the sink statement
            sink_function_range: Line range of the function containing the sink
            same_function_sources: List to store sources in the same function
            other_sources: List to store sources in other functions
            parser_sources: List to store command line argument sources
            added_sources: Set for tracking already added sources

        Returns:
            Tuple of (same_function_sources, other_sources, parser_sources)
        """
        # Step 6: Search for possible source statements within function, prioritize same function
        found_source_in_function = len(same_function_sources) > 0
        if (
            not found_source_in_function
            and sink_function_node
            and hasattr(visitor, "source_lines")
        ):
            # Collect all source patterns from config, prioritizing high priority sources (like NetworkInput)
            source_patterns = []
            high_priority_patterns = []

            for source_config in self.sources:
                patterns = source_config.get("patterns", [])
                source_name = source_config.get("name", "UnknownSource")
                priority = source_config.get("priority", "normal")

                # Collect high priority source patterns separately
                if priority == "high":
                    for pattern in patterns:
                        high_priority_patterns.append((pattern, source_name))
                else:
                    for pattern in patterns:
                        source_patterns.append((pattern, source_name))

            # Priority sorting: check high priority patterns first
            all_sorted_patterns = high_priority_patterns + source_patterns

            # Search for potential sources in function
            if sink_function_range:
                start_line, end_line = sink_function_range
                # Create list for potential sources
                potential_sources = []

                # Search for potential source statements in function
                for line_idx in range(
                    start_line, min(end_line, len(visitor.source_lines))
                ):
                    if line_idx == sink_line:
                        continue  # Skip the sink line

                    line = (
                        visitor.source_lines[line_idx - 1]
                        if line_idx > 0 and line_idx <= len(visitor.source_lines)
                        else ""
                    )
                    if not line:
                        continue

                    # Check if line contains source patterns from config
                    for pattern, source_name in all_sorted_patterns:
                        # Convert wildcard patterns to regex
                        if "*" in pattern:
                            pattern_regex = pattern.replace(".", "\\.").replace(
                                "*", ".*"
                            )
                            pattern_match = re.search(pattern_regex, line)
                            matches = bool(pattern_match)
                        else:
                            matches = pattern in line

                        if matches:
                            # Check if this is a variable assignment
                            if "=" in line and line.index("=") < line.find(pattern):
                                var_name = line.split("=")[0].strip()
                                # Check if sink statement uses this variable
                                sink_stmt = sink_stmt_info["statement"]
                                if var_name in sink_stmt:
                                    potential_sources.append(
                                        {
                                            "line": line_idx,
                                            "statement": line.strip(),
                                            "var": var_name,
                                            "in_same_function": True,
                                            "source_name": source_name,
                                            "pattern": pattern,
                                        }
                                    )
                                    break  # Found a match, exit inner loop

                # If sources found in same function, add to call chain
                if potential_sources:
                    # Sort by line number, prioritize sources closest to but before sink
                    potential_sources.sort(
                        key=lambda x: sink_line - x["line"]
                        if x["line"] < sink_line
                        else float("inf")
                    )
                    for src in potential_sources:
                        if src["line"] < sink_line:  # Prioritize sources before sink
                            source_stmt = {
                                "function": f"{src['var']} = {src['statement'].split('=')[1].strip()}"
                                if "=" in src["statement"]
                                else src["statement"],
                                "file": visitor.file_path,
                                "line": src["line"],
                                "statement": src["statement"],
                                "context_lines": [src["line"] - 1, src["line"] + 1],
                                "type": "source",
                                "description": f"Source of tainted data ({src['source_name']}) assigned to variable {src['var']}",
                            }

                            # Deduplication
                            source_key = f"{src['line']}:{source_stmt['statement']}"
                            if source_key not in added_sources:
                                added_sources.add(source_key)
                                same_function_sources.append(source_stmt)
                                found_source_in_function = True
                                if self.debug:
                                    debug(
                                        f"[DEBUG] Found source using pattern '{src['pattern']}' at line {src['line']}"
                                    )

        # Step 7: If no sources found in same function, search all potential sources
        if not found_source_in_function and hasattr(visitor, "var_assignments"):
            self._search_all_potential_sources(
                visitor,
                sink_function_range,
                sink_line,
                added_sources,
                same_function_sources,
                other_sources,
                parser_sources,
            )

        return same_function_sources, other_sources, parser_sources

    def _search_all_potential_sources(
        self,
        visitor: EnhancedTaintAnalysisVisitor,
        sink_function_range,
        sink_line: int,
        added_sources: Set[str],
        same_function_sources: List[Dict[str, Any]],
        other_sources: List[Dict[str, Any]],
        parser_sources: List[Dict[str, Any]],
    ) -> None:
        """
        Search all potential sources in the code.

        Args:
            visitor: Visitor instance
            sink_function_range: Line range of function containing sink
            sink_line: Line number of sink
            added_sources: Set of already added sources
            same_function_sources: List of sources in same function
            other_sources: List of sources in other functions
            parser_sources: List of command line argument sources
        """
        potential_sources = []

        # Get source types and patterns from config
        source_type_patterns = {}
        for source_config in self.sources:
            source_name = source_config.get("name", "UnknownSource")
            patterns = source_config.get("patterns", [])
            for pattern in patterns:
                source_type_patterns[pattern] = source_name

        # Check all variable assignments for potential sources
        for var_name, assign_info in visitor.var_assignments.items():
            if "line" in assign_info:
                # Skip if already found a source at this line
                line_no = assign_info["line"]
                if any(
                    source["line"] == line_no
                    for source in same_function_sources + other_sources
                ):
                    continue

                stmt = self.get_statement_at_line(visitor, line_no)["statement"]

                # Check if matches any source pattern from config
                matched_source_type = None
                matched_pattern = None

                for pattern, source_type in source_type_patterns.items():
                    # Handle wildcards
                    if "*" in pattern:
                        pattern_regex = pattern.replace(".", "\\.").replace("*", ".*")
                        if re.search(pattern_regex, stmt):
                            matched_source_type = source_type
                            matched_pattern = pattern
                            break
                    elif pattern in stmt:
                        matched_source_type = source_type
                        matched_pattern = pattern
                        break

                if matched_source_type:
                    # Check if in same function
                    in_same_function = False
                    if (
                        sink_function_range
                        and sink_function_range[0] <= line_no <= sink_function_range[1]
                    ):
                        in_same_function = True

                    is_command_line = "CommandLineArgs" in matched_source_type

                    potential_sources.append(
                        {
                            "var": var_name,
                            "line": line_no,
                            "statement": stmt,
                            "in_same_function": in_same_function,
                            "is_parser": is_command_line,
                            "source_name": matched_source_type,
                            "pattern": matched_pattern,
                        }
                    )

        # Add potential sources, prioritizing those in same function
        if potential_sources:
            # Sort first by same function flag, then by distance to sink
            potential_sources.sort(
                key=lambda x: (
                    not x.get("in_same_function", False),
                    abs(x["line"] - sink_line),
                )
            )

            # Categorize potential sources
            for src in potential_sources:
                # Deduplication
                source_key = f"{src['line']}:{src['statement']}"
                if source_key in added_sources:
                    continue

                source_stmt = {
                    "function": f"{src['var'] if 'var' in src else ''} = {src['statement'].split('=')[1].strip()}"
                    if "=" in src["statement"]
                    else src["statement"],
                    "file": visitor.file_path,
                    "line": src["line"],
                    "statement": src["statement"],
                    "context_lines": [src["line"] - 1, src["line"] + 1],
                    "type": "source",
                    "description": f"Source of tainted data ({src.get('source_name', 'Unknown')}) assigned to variable {src['var']}",
                }

                added_sources.add(source_key)

                if src.get("is_parser", False):
                    parser_sources.append(source_stmt)
                elif src.get("in_same_function", False):
                    same_function_sources.append(source_stmt)
                else:
                    other_sources.append(source_stmt)

                if self.debug:
                    debug(
                        f"[DEBUG] Found source using pattern '{src.get('pattern', 'unknown')}' at line {src['line']}"
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
