"""
Common utility functions for analysis.

This module consolidates various helper functions that were previously
scattered across multiple files.
"""

import re
from typing import Any, Dict, List, Optional, Set

from lanalyzer.logger import debug


class AnalysisHelpers:
    """
    Collection of utility functions for analysis operations.

    This class consolidates functionality from ast_helpers.py, utils.py,
    and other utility modules into a single, coherent interface.
    """

    def __init__(self, debug_mode: bool = False):
        self.debug = debug_mode

    def get_statement_at_line(
        self, source_lines: List[str], line: int, context_lines: int = 0
    ) -> Dict[str, Any]:
        """
        Extract statement at specified line with optional context.

        Args:
            source_lines: List of source code lines
            line: Target line number (1-based)
            context_lines: Number of context lines to include

        Returns:
            Dictionary containing statement and context information
        """
        if line <= 0 or line > len(source_lines):
            return {"statement": "", "context_start": line, "context_end": line}

        statement = source_lines[line - 1].strip()
        start_line = max(1, line - context_lines)
        end_line = min(len(source_lines), line + context_lines)

        context = None
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
        self,
        source_lines: List[str],
        line: int,
        dangerous_patterns: Optional[Dict[str, List[str]]] = None,
    ) -> Optional[str]:
        """
        Extract operation string at specified line for pattern matching.

        Args:
            source_lines: List of source code lines
            line: Target line number (1-based)
            dangerous_patterns: Dictionary of dangerous patterns to match

        Returns:
            Operation string if found, None otherwise
        """
        if line <= 0 or line > len(source_lines):
            if self.debug:
                debug(f"[AnalysisHelpers] Line {line} out of range.")
            return None

        line_content = source_lines[line - 1].strip()

        # Extract right-hand side of assignment or full line
        operation = (
            line_content.split("=", 1)[1].strip()
            if "=" in line_content
            else line_content
        )

        # Clean up comments and semicolons
        operation = re.sub(r"[;].*$", "", operation)
        operation = re.sub(r"#.*$", "", operation).strip()

        if dangerous_patterns:
            for sink_name, patterns in dangerous_patterns.items():
                for pattern in patterns:
                    if pattern in operation:
                        return operation

        return operation or None

    def find_function_containing_line(
        self, functions: Dict[str, Any], line: int
    ) -> Optional[Dict[str, Any]]:
        """
        Find the function that contains the given line number.

        Args:
            functions: Dictionary of function information
            line: Line number to search for

        Returns:
            Function information dictionary, or None if not found
        """
        for func_name, func_info in functions.items():
            func_line = func_info.get("line", 0)
            func_end_line = func_info.get("end_line", func_line + 100)  # Rough estimate

            if func_line <= line <= func_end_line:
                return func_info

        # If no function found, assume it's in global scope
        return {"name": "__main__", "line": 1, "args": []}

    def extract_variable_names_from_args(self, sink_args: List[str]) -> Set[str]:
        """
        Extract variable names from sink argument expressions.

        Args:
            sink_args: List of argument expressions

        Returns:
            Set of variable names found in arguments
        """
        var_names = set()

        for arg in sink_args:
            # Simple regex to find variable names
            # This is a simplified approach - a full implementation would use AST
            matches = re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", arg)
            var_names.update(matches)

        return var_names

    def is_variable_used_in_expression(self, var_name: str, expression: str) -> bool:
        """
        Check if a variable is used in an expression.

        Args:
            var_name: Variable name to check
            expression: Expression string

        Returns:
            True if variable is used in expression
        """
        # Use word boundaries to avoid partial matches
        pattern = r"\b" + re.escape(var_name) + r"\b"
        return bool(re.search(pattern, expression))

    def build_variable_usage_map(
        self, var_assignments: Dict[str, List[Dict[str, Any]]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Build a mapping of variable usage throughout the code.

        Args:
            var_assignments: Dictionary of variable assignments

        Returns:
            Processed usage mapping
        """
        usage_map = {}

        for var_name, assignments in var_assignments.items():
            # Sort assignments by line number
            sorted_assignments = sorted(assignments, key=lambda x: x.get("line", 0))
            usage_map[var_name] = sorted_assignments

        return usage_map

    def find_relevant_assignments(
        self,
        var_name: str,
        source_line: int,
        sink_line: int,
        usage_map: Dict[str, List[Dict[str, Any]]],
    ) -> List[Dict[str, Any]]:
        """
        Find variable assignments relevant to data flow between source and sink.

        Args:
            var_name: Variable name
            source_line: Source line number
            sink_line: Sink line number
            usage_map: Variable usage mapping

        Returns:
            List of relevant assignment information
        """
        relevant_assignments = []

        if var_name in usage_map:
            for assignment in usage_map[var_name]:
                assign_line = assignment.get("line", 0)

                # Only consider assignments between source and sink
                if source_line < assign_line < sink_line:
                    relevant_assignments.append(assignment)

        return relevant_assignments

    def deduplicate_vulnerabilities(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Remove duplicate vulnerabilities from the list.

        Args:
            vulnerabilities: List of vulnerability dictionaries

        Returns:
            Deduplicated list of vulnerabilities
        """
        seen = set()
        unique_vulnerabilities = []

        for vuln in vulnerabilities:
            # Create a hashable representation
            key_parts = [
                vuln.get("type", ""),
                str(vuln.get("source", {}).get("line", 0)),
                str(vuln.get("sink", {}).get("line", 0)),
                vuln.get("tainted_variable", ""),
            ]
            key = "|".join(key_parts)

            if key not in seen:
                seen.add(key)
                unique_vulnerabilities.append(vuln)

        return unique_vulnerabilities

    def merge_analysis_results(
        self, results_list: List[List[Dict[str, Any]]]
    ) -> List[Dict[str, Any]]:
        """
        Merge multiple analysis results into a single list.

        Args:
            results_list: List of analysis result lists

        Returns:
            Merged and deduplicated results
        """
        all_results = []

        for results in results_list:
            all_results.extend(results)

        return self.deduplicate_vulnerabilities(all_results)

    def calculate_severity(self, vulnerability: Dict[str, Any]) -> str:
        """
        Calculate severity level for a vulnerability.

        Args:
            vulnerability: Vulnerability information

        Returns:
            Severity level string
        """
        vuln_type = vulnerability.get("type", "").lower()

        # High severity vulnerabilities
        high_severity_types = [
            "code_execution",
            "sql_injection",
            "command_injection",
            "path_traversal",
            "deserialization",
        ]

        # Medium severity vulnerabilities
        medium_severity_types = ["xss", "open_redirect", "information_disclosure"]

        if any(high_type in vuln_type for high_type in high_severity_types):
            return "High"
        elif any(med_type in vuln_type for med_type in medium_severity_types):
            return "Medium"
        else:
            return "Low"
