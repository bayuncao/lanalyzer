"""
Description formatting utilities.

This module consolidates description formatting functionality
for vulnerability reports and analysis output.
"""

from typing import Any, Dict, List, Optional


class DescriptionFormatter:
    """
    Utility class for formatting descriptions and output messages.

    This class consolidates functionality from description_formatter.py
    and other formatting utilities.
    """

    @staticmethod
    def format_source_description(source_name: str, source_line: int) -> str:
        """
        Generate source node description.

        Args:
            source_name: Name of the source
            source_line: Line number of the source

        Returns:
            Formatted source description
        """
        return f"Contains source {source_name} at line {source_line}"

    @staticmethod
    def format_sink_description(
        sink_name: str,
        sink_line: int,
        arg_expressions: Optional[List[str]] = None,
        vulnerability_type: Optional[str] = None,
    ) -> str:
        """
        Generate sink node description.

        Args:
            sink_name: Name of the sink
            sink_line: Line number of the sink
            arg_expressions: Parsed argument expressions (if any)
            vulnerability_type: Vulnerability type description (if any)

        Returns:
            Formatted sink description
        """
        base = f"Contains sink {sink_name} at line {sink_line}"

        if vulnerability_type:
            base = f"Unsafe {sink_name} operation, potentially leading to {vulnerability_type}"

        if arg_expressions:
            base += f". Processing data from: {', '.join(arg_expressions)}"

        return base

    @staticmethod
    def format_vulnerability_description(
        vulnerability: Dict[str, Any], include_details: bool = True
    ) -> str:
        """
        Format a comprehensive vulnerability description.

        Args:
            vulnerability: Vulnerability information dictionary
            include_details: Whether to include detailed information

        Returns:
            Formatted vulnerability description
        """
        vuln_type = vulnerability.get("type", "Unknown")
        severity = vulnerability.get("severity", "Unknown")

        source_info = vulnerability.get("source", {})
        sink_info = vulnerability.get("sink", {})

        source_name = source_info.get("name", "Unknown")
        source_line = source_info.get("line", 0)
        source_file = source_info.get("file", "Unknown")

        sink_name = sink_info.get("name", "Unknown")
        sink_line = sink_info.get("line", 0)
        sink_file = sink_info.get("file", "Unknown")

        # Basic description
        description = f"{vuln_type} ({severity.upper()}): "
        description += f"Tainted data from {source_name} flows to {sink_name}"

        if include_details:
            description += f"\n  - Source: {source_name} at line {source_line}"
            if source_file != "Unknown":
                description += f" in {source_file}"

            description += f"\n  - Sink: {sink_name} at line {sink_line}"
            if sink_file != "Unknown":
                description += f" in {sink_file}"

            tainted_var = vulnerability.get("tainted_variable")
            if tainted_var:
                description += f"\n  - Tainted variable: {tainted_var}"

        return description

    @staticmethod
    def format_call_chain_description(call_chain: List[Dict[str, Any]]) -> str:
        """
        Format a call chain description.

        Args:
            call_chain: List of call chain steps

        Returns:
            Formatted call chain description
        """
        if not call_chain:
            return "No call chain available"

        description = "Call chain:\n"

        for i, step in enumerate(call_chain, 1):
            step_type = step.get("type", "unknown")
            function_name = step.get("function", "unknown")
            line = step.get("line", 0)
            file_path = step.get("file", "")

            # Format step based on type
            if step_type == "source":
                description += f"  {i}. [SOURCE] {function_name}"
            elif step_type == "sink":
                description += f"  {i}. [SINK] {function_name}"
            elif step_type == "data_flow":
                description += f"  {i}. [DATA FLOW] {function_name}"
            elif step_type == "entry_point":
                description += f"  {i}. [ENTRY] {function_name}"
            else:
                description += f"  {i}. {function_name}"

            if line > 0:
                description += f" (line {line})"

            if file_path:
                import os

                filename = os.path.basename(file_path)
                description += f" in {filename}"

            description += "\n"

        return description.rstrip()

    @staticmethod
    def format_analysis_summary(summary: Dict[str, Any]) -> str:
        """
        Format analysis summary information.

        Args:
            summary: Analysis summary dictionary

        Returns:
            Formatted summary string
        """
        lines = ["Analysis Summary:"]

        files_analyzed = summary.get("files_analyzed", 0)
        lines.append(f"  - Files analyzed: {files_analyzed}")

        functions_found = summary.get("functions_found", 0)
        lines.append(f"  - Functions found: {functions_found}")

        sources_found = summary.get("sources_found", 0)
        lines.append(f"  - Sources found: {sources_found}")

        sinks_found = summary.get("sinks_found", 0)
        lines.append(f"  - Sinks found: {sinks_found}")

        vulnerabilities_found = summary.get("vulnerabilities_found", 0)
        lines.append(f"  - Vulnerabilities found: {vulnerabilities_found}")

        tainted_variables = summary.get("tainted_variables", 0)
        lines.append(f"  - Tainted variables: {tainted_variables}")

        return "\n".join(lines)

    @staticmethod
    def format_function_signature(func_info: Dict[str, Any]) -> str:
        """
        Format a function signature for display.

        Args:
            func_info: Function information dictionary

        Returns:
            Formatted function signature
        """
        name = func_info.get("name", "unknown")
        args = func_info.get("args", [])

        if args:
            return f"{name}({', '.join(args)})"
        else:
            return f"{name}()"

    @staticmethod
    def format_location_info(
        file_path: str, line: int, col: Optional[int] = None
    ) -> str:
        """
        Format location information for display.

        Args:
            file_path: File path
            line: Line number
            col: Column number (optional)

        Returns:
            Formatted location string
        """
        import os

        filename = os.path.basename(file_path) if file_path else "unknown"

        location = f"{filename}:{line}"
        if col is not None and col > 0:
            location += f":{col}"

        return location

    @staticmethod
    def format_code_context(
        source_lines: List[str], target_line: int, context_lines: int = 2
    ) -> str:
        """
        Format code context around a target line.

        Args:
            source_lines: List of source code lines
            target_line: Target line number (1-based)
            context_lines: Number of context lines to include

        Returns:
            Formatted code context
        """
        if not source_lines or target_line <= 0 or target_line > len(source_lines):
            return "No code context available"

        start_line = max(1, target_line - context_lines)
        end_line = min(len(source_lines), target_line + context_lines)

        lines = []
        for i in range(start_line, end_line + 1):
            line_content = source_lines[i - 1].rstrip()
            marker = ">>> " if i == target_line else "    "
            lines.append(f"{marker}{i:3d}: {line_content}")

        return "\n".join(lines)

    @staticmethod
    def format_severity_badge(severity: str) -> str:
        """
        Format severity level with appropriate styling markers.

        Args:
            severity: Severity level string

        Returns:
            Formatted severity badge
        """
        severity_upper = severity.upper()

        if severity_upper == "HIGH":
            return f"🔴 {severity_upper}"
        elif severity_upper == "MEDIUM":
            return f"🟡 {severity_upper}"
        elif severity_upper == "LOW":
            return f"🟢 {severity_upper}"
        else:
            return f"⚪ {severity_upper}"
