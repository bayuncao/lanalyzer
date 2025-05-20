"""
Explanation MCP handler for Lanalyzer.

This module implements the explanation handlers for MCP requests to Lanalyzer.
"""

import os
import json
import logging
from typing import Dict, List, Any

from ..models import (
    ExplainVulnerabilityRequest,
    ExplainVulnerabilityResponse,
)
from .base import BaseMCPHandler

logger = logging.getLogger(__name__)


class ExplanationMCPHandler(BaseMCPHandler):
    """Handles MCP protocol explanation requests for Lanalyzer."""

    async def explain_vulnerabilities(
        self, request: ExplainVulnerabilityRequest
    ) -> ExplainVulnerabilityResponse:
        """
        Explain vulnerability analysis results, generating natural language descriptions.

        Args:
            request: ExplainVulnerabilityRequest request object

        Returns:
            ExplainVulnerabilityResponse: Explanation response
        """
        try:
            analysis_file = request.analysis_file
            if not os.path.exists(analysis_file):
                return ExplainVulnerabilityResponse(
                    success=False,
                    errors=[f"Analysis results file not found: {analysis_file}"],
                )

            # Read analysis results
            with open(analysis_file, "r", encoding="utf-8") as f:
                # Assuming the file contains the direct list of vulnerabilities
                # or a structure like {"vulnerabilities": [...]}
                raw_data = json.load(f)
                vulnerabilities_list = []
                if isinstance(raw_data, list):
                    vulnerabilities_list = raw_data
                elif isinstance(raw_data, dict) and "vulnerabilities" in raw_data:
                    vulnerabilities_list = raw_data["vulnerabilities"]
                else:
                    # Try to infer if it's a single vulnerability object not in a list
                    if (
                        isinstance(raw_data, dict) and "rule" in raw_data
                    ):  # Simple check
                        vulnerabilities_list = [raw_data]
                    else:
                        logger.error(
                            f"Unexpected format in analysis results file: {analysis_file}"
                        )
                        return ExplainVulnerabilityResponse(
                            success=False,
                            errors=[
                                f"Unexpected format in analysis results file: {analysis_file}. Expected a list of vulnerabilities or a dict with a 'vulnerabilities' key."
                            ],
                        )

            if not vulnerabilities_list:
                return ExplainVulnerabilityResponse(
                    success=True,
                    explanation="No security vulnerabilities found in the provided report.",
                    vulnerabilities_count=0,
                    files_affected=[],
                )

            # Extract affected files
            files_affected = sorted(
                list(
                    set(
                        v.get("file", v.get("file_path", ""))
                        for v in vulnerabilities_list
                        if v.get("file", v.get("file_path", ""))
                    )
                )
            )

            # Create explanation text
            if request.format == "markdown":
                explanation = self._generate_markdown_explanation(
                    vulnerabilities_list, request.level
                )
            else:
                explanation = self._generate_text_explanation(
                    vulnerabilities_list, request.level
                )

            return ExplainVulnerabilityResponse(
                success=True,
                explanation=explanation,
                vulnerabilities_count=len(vulnerabilities_list),
                files_affected=files_affected,
            )

        except json.JSONDecodeError as e:
            logger.exception(
                f"Error decoding JSON from analysis file {analysis_file}: {e}"
            )
            return ExplainVulnerabilityResponse(
                success=False,
                errors=[
                    f"Error decoding JSON from analysis file {analysis_file}: {str(e)}"
                ],
            )
        except Exception as e:
            logger.exception(f"Error explaining vulnerabilities: {e}")
            return ExplainVulnerabilityResponse(
                success=False,
                errors=[f"Failed to explain vulnerabilities: {str(e)}"],
            )

    def _generate_text_explanation(
        self, vulnerabilities: List[Dict[str, Any]], level: str
    ) -> str:
        """
        Generate text format vulnerability explanation.

        Args:
            vulnerabilities: List of vulnerabilities
            level: Detail level, "brief" or "detailed"

        Returns:
            str: Text format vulnerability explanation
        """
        if not vulnerabilities:
            return "No security vulnerabilities found."

        files_affected = sorted(
            list(
                set(
                    v.get("file", v.get("file_path", "Unknown File"))
                    for v in vulnerabilities
                    if v.get("file", v.get("file_path"))
                )
            )
        )

        explanation = [
            "Security Vulnerability Analysis Report",
            "====================================",
            f"Found {len(vulnerabilities)} potential security vulnerabilities, affecting {len(files_affected)} file(s).",
        ]

        # Group vulnerabilities by file
        vulns_by_file: Dict[str, List[Dict[str, Any]]] = {}
        for vuln in vulnerabilities:
            file_key = vuln.get("file", vuln.get("file_path", "Unknown File"))
            if file_key not in vulns_by_file:
                vulns_by_file[file_key] = []
            vulns_by_file[file_key].append(vuln)

        # Generate report per file
        for file_path_key, file_vulns in vulns_by_file.items():
            explanation.append(f"File: {file_path_key}")
            explanation.append(f"{'-' * (len(file_path_key) + 6)}")

            for i, vuln in enumerate(file_vulns, 1):
                rule_name = vuln.get(
                    "rule_name", vuln.get("rule", "Unknown Vulnerability Type")
                )
                severity = vuln.get("severity", "Unknown")
                sink_info = vuln.get("sink", {})
                line_no = sink_info.get("location", {}).get(
                    "line", sink_info.get("line", "Unknown")
                )
                message = vuln.get(
                    "message", vuln.get("description", "No description provided.")
                )

                explanation.append(f"Vulnerability #{i}: {rule_name}")
                explanation.append(f"  Severity: {severity}")
                explanation.append(f"  Location: Line {line_no}")
                explanation.append(f"  Description: {message}")

                if level == "detailed":
                    # Add call chain information
                    call_chain = vuln.get("call_chain", [])
                    if call_chain:
                        explanation.append("  Call Chain:")
                        for j, call in enumerate(call_chain, 1):
                            func = call.get(
                                "function_name",
                                call.get("function", "Unknown Function"),
                            )
                            call_line = call.get(
                                "line_number", call.get("line", "Unknown")
                            )
                            call_type = call.get("type", "Unknown Type")
                            call_desc = call.get("description", "")

                            explanation.append(
                                f"    {j}. [{call_type.capitalize()}] {func} (Line {call_line})"
                            )
                            if call_desc:
                                explanation.append(f"       {call_desc}")
                    snippet = vuln.get("code_snippet")
                    if snippet:
                        explanation.append("  Code Snippet:")
                        for line_content in snippet.splitlines():
                            explanation.append(f"    | {line_content}")

                explanation.append("")

            explanation.append("")

        # Add remediation suggestions
        explanation.append("Remediation Suggestions:")
        explanation.append("------------------------")

        # Collect unique rule names or primary types for suggestions
        unique_rule_types = set()
        for v in vulnerabilities:
            rule_name_val = v.get("rule_name", v.get("rule", ""))
            if rule_name_val:
                # Try to get a general type, e.g., "PickleDeserialization" from "rules.python.pickle.PickleDeserialization"
                primary_type = rule_name_val.split(".")[-1]
                unique_rule_types.add(primary_type)

        if (
            "PickleDeserialization" in unique_rule_types
            or "UnsafeDeserialization" in unique_rule_types
        ):
            explanation.append("1. For unsafe deserialization issues (e.g., pickle):")
            explanation.append(
                "   - Avoid using pickle.loads() or similar functions on untrusted data, especially from network or user input."
            )
            explanation.append(
                "   - Consider using safer serialization formats like JSON if the data structure allows."
            )
            explanation.append(
                "   - If pickle must be used with untrusted data, implement a custom Unpickler that restricts loadable object types to only known safe types."
            )
            explanation.append("")

        if "SQLInjection" in unique_rule_types:
            explanation.append("2. For SQL injection issues:")
            explanation.append(
                "   - Use parameterized queries (prepared statements) with your database driver instead of string concatenation or formatting."
            )
            explanation.append(
                "   - Utilize Object-Relational Mapping (ORM) frameworks like SQLAlchemy, which often handle parameterization automatically."
            )
            explanation.append(
                "   - Validate and sanitize all user input before incorporating it into database queries, even when using ORMs or parameterized queries as an additional layer of defense."
            )
            explanation.append("")

        explanation.append("3. General Recommendations:")
        explanation.append(
            "   - Implement robust input validation for all data received from external sources."
        )
        explanation.append(
            "   - Adhere to the principle of least privilege for all system components and users."
        )
        explanation.append(
            "   - Implement comprehensive security logging and monitoring to detect and respond to suspicious activities."
        )
        explanation.append(
            "   - Keep all libraries and dependencies up to date to patch known vulnerabilities."
        )

        return "\n".join(explanation)

    def _generate_markdown_explanation(
        self, vulnerabilities: List[Dict[str, Any]], level: str
    ) -> str:
        """
        Generate Markdown format vulnerability explanation.

        Args:
            vulnerabilities: List of vulnerabilities
            level: Detail level, "brief" or "detailed"

        Returns:
            str: Markdown format vulnerability explanation
        """
        if not vulnerabilities:
            return "No security vulnerabilities found."

        files_affected = sorted(
            list(
                set(
                    v.get("file", v.get("file_path", "Unknown File"))
                    for v in vulnerabilities
                    if v.get("file", v.get("file_path"))
                )
            )
        )

        explanation = [
            "# Security Vulnerability Analysis Report",
            f"Found **{len(vulnerabilities)}** potential security vulnerabilities, affecting **{len(files_affected)}** file(s).",
        ]

        # Group vulnerabilities by file
        vulns_by_file: Dict[str, List[Dict[str, Any]]] = {}
        for vuln in vulnerabilities:
            file_key = vuln.get("file", vuln.get("file_path", "Unknown File"))
            if file_key not in vulns_by_file:
                vulns_by_file[file_key] = []
            vulns_by_file[file_key].append(vuln)

        # Generate report per file
        for file_path_key, file_vulns in vulns_by_file.items():
            explanation.append(f"## File: `{file_path_key}`")

            for i, vuln in enumerate(file_vulns, 1):
                rule_name = vuln.get(
                    "rule_name", vuln.get("rule", "Unknown Vulnerability Type")
                )
                severity = vuln.get("severity", "Unknown").upper()
                sink_info = vuln.get("sink", {})
                line_no = sink_info.get("location", {}).get(
                    "line", sink_info.get("line", "Unknown")
                )
                message = vuln.get(
                    "message", vuln.get("description", "No description provided.")
                )

                severity_emoji = (
                    "🔴"
                    if severity == "HIGH"
                    else "🟠"
                    if severity == "MEDIUM"
                    else "🟡"
                    if severity == "LOW"
                    else "⚪"  # For INFO or UNKNOWN
                )

                explanation.append(
                    f"### {severity_emoji} Vulnerability #{i}: {rule_name}"
                )
                explanation.append(f"- **Severity**: {severity}")
                explanation.append(f"- **Location**: Line {line_no}")
                explanation.append(f"- **Description**: {message}")

                if level == "detailed":
                    # Add call chain information
                    call_chain = vuln.get("call_chain", [])
                    if call_chain:
                        explanation.append("\n  **Call Chain**:")
                        for j, call in enumerate(call_chain, 1):
                            func = call.get(
                                "function_name",
                                call.get("function", "Unknown Function"),
                            )
                            call_line = call.get(
                                "line_number", call.get("line", "Unknown")
                            )
                            call_type = call.get(
                                "type", "intermediate"
                            ).capitalize()  # e.g. source, sink, intermediate
                            call_desc = call.get("description", "")

                            type_icon = (
                                "🔍"
                                if call_type.lower() == "source"
                                else "🎯"
                                if call_type.lower() == "sink"
                                else "➡️"  # Using target/dartboard for sink  # Arrow for intermediate steps
                            )

                            explanation.append(
                                f"    {j}. {type_icon} **{func}** (Line {call_line}) - *{call_type}*"
                            )
                            if call_desc:
                                explanation.append(f"       - {call_desc}")
                    snippet = vuln.get("code_snippet")
                    if snippet:
                        explanation.append("  **Code Snippet**:")
                        explanation.append("  ```python")
                        explanation.extend(
                            [
                                f"  {line_content}"
                                for line_content in snippet.splitlines()
                            ]
                        )
                        explanation.append("  ```")

                explanation.append("")  # Adds a newline for better spacing in Markdown

        # Add remediation suggestions
        explanation.append("## Remediation Suggestions")

        unique_rule_types = set()
        for v in vulnerabilities:
            rule_name_val = v.get("rule_name", v.get("rule", ""))
            if rule_name_val:
                primary_type = rule_name_val.split(".")[-1]
                unique_rule_types.add(primary_type)

        if (
            "PickleDeserialization" in unique_rule_types
            or "UnsafeDeserialization" in unique_rule_types
        ):
            explanation.append(
                "### For unsafe deserialization issues (e.g., `pickle`):"
            )
            explanation.append(
                "- Avoid using `pickle.loads()` or similar functions on untrusted data, especially from network or user input."
            )
            explanation.append(
                "- Consider using safer serialization formats like JSON if the data structure allows."
            )
            explanation.append(
                "- If `pickle` must be used with untrusted data, implement a custom `Unpickler` that restricts loadable object types to only known safe types."
            )
            explanation.append("")

        if "SQLInjection" in unique_rule_types:
            explanation.append("### For SQL injection issues:")
            explanation.append(
                "- Use parameterized queries (prepared statements) with your database driver instead of string concatenation or formatting."
            )
            explanation.append(
                "- Utilize Object-Relational Mapping (ORM) frameworks like SQLAlchemy, which often handle parameterization automatically."
            )
            explanation.append(
                "- Validate and sanitize all user input before incorporating it into database queries, even when using ORMs or parameterized queries as an additional layer of defense."
            )
            explanation.append("")

        explanation.append("### General Recommendations:")
        explanation.append(
            "- Implement robust input validation for all data received from external sources."
        )
        explanation.append(
            "- Adhere to the principle of least privilege for all system components and users."
        )
        explanation.append(
            "- Implement comprehensive security logging and monitoring to detect and respond to suspicious activities."
        )
        explanation.append(
            "- Keep all libraries and dependencies up to date to patch known vulnerabilities."
        )

        return "\n".join(explanation)
