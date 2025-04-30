"""
JSON formatter for LanaLyzer output.

Formats analysis results as JSON.
"""

import contextlib
import datetime
import json
from typing import Any, Dict, List, Optional

from lanalyzer.output.formatter import OutputFormatter
from lanalyzer.utils.logging import debug


class JSONFormatter(OutputFormatter):
    """Formats analysis results as JSON."""

    def format_results(
        self, vulnerabilities: List[Dict[str, Any]], **kwargs: Any
    ) -> str:
        """
        Format vulnerabilities as JSON.

        Args:
            vulnerabilities: List of vulnerability dictionaries
            **kwargs: Additional options, including:
                - pretty: Whether to pretty-print the JSON (default: False)
                - include_summary: Whether to include summary statistics (default: True)
                - include_timestamp: Whether to include timestamp (default: True)

        Returns:
            JSON string
        """
        pretty = kwargs.get("pretty", False)
        include_summary = kwargs.get("include_summary", True)
        include_timestamp = kwargs.get("include_timestamp", True)

        filtered_vulnerabilities = []
        for vuln in vulnerabilities:
            # 创建漏洞对象的副本
            vuln_copy = vuln.copy()

            filtered_vulnerabilities.append(vuln_copy)

        result = {"vulnerabilities": filtered_vulnerabilities}

        # Add timestamp if requested
        if include_timestamp:
            result["timestamp"] = datetime.datetime.now().isoformat()

        # Add summary statistics if requested
        if include_summary:
            summary = {"total": len(vulnerabilities), "by_rule": {}}

            # Generate statistics by rule
            for vuln in vulnerabilities:
                rule = vuln.get("rule", "Unknown")
                if rule in summary["by_rule"]:
                    summary["by_rule"][rule] += 1
                else:
                    summary["by_rule"][rule] = 1

            # Add statistics by file
            summary["by_file"] = {}
            for vuln in vulnerabilities:
                file = vuln.get("file", "Unknown")
                if file in summary["by_file"]:
                    summary["by_file"][file] += 1
                else:
                    summary["by_file"][file] = 1

            result["summary"] = summary

        # Format as JSON
        if pretty:
            return json.dumps(result, indent=2)
        return json.dumps(result)

    def write_results(
        self,
        vulnerabilities: List[Dict[str, Any]],
        output_file: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """
        Write formatted results to a file or stdout.

        Args:
            vulnerabilities: List of vulnerability dictionaries
            output_file: Path to output file (None for stdout)
            **kwargs: Additional formatter-specific options
        """
        # Format results
        formatted_results = self.format_results(vulnerabilities, **kwargs)

        # Write to file or stdout
        with contextlib.closing(self._get_output_stream(output_file)) as output:
            output.write(formatted_results)

            # Add newline if writing to file
            if output_file:
                output.write("\n")
                debug(f"Wrote JSON output to {output_file}")


def format_as_json(vulnerabilities: List[Dict[str, Any]], **kwargs: Any) -> str:
    """
    Convenience function to format vulnerabilities as JSON.

    Args:
        vulnerabilities: List of vulnerability dictionaries
        **kwargs: Additional options to pass to JSONFormatter.format_results

    Returns:
        JSON string
    """
    formatter = JSONFormatter()
    return formatter.format_results(vulnerabilities, **kwargs)
