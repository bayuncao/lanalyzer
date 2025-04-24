"""
Console formatter for LanaLyzer output.

Formats analysis results for terminal display with color highlighting.
"""

import datetime
import sys
from typing import Any, Dict, List, Optional, Union

from colorama import Fore, Style, init

from lanalyzer.models import Vulnerability
from lanalyzer.output.formatter import OutputFormatter

# Initialize colorama
init()


class ConsoleFormatter(OutputFormatter):
    """
    Formats analysis results for terminal display with color highlighting.

    This formatter creates human-readable console output with color coding for
    different severity levels and formatted sections for better readability.
    """

    def __init__(self, use_color: bool = True):
        """
        Initialize the console formatter.

        Args:
            use_color: Whether to use colored output (default: True)
        """
        super().__init__()
        self.use_color = use_color

        # Define colors for different severities
        self.colors = {
            "high": Fore.RED,
            "medium": Fore.YELLOW,
            "low": Fore.BLUE,
            "info": Fore.GREEN,
            "unknown": Fore.WHITE,
            "header": Fore.CYAN,
            "reset": Style.RESET_ALL,
            "bold": Style.BRIGHT,
        }

        # Disable colors if requested or if not in a terminal
        if not use_color or not sys.stdout.isatty():
            for key in self.colors:
                self.colors[key] = ""

    def format_results(
        self, vulnerabilities: List[Union[Vulnerability, Dict[str, Any]]], **kwargs
    ) -> str:
        """
        Format analysis results for console output.

        Args:
            vulnerabilities: List of vulnerability objects or dictionaries
            **kwargs: Additional arguments:
                - show_summary: Whether to include summary statistics (default: True)
                - show_details: Whether to include detailed vulnerability information (default: True)
                - show_source_sink: Whether to include source and sink details (default: True)
                - show_remediation: Whether to include remediation suggestions (default: True)
                - target: The target of the analysis (default: "Unknown")
                - stats: Additional statistics about the analysis (default: {})

        Returns:
            Formatted string with analysis results
        """
        show_summary = kwargs.get("show_summary", True)
        show_details = kwargs.get("show_details", True)
        show_source_sink = kwargs.get("show_source_sink", True)
        show_remediation = kwargs.get("show_remediation", True)
        target = kwargs.get("target", "Unknown")
        stats = kwargs.get("stats", {})

        output = []

        # Header
        output.append(self._color("=" * 80, "header"))
        output.append(self._color(" LANALYZER VULNERABILITY REPORT", "header", True))
        output.append(
            self._color(
                f' Generated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
                "header",
            )
        )
        output.append(self._color(f" Target: {target}", "header"))
        output.append(self._color("=" * 80, "header"))
        output.append("")

        # Summary section if requested
        if show_summary:
            output.append(self._color("SUMMARY", "header", True))
            output.append("-" * 80)

            # Count vulnerabilities by severity
            severity_counts = {
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "unknown": 0,
            }

            for vuln in vulnerabilities:
                if isinstance(vuln, dict):
                    severity = vuln.get("severity", "unknown").lower()
                else:
                    severity = getattr(vuln, "severity", "unknown").lower()

                if severity in severity_counts:
                    severity_counts[severity] += 1
                else:
                    severity_counts["unknown"] += 1

            total = sum(severity_counts.values())
            output.append(f"Total vulnerabilities: {total}")
            output.append("")

            # Display vulnerability counts by severity
            output.append("By Severity:")
            for severity, count in severity_counts.items():
                if count > 0:
                    output.append(
                        f'  {self._color(severity.upper() + ":", severity, True)} {count}'
                    )

            # Display additional stats if provided
            if stats:
                output.append("")
                output.append("Analysis Stats:")
                for key, value in stats.items():
                    if key != "vulnerability_count":  # Already displayed above
                        output.append(f"  {key}: {value}")

            output.append("")

        # Detailed vulnerability information if requested
        if show_details and vulnerabilities:
            output.append(self._color("VULNERABILITIES", "header", True))
            output.append("-" * 80)

            # Process each vulnerability
            for i, vuln in enumerate(vulnerabilities):
                # Convert to dict if it's an object
                if not isinstance(vuln, dict):
                    if hasattr(vuln, "to_dict"):
                        vuln_dict = vuln.to_dict()
                    else:
                        vuln_dict = vars(vuln)
                else:
                    vuln_dict = vuln

                # Extract basic info
                rule = vuln_dict.get("rule", "Unknown Vulnerability")
                severity = vuln_dict.get("severity", "unknown").lower()
                file_path = vuln_dict.get("file", "Unknown")
                message = vuln_dict.get("message", "No details available")

                # Format vulnerability header with color based on severity
                output.append("")
                output.append(f"[{i+1}] {self._color(rule, severity, True)}")
                output.append(
                    f"  Severity: {self._color(severity.upper(), severity, True)}"
                )
                output.append(f"  File: {file_path}")
                output.append(f"  Message: {message}")

                # Show source and sink details if requested
                if show_source_sink:
                    source = vuln_dict.get("source", {})
                    sink = vuln_dict.get("sink", {})

                    if source:
                        source_line = source.get("location", {}).get(
                            "line", source.get("line", "Unknown")
                        )
                        source_name = source.get("name", "Unknown")
                        source_function = source.get("function_name", "Unknown")
                        output.append(
                            f"  Source: {source_name} in {source_function} at line {source_line}"
                        )

                    if sink:
                        sink_line = sink.get("location", {}).get(
                            "line", sink.get("line", "Unknown")
                        )
                        sink_name = sink.get("name", "Unknown")
                        sink_function = sink.get("function_name", "Unknown")
                        output.append(
                            f"  Sink: {sink_name} in {sink_function} at line {sink_line}"
                        )

                # Show tainted variable if available
                if "tainted_variable" in vuln_dict and vuln_dict["tainted_variable"]:
                    output.append(
                        f'  Tainted Variable: {vuln_dict["tainted_variable"]}'
                    )

                # Show remediation if requested
                if (
                    show_remediation
                    and "remediation" in vuln_dict
                    and vuln_dict["remediation"]
                ):
                    output.append("")
                    output.append(f'  Remediation: {vuln_dict["remediation"]}')

                # Show CWE if available
                if "cwe" in vuln_dict and vuln_dict["cwe"]:
                    output.append(f'  CWE: {vuln_dict["cwe"]}')

                output.append("-" * 80)

        # Footer
        output.append("")
        if vulnerabilities:
            output.append(
                f"End of report. {len(vulnerabilities)} vulnerabilities found."
            )
        else:
            output.append("No vulnerabilities found.")

        return "\n".join(output)

    def _color(self, text: str, color_key: str, bold: bool = False) -> str:
        """
        Apply color to text if colors are enabled.

        Args:
            text: Text to colorize
            color_key: Key for the color to use
            bold: Whether to make the text bold

        Returns:
            Colorized text string
        """
        if not self.use_color:
            return text

        color = self.colors.get(color_key, "")
        bold_style = self.colors.get("bold", "") if bold else ""
        reset = self.colors.get("reset", "")

        return f"{color}{bold_style}{text}{reset}"


def format_for_console(
    vulnerabilities: List[Union[Vulnerability, Dict[str, Any]]],
    output_file: Optional[str] = None,
    use_color: bool = True,
    **kwargs,
) -> str:
    """
    Convenience function to format analysis results for console output.

    Args:
        vulnerabilities: List of vulnerability objects or dictionaries
        output_file: Path to output file (if None, prints to stdout)
        use_color: Whether to use colored output
        **kwargs: Additional arguments to pass to the formatter

    Returns:
        Formatted string with the results
    """
    formatter = ConsoleFormatter(use_color=use_color)
    formatted = formatter.format_results(vulnerabilities, **kwargs)

    if output_file:
        formatter.write_results(formatted, output_file)

    return formatted
