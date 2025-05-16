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

        # Define colors for different severities and styles
        self.colors: Dict[str, str] = {
            "high": Fore.RED,
            "medium": Fore.YELLOW,
            "low": Fore.BLUE,
            "info": Fore.GREEN,
            "unknown": Fore.WHITE,
            "header": Fore.CYAN,
            "reset": Style.RESET_ALL,
            "bold": Style.BRIGHT,
        }

        # Disable colors if requested or if not in a TTY (e.g., when piping to a file)
        if not use_color or not sys.stdout.isatty():
            for key in self.colors:
                self.colors[key] = ""

    def format_results(
        self, vulnerabilities: List[Union[Vulnerability, Dict[str, Any]]], **kwargs: Any
    ) -> str:
        """
        Format analysis results for console output.

        Args:
            vulnerabilities: List of vulnerability objects or dictionaries.
            **kwargs: Additional arguments:
                - show_summary: Whether to include summary statistics (default: True).
                - show_details: Whether to include detailed vulnerability information (default: True).
                - show_source_sink: Whether to include source and sink details (default: True).
                - show_remediation: Whether to include remediation suggestions (default: True).
                - target: The target of the analysis (default: "Unknown").
                - stats: Additional statistics about the analysis (default: {}).

        Returns:
            Formatted string with analysis results.
        """
        show_summary = kwargs.get("show_summary", True)
        show_details = kwargs.get("show_details", True)
        show_source_sink = kwargs.get("show_source_sink", True)
        show_remediation = kwargs.get("show_remediation", True)
        target = kwargs.get("target", "Unknown")
        stats = kwargs.get("stats", {})

        output_lines = []

        # Report Header
        output_lines.append(self._color("=" * 80, "header"))
        output_lines.append(
            self._color(" LANALYZER VULNERABILITY REPORT", "header", bold=True)
        )
        output_lines.append(
            self._color(
                f' Generated: {datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")}',
                "header",
            )
        )
        output_lines.append(self._color(f" Target: {target}", "header"))
        output_lines.append(self._color("=" * 80, "header"))
        output_lines.append("")

        # Summary Section
        if show_summary:
            output_lines.append(self._color("SUMMARY", "header", bold=True))
            output_lines.append("-" * 80)

            # Count vulnerabilities by severity
            severity_counts: Dict[str, int] = {
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "unknown": 0,
            }
            for vuln_item in vulnerabilities:
                severity = ""
                if isinstance(vuln_item, dict):
                    severity = vuln_item.get("severity", "unknown").lower()
                elif hasattr(vuln_item, "severity"):
                    severity = getattr(vuln_item, "severity", "unknown").lower()

                if severity in severity_counts:
                    severity_counts[severity] += 1
                else:
                    severity_counts["unknown"] += 1

            total_vulnerabilities = sum(severity_counts.values())
            output_lines.append(f"Total vulnerabilities: {total_vulnerabilities}")
            output_lines.append("")

            # Display vulnerability counts by severity
            output_lines.append("By Severity:")
            for severity_level, count in severity_counts.items():
                if count > 0:
                    output_lines.append(
                        f'  {self._color(severity_level.upper() + ":", severity_level, bold=True)} {count}'
                    )

            # Display additional analysis statistics
            if stats:
                output_lines.append("")
                output_lines.append("Analysis Stats:")
                for key, value in stats.items():
                    if (
                        key != "vulnerability_count"
                    ):  # Already covered by total_vulnerabilities
                        output_lines.append(f"  {key}: {value}")
            output_lines.append("")

        # Detailed Vulnerability Information
        if show_details and vulnerabilities:
            output_lines.append(self._color("VULNERABILITIES", "header", bold=True))
            output_lines.append("-" * 80)

            for i, vuln_item in enumerate(vulnerabilities):
                # Ensure vulnerability data is in dictionary format
                vuln_dict: Dict[str, Any]
                if isinstance(vuln_item, Vulnerability) and hasattr(
                    vuln_item, "to_dict"
                ):
                    vuln_dict = vuln_item.to_dict()
                elif isinstance(vuln_item, dict):
                    vuln_dict = vuln_item
                else:  # Fallback for other object types
                    vuln_dict = vars(vuln_item)

                # Extract basic vulnerability info
                rule = vuln_dict.get("rule", "Unknown Vulnerability")
                severity = vuln_dict.get("severity", "unknown").lower()
                file_path = vuln_dict.get("file", "N/A")
                message = vuln_dict.get("message", "No details available.")

                # Format vulnerability header
                output_lines.append("")
                output_lines.append(f"[{i+1}] {self._color(rule, severity, bold=True)}")
                output_lines.append(
                    f"  Severity: {self._color(severity.upper(), severity, bold=True)}"
                )
                output_lines.append(f"  File: {file_path}")
                if "line" in vuln_dict and vuln_dict["line"]:
                    output_lines.append(f"  Line: {vuln_dict['line']}")
                output_lines.append(f"  Message: {message}")

                # Display source and sink details
                if show_source_sink:
                    source_info = vuln_dict.get("source", {})
                    sink_info = vuln_dict.get("sink", {})

                    if isinstance(source_info, dict) and source_info:
                        loc = source_info.get("location", {})
                        line = loc.get("line", source_info.get("line", "N/A"))
                        name = source_info.get("name", "N/A")
                        func = source_info.get("function_name", "N/A")
                        output_lines.append(
                            f"  Source: {name} in {func} at line {line}"
                        )

                    if isinstance(sink_info, dict) and sink_info:
                        loc = sink_info.get("location", {})
                        line = loc.get("line", sink_info.get("line", "N/A"))
                        name = sink_info.get("name", "N/A")
                        func = sink_info.get("function_name", "N/A")
                        output_lines.append(f"  Sink: {name} in {func} at line {line}")

                # Display tainted variable
                if vuln_dict.get("tainted_variable"):
                    output_lines.append(
                        f'  Tainted Variable: {vuln_dict["tainted_variable"]}'
                    )

                # Display remediation advice
                if show_remediation and vuln_dict.get("remediation"):
                    output_lines.append("")
                    output_lines.append(f'  Remediation: {vuln_dict["remediation"]}')

                # Display CWE identifier
                if vuln_dict.get("cwe"):
                    output_lines.append(f'  CWE: {vuln_dict["cwe"]}')

                output_lines.append("-" * 80)

        # Report Footer
        output_lines.append("")
        if vulnerabilities:
            output_lines.append(
                f"End of report. {len(vulnerabilities)} "
                f"vulnerabilit{'y' if len(vulnerabilities) == 1 else 'ies'} found."
            )
        else:
            output_lines.append("No vulnerabilities found.")

        return "\n".join(output_lines)

    def _color(self, text: str, color_key: str, bold: bool = False) -> str:
        """
        Apply color and style to text if colors are enabled.

        Args:
            text: Text to colorize.
            color_key: Key for the color to use from self.colors.
            bold: Whether to make the text bold.

        Returns:
            Colorized text string.
        """
        if not self.use_color:  # Also handles cases where self.colors are emptied
            return text

        color_code = self.colors.get(color_key, "")
        bold_style = self.colors.get("bold", "") if bold else ""
        reset_code = self.colors.get("reset", "")

        return f"{color_code}{bold_style}{text}{reset_code}"

    def write_results(
        self,
        vulnerabilities: List[Union[Vulnerability, Dict[str, Any]]],
        output_file: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """
        Write formatted results to a file or stdout.
        Overrides the base class method to use self.use_color for the formatter.

        Args:
            vulnerabilities: List of vulnerability objects or dictionaries.
            output_file: Path to output file (None for stdout).
            **kwargs: Additional formatter-specific options.
        """
        # When writing to a file, typically colors are not desired unless explicitly forced.
        # However, self.use_color is initialized considering TTY, so we respect it.
        # If output_file is specified, self.use_color might have already been set to False
        # if the original intent was `use_color=True` but stdout wasn't a TTY.
        # This logic is handled in __init__.

        # For file output, we might want to force no colors,
        # but current implementation relies on initial `use_color` and TTY check.
        # Let's assume the `use_color` flag passed to `__init__` is the final authority.
        formatted_text = self.format_results(vulnerabilities, **kwargs)

        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(formatted_text)
                f.write("\n")  # Ensure newline at end of file
        else:
            sys.stdout.write(formatted_text + "\n")


def format_for_console(
    vulnerabilities: List[Union[Vulnerability, Dict[str, Any]]],
    use_color: bool = True,
    **kwargs: Any,
) -> str:
    """
    Convenience function to format analysis results for console output.

    Args:
        vulnerabilities: List of vulnerability objects or dictionaries.
        use_color: Whether to use colored output.
        **kwargs: Additional arguments to pass to the ConsoleFormatter.format_results.

    Returns:
        Formatted string with the results.
    """
    formatter = ConsoleFormatter(use_color=use_color)
    return formatter.format_results(vulnerabilities, **kwargs)
