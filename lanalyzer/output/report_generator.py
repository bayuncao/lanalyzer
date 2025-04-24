"""
Report generator for LanaLyzer.

Generates comprehensive reports from analysis results.
"""

import datetime
import json
from typing import Any, Dict, Optional, Union

from lanalyzer.models import AnalysisResults


class ReportGenerator:
    """
    Generates comprehensive reports from analysis results.

    This class provides methods for creating various types of reports
    from analysis results, including HTML, Markdown, and text reports.
    """

    def __init__(self, results: Union[AnalysisResults, Dict[str, Any]]):
        """
        Initialize with analysis results.

        Args:
            results: Analysis results (either AnalysisResults object or dict)
        """
        if isinstance(results, AnalysisResults):
            self.results = results
            self.vulns = results.vulnerabilities
        else:
            self.results = results
            self.vulns = results.get("vulnerabilities", [])

        self.timestamp = datetime.datetime.now().isoformat()
        self.report_data = self._prepare_report_data()

    def _prepare_report_data(self) -> Dict[str, Any]:
        """
        Prepare data for report generation.

        Returns:
            Dictionary with report data
        """
        # Basic report data
        report_data = {
            "timestamp": self.timestamp,
            "title": "LanaLyzer Vulnerability Report",
            "total_vulnerabilities": len(self.vulns),
            "vulnerabilities": self.vulns,
            "summary": {},
        }

        # Add targets information
        if isinstance(self.results, AnalysisResults):
            report_data["target"] = self.results.target
            report_data["summary"] = self.results.summary

            # Extract stats if available
            if hasattr(self.results, "stats"):
                report_data["stats"] = self.results.stats
        elif isinstance(self.results, dict):
            report_data["target"] = self.results.get("target", "Unknown")
            report_data["summary"] = self.results.get("summary", {})
            report_data["stats"] = self.results.get("stats", {})

        # Generate severity counts if not in summary
        if "by_severity" not in report_data["summary"]:
            severity_counts = {"high": 0, "medium": 0, "low": 0, "unknown": 0}
            for vuln in self.vulns:
                severity = vuln.get("severity", "unknown").lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1
                else:
                    severity_counts["unknown"] += 1
            report_data["summary"]["by_severity"] = severity_counts

        # Generate rule counts if not in summary
        if "by_rule" not in report_data["summary"]:
            rule_counts = {}
            for vuln in self.vulns:
                rule = vuln.get("rule", "Unknown")
                rule_counts[rule] = rule_counts.get(rule, 0) + 1
            report_data["summary"]["by_rule"] = rule_counts

        # Generate file counts if not in summary
        if "by_file" not in report_data["summary"]:
            file_counts = {}
            for vuln in self.vulns:
                file = vuln.get("file", "Unknown")
                file_counts[file] = file_counts.get(file, 0) + 1
            report_data["summary"]["by_file"] = file_counts

        return report_data

    def generate_text_report(self, output_file: Optional[str] = None) -> str:
        """
        Generate a plain text report.

        Args:
            output_file: Path to output file (optional)

        Returns:
            Report as a string
        """
        report = []

        # Header
        report.append("=" * 80)
        report.append("LANALYZER VULNERABILITY REPORT")
        report.append(f"Generated: {self.report_data['timestamp']}")
        report.append(f"Target: {self.report_data['target']}")
        report.append("=" * 80)

        # Summary
        report.append("\nSUMMARY")
        report.append("-" * 80)
        report.append(
            f"Total vulnerabilities: {self.report_data['total_vulnerabilities']}"
        )

        # Severity breakdown
        severity_counts = self.report_data["summary"].get("by_severity", {})
        report.append("\nBy Severity:")
        for severity, count in severity_counts.items():
            report.append(f"  {severity.upper()}: {count}")

        # Rule breakdown
        rule_counts = self.report_data["summary"].get("by_rule", {})
        report.append("\nBy Rule:")
        for rule, count in sorted(
            rule_counts.items(), key=lambda x: x[1], reverse=True
        ):
            report.append(f"  {rule}: {count}")

        # Stats if available
        stats = self.report_data.get("stats", {})
        if stats:
            report.append("\nStatistics:")
            for key, value in stats.items():
                if key != "vulnerability_count":  # Already reported
                    report.append(f"  {key}: {value}")

        # Detailed vulnerabilities
        report.append("\nDETAILED VULNERABILITIES")
        report.append("-" * 80)

        for i, vuln in enumerate(self.vulns):
            report.append(f"\n[{i+1}] {vuln.get('rule', 'Unknown Vulnerability')}")
            report.append(f"  Severity: {vuln.get('severity', 'unknown').upper()}")
            report.append(f"  File: {vuln.get('file', 'Unknown')}")
            report.append(f"  Message: {vuln.get('message', 'No details available')}")

            # Show source and sink if available
            source = vuln.get("source", {})
            sink = vuln.get("sink", {})

            if source:
                source_line = source.get("location", {}).get(
                    "line", source.get("line", "Unknown")
                )
                source_name = source.get("name", "Unknown")
                source_function = source.get("function_name", "Unknown")
                report.append(
                    f"  Source: {source_name} in {source_function} at line {source_line}"
                )

            if sink:
                sink_line = sink.get("location", {}).get(
                    "line", sink.get("line", "Unknown")
                )
                sink_name = sink.get("name", "Unknown")
                sink_function = sink.get("function_name", "Unknown")
                report.append(
                    f"  Sink: {sink_name} in {sink_function} at line {sink_line}"
                )

            # Show tainted variable if available
            if "tainted_variable" in vuln and vuln["tainted_variable"]:
                report.append(f"  Tainted Variable: {vuln['tainted_variable']}")

            # Show remediation if available
            if "remediation" in vuln and vuln["remediation"]:
                report.append(f"\n  Remediation: {vuln['remediation']}")

            # Show CWE if available
            if "cwe" in vuln and vuln["cwe"]:
                report.append(f"  CWE: {vuln['cwe']}")

            report.append("-" * 80)

        # Footer
        report.append(
            f"\nEnd of report. {self.report_data['total_vulnerabilities']} vulnerabilities found."
        )

        report_text = "\n".join(report)

        # Write to file if requested
        if output_file:
            try:
                with open(output_file, "w") as f:
                    f.write(report_text)
                print(f"Report written to {output_file}")
            except Exception as e:
                print(f"Error writing report to {output_file}: {e}")

        return report_text

    def generate_markdown_report(self, output_file: Optional[str] = None) -> str:
        """
        Generate a Markdown report.

        Args:
            output_file: Path to output file (optional)

        Returns:
            Report as a Markdown string
        """
        report = []

        # Header
        report.append("# LanaLyzer Vulnerability Report")
        report.append(f"**Generated:** {self.report_data['timestamp']}")
        report.append(f"**Target:** {self.report_data['target']}")
        report.append("")

        # Summary
        report.append("## Summary")
        report.append(
            f"**Total vulnerabilities:** {self.report_data['total_vulnerabilities']}"
        )

        # Severity breakdown
        severity_counts = self.report_data["summary"].get("by_severity", {})
        report.append("\n### By Severity")
        for severity, count in severity_counts.items():
            report.append(f"- **{severity.upper()}:** {count}")

        # Rule breakdown
        rule_counts = self.report_data["summary"].get("by_rule", {})
        report.append("\n### By Rule")
        for rule, count in sorted(
            rule_counts.items(), key=lambda x: x[1], reverse=True
        ):
            report.append(f"- **{rule}:** {count}")

        # Stats if available
        stats = self.report_data.get("stats", {})
        if stats:
            report.append("\n### Statistics")
            for key, value in stats.items():
                if key != "vulnerability_count":  # Already reported
                    report.append(f"- **{key}:** {value}")

        # Detailed vulnerabilities
        report.append("\n## Detailed Vulnerabilities")

        for i, vuln in enumerate(self.vulns):
            report.append(f"\n### [{i+1}] {vuln.get('rule', 'Unknown Vulnerability')}")
            report.append(f"- **Severity:** {vuln.get('severity', 'unknown').upper()}")
            report.append(f"- **File:** `{vuln.get('file', 'Unknown')}`")
            report.append(
                f"- **Message:** {vuln.get('message', 'No details available')}"
            )

            # Show source and sink if available
            source = vuln.get("source", {})
            sink = vuln.get("sink", {})

            if source:
                source_line = source.get("location", {}).get(
                    "line", source.get("line", "Unknown")
                )
                source_name = source.get("name", "Unknown")
                source_function = source.get("function_name", "Unknown")
                report.append(
                    f"- **Source:** {source_name} in `{source_function}` at line {source_line}"
                )

            if sink:
                sink_line = sink.get("location", {}).get(
                    "line", sink.get("line", "Unknown")
                )
                sink_name = sink.get("name", "Unknown")
                sink_function = sink.get("function_name", "Unknown")
                report.append(
                    f"- **Sink:** {sink_name} in `{sink_function}` at line {sink_line}"
                )

            # Show tainted variable if available
            if "tainted_variable" in vuln and vuln["tainted_variable"]:
                report.append(f"- **Tainted Variable:** `{vuln['tainted_variable']}`")

            # Show remediation if available
            if "remediation" in vuln and vuln["remediation"]:
                report.append(f"\n**Remediation:**\n\n> {vuln['remediation']}")

            # Show CWE if available
            if "cwe" in vuln and vuln["cwe"]:
                report.append(
                    f"- **CWE:** [{vuln['cwe']}](https://cwe.mitre.org/data/definitions/{vuln['cwe'].replace('CWE-', '')}.html)"
                )

            # Show code snippet if available
            if "code_snippet" in vuln and vuln["code_snippet"]:
                report.append("\n**Code Snippet:**")
                report.append("```python")
                report.append(vuln["code_snippet"])
                report.append("```")

        # Footer
        report.append(
            f"\n---\nEnd of report. {self.report_data['total_vulnerabilities']} vulnerabilities found."
        )

        report_text = "\n".join(report)

        # Write to file if requested
        if output_file:
            try:
                with open(output_file, "w") as f:
                    f.write(report_text)
                print(f"Report written to {output_file}")
            except Exception as e:
                print(f"Error writing report to {output_file}: {e}")

        return report_text

    def generate_html_report(self, output_file: Optional[str] = None) -> str:
        """
        Generate an HTML report.

        Args:
            output_file: Path to output file (optional)

        Returns:
            Report as an HTML string
        """
        html = []

        # Start HTML document
        html.append("<!DOCTYPE html>")
        html.append('<html lang="en">')
        html.append("<head>")
        html.append('    <meta charset="UTF-8">')
        html.append(
            '    <meta name="viewport" content="width=device-width, initial-scale=1.0">'
        )
        html.append(f"    <title>{self.report_data['title']}</title>")
        html.append("    <style>")
        html.append(
            "        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; color: #333; }"
        )
        html.append(
            "        h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }"
        )
        html.append(
            "        h2 { color: #2c3e50; border-bottom: 1px solid #ddd; padding-bottom: 5px; margin-top: 30px; }"
        )
        html.append("        h3 { margin-top: 25px; }")
        html.append("        .container { max-width: 1200px; margin: 0 auto; }")
        html.append(
            "        .summary { background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }"
        )
        html.append(
            "        .vulnerability { background: #fff; padding: 15px; border-radius: 5px; margin-bottom: 15px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }"
        )
        html.append("        .high { border-left: 5px solid #e74c3c; }")
        html.append("        .medium { border-left: 5px solid #f39c12; }")
        html.append("        .low { border-left: 5px solid #3498db; }")
        html.append("        .unknown { border-left: 5px solid #95a5a6; }")
        html.append(
            "        .meta { color: #7f8c8d; font-size: 0.9em; margin-bottom: 10px; }"
        )
        html.append(
            "        .remediation { background: #eafaf1; padding: 10px; border-radius: 3px; margin-top: 10px; }"
        )
        html.append(
            "        pre { background: #f8f9fa; padding: 10px; border-radius: 3px; overflow-x: auto; }"
        )
        html.append(
            "        code { font-family: Consolas, Monaco, 'Andale Mono', monospace; font-size: 0.9em; }"
        )
        html.append(
            "        .stat-card { display: inline-block; padding: 10px; margin: 5px; background: #fff; border-radius: 5px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); min-width: 120px; text-align: center; }"
        )
        html.append(
            "        .stat-value { font-size: 1.5em; font-weight: bold; color: #2c3e50; }"
        )
        html.append("        .stat-label { color: #7f8c8d; }")
        html.append(
            "        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }"
        )
        html.append(
            "        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }"
        )
        html.append("        th { background-color: #f2f2f2; }")
        html.append("    </style>")
        html.append("</head>")
        html.append("<body>")
        html.append('    <div class="container">')

        # Header
        html.append(f"        <h1>{self.report_data['title']}</h1>")
        html.append('        <div class="meta">')
        html.append(
            f"            <strong>Generated:</strong> {self.report_data['timestamp']}<br>"
        )
        html.append(
            f"            <strong>Target:</strong> {self.report_data['target']}"
        )
        html.append("        </div>")

        # Summary
        html.append('        <div class="summary">')
        html.append("            <h2>Summary</h2>")

        # Stat cards
        html.append("            <div>")
        html.append('                <div class="stat-card">')
        html.append(
            f"                    <div class=\"stat-value\">{self.report_data['total_vulnerabilities']}</div>"
        )
        html.append(
            '                    <div class="stat-label">Total Vulnerabilities</div>'
        )
        html.append("                </div>")

        # Severity counts
        severity_counts = self.report_data["summary"].get("by_severity", {})
        for severity, count in severity_counts.items():
            html.append(f'                <div class="stat-card {severity}">')
            html.append(f'                    <div class="stat-value">{count}</div>')
            html.append(
                f'                    <div class="stat-label">{severity.upper()}</div>'
            )
            html.append("                </div>")
        html.append("            </div>")

        # Rule breakdown
        rule_counts = self.report_data["summary"].get("by_rule", {})
        if rule_counts:
            html.append("            <h3>Vulnerability Types</h3>")
            html.append("            <table>")
            html.append("                <tr><th>Rule</th><th>Count</th></tr>")

            for rule, count in sorted(
                rule_counts.items(), key=lambda x: x[1], reverse=True
            ):
                html.append(f"                <tr><td>{rule}</td><td>{count}</td></tr>")

            html.append("            </table>")

        # File breakdown
        file_counts = self.report_data["summary"].get("by_file", {})
        if file_counts:
            html.append("            <h3>Affected Files</h3>")
            html.append("            <table>")
            html.append("                <tr><th>File</th><th>Count</th></tr>")

            for file, count in sorted(
                file_counts.items(), key=lambda x: x[1], reverse=True
            ):
                html.append(f"                <tr><td>{file}</td><td>{count}</td></tr>")

            html.append("            </table>")

        # End of summary
        html.append("        </div>")

        # Detailed vulnerabilities
        html.append("        <h2>Detailed Vulnerabilities</h2>")

        for i, vuln in enumerate(self.vulns):
            severity = vuln.get("severity", "unknown").lower()
            html.append(f'        <div class="vulnerability {severity}">')
            html.append(
                f"            <h3>[{i+1}] {vuln.get('rule', 'Unknown Vulnerability')}</h3>"
            )
            html.append('            <div class="meta">')
            html.append(
                f"                <strong>Severity:</strong> {severity.upper()}<br>"
            )
            html.append(
                f"                <strong>File:</strong> {vuln.get('file', 'Unknown')}"
            )
            html.append("            </div>")
            html.append(
                f"            <p><strong>Message:</strong> {vuln.get('message', 'No details available')}</p>"
            )

            # Show source and sink if available
            source = vuln.get("source", {})
            sink = vuln.get("sink", {})

            if source:
                source_line = source.get("location", {}).get(
                    "line", source.get("line", "Unknown")
                )
                source_name = source.get("name", "Unknown")
                source_function = source.get("function_name", "Unknown")
                html.append(
                    f"            <p><strong>Source:</strong> {source_name} in <code>{source_function}</code> at line {source_line}</p>"
                )

            if sink:
                sink_line = sink.get("location", {}).get(
                    "line", sink.get("line", "Unknown")
                )
                sink_name = sink.get("name", "Unknown")
                sink_function = sink.get("function_name", "Unknown")
                html.append(
                    f"            <p><strong>Sink:</strong> {sink_name} in <code>{sink_function}</code> at line {sink_line}</p>"
                )

            # Show tainted variable if available
            if "tainted_variable" in vuln and vuln["tainted_variable"]:
                html.append(
                    f"            <p><strong>Tainted Variable:</strong> <code>{vuln['tainted_variable']}</code></p>"
                )

            # Show remediation if available
            if "remediation" in vuln and vuln["remediation"]:
                html.append('            <div class="remediation">')
                html.append(
                    f"                <strong>Remediation:</strong> {vuln['remediation']}"
                )
                html.append("            </div>")

            # Show CWE if available
            if "cwe" in vuln and vuln["cwe"]:
                cwe_number = vuln["cwe"].replace("CWE-", "")
                html.append(
                    f"            <p><strong>CWE:</strong> <a href=\"https://cwe.mitre.org/data/definitions/{cwe_number}.html\" target=\"_blank\">{vuln['cwe']}</a></p>"
                )

            # Show code snippet if available
            if "code_snippet" in vuln and vuln["code_snippet"]:
                html.append("            <div>")
                html.append("                <strong>Code Snippet:</strong>")
                html.append("                <pre><code>")
                html.append(self._escape_html(vuln["code_snippet"]))
                html.append("                </code></pre>")
                html.append("            </div>")

            html.append("        </div>")

        # Footer
        html.append(
            '        <div class="meta" style="margin-top: 40px; text-align: center;">'
        )
        html.append(
            f"            End of report. {self.report_data['total_vulnerabilities']} vulnerabilities found."
        )
        html.append("        </div>")

        # End document
        html.append("    </div>")
        html.append("</body>")
        html.append("</html>")

        html_report = "\n".join(html)

        # Write to file if requested
        if output_file:
            try:
                with open(output_file, "w") as f:
                    f.write(html_report)
                print(f"HTML report written to {output_file}")
            except Exception as e:
                print(f"Error writing HTML report to {output_file}: {e}")

        return html_report

    def generate_json_report(
        self, output_file: Optional[str] = None, pretty: bool = True
    ) -> str:
        """
        Generate a JSON report.

        Args:
            output_file: Path to output file (optional)
            pretty: Whether to format the JSON for readability

        Returns:
            Report as a JSON string
        """
        # Create a clean report data without any complex objects
        report_data = {
            "timestamp": self.report_data["timestamp"],
            "target": self.report_data["target"],
            "total_vulnerabilities": self.report_data["total_vulnerabilities"],
            "summary": self.report_data["summary"],
            "vulnerabilities": [],
        }

        # Add stats if available
        if "stats" in self.report_data:
            report_data["stats"] = self.report_data["stats"]

        # Convert all vulnerabilities to dictionaries
        for vuln in self.vulns:
            if hasattr(vuln, "to_dict"):
                report_data["vulnerabilities"].append(vuln.to_dict())
            else:
                report_data["vulnerabilities"].append(vuln)

        # Generate JSON
        if pretty:
            json_report = json.dumps(report_data, indent=2)
        else:
            json_report = json.dumps(report_data)

        # Write to file if requested
        if output_file:
            try:
                with open(output_file, "w") as f:
                    f.write(json_report)
                print(f"JSON report written to {output_file}")
            except Exception as e:
                print(f"Error writing JSON report to {output_file}: {e}")

        return json_report

    def _escape_html(self, text: str) -> str:
        """
        Escape HTML special characters.

        Args:
            text: Text to escape

        Returns:
            Escaped text
        """
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )
