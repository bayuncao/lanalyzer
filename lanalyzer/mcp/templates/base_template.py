"""
Base template class for vulnerability reports.

This module provides the base class and common functionality for all
vulnerability report templates.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List


class BaseReportTemplate(ABC):
    """
    Base class for vulnerability report templates.

    This class defines the common interface and functionality that all
    vulnerability report templates should implement.
    """

    # Common fields that all reports should have
    COMMON_REQUIRED_FIELDS = [
        "title",
        "description",
        "severity",
        "affected_component",
        "discovery_date",
    ]

    # Template-specific required fields (to be defined by subclasses)
    TEMPLATE_REQUIRED_FIELDS: List[str] = []

    def __init__(self):
        """Initialize the base template."""
        self.template_name = self.__class__.__name__

    @property
    def required_fields(self) -> List[str]:
        """Get all required fields for this template."""
        return self.COMMON_REQUIRED_FIELDS + self.TEMPLATE_REQUIRED_FIELDS

    @abstractmethod
    def format_report(self, data: Dict[str, Any]) -> str:
        """
        Format vulnerability data into a report.

        Args:
            data: Dictionary containing vulnerability information

        Returns:
            Formatted report string

        Raises:
            ValueError: If required fields are missing
        """
        pass

    def validate_data(self, data: Dict[str, Any]) -> None:
        """
        Validate that all required fields are present in the data.

        Args:
            data: Dictionary containing vulnerability information

        Raises:
            ValueError: If required fields are missing
        """
        missing_fields = []
        for field in self.required_fields:
            if field not in data or data[field] is None:
                missing_fields.append(field)

        if missing_fields:
            raise ValueError(
                f"Missing required fields for {self.template_name}: {missing_fields}"
            )

    def format_severity(self, severity: str) -> str:
        """
        Format severity level with appropriate styling.

        Args:
            severity: Severity level string

        Returns:
            Formatted severity string
        """
        severity_upper = severity.upper()

        severity_mapping = {
            "CRITICAL": "🔴 严重",
            "HIGH": "🟠 高危",
            "MEDIUM": "🟡 中危",
            "LOW": "🟢 低危",
            "INFO": "ℹ️ 信息",
        }

        return severity_mapping.get(severity_upper, f"⚪ {severity_upper}")

    def format_date(self, date_value: Any) -> str:
        """
        Format date value to standard string format.

        Args:
            date_value: Date value (datetime, string, or None)

        Returns:
            Formatted date string
        """
        if isinstance(date_value, datetime):
            return date_value.strftime("%Y-%m-%d")
        elif isinstance(date_value, str):
            return date_value
        else:
            return datetime.now().strftime("%Y-%m-%d")

    def extract_vulnerability_info(
        self, vulnerability_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Extract and normalize vulnerability information from analysis results.

        Args:
            vulnerability_data: Raw vulnerability data from analysis

        Returns:
            Normalized vulnerability information
        """
        # Extract basic information
        extracted = {
            "title": vulnerability_data.get("rule_name", "Unknown Vulnerability"),
            "description": vulnerability_data.get(
                "message", "No description available"
            ),
            "severity": vulnerability_data.get("severity", "MEDIUM"),
            "affected_component": vulnerability_data.get("file_path", "Unknown"),
            "discovery_date": self.format_date(None),
            "line_number": vulnerability_data.get("line", 0),
            "code_snippet": vulnerability_data.get("code_snippet", ""),
        }

        # Extract source and sink information if available
        if "source" in vulnerability_data:
            source = vulnerability_data["source"]
            extracted["source_info"] = {
                "name": source.get("name", ""),
                "line": source.get("line", 0),
                "type": source.get("type", ""),
                "value": source.get("value", ""),
            }

        if "sink" in vulnerability_data:
            sink = vulnerability_data["sink"]
            extracted["sink_info"] = {
                "name": sink.get("name", ""),
                "line": sink.get("line", 0),
                "context": sink.get("context", ""),
            }

        # Extract call chain if available
        if "call_chain" in vulnerability_data:
            extracted["call_chain"] = vulnerability_data["call_chain"]

        return extracted
