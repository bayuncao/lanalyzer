"""
Analysis results model for LanaLyzer.

Represents the complete results of a taint analysis.
"""

import datetime
from dataclasses import dataclass, field
from typing import Any, Dict, List

from lanalyzer.models.base import BaseModel
from lanalyzer.models.vulnerability import Vulnerability


@dataclass
class AnalysisResults(BaseModel):
    """
    Represents the complete results of a taint analysis.

    This model aggregates all vulnerabilities found during an analysis run
    along with metadata about the analysis.

    Attributes:
        vulnerabilities: List of detected vulnerabilities
        timestamp: Timestamp when the analysis was performed
        target: Target file or directory that was analyzed
        stats: Statistics about the analysis (e.g. files analyzed, execution time)
        config: Configuration used for the analysis
        summary: Summary of the analysis results
    """

    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.datetime.now().isoformat())
    target: str = ""
    stats: Dict[str, Any] = field(default_factory=dict)
    config: Dict[str, Any] = field(default_factory=dict)
    summary: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Initialize default values and convert vulnerabilities to objects if needed."""
        # Convert vulnerability dictionaries to objects if needed
        vuln_objects = []
        for vuln in self.vulnerabilities:
            if isinstance(vuln, dict):
                vuln_objects.append(Vulnerability.from_dict(vuln))
            else:
                vuln_objects.append(vuln)
        self.vulnerabilities = vuln_objects

        # Initialize summary if not provided
        if not self.summary:
            self.generate_summary()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AnalysisResults":
        """
        Create an AnalysisResults instance from a dictionary.

        Args:
            data: Dictionary with analysis results data

        Returns:
            AnalysisResults instance
        """
        # Extract vulnerabilities
        vuln_data = data.get("vulnerabilities", [])
        vulnerabilities = [
            Vulnerability.from_dict(v) if isinstance(v, dict) else v for v in vuln_data
        ]

        return cls(
            vulnerabilities=vulnerabilities,
            timestamp=data.get("timestamp", datetime.datetime.now().isoformat()),
            target=data.get("target", ""),
            stats=data.get("stats", {}),
            config=data.get("config", {}),
            summary=data.get("summary", {}),
        )

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for serialization.

        Returns:
            Dictionary representation
        """
        return {
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "timestamp": self.timestamp,
            "target": self.target,
            "stats": self.stats,
            "config": self.config,
            "summary": self.summary,
        }

    def generate_summary(self) -> Dict[str, Any]:
        """
        Generate a summary of the analysis results.

        Returns:
            Summary dictionary
        """
        # Count vulnerabilities by rule
        by_rule = {}
        for vuln in self.vulnerabilities:
            rule = vuln.rule
            by_rule[rule] = by_rule.get(rule, 0) + 1

        # Count vulnerabilities by severity
        by_severity = {}
        for vuln in self.vulnerabilities:
            severity = vuln.severity
            by_severity[severity] = by_severity.get(severity, 0) + 1

        # Count vulnerabilities by file
        by_file = {}
        for vuln in self.vulnerabilities:
            file = vuln.file
            by_file[file] = by_file.get(file, 0) + 1

        # Create summary
        self.summary = {
            "total": len(self.vulnerabilities),
            "by_rule": by_rule,
            "by_severity": by_severity,
            "by_file": by_file,
        }

        return self.summary

    def get_high_severity_vulnerabilities(self) -> List[Vulnerability]:
        """
        Get all high severity vulnerabilities.

        Returns:
            List of high severity vulnerabilities
        """
        return [v for v in self.vulnerabilities if v.severity.lower() == "high"]

    def get_vulnerabilities_by_rule(self, rule: str) -> List[Vulnerability]:
        """
        Get all vulnerabilities matching a specific rule.

        Args:
            rule: Rule name to filter by

        Returns:
            List of vulnerabilities matching the rule
        """
        return [v for v in self.vulnerabilities if v.rule == rule]

    def get_vulnerabilities_by_file(self, file_path: str) -> List[Vulnerability]:
        """
        Get all vulnerabilities in a specific file.

        Args:
            file_path: File path to filter by

        Returns:
            List of vulnerabilities in the file
        """
        return [v for v in self.vulnerabilities if v.file == file_path]
