"""
Settings module for LanaLyzer.

This module provides the Settings class for configuration management.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Settings:
    """
    Configuration settings for the LanaLyzer tool.

    This class provides a structured way to manage configuration options
    for the taint analysis process.
    """

    # Analysis depth settings
    max_depth: int = 5
    follow_imports: bool = False
    analyze_dependencies: bool = False

    # Taint propagation settings
    ignore_sanitizers: bool = False
    max_iterations: int = 50

    # Rule settings
    sources: List[Dict[str, Any]] = field(default_factory=list)
    sinks: List[Dict[str, Any]] = field(default_factory=list)
    sanitizers: List[Dict[str, Any]] = field(default_factory=list)

    # Reporting settings
    minimum_confidence: float = 50.0
    report_template: Optional[str] = None
    report_format: str = "html"

    # Output settings
    output_file: Optional[str] = None
    pretty_print: bool = True

    # Debug settings
    debug: bool = False
    verbose: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert settings to a dictionary.

        Returns:
            Dictionary representation of the settings
        """
        return {
            "max_depth": self.max_depth,
            "follow_imports": self.follow_imports,
            "analyze_dependencies": self.analyze_dependencies,
            "ignore_sanitizers": self.ignore_sanitizers,
            "max_iterations": self.max_iterations,
            "sources": self.sources,
            "sinks": self.sinks,
            "sanitizers": self.sanitizers,
            "minimum_confidence": self.minimum_confidence,
            "report_template": self.report_template,
            "report_format": self.report_format,
            "output_file": self.output_file,
            "pretty_print": self.pretty_print,
            "debug": self.debug,
            "verbose": self.verbose,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Settings":
        """
        Create settings from a dictionary.

        Args:
            data: Dictionary containing settings

        Returns:
            Settings object
        """
        return cls(
            max_depth=data.get("max_depth", 5),
            follow_imports=data.get("follow_imports", False),
            analyze_dependencies=data.get("analyze_dependencies", False),
            ignore_sanitizers=data.get("ignore_sanitizers", False),
            max_iterations=data.get("max_iterations", 50),
            sources=data.get("sources", []),
            sinks=data.get("sinks", []),
            sanitizers=data.get("sanitizers", []),
            minimum_confidence=data.get("minimum_confidence", 50.0),
            report_template=data.get("report_template"),
            report_format=data.get("report_format", "html"),
            output_file=data.get("output_file"),
            pretty_print=data.get("pretty_print", True),
            debug=data.get("debug", False),
            verbose=data.get("verbose", False),
        )
