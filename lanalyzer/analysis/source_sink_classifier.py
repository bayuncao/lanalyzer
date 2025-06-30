"""source_sink_classifier.py
Extract source/sink classification judgment logic for use by AST visitors, etc.
"""
from __future__ import annotations

import re
from typing import Optional

from lanalyzer.logger import get_logger

logger = get_logger("lanalyzer.analysis.source_sink_classifier")


class SourceSinkClassifier:
    """Judgement logic for classifying functions as sources or sinks based on configuration."""

    def __init__(self, visitor) -> None:
        # The visitor must expose .sources, .sinks, .debug, and import mappings
        self.visitor = visitor
        # For storage of new architecture configuration
        self._sources = []
        self._sinks = []
        self.config = None

    def configure(self, sources, sinks, config=None):
        """Configure source and sink definitions (for new architecture)"""
        self._sources = sources or []
        self._sinks = sinks or []
        self.config = config
        # Also update visitor attributes for compatibility
        if hasattr(self.visitor, "sources"):
            self.visitor.sources = self._sources
        if hasattr(self.visitor, "sinks"):
            self.visitor.sinks = self._sinks

    @property
    def sources(self):
        """Get source configuration"""
        if hasattr(self.visitor, "sources") and self.visitor.sources:
            return self.visitor.sources
        return self._sources

    @property
    def sinks(self):
        """Get sink configuration"""
        if hasattr(self.visitor, "sinks") and self.visitor.sinks:
            return self.visitor.sinks
        return self._sinks

    # --------------------------- public helpers ---------------------------
    def is_source(self, func_name: str, full_name: Optional[str] = None) -> bool:
        return self._match_patterns(self.sources, func_name, full_name)

    def source_type(self, func_name: str, full_name: Optional[str] = None) -> str:
        return self._get_type(self.sources, func_name, full_name)

    def is_sink(self, func_name: str, full_name: Optional[str] = None) -> bool:
        return self._match_patterns(self.sinks, func_name, full_name)

    def sink_type(self, func_name: str, full_name: Optional[str] = None) -> str:
        return self._get_type(self.sinks, func_name, full_name)

    def sink_vulnerability_type(self, sink_type: str) -> str:
        for sink in self.sinks:
            if sink.get("name") == sink_type:
                return sink.get("vulnerability_type", "vulnerability")
        return "vulnerability"

    # --------------------------- internal utils ---------------------------
    @staticmethod
    def _match_patterns(config_list, func_name: str, full_name: Optional[str]) -> bool:
        if not isinstance(func_name, str):
            return False
        if full_name is not None and not isinstance(full_name, str):
            full_name = None
        for item in config_list:
            for pattern in item.get("patterns", []):
                # Normalize pattern by removing trailing parentheses for function calls
                normalized_pattern = pattern.rstrip("(")

                # Direct match with normalized pattern
                if normalized_pattern == func_name or (
                    full_name and normalized_pattern == full_name
                ):
                    return True

                # Check if pattern is contained in full_name
                if pattern in (full_name or ""):
                    return True

                # Check if normalized pattern is contained in full_name
                if normalized_pattern in (full_name or ""):
                    return True

                # Wildcard matching
                if "*" in pattern:
                    regex_pattern = pattern.replace(".", "\\.").replace("*", ".*")
                    if re.match(regex_pattern, func_name) or (
                        full_name and re.match(regex_pattern, full_name)
                    ):
                        return True
        return False

    @staticmethod
    def _get_type(config_list, func_name: str, full_name: Optional[str]) -> str:
        if full_name is not None and not isinstance(full_name, str):
            full_name = None
        for item in config_list:
            for pattern in item.get("patterns", []):
                # Normalize pattern by removing trailing parentheses for function calls
                normalized_pattern = pattern.rstrip("(")

                # Direct match with normalized pattern
                if normalized_pattern == func_name or (
                    full_name and normalized_pattern == full_name
                ):
                    return item.get("name", "Unknown")

                # Check if pattern is contained in full_name
                if pattern in (full_name or ""):
                    return item.get("name", "Unknown")

                # Check if normalized pattern is contained in full_name
                if normalized_pattern in (full_name or ""):
                    return item.get("name", "Unknown")

                # Wildcard matching
                if "*" in pattern:
                    regex_pattern = pattern.replace(".", "\\.").replace("*", ".*")
                    if re.match(regex_pattern, func_name) or (
                        full_name and re.match(regex_pattern, full_name)
                    ):
                        return item.get("name", "Unknown")
        return "Unknown"
