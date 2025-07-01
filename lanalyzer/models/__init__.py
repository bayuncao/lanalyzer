"""
Data models for LanaLyzer.

This package provides data models for representing sources, sinks, vulnerabilities and analysis results.
"""

from lanalyzer.models.base import BaseModel, Location
from lanalyzer.models.results import AnalysisResults
from lanalyzer.models.sink import Sink
from lanalyzer.models.source import Source
from lanalyzer.models.vulnerability import Vulnerability

__all__ = [
    "BaseModel",
    "Location",
    "Source",
    "Sink",
    "Vulnerability",
    "AnalysisResults",
]
