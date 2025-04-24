"""
Taint models for LanaLyzer.

This module provides models for representing taint sources, sinks and flows.
Some functionality has been moved to the enhanced analysis module and may be removed in future versions.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from lanalyzer.models.base import BaseModel, Location


@dataclass
class TaintSource(BaseModel):
    """
    Represents a source of tainted data.

    A source is a function or method that returns data that can be controlled
    by an attacker or comes from an untrusted source.

    Note: This implementation may be deprecated in favor of enhanced analysis module.
    """

    name: str
    pattern: str
    description: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "name": self.name,
            "pattern": self.pattern,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TaintSource":
        """Create from dictionary."""
        return cls(
            name=data["name"],
            pattern=data["pattern"],
            description=data.get("description"),
        )


@dataclass
class TaintSink(BaseModel):
    """
    Represents a sink for tainted data.

    A sink is a function or method that can be potentially dangerous if
    called with tainted (untrusted) data.

    Note: This implementation may be deprecated in favor of enhanced analysis module.
    """

    name: str
    pattern: str
    vulnerability_type: str
    description: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "name": self.name,
            "pattern": self.pattern,
            "vulnerability_type": self.vulnerability_type,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TaintSink":
        """Create from dictionary."""
        return cls(
            name=data["name"],
            pattern=data["pattern"],
            vulnerability_type=data["vulnerability_type"],
            description=data.get("description"),
        )


@dataclass
class TaintFlow(BaseModel):
    """
    Represents a flow of tainted data from a source to a sink.

    A taint flow indicates a potential vulnerability where untrusted data
    from a source reaches a potentially dangerous sink.

    Note: This implementation may be deprecated in favor of enhanced analysis module.
    """

    source: TaintSource
    sink: TaintSink
    vulnerability_type: str
    confidence: float = 100.0
    source_location: Optional[Location] = None
    sink_location: Optional[Location] = None
    path: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "source": self.source.to_dict(),
            "sink": self.sink.to_dict(),
            "vulnerability_type": self.vulnerability_type,
            "confidence": self.confidence,
            "source_location": self.source_location.to_dict()
            if self.source_location
            else None,
            "sink_location": self.sink_location.to_dict()
            if self.sink_location
            else None,
            "path": self.path,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TaintFlow":
        """Create from dictionary."""
        source = TaintSource.from_dict(data["source"])
        sink = TaintSink.from_dict(data["sink"])

        source_location = None
        if data.get("source_location"):
            source_location = Location.from_dict(data["source_location"])

        sink_location = None
        if data.get("sink_location"):
            sink_location = Location.from_dict(data["sink_location"])

        return cls(
            source=source,
            sink=sink,
            vulnerability_type=data["vulnerability_type"],
            confidence=data.get("confidence", 100.0),
            source_location=source_location,
            sink_location=sink_location,
            path=data.get("path", []),
        )
