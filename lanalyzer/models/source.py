"""
Source model for LanaLyzer.

Represents sources of untrusted data in the analyzed code.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List

from lanalyzer.models.base import BaseModel, Location


@dataclass
class Source(BaseModel):
    """
    Represents a source of untrusted data in the code.

    A source is a function or method that returns untrusted data, such as
    user input, file content, or network data.

    Attributes:
        name: Name of the source type (e.g., 'UserInput', 'FileRead')
        patterns: List of function/method names that are considered sources
        function_name: Name of the function that was called
        location: Location where the source was found
        context: Additional context information about the source
    """

    name: str
    patterns: List[str] = field(default_factory=list)
    function_name: str = ""
    location: Location = field(default_factory=Location)
    context: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Initialize default values if needed."""
        if isinstance(self.location, dict):
            self.location = Location(**self.location)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Source":
        """
        Create a Source instance from a dictionary.

        Args:
            data: Dictionary with source data

        Returns:
            Source instance
        """
        # Extract location data if present
        location_data = data.pop("location", None)
        if location_data:
            location = Location(**location_data)
        else:
            # Legacy format support
            location = Location(
                file=data.pop("file", ""),
                line=data.pop("line", 0),
                col=data.pop("col", 0),
            )

        return cls(
            name=data.get("name", "Unknown"),
            patterns=data.get("patterns", []),
            function_name=data.get("function_name", ""),
            location=location,
            context=data.get("context", {}),
        )

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for serialization.

        Returns:
            Dictionary representation
        """
        return {
            "name": self.name,
            "patterns": self.patterns,
            "function_name": self.function_name,
            "location": self.location.to_dict() if self.location else {},
            "context": self.context,
        }

    def get_description(self) -> str:
        """
        Get a human-readable description of the source.

        Returns:
            Description string
        """
        if self.function_name:
            return f"{self.name} source from {self.function_name}() at {self.location}"
        return f"{self.name} source at {self.location}"
