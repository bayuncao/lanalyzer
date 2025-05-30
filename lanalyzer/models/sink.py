"""
Sink model for LanaLyzer.

Represents sinks where untrusted data could lead to vulnerabilities.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List

from lanalyzer.models.base import BaseModel, Location


@dataclass
class Sink(BaseModel):
    """
    Represents a sink where untrusted data could lead to vulnerabilities.

    A sink is a function or method that could lead to vulnerabilities if called
    with untrusted data, such as SQL queries, command execution, or file operations.

    Attributes:
        name: Name of the sink type (e.g., 'SQLQuery', 'CommandExecution')
        patterns: List of function/method names that are considered sinks
        function_name: Name of the function that was called
        location: Location where the sink was found
        tainted_args: List of tainted arguments passed to the sink
        tainted_arg_indices: List of indices of tainted arguments
        context: Additional context information about the sink
    """

    name: str
    patterns: List[str] = field(default_factory=list)
    function_name: str = ""
    location: Location = field(default_factory=Location)
    tainted_args: List[Dict[str, Any]] = field(default_factory=list)
    tainted_arg_indices: List[int] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Initialize default values if needed."""
        if isinstance(self.location, dict):
            self.location = Location(**self.location)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Sink":
        """
        Create a Sink instance from a dictionary.

        Args:
            data: Dictionary with sink data

        Returns:
            Sink instance
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
            tainted_args=data.get("tainted_args", []),
            tainted_arg_indices=data.get("tainted_arg_indices", []),
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
            "tainted_args": self.tainted_args,
            "tainted_arg_indices": self.tainted_arg_indices,
            "context": self.context,
        }

    def get_description(self) -> str:
        """
        Get a human-readable description of the sink.

        Returns:
            Description string
        """
        if self.function_name:
            args_info = ""
            if self.tainted_arg_indices:
                args_info = f" (tainted argument(s): {', '.join(map(str, self.tainted_arg_indices))})"

            return f"{self.name} sink in {self.function_name}(){args_info} at {self.location}"

        return f"{self.name} sink at {self.location}"
