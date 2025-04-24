"""
Base models for LanaLyzer.

Provides the base model classes that other models will inherit from.
"""

import abc
from typing import Any, Dict


class BaseModel(abc.ABC):
    """Base class for all LanaLyzer models."""

    @abc.abstractmethod
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the model to a dictionary for serialization.

        Returns:
            Dictionary representation of the model
        """
        pass

    def __str__(self) -> str:
        """
        Get a string representation of the model.

        Returns:
            String representation
        """
        return str(self.to_dict())

    def __repr__(self) -> str:
        """
        Get a developer-friendly representation of the model.

        Returns:
            Developer-friendly representation
        """
        class_name = self.__class__.__name__
        attrs = [f"{k}={repr(v)}" for k, v in self.to_dict().items()]
        return f"{class_name}({', '.join(attrs)})"


class Location:
    """
    Represents a location in a source file.

    This is used to track where in the source code a model element was found.
    """

    def __init__(
        self,
        file: str = "",
        line: int = 0,
        col: int = 0,
        end_line: int = 0,
        end_col: int = 0,
    ):
        """
        Initialize the location.

        Args:
            file: Path to the source file
            line: Line number (1-indexed)
            col: Column number (1-indexed)
            end_line: End line number (1-indexed, inclusive)
            end_col: End column number (1-indexed, inclusive)
        """
        self.file = file
        self.line = line
        self.col = col
        self.end_line = end_line or line  # Default to single-line location
        self.end_col = end_col or col  # Default to single-column location

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for serialization.

        Returns:
            Dictionary representation
        """
        return {
            "file": self.file,
            "line": self.line,
            "col": self.col,
            "end_line": self.end_line,
            "end_col": self.end_col,
        }

    def __str__(self) -> str:
        """
        Get a string representation of the location.

        Returns:
            String in the format "file:line:col"
        """
        return f"{self.file}:{self.line}:{self.col}"

    def __repr__(self) -> str:
        """
        Get a developer-friendly representation of the location.

        Returns:
            Developer-friendly representation
        """
        return (
            f"Location(file='{self.file}', line={self.line}, col={self.col}, "
            f"end_line={self.end_line}, end_col={self.end_col})"
        )
