"""
Base formatter for LanaLyzer output.

Defines the interface for different output formatters.
"""

import abc
import sys
from typing import IO, Any, Dict, List, Optional


class OutputFormatter(abc.ABC):
    """Base class for all output formatters."""

    @abc.abstractmethod
    def format_results(
        self, vulnerabilities: List[Dict[str, Any]], **kwargs: Any
    ) -> str:
        """
        Format analysis results as a string.

        Args:
            vulnerabilities: List of vulnerability dictionaries.
            **kwargs: Additional formatter-specific options.

        Returns:
            Formatted results as a string.
        """
        pass

    @abc.abstractmethod
    def write_results(
        self,
        vulnerabilities: List[Dict[str, Any]],
        output_file: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """
        Write formatted results to a file or stdout.

        Args:
            vulnerabilities: List of vulnerability dictionaries.
            output_file: Path to output file (None for stdout).
            **kwargs: Additional formatter-specific options.
        """
        pass

    def _get_output_stream(self, output_file: Optional[str] = None) -> IO[str]:
        """
        Get the output stream for writing results.

        Args:
            output_file: Path to output file (None for stdout).

        Returns:
            File-like object for writing.
        """
        if output_file:
            # Ensure encoding is specified for consistency, utf-8 is a safe default.
            return open(output_file, "w", encoding="utf-8")
        return sys.stdout
