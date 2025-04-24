"""
Command Line Interface for LAnaLyzer.

This module provides the command-line interface for the LAnaLyzer tool.
"""

from lanalyzer.cli.base import main
from lanalyzer.cli.enhanced import enhanced_cli_main

__all__ = ["main", "enhanced_cli_main"]
