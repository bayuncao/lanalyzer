#!/usr/bin/env python3
"""
Base CLI functionality for LAnaLyzer.

Provides the main entry point and shared CLI functionality.
"""

import argparse
import sys
from typing import List, Optional

from lanalyzer.cli.enhanced import enhanced_cli_main


def create_parser() -> argparse.ArgumentParser:
    """
    Create the command-line argument parser.

    Returns:
        argparse.ArgumentParser: The argument parser
    """
    parser = argparse.ArgumentParser(
        description="Lanalyzer - Enhanced Python taint analysis tool"
    )

    # Since only enhanced mode exists, subcommands are no longer needed
    # Directly use enhanced mode parameters as main parameters
    parser.add_argument(
        "--target",
        required=True,
        help="Target file or directory to analyze",
    )
    parser.add_argument(
        "--config",
        help="Path to configuration file (JSON)",
    )
    parser.add_argument("--output", help="Path to output file (JSON)")
    parser.add_argument(
        "--pretty", action="store_true", help="Pretty-print JSON output"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument(
        "--list-files",
        action="store_true",
        help="List all Python files that would be analyzed",
    )

    parser.add_argument(
        "--log-file",
        help="Path to log file for debug and analysis output",
    )

    return parser


def main(args: Optional[List[str]] = None) -> int:
    """
    Main entry point for the CLI.

    Args:
        args: Command-line arguments

    Returns:
        Exit code
    """
    # 直接调用enhanced_cli_main
    return enhanced_cli_main()


if __name__ == "__main__":
    sys.exit(main())
