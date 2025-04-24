#!/usr/bin/env python

"""
Main entry point for the lanalyzer command-line tool.
"""

import sys

from lanalyzer.cli.enhanced import enhanced_cli_main


def run_lanalyzer():
    """Run the lanalyzer CLI."""
    try:
        return enhanced_cli_main()
    except Exception as e:
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(run_lanalyzer())
