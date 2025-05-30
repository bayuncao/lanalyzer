#!/usr/bin/env python

"""
Main entry point for the lanalyzer command-line tool.
"""

import sys
import traceback

from lanalyzer.cli.enhanced import enhanced_cli_main
from lanalyzer.logger import error, setup_application_logging


def run_lanalyzer() -> int:  # Added return type hint
    """Run the lanalyzer CLI."""
    # Setup basic logging
    # Debug status can be re-evaluated by enhanced_cli_main if it parses args
    setup_application_logging(debug=("--debug" in sys.argv))

    try:
        # enhanced_cli_main is expected to handle Click's standalone_mode internally
        # or sys.exit itself if it's a Click command group.
        # If enhanced_cli_main is a simple function returning an exit code:
        exit_code = enhanced_cli_main()
        return exit_code if isinstance(exit_code, int) else 0
    except SystemExit as e:
        # Click's main entry points often raise SystemExit.
        # We should let these propagate or return their exit code.
        return (
            e.code if isinstance(e.code, int) else 1
        )  # Default to 1 if code is None or not int
    except Exception as e:
        error(f"Error: {e}")
        # Check for debug flag to print full traceback
        if (
            "--debug" in sys.argv
        ):  # Simple check, Click's context is better if available
            error("Traceback:")
            error(traceback.format_exc())
        return 1


if __name__ == "__main__":
    sys.exit(run_lanalyzer())
