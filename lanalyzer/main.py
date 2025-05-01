#!/usr/bin/env python

"""
Main entry point for the lanalyzer command-line tool.
"""

import sys
import traceback

from lanalyzer.cli.enhanced import enhanced_cli_main
from lanalyzer.logger import error, setup_application_logging


def run_lanalyzer():
    """Run the lanalyzer CLI."""
    # 设置基本日志
    setup_application_logging(debug=False)

    try:
        return enhanced_cli_main()
    except Exception as e:
        error(f"错误: {e}")
        if "--debug" in sys.argv:
            error(traceback.format_exc())
        return 1


if __name__ == "__main__":
    sys.exit(run_lanalyzer())
