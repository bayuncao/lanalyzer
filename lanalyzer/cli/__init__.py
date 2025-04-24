"""
LAnaLyzer Command Line Interface Package

This package contains the command line interface implementation for LAnaLyzer.
Correct usage involves importing specific modules rather than executing the package directly.
"""

# 预导入以避免循环导入和导入顺序问题
from lanalyzer.cli.log_utils import LogTee, get_timestamp
from lanalyzer.cli.file_utils import list_target_files, gather_target_files
from lanalyzer.cli.config_utils import load_configuration, save_output

from lanalyzer.cli.enhanced import main, enhanced_cli_main

__all__ = ["main", "enhanced_cli_main"]
