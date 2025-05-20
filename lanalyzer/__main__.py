#!/usr/bin/env python
"""
Lanalyzer 包的主入口点，允许通过 python -m lanalyzer 执行。
"""

import sys
from lanalyzer.main import run_lanalyzer

if __name__ == "__main__":
    sys.exit(run_lanalyzer())
