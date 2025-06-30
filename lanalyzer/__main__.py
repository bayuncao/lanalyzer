#!/usr/bin/env python
"""
Lanalyzer package main entry point, allowing execution via `python -m lanalyzer`.
"""

import sys

from lanalyzer.main import run_lanalyzer

if __name__ == "__main__":
    sys.exit(run_lanalyzer())
