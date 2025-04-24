"""
LAnaLyzer - Python Taint Analysis Tool

A static analysis tool for detecting potential vulnerabilities in Python code
through taint analysis.
"""

__version__ = "0.1.0"
__author__ = "LAnaLyzer Team"

# Public API imports for easy access
from lanalyzer.cli.enhanced import main
from lanalyzer.output.report_generator import ReportGenerator

# Define what's available when using "from lanalyzer import *"
__all__ = [
    "main",
    "TaintAnalyzer",
    "TaintSource",
    "TaintSink",
    "TaintFlow",
    "ReportGenerator",
    "Settings",
]
