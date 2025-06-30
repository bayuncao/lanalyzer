#!/usr/bin/env python3
"""
Main entry point for the MCP module, allowing execution via `python -m lanalyzer.mcp`.
Based on FastMCP implementation.
"""

import sys

from .server.mcpserver import cli

if __name__ == "__main__":
    sys.exit(cli())
