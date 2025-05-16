#!/usr/bin/env python3
"""
MCP模块的主入口点，允许通过python -m lanalyzer.mcp执行。
基于FastMCP实现。
"""

import sys
from lanalyzer.mcp.mcpserver import cli

if __name__ == "__main__":
    sys.exit(cli())
