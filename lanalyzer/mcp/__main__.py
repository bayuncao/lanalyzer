#!/usr/bin/env python3
"""
MCP模块的主入口点，允许通过python -m lanalyzer.mcp执行。
使用FastMCP实现。
"""

import sys
from lanalyzer.mcp.mcp_cmd import cli

if __name__ == "__main__":
    sys.exit(cli())  # 直接调用cli函数而不是main
