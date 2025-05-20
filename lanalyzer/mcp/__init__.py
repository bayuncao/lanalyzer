"""
Model Context Protocol (MCP) support for Lanalyzer.

This module provides MCP server implementation for Lanalyzer,
allowing it to be integrated with MCP-enabled tools and services.
"""

try:
    from fastmcp import FastMCP, Context
except ImportError:
    raise ImportError(
        "FastMCP dependency not found. "
        "Please install with `pip install lanalyzer[mcp]` "
        "or `pip install fastmcp`"
    )

from .server import *
from .cli import *
from .tools import *
from .handlers import *
from .models import *

__all__ = [
    "FastMCP",
    "Context",
    # server
    "create_mcp_server",
    "server",
    "STREAMABLE_HTTP_AVAILABLE",
    # cli
    "cli",
    # tools
    "analyze_code",
    "analyze_file",
    "get_config",
    "validate_config",
    "create_config",
    # handlers
    "LanalyzerMCPHandler",
    # models
    "AnalysisRequest",
    "AnalysisResponse",
    "ConfigurationRequest",
    "ConfigurationResponse",
    "VulnerabilityInfo",
    "FileAnalysisRequest",
    "ExplainVulnerabilityRequest",
    "ExplainVulnerabilityResponse",
    "ServerInfoResponse",
]

if __name__ == "__main__":
    import sys

    sys.exit(cli())
