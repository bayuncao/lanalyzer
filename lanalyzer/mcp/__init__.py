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

from lanalyzer.mcp.mcpserver import create_mcp_server, cli

from lanalyzer.mcp.handlers import LanalyzerMCPHandler

from lanalyzer.mcp.models import (
    AnalysisRequest,
    AnalysisResponse,
    ConfigurationRequest,
    ConfigurationResponse,
    VulnerabilityInfo,
    FileAnalysisRequest,
    ExplainVulnerabilityRequest,
    ExplainVulnerabilityResponse,
    ServerInfoResponse,
)

__all__ = [
    "FastMCP",
    "Context",
    "create_mcp_server",
    "cli",
    "LanalyzerMCPHandler",
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
