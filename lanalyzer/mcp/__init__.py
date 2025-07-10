"""
Model Context Protocol (MCP) support for Lanalyzer.

This module provides MCP server implementation for Lanalyzer,
allowing it to be integrated with MCP-enabled tools and services.
"""

try:
    from fastmcp import Context, FastMCP
except ImportError:
    raise ImportError(
        "FastMCP dependency not found. "
        "Please install with `pip install lanalyzer[mcp]` "
        "or `pip install fastmcp`"
    )

from .cli import *
from .exceptions import (
    MCPAnalysisError,
    MCPConfigurationError,
    MCPDependencyError,
    MCPError,
    MCPFileError,
    MCPInitializationError,
    MCPToolError,
    MCPTransportError,
    MCPValidationError,
)
from .handlers import *
from .models import *
from .server import *
from .settings import LogLevel, MCPClientSettings, MCPServerSettings, TransportType
from .tools import *

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
    "analyze_path",
    "get_config",
    "validate_config",
    "create_config",
    "explain_vulnerabilities",
    "write_vulnerability_report",
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
    "VulnerabilityReportRequest",
    "VulnerabilityReportResponse",
    "ReportType",
    # settings
    "MCPServerSettings",
    "MCPClientSettings",
    "TransportType",
    "LogLevel",
    # exceptions
    "MCPError",
    "MCPConfigurationError",
    "MCPAnalysisError",
    "MCPValidationError",
    "MCPTransportError",
    "MCPInitializationError",
    "MCPToolError",
    "MCPDependencyError",
    "MCPFileError",
]

if __name__ == "__main__":
    import sys

    sys.exit(cli())
