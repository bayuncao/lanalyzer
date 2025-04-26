"""
Model Context Protocol (MCP) support for Lanalyzer.

This module provides MCP server implementation for Lanalyzer,
allowing it to be integrated with MCP-enabled tools and services.
"""

from lanalyzer.mcp.server import MCPServer
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
)

__all__ = [
    "MCPServer",
    "LanalyzerMCPHandler",
    "AnalysisRequest",
    "AnalysisResponse",
    "ConfigurationRequest",
    "ConfigurationResponse",
    "VulnerabilityInfo",
    "FileAnalysisRequest",
    "ExplainVulnerabilityRequest",
    "ExplainVulnerabilityResponse",
]
