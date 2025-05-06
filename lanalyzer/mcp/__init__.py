"""
Model Context Protocol (MCP) support for Lanalyzer.

This module provides MCP server implementation for Lanalyzer,
allowing it to be integrated with MCP-enabled tools and services.
现在使用FastMCP提供更强大的MCP功能。
"""

try:
    from fastmcp import FastMCP, Context
except ImportError:
    raise ImportError(
        "FastMCP dependency not found. "
        "Please install with `pip install lanalyzer[mcp]` "
        "or `pip install fastmcp`"
    )

# 导入主要MCP组件
from lanalyzer.mcp.mcp_cmd import mcp as mcp_server, server, create_mcp_server, cli

# 导入处理器
from lanalyzer.mcp.handlers import LanalyzerMCPHandler

# 导入数据模型
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
    # MCP核心组件
    "FastMCP",
    "Context",
    "mcp_server",
    "server",
    "create_mcp_server",
    "cli",
    # 处理器
    "LanalyzerMCPHandler",
    # 数据模型
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
