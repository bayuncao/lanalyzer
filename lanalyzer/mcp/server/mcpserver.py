#!/usr/bin/env python
"""
MCP server command-line entry point, implemented using FastMCP.
Provides Model Context Protocol (MCP) functionality for lanalyzer.
"""

import logging
from typing import Optional, Dict, Any

try:
    # Import FastMCP core components
    from fastmcp import FastMCP, Context

    # Check if streamable HTTP support is available
    try:
        from fastmcp.transport.streamable_http import StreamableHTTPTransport
        from fastmcp.storage.memory import InMemoryEventStore

        STREAMABLE_HTTP_AVAILABLE = True
    except ImportError:
        STREAMABLE_HTTP_AVAILABLE = False
except ImportError:
    raise ImportError(
        "FastMCP dependency not found. "
        "Please install with `pip install lanalyzer[mcp]` "
        "or `pip install fastmcp`"
    )

from lanalyzer.__version__ import __version__
from lanalyzer.mcp.handlers import LanalyzerMCPHandler
from lanalyzer.mcp.tools import (
    analyze_code,
    analyze_file,
    get_config,
    validate_config,
    create_config,
)
from lanalyzer.mcp.cli import cli
from lanalyzer.mcp.utils import debug_tool_args


def create_mcp_server(debug: bool = False) -> FastMCP:
    """
    Create FastMCP server instance.

    This is the core factory function for the MCP module, used to create and configure FastMCP server instances.

    Args:
        debug: Whether to enable debug mode.

    Returns:
        FastMCP: Server instance.
    """
    # Configure logging level
    log_level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Check FastMCP version
    try:
        fastmcp_version = __import__("fastmcp").__version__
        logging.info(f"FastMCP version: {fastmcp_version}")
    except (ImportError, AttributeError):
        logging.warning("Could not determine FastMCP version")
        fastmcp_version = "unknown"

    # Create FastMCP instance - with proper configuration for initialization
    mcp_instance = FastMCP(  # Renamed to avoid conflict with mcp subcommand
        "Lanalyzer",
        title="Lanalyzer - Python Taint Analysis Tool",
        description="MCP server for Lanalyzer, providing taint analysis for Python code to detect security vulnerabilities.",
        version=__version__,
        debug=debug,
        # Add session expiration and initialization settings to improve client connections
        session_keepalive_timeout=120,  # 2 minutes keepalive
        session_expiry_timeout=1800,  # 30 minutes overall session expiry
        initialization_timeout=5.0,  # 5 seconds initialization timeout
    )

    # Create handler instance
    handler = LanalyzerMCPHandler(debug=debug)

    # Enable request logging in debug mode
    if debug:
        try:

            @mcp_instance.middleware  # Use the renamed mcp_instance
            async def log_requests(request, call_next):
                """Middleware to log requests and responses"""
                logging.debug(f"Received request: {request.method} {request.url}")
                try:
                    if request.method == "POST":
                        body = await request.json()
                        logging.debug(f"Request body: {body}")
                except Exception as e:
                    logging.debug(f"Could not parse request body: {e}")

                response = await call_next(request)
                return response

        except AttributeError:
            # If FastMCP does not support middleware, log a warning
            logging.warning(
                "Current FastMCP version does not support middleware, request logging will be disabled"
            )

    # Register tools with the handler wrapped in debug_tool_args if debug mode is enabled
    @mcp_instance.tool()
    async def analyze_code_wrapper(
        code: str,
        file_path: str,
        config_path: str,
        ctx: Optional[Context] = None,
    ) -> Dict[str, Any]:
        """Wrapper for analyze_code tool that includes handler instance."""
        return await analyze_code(code, file_path, config_path, handler, ctx)

    @mcp_instance.tool()
    async def analyze_file_wrapper(
        file_path: str,
        config_path: str,
        ctx: Optional[Context] = None,
    ) -> Dict[str, Any]:
        """Wrapper for analyze_file tool that includes handler instance."""
        return await analyze_file(file_path, config_path, handler, ctx)

    @mcp_instance.tool()
    async def get_config_wrapper(
        config_path: Optional[str] = None,
        ctx: Optional[Context] = None,
    ) -> Dict[str, Any]:
        """Wrapper for get_config tool that includes handler instance."""
        return await get_config(handler, config_path, ctx)

    @mcp_instance.tool()
    async def validate_config_wrapper(
        config_data: Optional[Dict[str, Any]] = None,
        config_path: Optional[str] = None,
        ctx: Optional[Context] = None,
    ) -> Dict[str, Any]:
        """Wrapper for validate_config tool that includes handler instance."""
        return await validate_config(handler, config_data, config_path, ctx)

    @mcp_instance.tool()
    async def create_config_wrapper(
        config_data: Dict[str, Any],
        config_path: Optional[str] = None,
        ctx: Optional[Context] = None,
    ) -> Dict[str, Any]:
        """Wrapper for create_config tool that includes handler instance."""
        return await create_config(handler, config_data, config_path, ctx)

    # Apply debug decorators if debug mode is enabled
    if debug:
        analyze_code_wrapper = debug_tool_args(analyze_code_wrapper)
        analyze_file_wrapper = debug_tool_args(analyze_file_wrapper)
        get_config_wrapper = debug_tool_args(get_config_wrapper)
        validate_config_wrapper = debug_tool_args(validate_config_wrapper)
        create_config_wrapper = debug_tool_args(create_config_wrapper)

    return mcp_instance


# Provide temporary server variable for FastMCP command line compatibility
# This instance is created with default debug=False.
# The 'run' command will create its own instance with its specific debug flag.
# The 'mcpcmd' (fastmcp dev/run) will refer to this 'server' instance.
server = create_mcp_server()


if __name__ == "__main__":
    cli()
