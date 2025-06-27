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
    from ..exceptions import MCPDependencyError
    raise MCPDependencyError(
        "FastMCP dependency not found.",
        missing_packages=["fastmcp"],
        install_command="pip install lanalyzer[mcp] or pip install fastmcp"
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
from lanalyzer.mcp.settings import MCPServerSettings, TransportType
from lanalyzer.mcp.exceptions import MCPError, MCPInitializationError, handle_exception


def create_mcp_server(
    settings: Optional[MCPServerSettings] = None,
    debug: Optional[bool] = None
) -> FastMCP:
    """
    Create FastMCP server instance.

    This is the core factory function for the MCP module, used to create and configure FastMCP server instances.

    Args:
        settings: Server configuration settings. If None, uses default settings.
        debug: Whether to enable debug mode. If None, uses settings.debug.

    Returns:
        FastMCP: Server instance.

    Raises:
        MCPInitializationError: If server initialization fails.
    """
    try:
        # Use provided settings or create default
        if settings is None:
            settings = MCPServerSettings()

        # Override debug setting if explicitly provided
        if debug is not None:
            settings.debug = debug

        # Configure logging level
        log_level = getattr(logging, settings.log_level.value)
        logging.basicConfig(
            level=log_level,
            format=settings.log_format,
            force=True,  # Ensure reconfiguration
        )

        # Check FastMCP version
        try:
            fastmcp_version = __import__("fastmcp").__version__
            logging.info(f"FastMCP version: {fastmcp_version}")
        except (ImportError, AttributeError):
            logging.warning("Could not determine FastMCP version")
            fastmcp_version = "unknown"

        # Create FastMCP instance with correct API parameters
        # Note: debug, host, port, json_response should be passed to run() method instead
        mcp_instance = FastMCP(
            name=settings.name,
            instructions=settings.description,
            version=__version__,
        )

        # Create handler instance
        handler = LanalyzerMCPHandler(debug=settings.debug)

        # Enable request logging in debug mode
        if settings.enable_request_logging and settings.debug:
            try:

                @mcp_instance.middleware
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
            """Wrapper for get_config tool tool that includes handler instance."""
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
        if settings.enable_tool_debugging and settings.debug:
            analyze_code_wrapper = debug_tool_args(analyze_code_wrapper)
            analyze_file_wrapper = debug_tool_args(analyze_file_wrapper)
            get_config_wrapper = debug_tool_args(get_config_wrapper)
            validate_config_wrapper = debug_tool_args(validate_config_wrapper)
            create_config_wrapper = debug_tool_args(create_config_wrapper)

        logging.info(f"MCP server '{settings.name}' created successfully")
        return mcp_instance

    except Exception as e:
        error_info = handle_exception(e)
        logging.error(f"Failed to create MCP server: {error_info}")
        raise MCPInitializationError(
            f"Server initialization failed: {str(e)}",
            details=error_info
        )


# Provide temporary server variable for FastMCP command line compatibility
# This instance is created with default settings.
# The 'run' command will create its own instance with its specific debug flag.
# The 'mcpcmd' (fastmcp dev/run) will refer to this 'server' instance.
server = create_mcp_server()


if __name__ == "__main__":
    cli()
