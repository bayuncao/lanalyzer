#!/usr/bin/env python
"""
MCP server command-line entry point, implemented using FastMCP.
Provides Model Context Protocol (MCP) functionality for lanalyzer.
"""

import os
import sys
import logging
import click
from typing import Optional, Dict, Any

try:
    # Import FastMCP core components
    from fastmcp import FastMCP, Context
except ImportError:
    raise ImportError(
        "FastMCP dependency not found. "
        "Please install with `pip install lanalyzer[mcp]` "
        "or `pip install fastmcp`"
    )

from lanalyzer.__version__ import __version__
from lanalyzer.mcp.handlers import LanalyzerMCPHandler
from lanalyzer.mcp.models import (
    AnalysisRequest,
    FileAnalysisRequest,  # Assuming this model will be used by the handler
    ExplainVulnerabilityRequest,
    ConfigurationRequest,
)


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

    # Create FastMCP instance - some options removed for compatibility with version 2.2.8
    mcp_instance = FastMCP(  # Renamed to avoid conflict with mcp subcommand
        "Lanalyzer",
        title="Lanalyzer - Python Taint Analysis Tool",
        description="MCP server for Lanalyzer, providing taint analysis for Python code to detect security vulnerabilities.",
        version=__version__,
        debug=debug,
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

    @mcp_instance.tool()
    async def analyze_code(
        code: str,
        file_path: str,
        config_path: str,
        ctx: Optional[Context] = None,  # Added Optional
    ) -> Dict[str, Any]:
        """
        Analyze provided Python code to detect security vulnerabilities.

        Args:
            code: Python code to analyze.
            file_path: File path of the code (for reporting).
            config_path: Configuration file path (required).
            ctx: MCP context.

        Returns:
            Analysis results, including detected vulnerability information.
        """
        # Log original parameters to aid debugging
        logging.debug(
            f"analyze_code original parameters: code=<omitted>, file_path={file_path}, config_path={config_path}"
        )

        # Handle possible nested parameter structure
        actual_file_path = file_path
        actual_config_path = config_path
        actual_code = code

        # Nested parameter handling
        if isinstance(config_path, dict) and not isinstance(
            code, str
        ):  # If config_path is a dict, assume it contains all params
            logging.warning(
                f"Detected nested parameter structure (config_path is dict): {config_path}"
            )
            actual_code = config_path.get("code", actual_code)
            actual_file_path = config_path.get("file_path", actual_file_path)
            actual_config_path = config_path.get(
                "config_path", actual_config_path
            )  # This will re-assign if "config_path" is a key

        # If actual_code is still not a string after potential extraction, it's an error.
        if not isinstance(actual_code, str):
            error_msg = "Cannot extract a valid code parameter from the request"
            if ctx:
                await ctx.error(error_msg)
            return {"success": False, "errors": [error_msg]}
        if not isinstance(actual_file_path, str):
            error_msg = "Cannot extract a valid file_path parameter from the request (must be string)"
            if ctx:
                await ctx.error(error_msg)
            return {"success": False, "errors": [error_msg]}
        if not isinstance(actual_config_path, str):
            error_msg = "Cannot extract a valid config_path parameter from the request (must be string)"
            if ctx:
                await ctx.error(error_msg)
            return {"success": False, "errors": [error_msg]}

        if ctx:
            await ctx.info(f"Starting code analysis, file path: {actual_file_path}")
            await ctx.info(f"Using configuration file: {actual_config_path}")

        request_obj = (
            AnalysisRequest(  # Renamed to avoid conflict with middleware 'request'
                code=actual_code,
                file_path=actual_file_path,
                config_path=actual_config_path,
            )
        )
        result = await handler.handle_analysis_request(request_obj)

        if ctx and result.vulnerabilities:
            await ctx.warning(
                f"Detected {len(result.vulnerabilities)} potential vulnerabilities"
            )

        return result.model_dump()

    @mcp_instance.tool()
    async def analyze_file(
        file_path: str,
        config_path: str,
        ctx: Optional[Context] = None,  # Added Optional
    ) -> Dict[str, Any]:
        """
        Analyze Python code at the specified file path.

        Args:
            file_path: Path of the Python file to analyze.
            config_path: Configuration file path (required).
            ctx: MCP context.

        Returns:
            Analysis results, including detected vulnerability information.
        """
        # Log original parameters to aid debugging
        logging.debug(
            f"analyze_file original parameters: file_path={file_path}, config_path={config_path}"
        )

        actual_file_path = file_path
        actual_config_path = config_path

        # Handle nested parameter situations where arguments might be passed as a single dictionary
        # Scenario 1: file_path is a dict containing all arguments
        if isinstance(file_path, dict):
            logging.warning(
                f"Nested parameter situation (file_path is dict): {file_path}"
            )
            actual_file_path = file_path.get("file_path", actual_file_path)
            actual_config_path = file_path.get("config_path", actual_config_path)
        # Scenario 2: config_path is a dict (less common if file_path is also a direct arg, but possible)
        elif isinstance(config_path, dict):
            logging.warning(
                f"Nested parameter situation (config_path is dict): {config_path}"
            )
            # file_path would be from direct arg, actual_file_path already set
            actual_config_path = config_path.get("config_path", actual_config_path)
            # Potentially, file_path might also be in this dict, overriding the direct arg
            if "file_path" in config_path:
                actual_file_path = config_path.get("file_path")

        # Parameter validation after attempting to de-nest
        if not isinstance(actual_file_path, str):
            error_msg = (
                f"File path must be a string, received: {type(actual_file_path)}"
            )
            if ctx:
                await ctx.error(error_msg)
            return {"success": False, "errors": [error_msg]}

        if not isinstance(actual_config_path, str):
            error_msg = f"Configuration path must be a string, received: {type(actual_config_path)}"
            if ctx:
                await ctx.error(error_msg)
            return {"success": False, "errors": [error_msg]}

        if ctx:
            await ctx.info(f"Starting file analysis: {actual_file_path}")
            await ctx.info(f"Using configuration file: {actual_config_path}")

        # Create request object and process
        # Assuming FileAnalysisRequest takes file_path and config_path directly
        # The handler for FileAnalysisRequest needs to be implemented or use a generic one.
        # For now, we'll assume it's similar to analyze_code but reads code from file.
        # This might require the handler to change or this tool to directly use handle_analysis_request
        # by reading the file content first.
        # Using the provided FileAnalysisRequest model for the call to handler:
        request_obj = FileAnalysisRequest(
            target_path=actual_file_path, config_path=actual_config_path
        )
        # The handler method might be handle_file_path_analysis if that's what FileAnalysisRequest is for.
        result = await handler.handle_file_path_analysis(request_obj)

        if ctx and result.vulnerabilities:
            await ctx.warning(
                f"Detected {len(result.vulnerabilities)} potential vulnerabilities"
            )

        return result.model_dump()

    @mcp_instance.tool()
    async def get_config(
        config_path: Optional[str] = None,
        ctx: Optional[Context] = None,  # Added Optional
    ) -> Dict[str, Any]:
        """
        Get configuration content.

        Args:
            config_path: Path to the configuration file.
            ctx: MCP context.

        Returns:
            Configuration data.
        """
        if ctx:
            config_desc = config_path if config_path else "default configuration"
            await ctx.info(f"Getting configuration: {config_desc}")

        request_obj = ConfigurationRequest(operation="get", config_path=config_path)
        result = await handler.handle_configuration_request(request_obj)
        return result.model_dump()

    @mcp_instance.tool()
    async def validate_config(
        config_data: Optional[Dict[str, Any]] = None,  # Made Optional
        config_path: Optional[str] = None,
        ctx: Optional[Context] = None,  # Added Optional
    ) -> Dict[str, Any]:
        """
        Validate configuration content.

        Args:
            config_data: Configuration data to validate.
            config_path: Optional configuration file path (if provided, will read from file).
            ctx: MCP context.

        Returns:
            Validation result.
        """
        if ctx:
            await ctx.info("Validating configuration...")

        request_obj = ConfigurationRequest(
            operation="validate", config_path=config_path, config_data=config_data
        )
        result = await handler.handle_configuration_request(request_obj)

        if ctx:
            if result.success:
                await ctx.info("Configuration validation successful")
            else:
                await ctx.error(f"Configuration validation failed: {result.errors}")

        return result.model_dump()

    @mcp_instance.tool()
    async def create_config(
        config_data: Dict[str, Any],
        config_path: Optional[str] = None,
        ctx: Optional[Context] = None,  # Added Optional
    ) -> Dict[str, Any]:
        """
        Create a new configuration file.

        Args:
            config_data: Configuration data.
            config_path: Optional output file path.
            ctx: MCP context.

        Returns:
            Result of the create operation.
        """
        if ctx:
            path_info = f", saving to: {config_path}" if config_path else ""
            await ctx.info(f"Creating configuration{path_info}")

        request_obj = ConfigurationRequest(
            operation="create", config_path=config_path, config_data=config_data
        )
        result = await handler.handle_configuration_request(request_obj)

        if ctx and result.success:
            await ctx.info("Configuration creation successful")
        elif ctx and not result.success:
            await ctx.error(f"Configuration creation failed: {result.errors}")

        return result.model_dump()

    return mcp_instance


# Provide temporary server variable for FastMCP command line compatibility
# This instance is created with default debug=False.
# The 'run' command will create its own instance with its specific debug flag.
# The 'mcpcmd' (fastmcp dev/run) will refer to this 'server' instance.
server = create_mcp_server()


# Debug tool function decorator, used in debug mode
def debug_tool_args(func):
    """Log tool function parameters for debugging"""

    async def wrapper(*args, **kwargs):
        logging.debug(
            f"Calling tool {func.__name__} with args: {args}, kwargs: {kwargs}"
        )
        try:
            result = await func(*args, **kwargs)
            return result
        except Exception as e:
            logging.error(f"Tool {func.__name__} call failed: {e}")
            import traceback

            logging.error(traceback.format_exc())
            raise

    return wrapper


@click.group()
def cli():
    """Lanalyzer MCP command-line tool"""
    pass


@cli.command()
@click.option("--debug", is_flag=True, help="Enable debug mode.")
@click.option("--host", default="127.0.0.1", help="Host address.")
@click.option("--port", default=8000, type=int, help="Port number.")
def run(debug, host, port):
    """Start the MCP server."""
    # Configure logging (again, specific for this command's context)
    log_level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        force=True,  # Ensure reconfiguration if already configured
    )

    click.echo(
        f"Starting Lanalyzer MCP server - Using FastMCP v{__import__('fastmcp').__version__}"
    )
    click.echo(f"Server Name: Lanalyzer")
    click.echo(f"Server Version: {__version__}")
    click.echo(f"Server Address: http://{host}:{port}")  # Added http:// for clarity

    # Create FastMCP server instance specifically for this run command
    # This ensures the 'debug' flag from CLI is correctly applied to this server instance
    current_run_server = create_mcp_server(debug=debug)

    # Start server in a way compatible with version 2.2.8
    click.echo(f"Starting FastMCP server using SSE transport")

    # According to the help documentation, FastMCP 2.2.8 only supports 'stdio' and 'sse' transport methods
    current_run_server.run(
        transport="sse",  # Explicitly specify using sse transport
        host=host,
        port=port,
    )


@cli.command(
    name="mcp"
)  # Explicitly name the command to avoid conflict with variable 'mcp' if any
@click.argument("command_args", nargs=-1)
@click.option(
    "--debug", is_flag=True, help="Enable debug mode for the FastMCP subprocess."
)
def mcpcmd(command_args, debug):
    """Run the server using FastMCP command-line tool (e.g., dev, run, install)."""
    import subprocess

    # Get the absolute path of this file
    script_path = os.path.abspath(__file__)

    # Build FastMCP command
    cmd = ["fastmcp"] + list(command_args)
    if not command_args or command_args[0] not in ["dev", "run", "install"]:
        # If no valid subcommand is provided, default to dev
        cmd = ["fastmcp", "dev"]

    # Add module path - FastMCP will look for the 'server' variable in the script.
    cmd.append(f"{script_path}:server")

    # Explicitly specify transport as sse to avoid default http for dev/run
    # Note: FastMCP 2.2.8 only supports stdio and sse transport for these commands
    if command_args and command_args[0] in ["dev", "run"]:
        if "--transport" not in command_args:  # Add only if not specified by user
            cmd.append("--transport=sse")

    if debug:
        if "--with-debug" not in command_args:  # Add only if not specified by user
            cmd.append("--with-debug")

    click.echo(f"Executing command: {' '.join(cmd)}")

    # Execute command and pass output to the current terminal
    try:
        # The 'server' instance at the bottom of the file will be used by fastmcp
        process = subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        click.echo(f"Command execution failed: {e}", err=True)
        sys.exit(1)
    except FileNotFoundError:
        click.echo(
            "Error: fastmcp command not found. Please ensure FastMCP is installed: pip install fastmcp",
            err=True,
        )
        sys.exit(1)


if __name__ == "__main__":
    cli()
