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
    FileAnalysisRequest,
    ExplainVulnerabilityRequest,
    ConfigurationRequest,
)


# Create FastMCP instance
def create_mcp_server(debug: bool = False) -> FastMCP:
    """
    Create FastMCP server instance.

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

    # Create FastMCP instance - parameters removed for compatibility with version 2.2.8
    mcp = FastMCP(
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

        @mcp.middleware
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

    @mcp.tool()
    async def analyze_code(
        code: str, file_path: str, config_path: str, ctx: Context = None
    ) -> Dict[str, Any]:
        """
        Analyze provided Python code for security vulnerabilities.

        Args:
            code: Python code to analyze.
            file_path: File path of the code (for reporting).
            config_path: Configuration file path (required).
            ctx: MCP context.

        Returns:
            Analysis results, including detected vulnerability information.
        """
        # Log original parameters to help debugging
        logging.debug(
            f"analyze_code original parameters: code=<omitted>, file_path={file_path}, config_path={config_path}"
        )

        # Handle possible nested parameter structure
        actual_file_path = file_path
        actual_config_path = config_path
        actual_code = code

        # Nested parameter handling
        if isinstance(config_path, dict) and not isinstance(code, str):
            logging.warning(f"Detected nested parameter structure: {config_path}")

            # Try to extract parameters from the nested structure
            if "file_path" in config_path and isinstance(config_path["file_path"], str):
                actual_file_path = config_path["file_path"]
                logging.warning(
                    f"Extracted file_path from nested structure: {actual_file_path}"
                )

            if "config_path" in config_path and isinstance(
                config_path["config_path"], str
            ):
                actual_config_path = config_path["config_path"]
                logging.warning(
                    f"Extracted config_path from nested structure: {actual_config_path}"
                )

            if "code" in config_path and isinstance(config_path["code"], str):
                actual_code = config_path["code"]
                logging.warning("Extracted code from nested structure")

            # If no valid code is found
            if not isinstance(actual_code, str):
                error_msg = "Could not extract a valid code parameter from the request"
                if ctx:
                    await ctx.error(error_msg)
                return {"success": False, "errors": [error_msg]}

        if ctx:
            await ctx.info(f"Starting code analysis, file path: {actual_file_path}")
            await ctx.info(f"Using configuration file: {actual_config_path}")

        # Parameter validation
        if not isinstance(actual_config_path, str):
            error_msg = f"Configuration path must be a string, received: {type(actual_config_path)}"
            if ctx:
                await ctx.error(error_msg)
            return {"success": False, "errors": [error_msg]}

        if not isinstance(actual_file_path, str):
            error_msg = (
                f"File path must be a string, received: {type(actual_file_path)}"
            )
            if ctx:
                await ctx.error(error_msg)
            return {"success": False, "errors": [error_msg]}

        request = AnalysisRequest(
            code=actual_code, file_path=actual_file_path, config_path=actual_config_path
        )
        result = await handler.handle_analysis_request(request)

        if ctx and result.vulnerabilities:
            await ctx.warning(
                f"Detected {len(result.vulnerabilities)} potential vulnerabilities"
            )

        return result.model_dump()

    @mcp.tool()
    async def analyze_file(
        file_path: str, config_path: str, ctx: Context = None
    ) -> Dict[str, Any]:
        """
        Analyze Python code at the specified file path.

        Args:
            file_path: Path to the Python file to analyze.
            config_path: Configuration file path (required).
            ctx: MCP context.

        Returns:
            Analysis results, including detected vulnerability information.
        """
        # Log original parameters to help debugging
        logging.debug(
            f"analyze_file original parameters: file_path={file_path}, config_path={config_path}"
        )

        # Handle nested parameter situation
        # Correct when the client mistakenly sends a nested parameter structure
        actual_file_path = file_path
        actual_config_path = config_path
        is_nested_params = False

        # If config_path is a dictionary instead of a string, try to extract the correct parameters
        if isinstance(config_path, dict):
            is_nested_params = True
            logging.warning(f"Received nested parameter structure: {config_path}")

            # Try to extract file_path from the config_path dictionary
            if "file_path" in config_path and isinstance(config_path["file_path"], str):
                actual_file_path = config_path["file_path"]
                logging.warning(
                    f"Extracted file_path from nested structure: {actual_file_path}"
                )

            # Try to extract config_path from the config_path dictionary
            if "config_path" in config_path and isinstance(
                config_path["config_path"], str
            ):
                actual_config_path = config_path["config_path"]
                logging.warning(
                    f"Extracted config_path from nested structure: {actual_config_path}"
                )

            # If a valid file_path still cannot be found
            if actual_file_path != file_path and not isinstance(actual_file_path, str):
                # Provide detailed error message and correct request format example
                error_msg = """
Could not extract a valid file_path parameter from the request.
Your request format is incorrect. The correct request format should be:

{
  "method": "tools/call",
  "params": {
    "name": "analyze_file",
    "arguments": {
      "file_path": "/path/to/your/file.py",
      "config_path": "/path/to/your/config.json"
    }
  }
}

However, the request you sent seems to use a nested parameter structure, such as:

{
  "method": "tools/call",
  "params": {
    "name": "analyze_file",
    "arguments": {
      "config_path": {
        "file_path": "...",
        "config_path": "..."
      }
    }
  }
}

Please correct your request format to ensure parameters are top-level key-value pairs.
"""
                if ctx:
                    await ctx.error(error_msg)
                return {"success": False, "errors": [error_msg]}

        if ctx:
            await ctx.info(f"Starting file analysis: {actual_file_path}")
            await ctx.info(f"Using configuration file: {actual_config_path}")

            # If nested parameters, provide a warning
            if is_nested_params:
                await ctx.warning(
                    """
Note: Nested parameter structure detected. Although the system attempted a correction, this is not the standard format. Please update your client to use the correct parameter format:
- file_path and config_path should be top-level parameters, not nested.
"""
                )

        # Log processed parameters for easy debugging
        logging.debug(
            f"analyze_file processed parameters: file_path={actual_file_path}, config_path={actual_config_path}"
        )

        # Ensure config_path is a string
        if not isinstance(actual_config_path, str):
            error_msg = f"Configuration path must be a string, received: {type(actual_config_path)}"
            if ctx:
                await ctx.error(error_msg)
            return {"success": False, "errors": [error_msg]}

        # Ensure file_path is a string
        if not isinstance(actual_file_path, str):
            error_msg = (
                f"File path must be a string, received: {type(actual_file_path)}"
            )
            if ctx:
                await ctx.error(error_msg)
            return {"success": False, "errors": [error_msg]}

        result = await handler.handle_file_analysis_request(
            actual_file_path, actual_config_path
        )

        if ctx and result.vulnerabilities:
            await ctx.warning(
                f"Detected {len(result.vulnerabilities)} potential vulnerabilities"
            )

        return result.model_dump()

    @mcp.tool()
    async def analyze_path(
        target_path: str,
        config_path: str,
        output_path: Optional[str] = None,
        ctx: Context = None,
    ) -> Dict[str, Any]:
        """
        Analyze Python code in a directory or file path.

        Args:
            target_path: Target file or directory path.
            config_path: Configuration file path (required).
            output_path: Optional path for analysis result output.
            ctx: MCP context.

        Returns:
            Analysis results, including detected vulnerability information.
        """
        # Log original parameters
        logging.debug(
            f"analyze_path original parameters: target_path={target_path}, config_path={config_path}, output_path={output_path}"
        )

        # Handle nested parameter structure
        actual_target_path = target_path
        actual_config_path = config_path
        actual_output_path = output_path

        # If config_path is a dictionary instead of a string, try to extract the correct parameters
        if isinstance(config_path, dict):
            logging.warning(f"Received nested parameter structure: {config_path}")

            # Try to extract parameters from the nested structure
            if "target_path" in config_path and isinstance(
                config_path["target_path"], str
            ):
                actual_target_path = config_path["target_path"]
                logging.warning(
                    f"Extracted target_path from nested structure: {actual_target_path}"
                )

            if "config_path" in config_path and isinstance(
                config_path["config_path"], str
            ):
                actual_config_path = config_path["config_path"]
                logging.warning(
                    f"Extracted config_path from nested structure: {actual_config_path}"
                )

            if "output_path" in config_path and (
                isinstance(config_path["output_path"], str)
                or config_path["output_path"] is None
            ):
                actual_output_path = config_path["output_path"]
                logging.warning(
                    f"Extracted output_path from nested structure: {actual_output_path}"
                )

            # Check necessary parameters
            if not isinstance(actual_target_path, str):
                error_msg = (
                    "Could not extract a valid target_path parameter from the request"
                )
                if ctx:
                    await ctx.error(error_msg)
                return {"success": False, "errors": [error_msg]}

        if ctx:
            await ctx.info(f"Starting path analysis: {actual_target_path}")
            await ctx.info(f"Using configuration file: {actual_config_path}")

        # Parameter validation
        if not isinstance(actual_config_path, str):
            error_msg = f"Configuration path must be a string, received: {type(actual_config_path)}"
            if ctx:
                await ctx.error(error_msg)
            return {"success": False, "errors": [error_msg]}

        if actual_output_path is not None and not isinstance(actual_output_path, str):
            error_msg = f"Output path must be a string or null, received: {type(actual_output_path)}"
            if ctx:
                await ctx.error(error_msg)
            return {"success": False, "errors": [error_msg]}

        request = FileAnalysisRequest(
            target_path=actual_target_path,
            config_path=actual_config_path,
            output_path=actual_output_path,
        )

        # For large analyses, report progress
        if ctx:
            await ctx.info("Collecting target files...")

        result = await handler.handle_file_path_analysis(request)

        if ctx and result.vulnerabilities:
            await ctx.warning(
                f"Detected {len(result.vulnerabilities)} potential vulnerabilities"
            )

        return result.model_dump()

    @mcp.tool()
    async def explain_vulnerabilities(
        analysis_file: str,
        format: str = "text",
        level: str = "detailed",
        ctx: Context = None,
    ) -> Dict[str, Any]:
        """
        Explain vulnerabilities in analysis results.

        Args:
            analysis_file: Path to the analysis results file.
            format: Output format (text or markdown).
            level: Detail level (brief or detailed).
            ctx: MCP context.

        Returns:
            Vulnerability explanation results.
        """
        if ctx:
            await ctx.info(f"Explaining vulnerabilities, file: {analysis_file}")

        request = ExplainVulnerabilityRequest(
            analysis_file=analysis_file, format=format, level=level
        )
        result = await handler.explain_vulnerabilities(request)

        if ctx:
            await ctx.info(f"Explained {result.vulnerabilities_count} vulnerabilities")

        return result.model_dump()

    @mcp.tool()
    async def get_config(
        config_path: Optional[str] = None, ctx: Context = None
    ) -> Dict[str, Any]:
        """
        Get configuration file content.

        Args:
            config_path: Configuration file path, uses built-in config by default.
            ctx: MCP context.

        Returns:
            Configuration content and operation status.
        """
        if ctx:
            config_desc = config_path if config_path else "default configuration"
            await ctx.info(f"Getting configuration: {config_desc}")

        request = ConfigurationRequest(operation="get", config_path=config_path)
        result = await handler.handle_configuration_request(request)
        return result.model_dump()

    @mcp.tool()
    async def validate_config(
        config_data: Dict[str, Any] = None,
        config_path: Optional[str] = None,
        ctx: Context = None,
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

        request = ConfigurationRequest(
            operation="validate", config_path=config_path, config_data=config_data
        )
        result = await handler.handle_configuration_request(request)

        if ctx:
            if result.success:
                await ctx.info("Configuration validation successful")
            else:
                await ctx.error("Configuration validation failed")

        return result.model_dump()

    @mcp.tool()
    async def create_config(
        config_data: Dict[str, Any],
        config_path: Optional[str] = None,
        ctx: Context = None,
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

        request = ConfigurationRequest(
            operation="create", config_path=config_path, config_data=config_data
        )
        result = await handler.handle_configuration_request(request)

        if ctx and result.success:
            await ctx.info("Configuration creation successful")

        return result.model_dump()

    return mcp


# Create global MCP server instance
mcp_instance = (
    create_mcp_server()
)  # Renamed to avoid conflict with mcp subcommand parameter

# Provide alias for compatibility, FastMCP>=2.2 looks for a variable named "server"
mcp_server = mcp_instance
server = mcp_instance


# Add tool function debug decorator, used in debug mode
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
@click.option("--debug", is_flag=True, help="Enable debug mode")
@click.option("--host", default="127.0.0.1", help="Host address")
@click.option("--port", default=8000, type=int, help="Port number")
def run(debug, host, port):
    """Start the MCP server"""
    # Configure logging
    log_level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    click.echo(
        f"Starting Lanalyzer MCP server - Using FastMCP v{__import__('fastmcp').__version__}"
    )
    click.echo(f"Server Name: Lanalyzer")
    click.echo(f"Server Version: {__version__}")
    click.echo(f"Server Address: {host}:{port}")

    # Create FastMCP server instance
    # The global 'server' or 'mcp_server' instance should be used if it's pre-configured,
    # otherwise, a new one is created here.
    # Re-creating it ensures CLI options like --debug are respected for this run.
    current_server = create_mcp_server(debug=debug)

    # Start server in a way compatible with version 2.2.8
    click.echo(f"Starting FastMCP server using SSE transport")

    # As seen from the help documentation, FastMCP 2.2.8 only supports 'stdio' and 'sse' transport methods
    current_server.run(
        transport="sse",  # Explicitly specify using sse transport
        host=host,
        port=port,
    )


# Add support for mcp subcommands, maintaining original functionality
@cli.command(name="mcp")  # Renamed parameter to avoid conflict with global mcp_instance
@click.argument("mcp_command_args", nargs=-1)
@click.option("--debug", is_flag=True, help="Enable debug mode")
def mcp_cli_command(mcp_command_args, debug):
    """Run the server using FastMCP command-line tool (dev/run/install)"""
    import subprocess

    # Get the absolute path of this file
    script_path = os.path.abspath(__file__)

    # Build FastMCP command
    cmd = ["fastmcp"] + list(mcp_command_args)
    if not mcp_command_args or mcp_command_args[0] not in ["dev", "run", "install"]:
        # If no valid subcommand is provided, default to dev
        cmd = ["fastmcp", "dev"]

    # Add module path - use the global instance name 'server' or 'mcp_server' that FastMCP expects
    cmd.append(
        script_path + ":server"
    )  # Or :mcp_server, depending on what FastMCP expects by default

    # Explicitly specify transport as sse to avoid default http
    # Note: FastMCP 2.2.8 only supports stdio and sse transport
    if mcp_command_args and mcp_command_args[0] in ["dev", "run"]:
        cmd.append("--transport=sse")

    if debug:
        cmd.append("--with-debug")

    click.echo(f"Executing command: {' '.join(cmd)}")

    # Execute command and pass output to the current terminal
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        click.echo(f"Command execution failed: {e}")
        sys.exit(1)
    except FileNotFoundError:
        click.echo(
            "Error: fastmcp command not found. Please ensure FastMCP is installed: pip install fastmcp"
        )
        sys.exit(1)


def main():
    """Main function"""
    cli()


if __name__ == "__main__":
    main()
