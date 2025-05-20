#!/usr/bin/env python
"""
MCP server command-line entry point, implemented using FastMCP.
Provides Model Context Protocol (MCP) functionality for lanalyzer.
"""

import os
import sys
import logging
import click
import asyncio
import contextlib
from typing import Optional, Dict, Any, AsyncIterator
import time

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
from lanalyzer.mcp.models import (
    AnalysisRequest,
    FileAnalysisRequest,  # Assuming this model will be used by the handler
    ConfigurationRequest,
)


# Create a simple in-memory event store for session management and resumability
class SimpleEventStore:
    """
    Simple in-memory event store for session management.

    This provides basic event persistence capability for streamable HTTP connections,
    allowing clients to recover missed events after reconnection.
    """

    def __init__(self, max_events=1000):
        self.events = {}
        self.max_events = max_events

    async def store_event(self, session_id, event_id, event_data):
        if session_id not in self.events:
            self.events[session_id] = []

        self.events[session_id].append((event_id, event_data))

        # Trim events if needed
        if len(self.events[session_id]) > self.max_events:
            self.events[session_id] = self.events[session_id][-self.max_events :]

    async def get_events_since(self, session_id, last_event_id=None):
        if session_id not in self.events:
            return []

        if not last_event_id:
            return self.events[session_id]

        # Find the index of the last event
        for i, (event_id, _) in enumerate(self.events[session_id]):
            if event_id == last_event_id:
                return self.events[session_id][i + 1 :]

        # If not found, return all events
        return self.events[session_id]

    async def cleanup_session(self, session_id):
        if session_id in self.events:
            del self.events[session_id]


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


# Add a client code generation function before the CLI commands
def generate_client_code_example(host: str, port: int, transport: str = "sse"):
    """
    Generate example code for a Python client to connect to this server.

    Args:
        host: Server host address
        port: Server port
        transport: Transport protocol ("sse" or "streamable-http")

    Returns:
        str: Example Python client code
    """
    if transport == "streamable-http":
        code = f"""
import asyncio
from mcp.client.session import ClientSession
from mcp.client.http import http_client

async def run_client():
    base_url = "http://{host}:{port}"
    print(f"Connecting to {{base_url}}...")
    
    try:
        async with http_client(base_url) as streams:
            print("HTTP connection established")
            read_stream, write_stream = streams
            async with ClientSession(read_stream, write_stream) as session:
                print("ClientSession created, explicitly initializing...")
                
                # IMPORTANT: Explicitly initialize the session to avoid the 
                # "Received request before initialization was complete" error
                max_retries = 3
                retry_delay = 1.0  # seconds
                
                # Try initialization with retries
                for attempt in range(max_retries):
                    try:
                        await session.initialize()
                        print("Session initialized successfully")
                        break
                    except Exception as e:
                        if attempt < max_retries - 1:
                            print(f"Initialization attempt {{attempt+1}} failed: {{e}}")
                            print(f"Retrying in {{retry_delay}} seconds...")
                            await asyncio.sleep(retry_delay)
                            retry_delay *= 1.5  # Exponential backoff
                        else:
                            print(f"All initialization attempts failed: {{e}}")
                            raise
                
                # Now safe to make tool calls
                info = await session.get_server_info()
                print(f"Server info: {{info}}")
                
                # Example tool call:
                # result = await session.call_tool("analyze_file", {{
                #     "file_path": "path/to/your/file.py",
                #     "config_path": "path/to/your/config.json"
                # }})
                # print(f"Analysis result: {{result}}")
                
    except Exception as e:
        print(f"Error: {{e}}")

if __name__ == "__main__":
    asyncio.run(run_client())
"""
    else:  # SSE transport
        code = f"""
import asyncio
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client

async def run_client():
    sse_url = "http://{host}:{port}/sse"
    print(f"Connecting to {{sse_url}}...")
    
    try:
        async with sse_client(sse_url) as streams:
            print("SSE connection established")
            read_stream, write_stream = streams
            async with ClientSession(read_stream, write_stream) as session:
                print("ClientSession created, explicitly initializing...")
                
                # IMPORTANT: Explicitly initialize the session to avoid the 
                # "Received request before initialization was complete" error
                max_retries = 3
                retry_delay = 1.0  # seconds
                
                # Try initialization with retries
                for attempt in range(max_retries):
                    try:
                        await session.initialize()
                        print("Session initialized successfully")
                        break
                    except Exception as e:
                        if attempt < max_retries - 1:
                            print(f"Initialization attempt {{attempt+1}} failed: {{e}}")
                            print(f"Retrying in {{retry_delay}} seconds...")
                            await asyncio.sleep(retry_delay)
                            retry_delay *= 1.5  # Exponential backoff
                        else:
                            print(f"All initialization attempts failed: {{e}}")
                            raise
                
                # Now safe to make tool calls
                info = await session.get_server_info()
                print(f"Server info: {{info}}")
                
                # Example tool call:
                # result = await session.call_tool("analyze_file", {{
                #     "file_path": "path/to/your/file.py",
                #     "config_path": "path/to/your/config.json"
                # }})
                # print(f"Analysis result: {{result}}")
                
    except Exception as e:
        print(f"Error: {{e}}")

if __name__ == "__main__":
    asyncio.run(run_client())
"""
    return code


@cli.command()
@click.option("--debug", is_flag=True, help="Enable debug mode.")
@click.option("--host", default="127.0.0.1", help="Host address.")
@click.option("--port", default=8000, type=int, help="Port number.")
@click.option(
    "--transport",
    default="sse",
    type=click.Choice(["sse", "streamable-http"]),
    help="Transport protocol to use (sse or streamable-http).",
)
@click.option(
    "--json-response",
    is_flag=True,
    help="Use JSON responses with streamable-http transport.",
)
@click.option(
    "--show-client",
    is_flag=True,
    help="Show example client code before starting the server.",
)
def run(debug, host, port, transport, json_response, show_client):
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
    click.echo("Server Name: Lanalyzer")
    click.echo(f"Server Version: {__version__}")
    click.echo(f"Server Address: http://{host}:{port}")  # Added http:// for clarity
    click.echo(f"Transport: {transport}")

    # Show client example if requested
    if show_client:
        click.echo("\n=== Example Python Client Code ===")
        click.echo(generate_client_code_example(host, port, transport))
        click.echo("=== End Example Client Code ===\n")
        click.echo(
            "You can save this code to a file and run it to connect to the server."
        )
        click.echo(
            "Remember to install the MCP client library: pip install mcp-client\n"
        )

    # Create FastMCP server instance specifically for this run command
    # This ensures the 'debug' flag from CLI is correctly applied to this server instance
    current_run_server = create_mcp_server(debug=debug)

    # Use streamable HTTP transport if specified and available
    if transport == "streamable-http":
        if not STREAMABLE_HTTP_AVAILABLE:
            click.echo(
                "Error: Streamable HTTP transport not available in this FastMCP version"
            )
            click.echo("Falling back to SSE transport")
            transport = "sse"
        else:
            click.echo(
                "Using Streamable HTTP transport with event store for resumability"
            )
            # Create in-memory event store for streamable HTTP
            event_store = InMemoryEventStore() if STREAMABLE_HTTP_AVAILABLE else None

    # Print startup message indicating initialization
    click.echo(f"Starting FastMCP server using {transport} transport")
    logging.info("Initializing MCP server...")

    # Setup pre-server start initialization
    click.echo("\nIMPORTANT CONNECTION INFORMATION:")
    click.echo("==================================")
    click.echo("When connecting to this server with a Python client, you MUST:")
    click.echo("1. Create your ClientSession normally")
    click.echo("2. Call 'await session.initialize()' BEFORE any tool calls")
    click.echo("3. Wait for initialization to complete before making requests")
    click.echo("==================================\n")

    # Add a small delay to ensure everything is printed before server starts
    time.sleep(0.5)

    # Now start the server with the appropriate transport
    if transport == "streamable-http" and STREAMABLE_HTTP_AVAILABLE:
        # Use Streamable HTTP transport with event store
        current_run_server.run(
            transport=StreamableHTTPTransport(
                event_store=event_store, json_response=json_response
            ),
            host=host,
            port=port,
        )
    else:
        # Use regular SSE transport
        current_run_server.run(
            transport="sse",
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
@click.option(
    "--transport",
    default="sse",
    type=click.Choice(["sse", "streamable-http"]),
    help="Transport protocol to use (sse or streamable-http).",
)
def mcpcmd(command_args, debug, transport):
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

    # Explicitly specify transport
    if command_args and command_args[0] in ["dev", "run"]:
        if "--transport" not in " ".join(
            command_args
        ):  # Add only if not specified by user
            if transport == "streamable-http" and STREAMABLE_HTTP_AVAILABLE:
                cmd.append("--transport=streamable-http")
            else:
                cmd.append("--transport=sse")

    if debug:
        if "--with-debug" not in command_args:  # Add only if not specified by user
            cmd.append("--with-debug")

    click.echo(f"Executing command: {' '.join(cmd)}")

    # Execute command and pass output to the current terminal
    try:
        # The 'server' instance at the bottom of the file will be used by fastmcp
        subprocess.run(cmd, check=True)
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
