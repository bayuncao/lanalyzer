#!/usr/bin/env python
"""
CLI commands for MCP server.
"""

import os
import subprocess
import sys
import time

import click

from lanalyzer.__version__ import __version__
from lanalyzer.logger import info
from lanalyzer.mcp.settings import MCPServerSettings, TransportType
from lanalyzer.mcp.utils import generate_client_code_example


@click.group()
def cli():
    """Lanalyzer MCP command-line tool"""
    pass


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
    # Create settings from command line arguments
    settings = MCPServerSettings(
        host=host,
        port=port,
        transport=TransportType(transport),
        debug=debug,
        json_response=json_response,
    )

    # Import here to avoid circular imports
    from lanalyzer.mcp.server.mcpserver import create_mcp_server

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
    # This ensures the settings from CLI are correctly applied to this server instance
    current_run_server = create_mcp_server(settings=settings)

    # Store settings for run() method (as transport_kwargs)
    run_kwargs = {
        "host": settings.host,
        "port": settings.port,
    }

    # Add transport-specific kwargs
    if settings.json_response:
        run_kwargs["json_response"] = settings.json_response

    # Check transport availability
    if transport == "streamable-http":
        click.echo("Using Streamable HTTP transport")
    else:
        click.echo("Using SSE transport")

    # Print startup message indicating initialization
    click.echo(f"Starting FastMCP server using {transport} transport")
    info("Initializing MCP server...")

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
    # Pass runtime settings to run() method as recommended by FastMCP
    if transport == "streamable-http":
        current_run_server.run(transport="streamable-http", **run_kwargs)
    else:
        # Use regular SSE transport
        current_run_server.run(transport="sse", **run_kwargs)


@cli.command(name="mcp")
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
    # Get the absolute path of mcpserver.py file
    script_path = os.path.join(
        os.path.dirname(__file__), "..", "server", "mcpserver.py"
    )
    script_path = os.path.abspath(script_path)

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
            if transport == "streamable-http":
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
