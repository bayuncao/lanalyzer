#!/usr/bin/env python3
"""
Lanalyzer CLI module.

Provides the command-line interface for enhanced taint analysis with 
complete propagation and call chains.
"""

import sys
import argparse
from typing import List, Optional

from lanalyzer.analysis.tracker import EnhancedTaintTracker
from lanalyzer.logger import (
    LogTee,
    setup_application_logging,
    info,
    error,
    debug,
    warning,
)
from lanalyzer.cli.file_utils import list_target_files, gather_target_files
from lanalyzer.cli.config_utils import load_configuration, save_output
from lanalyzer.cli.analysis_utils import (
    analyze_files_with_logging,
    print_summary,
)


def create_parser() -> argparse.ArgumentParser:
    """
    Create the command-line argument parser.

    Returns:
        argparse.ArgumentParser: The argument parser
    """
    parser = argparse.ArgumentParser(
        description="Lanalyzer - Enhanced Python taint analysis tool"
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    analyze_parser = subparsers.add_parser(
        "analyze", help="Analyze Python code for vulnerabilities"
    )

    analyze_parser.add_argument(
        "--target",
        required=True,
        help="Target file or directory to analyze",
    )
    analyze_parser.add_argument(
        "--config",
        help="Path to configuration file (JSON)",
    )
    analyze_parser.add_argument("--output", help="Path to output file (JSON)")
    analyze_parser.add_argument(
        "--pretty", action="store_true", help="Pretty-print JSON output"
    )
    analyze_parser.add_argument(
        "--debug", action="store_true", help="Enable debug output"
    )
    analyze_parser.add_argument(
        "--verbose", action="store_true", help="Enable verbose output"
    )
    analyze_parser.add_argument(
        "--list-files",
        action="store_true",
        help="List all Python files that would be analyzed",
    )
    analyze_parser.add_argument(
        "--log-file",
        help="Path to log file for debug and analysis output",
    )

    mcp_parser = subparsers.add_parser("mcp", help="MCP server commands")
    mcp_subparsers = mcp_parser.add_subparsers(dest="mcp_command", help="MCP commands")

    # Run command
    run_parser = mcp_subparsers.add_parser("run", help="Start MCP server")
    run_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host address (default: 127.0.0.1)",
    )
    run_parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port number (default: 8000)",
    )
    run_parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode",
    )

    # Development mode command
    dev_parser = mcp_subparsers.add_parser("dev", help="Start MCP in development mode")
    dev_parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode",
    )

    # Install command
    mcp_subparsers.add_parser("install", help="Install MCP to Claude Desktop")

    parser.add_argument(
        "--target",
        help="Target file or directory to analyze",
    )
    parser.add_argument(
        "--config",
        help="Path to configuration file (JSON)",
    )
    parser.add_argument("--output", help="Path to output file (JSON)")
    parser.add_argument(
        "--pretty", action="store_true", help="Pretty-print JSON output"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument(
        "--list-files",
        action="store_true",
        help="List all Python files that would be analyzed",
    )
    parser.add_argument(
        "--log-file",
        help="Path to log file for debug and analysis output",
    )

    return parser


def enhanced_cli_main() -> int:
    """
    Main entry point for the Lanalyzer enhanced CLI.

    Returns:
        Exit code
    """
    parser = create_parser()
    args = parser.parse_args()

    if args.command == "mcp":
        try:
            from lanalyzer.mcp.mcpserver import create_mcp_server, server

            info("Starting Lanalyzer MCP server using FastMCP")

            debug_mode = False
            host = "127.0.0.1"
            port = 8000

            # Get parameters
            if hasattr(args, "debug") and args.debug:
                debug_mode = True
            if hasattr(args, "host") and args.host:
                host = args.host
            if hasattr(args, "port") and args.port:
                port = args.port

            # Create and start the server
            if hasattr(args, "mcp_command") and args.mcp_command == "dev":
                info(f"Starting server in development mode: {host}:{port}")
                # Use FastMCP command line tool in dev mode
                import subprocess

                # Get absolute path to mcpserver.py
                from pathlib import Path

                mcp_module_path = Path(__file__).parent.parent / "mcp" / "mcpserver.py"

                # Use absolute path to call FastMCP
                cmd = ["fastmcp", "dev", f"{mcp_module_path}:server"]
                if debug_mode:
                    cmd.append("--with-debug")

                info(f"Executing command: {' '.join(cmd)}")
                try:
                    subprocess.run(cmd, check=True)
                except subprocess.CalledProcessError as e:
                    error(f"Command execution failed: {e}")
                    if debug_mode:
                        import traceback

                        error(traceback.format_exc())
                    return 1
                except FileNotFoundError:
                    error(
                        "Error: fastmcp command not found. Please ensure FastMCP is installed: pip install fastmcp"
                    )
                    return 1
            elif hasattr(args, "mcp_command") and args.mcp_command == "install":
                info("Installing MCP server to Claude Desktop")
                # Use FastMCP command line tool in install mode
                import subprocess

                # Get absolute path to mcpserver.py
                from pathlib import Path

                mcp_module_path = Path(__file__).parent.parent / "mcp" / "mcpserver.py"

                # Use absolute path to call FastMCP
                cmd = ["fastmcp", "install", f"{mcp_module_path}:server"]
                info(f"Executing command: {' '.join(cmd)}")
                try:
                    subprocess.run(cmd, check=True)
                except subprocess.CalledProcessError as e:
                    error(f"Command execution failed: {e}")
                    if debug_mode:
                        import traceback

                        error(traceback.format_exc())
                    return 1
                except FileNotFoundError:
                    error(
                        "Error: fastmcp command not found. Please ensure FastMCP is installed: pip install fastmcp"
                    )
                    return 1
            else:
                # Standard run mode
                info(f"Starting server: {host}:{port}")
                if debug_mode:
                    info("Debug mode: Enabled")

                server = create_mcp_server(debug=debug_mode)
                server.run(transport="sse", host=host, port=port)

            return 0
        except ImportError as e:
            error("Error: MCP server dependencies not installed.")
            error("Please install with: pip install lanalyzer[mcp]")
            if hasattr(args, "debug") and args.debug:
                error(f"Detailed error: {str(e)}")
                import traceback

                error(traceback.format_exc())
            return 1
        except Exception as e:
            error(f"Error: Failed to start MCP server: {str(e)}")
            if hasattr(args, "debug") and args.debug:
                import traceback

                error(traceback.format_exc())
            return 1

    if args.command == "analyze" or (args.command is None and args.target):
        return run_analysis(args)

    if args.command is None:
        parser.print_help()
        return 0

    return 0


def run_analysis(args) -> int:
    """
    Run the analysis with the provided arguments.

    Args:
        args: The parsed command-line arguments

    Returns:
        Exit code
    """
    debug_mode = args.debug
    verbose = args.verbose
    target_path = args.target
    config_path = args.config
    output_path = args.output
    pretty = args.pretty
    list_files = args.list_files
    log_file = args.log_file

    if list_files:
        list_target_files(target_path)
        return 0

    if log_file:
        loggers = setup_application_logging(log_file, debug_mode)
        sys.stdout = LogTee(sys.stdout, loggers)
        sys.stderr = LogTee(sys.stderr, loggers)

    target_files = gather_target_files(target_path)
    if not target_files:
        error(
            "Error: No Python files found for analysis. Please check the target path."
        )
        return 1

    if verbose:
        info(f"Target files to analyze ({len(target_files)}):")
        for i, file_path in enumerate(target_files, 1):
            info(f"{i}. {file_path}")

    try:
        config = load_configuration(config_path, debug_mode)
        tracker = EnhancedTaintTracker.from_config(config, debug_mode)
        vulnerabilities = analyze_files_with_logging(tracker, target_files, debug_mode)

        if output_path:
            save_output(vulnerabilities, output_path, pretty, debug_mode)

        # Print a comprehensive summary
        summary = tracker.get_summary()
        print_summary(summary, vulnerabilities)

    except Exception as e:
        error(f"Error running analysis: {e}")
        if debug_mode:
            import traceback

            error(traceback.format_exc())
        return 1

    return 0


def main(args: Optional[List[str]] = None) -> int:
    """
    Main entry point for the Lanalyzer CLI.

    Args:
        args: The command-line arguments

    Returns:
        Exit code
    """
    if args:
        sys.argv = [sys.argv[0]] + args

    try:
        return enhanced_cli_main()
    except Exception as e:
        error(f"Unexpected error: {e}")
        import traceback

        error(traceback.format_exc())
        return 1


if __name__ == "__main__":
    sys.exit(main())
