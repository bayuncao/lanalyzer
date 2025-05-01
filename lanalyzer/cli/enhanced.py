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
from lanalyzer.logger import LogTee, get_timestamp
from lanalyzer.cli.file_utils import list_target_files, gather_target_files
from lanalyzer.cli.config_utils import load_configuration, save_output
from lanalyzer.cli.analysis_utils import (
    analyze_files_with_logging,
    print_summary,
    print_detailed_summary,
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

    mcp_parser = subparsers.add_parser("mcp", help="Start MCP server")
    mcp_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind the server to (default: 127.0.0.1)",
    )
    mcp_parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind the server to (default: 8000)",
    )
    mcp_parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode",
    )

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
            from lanalyzer.mcp.server import MCPServer

            print(f"Starting Lanalyzer MCP Server on {args.host}:{args.port}")
            if args.debug:
                print("Debug mode: enabled")

            server = MCPServer(
                host=args.host,
                port=args.port,
                debug=args.debug,
            )

            server.run()
            return 0
        except ImportError:
            print("Error: MCP server dependencies not installed.")
            print("Please install with: pip install lanalyzer[mcp]")
            return 1
        except Exception as e:
            print(f"Error starting MCP server: {e}")
            if args.debug:
                import traceback

                traceback.print_exc()
            return 1

    if args.command == "analyze" or (args.command is None and args.target):
        return run_analysis(args)

    if args.command is None:
        parser.print_help()
        return 0

    return 0


def run_analysis(args) -> int:
    """
    Run the analysis based on command line arguments.

    Args:
        args: Command line arguments

    Returns:
        Exit code
    """
    log_file = None
    original_stdout = sys.stdout
    original_stderr = sys.stderr

    if args.log_file:
        try:
            log_file = open(args.log_file, "w", encoding="utf-8")
            sys.stdout = LogTee(sys.stdout, log_file)
            sys.stderr = LogTee(sys.stderr, log_file)
            print(f"[Log] Started logging to file: {args.log_file}")
            print(f"[Log] Time: {get_timestamp()}")
        except Exception as e:
            print(f"[Error] Failed to open log file {args.log_file}: {e}")
            sys.stdout = original_stdout
            sys.stderr = original_stderr

    try:
        print("[Start] Lanalyzer enhanced mode starting")
        print(f"[Args] Target: {args.target}")
        print(f"[Args] Config: {args.config}")
        print(f"[Args] Output: {args.output}")
        print(f"[Args] Debug Mode: {args.debug}")
        print(f"[Args] Log File: {args.log_file}")

        if args.list_files:
            list_target_files(args.target)
            return 0

        config = load_configuration(args.config, args.debug)

        target_files = gather_target_files(args.target)
        if args.debug:
            print(
                f"[File List] The following {len(target_files)} files will be analyzed:"
            )
            for idx, file_path in enumerate(target_files, 1):
                print(f"  {idx}. {file_path}")

        tracker = EnhancedTaintTracker(config, debug=args.debug)

        vulnerabilities = analyze_files_with_logging(
            tracker, target_files, debug=args.debug
        )

        if args.output:
            save_output(vulnerabilities, args.output, args.pretty, args.debug)

        summary = tracker.get_summary()
        detailed_summary = tracker.get_detailed_summary(vulnerabilities)

        print_summary(summary, vulnerabilities)

        print_detailed_summary(detailed_summary)

        if vulnerabilities and args.verbose:
            print("\n" + "=" * 60)
            print("DETAILED VULNERABILITY INFORMATION")
            print("-" * 60)
            for i, vuln in enumerate(vulnerabilities, 1):
                print(f"\nVulnerability #{i}:")
                tracker.print_detailed_vulnerability(vuln)

        return 0

    except Exception as e:
        if args.debug:
            import traceback

            traceback.print_exc()
        else:
            print(f"Error during analysis: {e}")
        return 1

    finally:
        if log_file:
            print(f"[Log] End time: {get_timestamp()}")
            print("[Log] Logging complete")
            sys.stdout = original_stdout
            sys.stderr = original_stderr
            log_file.close()


def main(args: Optional[List[str]] = None) -> int:
    """
    Main entry point for the CLI.

    Args:
        args: Command-line arguments

    Returns:
        Exit code
    """
    return enhanced_cli_main()


if __name__ == "__main__":
    sys.exit(main())
