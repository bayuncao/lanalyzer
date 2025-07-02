#!/usr/bin/env python
"""
MCP server command-line entry point, implemented using FastMCP.
Provides Model Context Protocol (MCP) functionality for lanalyzer.
"""

import logging
from typing import Any, Dict, Optional

from lanalyzer.logger import error, info, warning

try:
    # Import FastMCP core components
    from fastmcp import Context, FastMCP

    # Check if streamable HTTP support is available
    # Note: FastMCP 2.2.8 only supports 'stdio' and 'sse' transports
    # Streamable HTTP is not available in the current version
    STREAMABLE_HTTP_AVAILABLE = False
except ImportError:
    from ..exceptions import MCPDependencyError

    raise MCPDependencyError(
        "FastMCP dependency not found.",
        missing_packages=["fastmcp"],
        install_command="pip install lanalyzer[mcp] or pip install fastmcp",
    )

from lanalyzer.__version__ import __version__
from lanalyzer.mcp.cli import cli
from lanalyzer.mcp.exceptions import MCPInitializationError, handle_exception
from lanalyzer.mcp.handlers import LanalyzerMCPHandler
from lanalyzer.mcp.settings import MCPServerSettings
from lanalyzer.mcp.tools import (
    analyze_code,
    analyze_file,
    analyze_path,
    create_config,
    explain_vulnerabilities,
    get_config,
    validate_config,
)
from lanalyzer.mcp.utils import debug_tool_args


def create_mcp_server(
    settings: Optional[MCPServerSettings] = None, debug: Optional[bool] = None
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
            info(f"FastMCP version: {fastmcp_version}")
        except (ImportError, AttributeError):
            warning("Could not determine FastMCP version")
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
                    debug(f"Received request: {request.method} {request.url}")
                    try:
                        if request.method == "POST":
                            body = await request.json()
                            debug(f"Request body: {body}")
                    except Exception as e:
                        debug(f"Could not parse request body: {e}")

                    response = await call_next(request)
                    return response

            except AttributeError:
                # If FastMCP does not support middleware, log a warning
                warning(
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
            """
            Analyze Python code string for security vulnerabilities using Lanalyzer's taint analysis engine.

            This tool performs static analysis on the provided Python code to detect potential security
            vulnerabilities such as SQL injection, command injection, path traversal, and other taint-based
            security issues. It uses configurable detection rules and provides detailed vulnerability reports.

            Args:
                code (str): The Python source code to analyze. Must be valid Python syntax.
                file_path (str): Virtual file path for the code (used in reporting). Can be any descriptive path.
                config_path (str): Path to the Lanalyzer configuration file that defines detection rules and settings.
                ctx (Optional[Context]): MCP context for logging and progress updates.

            Returns:
                Dict[str, Any]: Analysis results containing:
                    - success (bool): Whether the analysis completed successfully
                    - vulnerabilities (List[Dict]): List of detected vulnerabilities with details
                    - summary (Dict): Analysis summary statistics
                    - errors (List[str]): Any errors encountered during analysis
                    - call_chains (List[Dict]): Detailed taint flow information (if available)
                    - imports (Dict): Information about imported libraries and methods

            Example:
                {
                    "success": true,
                    "vulnerabilities": [
                        {
                            "rule_type": "SQLInjection",
                            "severity": "high",
                            "line": 5,
                            "message": "Potential SQL injection vulnerability",
                            "source": "user_input",
                            "sink": "execute"
                        }
                    ],
                    "summary": {"total_vulnerabilities": 1, "high_severity": 1},
                    "errors": []
                }
            """
            return await analyze_code(code, file_path, config_path, handler, ctx)

        @mcp_instance.tool()
        async def analyze_file_wrapper(
            file_path: str,
            config_path: str,
            ctx: Optional[Context] = None,
        ) -> Dict[str, Any]:
            """
            Analyze a Python file for security vulnerabilities using Lanalyzer's taint analysis engine.

            This tool reads and analyzes a Python source file from the filesystem to detect potential
            security vulnerabilities. It performs the same analysis as analyze_code but reads the code
            from a file rather than accepting it as a string parameter.

            Args:
                file_path (str): Path to the Python file to analyze. Must be a valid file path that exists.
                config_path (str): Path to the Lanalyzer configuration file that defines detection rules and settings.
                ctx (Optional[Context]): MCP context for logging and progress updates.

            Returns:
                Dict[str, Any]: Analysis results containing:
                    - success (bool): Whether the analysis completed successfully
                    - vulnerabilities (List[Dict]): List of detected vulnerabilities with details
                    - summary (Dict): Analysis summary statistics
                    - errors (List[str]): Any errors encountered during analysis
                    - call_chains (List[Dict]): Detailed taint flow information (if available)
                    - imports (Dict): Information about imported libraries and methods

            Example:
                {
                    "success": true,
                    "vulnerabilities": [
                        {
                            "rule_type": "CommandInjection",
                            "severity": "critical",
                            "line": 12,
                            "message": "Potential command injection vulnerability",
                            "file": "/path/to/file.py"
                        }
                    ],
                    "summary": {"total_vulnerabilities": 1, "critical_severity": 1}
                }
            """
            return await analyze_file(file_path, config_path, handler, ctx)

        @mcp_instance.tool()
        async def get_config_wrapper(
            config_path: Optional[str] = None,
            ctx: Optional[Context] = None,
        ) -> Dict[str, Any]:
            """
            Retrieve Lanalyzer configuration content from a file or get the default configuration.

            This tool allows you to examine the current configuration settings used by Lanalyzer
            for vulnerability detection. It can read from a specific configuration file or return
            the default configuration if no path is provided.

            Args:
                config_path (Optional[str]): Path to the configuration file to read. If None,
                    returns the default configuration.
                ctx (Optional[Context]): MCP context for logging and progress updates.

            Returns:
                Dict[str, Any]: Configuration data containing:
                    - success (bool): Whether the operation completed successfully
                    - config (Dict): The configuration data with detection rules and settings
                    - errors (List[str]): Any errors encountered while reading the configuration
                    - config_path (str): The path of the configuration file used

            Example:
                {
                    "success": true,
                    "config": {
                        "sources": ["input", "request.args", "request.form"],
                        "sinks": ["execute", "eval", "subprocess.call"],
                        "taint_propagation": {...},
                        "rules": {...}
                    },
                    "config_path": "/path/to/config.json"
                }
            """
            return await get_config(handler, config_path, ctx)

        @mcp_instance.tool()
        async def validate_config_wrapper(
            config_data: Optional[Dict[str, Any]] = None,
            config_path: Optional[str] = None,
            ctx: Optional[Context] = None,
        ) -> Dict[str, Any]:
            """
            Validate Lanalyzer configuration data for correctness and completeness.

            This tool checks whether a configuration is valid and can be used by Lanalyzer
            for vulnerability detection. It validates the structure, required fields, and
            data types of the configuration. You can validate either configuration data
            directly or read and validate from a file.

            Args:
                config_data (Optional[Dict[str, Any]]): Configuration data to validate directly.
                    If provided, this takes precedence over config_path.
                config_path (Optional[str]): Path to a configuration file to read and validate.
                    Used only if config_data is not provided.
                ctx (Optional[Context]): MCP context for logging and progress updates.

            Returns:
                Dict[str, Any]: Validation results containing:
                    - success (bool): Whether the configuration is valid
                    - errors (List[str]): List of validation errors found
                    - warnings (List[str]): List of validation warnings (if any)
                    - config_path (str): Path of the configuration file (if applicable)

            Example:
                {
                    "success": false,
                    "errors": [
                        "Missing required field: 'sources'",
                        "Invalid sink format in 'sinks' array"
                    ],
                    "warnings": ["Deprecated field 'old_setting' found"]
                }
            """
            return await validate_config(handler, config_data, config_path, ctx)

        @mcp_instance.tool()
        async def create_config_wrapper(
            config_data: Dict[str, Any],
            config_path: Optional[str] = None,
            ctx: Optional[Context] = None,
        ) -> Dict[str, Any]:
            """
            Create a new Lanalyzer configuration file with the provided settings.

            This tool creates a new configuration file for Lanalyzer with the specified
            detection rules and settings. The configuration will be validated before
            creation to ensure it's properly formatted and contains all required fields.

            Args:
                config_data (Dict[str, Any]): Configuration data to write to the file.
                    Must contain valid Lanalyzer configuration structure with sources,
                    sinks, rules, and other required fields.
                config_path (Optional[str]): Path where the configuration file should be saved.
                    If not provided, a default location will be used.
                ctx (Optional[Context]): MCP context for logging and progress updates.

            Returns:
                Dict[str, Any]: Creation results containing:
                    - success (bool): Whether the configuration file was created successfully
                    - config_path (str): Path where the configuration was saved
                    - errors (List[str]): Any errors encountered during creation
                    - validation_errors (List[str]): Configuration validation errors (if any)

            Example:
                {
                    "success": true,
                    "config_path": "/path/to/new_config.json",
                    "errors": []
                }
            """
            return await create_config(handler, config_data, config_path, ctx)

        @mcp_instance.tool()
        async def analyze_path_wrapper(
            target_path: str,
            config_path: str,
            ctx: Optional[Context] = None,
        ) -> Dict[str, Any]:
            """
            Analyze a file or directory path for security vulnerabilities using Lanalyzer's taint analysis engine.

            This tool can analyze either a single Python file or an entire directory/project for security
            vulnerabilities. When analyzing a directory, it recursively processes all Python files found
            within the directory structure and provides a comprehensive security analysis report.

            Args:
                target_path (str): Path to the file or directory to analyze. Must be a valid path that exists.
                config_path (str): Path to the Lanalyzer configuration file that defines detection rules and settings.
                ctx (Optional[Context]): MCP context for logging and progress updates.

            Returns:
                Dict[str, Any]: Analysis results containing:
                    - success (bool): Whether the analysis completed successfully
                    - vulnerabilities (List[Dict]): List of detected vulnerabilities across all analyzed files
                    - summary (Dict): Analysis summary statistics including files analyzed count
                    - errors (List[str]): Any errors encountered during analysis
                    - call_chains (List[Dict]): Detailed taint flow information (if available)
                    - imports (Dict): Information about imported libraries and methods across all files

            Example:
                {
                    "success": true,
                    "vulnerabilities": [
                        {
                            "rule_type": "PathTraversal",
                            "severity": "medium",
                            "line": 8,
                            "file": "/project/utils/file_handler.py",
                            "message": "Potential path traversal vulnerability"
                        }
                    ],
                    "summary": {"files_analyzed": 15, "total_vulnerabilities": 3}
                }
            """
            return await analyze_path(target_path, config_path, handler, ctx)

        @mcp_instance.tool()
        async def explain_vulnerabilities_wrapper(
            analysis_file: str,
            format: str = "text",
            level: str = "brief",
            ctx: Optional[Context] = None,
        ) -> Dict[str, Any]:
            """
            Generate natural language explanations for vulnerability analysis results.

            This tool takes the JSON output from a vulnerability analysis and generates human-readable
            explanations of the security issues found. It can provide both brief summaries and detailed
            explanations with remediation suggestions, formatted as either plain text or Markdown.

            Args:
                analysis_file (str): Path to the analysis results file in JSON format (output from analyze_* tools).
                format (str): Output format, either "text" or "markdown" (default: "text").
                level (str): Detail level, either "brief" or "detailed" (default: "brief").
                ctx (Optional[Context]): MCP context for logging and progress updates.

            Returns:
                Dict[str, Any]: Explanation results containing:
                    - success (bool): Whether the explanation generation completed successfully
                    - explanation (str): Natural language explanation of the vulnerabilities
                    - vulnerabilities_count (int): Number of vulnerabilities explained
                    - files_affected (List[str]): List of files that contain vulnerabilities
                    - errors (List[str]): Any errors encountered during explanation generation

            Example:
                {
                    "success": true,
                    "explanation": "Security Vulnerability Analysis Report\\n==================================\\nFound 2 potential security vulnerabilities affecting 1 file(s)...",
                    "vulnerabilities_count": 2,
                    "files_affected": ["/path/to/vulnerable_file.py"]
                }
            """
            return await explain_vulnerabilities(
                analysis_file, format, level, handler, ctx
            )

        # Apply debug decorators if debug mode is enabled
        if settings.enable_tool_debugging and settings.debug:
            analyze_code_wrapper = debug_tool_args(analyze_code_wrapper)
            analyze_file_wrapper = debug_tool_args(analyze_file_wrapper)
            analyze_path_wrapper = debug_tool_args(analyze_path_wrapper)
            get_config_wrapper = debug_tool_args(get_config_wrapper)
            validate_config_wrapper = debug_tool_args(validate_config_wrapper)
            create_config_wrapper = debug_tool_args(create_config_wrapper)
            explain_vulnerabilities_wrapper = debug_tool_args(
                explain_vulnerabilities_wrapper
            )

        info(f"MCP server '{settings.name}' created successfully")
        return mcp_instance

    except Exception as e:
        error_info = handle_exception(e)
        error(f"Failed to create MCP server: {error_info}")
        raise MCPInitializationError(
            f"Server initialization failed: {str(e)}", details=error_info
        )


# Provide temporary server variable for FastMCP command line compatibility
# This instance is created with default settings.
# The 'run' command will create its own instance with its specific debug flag.
# The 'mcpcmd' (fastmcp dev/run) will refer to this 'server' instance.
server = create_mcp_server()


if __name__ == "__main__":
    cli()
