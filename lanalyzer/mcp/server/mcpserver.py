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
    write_vulnerability_report,
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

        @mcp_instance.tool()
        async def write_vulnerability_report_wrapper(
            report_type: str,
            vulnerability_data: Dict[str, Any],
            additional_info: Optional[Dict[str, Any]] = None,
            # CVE-specific parameters
            cve_id: Optional[str] = None,
            cvss_score: Optional[float] = None,
            cvss_vector: Optional[str] = None,
            affected_products: Optional[str] = None,
            vulnerability_type: Optional[str] = None,
            attack_vector: Optional[str] = None,
            attack_complexity: Optional[str] = None,
            privileges_required: Optional[str] = None,
            user_interaction: Optional[str] = None,
            scope: Optional[str] = None,
            confidentiality_impact: Optional[str] = None,
            integrity_impact: Optional[str] = None,
            availability_impact: Optional[str] = None,
            # CNVD-specific parameters
            cnvd_id: Optional[str] = None,
            cnnvd_id: Optional[str] = None,
            threat_level: Optional[str] = None,
            exploit_difficulty: Optional[str] = None,
            remote_exploit: Optional[str] = None,
            local_exploit: Optional[str] = None,
            poc_available: Optional[str] = None,
            exploit_available: Optional[str] = None,
            vendor_patch: Optional[str] = None,
            third_party_patch: Optional[str] = None,
            ctx: Optional[Context] = None,
        ) -> Dict[str, Any]:
            """
            Generate a vulnerability report in the specified format (CVE or CNVD).

            This tool creates standardized vulnerability reports based on analysis results from Lanalyzer.
            It supports two main report formats: CVE (Common Vulnerabilities and Exposures) and CNVD
            (China National Vulnerability Database).

            Args:
                report_type (str): Type of report to generate. Supported values: "CVE", "CNVD"
                vulnerability_data (Dict[str, Any]): Vulnerability analysis results from Lanalyzer containing:
                    - rule_name: Name of the rule that detected the vulnerability
                    - message: Description of the vulnerability
                    - severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
                    - file_path: Path to the file containing the vulnerability
                    - line: Line number where vulnerability was found
                    - source: Information about the vulnerability source
                    - sink: Information about the vulnerability sink
                    - code_snippet: Code snippet showing the vulnerability
                additional_info (Optional[Dict[str, Any]]): Additional information for report generation
                **kwargs: Report-specific parameters (CVE or CNVD fields)

            Returns:
                Dict containing:
                    - success (bool): Whether report generation was successful
                    - report_content (str): Generated vulnerability report content
                    - report_type (str): Type of report that was generated
                    - metadata (Dict): Additional metadata about the generated report
                    - errors (List[str]): Any errors encountered during report generation

            Example:
                {
                    "success": true,
                    "report_content": "# CVE漏洞报告\\n\\n## 基本信息\\n- **CVE编号**: CVE-2024-0001...",
                    "report_type": "CVE",
                    "metadata": {
                        "cve_id": "CVE-2024-0001",
                        "cvss_score": 7.5,
                        "generation_timestamp": "2024-01-01"
                    },
                    "errors": []
                }
            """
            # Collect all report-specific parameters
            kwargs = {}
            if cve_id is not None:
                kwargs['cve_id'] = cve_id
            if cvss_score is not None:
                kwargs['cvss_score'] = cvss_score
            if cvss_vector is not None:
                kwargs['cvss_vector'] = cvss_vector
            if affected_products is not None:
                kwargs['affected_products'] = affected_products
            if vulnerability_type is not None:
                kwargs['vulnerability_type'] = vulnerability_type
            if attack_vector is not None:
                kwargs['attack_vector'] = attack_vector
            if attack_complexity is not None:
                kwargs['attack_complexity'] = attack_complexity
            if privileges_required is not None:
                kwargs['privileges_required'] = privileges_required
            if user_interaction is not None:
                kwargs['user_interaction'] = user_interaction
            if scope is not None:
                kwargs['scope'] = scope
            if confidentiality_impact is not None:
                kwargs['confidentiality_impact'] = confidentiality_impact
            if integrity_impact is not None:
                kwargs['integrity_impact'] = integrity_impact
            if availability_impact is not None:
                kwargs['availability_impact'] = availability_impact
            if cnvd_id is not None:
                kwargs['cnvd_id'] = cnvd_id
            if cnnvd_id is not None:
                kwargs['cnnvd_id'] = cnnvd_id
            if threat_level is not None:
                kwargs['threat_level'] = threat_level
            if exploit_difficulty is not None:
                kwargs['exploit_difficulty'] = exploit_difficulty
            if remote_exploit is not None:
                kwargs['remote_exploit'] = remote_exploit
            if local_exploit is not None:
                kwargs['local_exploit'] = local_exploit
            if poc_available is not None:
                kwargs['poc_available'] = poc_available
            if exploit_available is not None:
                kwargs['exploit_available'] = exploit_available
            if vendor_patch is not None:
                kwargs['vendor_patch'] = vendor_patch
            if third_party_patch is not None:
                kwargs['third_party_patch'] = third_party_patch

            return await write_vulnerability_report(
                report_type, vulnerability_data, handler, additional_info, ctx, **kwargs
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
            write_vulnerability_report_wrapper = debug_tool_args(
                write_vulnerability_report_wrapper
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
