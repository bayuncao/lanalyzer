#!/usr/bin/env python
"""
Tool implementations for MCP server.

This module provides the actual tool implementations that are exposed
through the MCP server interface.
"""

from typing import Any, Dict, Optional

from fastmcp import Context

from lanalyzer.logger import debug, error, warning

from ..exceptions import MCPValidationError, handle_exception
from ..models import (
    AnalysisRequest,
    ConfigurationRequest,
    ExplainVulnerabilityRequest,
    FileAnalysisRequest,
)


# Tool implementations
async def analyze_code(
    code: str,
    file_path: str,
    config_path: str,
    handler,
    ctx: Optional[Context] = None,
) -> Dict[str, Any]:
    """
    Analyze provided Python code to detect security vulnerabilities.

    Args:
        code: Python code to analyze.
        file_path: File path of the code (for reporting).
        config_path: Configuration file path (required).
        handler: Instance of LanalyzerMCPHandler.
        ctx: MCP context.

    Returns:
        Analysis results, including detected vulnerability information.
    """
    # Log original parameters to aid debugging
    debug(
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
        warning(
            f"Detected nested parameter structure (config_path is dict): {config_path}"
        )
        actual_code = config_path.get("code", actual_code)
        actual_file_path = config_path.get("file_path", actual_file_path)
        actual_config_path = config_path.get(
            "config_path", actual_config_path
        )  # This will re-assign if "config_path" is a key

    # Validate extracted parameters
    try:
        if not isinstance(actual_code, str):
            raise MCPValidationError(
                "Code parameter must be a string",
                field_errors=[{"field": "code", "error": "Invalid type"}],
            )
        if not isinstance(actual_file_path, str):
            raise MCPValidationError(
                "File path parameter must be a string",
                field_errors=[{"field": "file_path", "error": "Invalid type"}],
            )
        if not isinstance(actual_config_path, str):
            raise MCPValidationError(
                "Config path parameter must be a string",
                field_errors=[{"field": "config_path", "error": "Invalid type"}],
            )
    except MCPValidationError as e:
        error_info = e.to_dict()
        if ctx:
            await ctx.error(error_info["message"])
        return {
            "success": False,
            "errors": [error_info["message"]],
            "validation_errors": error_info["field_errors"],
        }

    try:
        if ctx:
            await ctx.info(f"Starting code analysis, file path: {actual_file_path}")
            await ctx.info(f"Using configuration file: {actual_config_path}")

        request_obj = AnalysisRequest(
            code=actual_code,
            file_path=actual_file_path,
            config_path=actual_config_path,
        )
        result = await handler.handle_analysis_request(request_obj)

        if ctx and result.vulnerabilities:
            await ctx.warning(
                f"Detected {len(result.vulnerabilities)} potential vulnerabilities"
            )

        return result.model_dump()

    except Exception as e:
        error_info = handle_exception(e)
        error(f"Code analysis failed: {error_info}")
        if ctx:
            await ctx.error(f"Analysis failed: {error_info.get('message', str(e))}")

        return {
            "success": False,
            "errors": [error_info.get("message", str(e))],
            "vulnerabilities": [],
            "summary": {},
        }


async def analyze_file(
    file_path: str,
    config_path: str,
    handler,
    ctx: Optional[Context] = None,
) -> Dict[str, Any]:
    """
    Analyze Python code at the specified file path.

    Args:
        file_path: Path of the Python file to analyze.
        config_path: Configuration file path (required).
        handler: Instance of LanalyzerMCPHandler.
        ctx: MCP context.

    Returns:
        Analysis results, including detected vulnerability information.
    """
    # Log original parameters to aid debugging
    debug(
        f"analyze_file original parameters: file_path={file_path}, config_path={config_path}"
    )

    actual_file_path = file_path
    actual_config_path = config_path

    # Handle nested parameter situations where arguments might be passed as a single dictionary
    # Scenario 1: file_path is a dict containing all arguments
    if isinstance(file_path, dict):
        warning(f"Nested parameter situation (file_path is dict): {file_path}")
        actual_file_path = file_path.get("file_path", actual_file_path)
        actual_config_path = file_path.get("config_path", actual_config_path)
    # Scenario 2: config_path is a dict (less common if file_path is also a direct arg, but possible)
    elif isinstance(config_path, dict):
        warning(f"Nested parameter situation (config_path is dict): {config_path}")
        # file_path would be from direct arg, actual_file_path already set
        actual_config_path = config_path.get("config_path", actual_config_path)
        # Potentially, file_path might also be in this dict, overriding the direct arg
        if "file_path" in config_path:
            actual_file_path = config_path.get("file_path")

    # Parameter validation after attempting to de-nest
    if not isinstance(actual_file_path, str):
        error_msg = f"File path must be a string, received: {type(actual_file_path)}"
        if ctx:
            await ctx.error(error_msg)
        return {"success": False, "errors": [error_msg]}

    if not isinstance(actual_config_path, str):
        error_msg = (
            f"Configuration path must be a string, received: {type(actual_config_path)}"
        )
        if ctx:
            await ctx.error(error_msg)
        return {"success": False, "errors": [error_msg]}

    if ctx:
        await ctx.info(f"Starting file analysis: {actual_file_path}")
        await ctx.info(f"Using configuration file: {actual_config_path}")

    request_obj = FileAnalysisRequest(
        target_path=actual_file_path, config_path=actual_config_path
    )
    result = await handler.handle_file_path_analysis(request_obj)

    if ctx and result.vulnerabilities:
        await ctx.warning(
            f"Detected {len(result.vulnerabilities)} potential vulnerabilities"
        )

    return result.model_dump()


async def get_config(
    handler,
    config_path: Optional[str] = None,
    ctx: Optional[Context] = None,
) -> Dict[str, Any]:
    """
    Get configuration content.

    Args:
        handler: Instance of LanalyzerMCPHandler.
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


async def validate_config(
    handler,
    config_data: Optional[Dict[str, Any]] = None,
    config_path: Optional[str] = None,
    ctx: Optional[Context] = None,
) -> Dict[str, Any]:
    """
    Validate configuration content.

    Args:
        handler: Instance of LanalyzerMCPHandler.
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


async def create_config(
    handler,
    config_data: Dict[str, Any],
    config_path: Optional[str] = None,
    ctx: Optional[Context] = None,
) -> Dict[str, Any]:
    """
    Create a new configuration file.

    Args:
        handler: Instance of LanalyzerMCPHandler.
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


async def analyze_path(
    target_path: str,
    config_path: str,
    handler,
    ctx: Optional[Context] = None,
) -> Dict[str, Any]:
    """
    Analyze a file or directory path for security vulnerabilities.

    Args:
        target_path: Path to the file or directory to analyze.
        config_path: Configuration file path (required).
        handler: Instance of LanalyzerMCPHandler.
        ctx: MCP context.

    Returns:
        Analysis results, including detected vulnerability information.
    """
    # Log original parameters to aid debugging
    debug(
        f"analyze_path original parameters: target_path={target_path}, config_path={config_path}"
    )

    actual_target_path = target_path
    actual_config_path = config_path

    # Handle nested parameter situations
    if isinstance(target_path, dict):
        warning(f"Nested parameter situation (target_path is dict): {target_path}")
        actual_target_path = target_path.get("target_path", actual_target_path)
        actual_config_path = target_path.get("config_path", actual_config_path)
    elif isinstance(config_path, dict):
        warning(f"Nested parameter situation (config_path is dict): {config_path}")
        actual_config_path = config_path.get("config_path", actual_config_path)
        if "target_path" in config_path:
            actual_target_path = config_path.get("target_path")

    # Parameter validation
    if not isinstance(actual_target_path, str):
        error_msg = (
            f"Target path must be a string, received: {type(actual_target_path)}"
        )
        if ctx:
            await ctx.error(error_msg)
        return {"success": False, "errors": [error_msg]}

    if not isinstance(actual_config_path, str):
        error_msg = (
            f"Configuration path must be a string, received: {type(actual_config_path)}"
        )
        if ctx:
            await ctx.error(error_msg)
        return {"success": False, "errors": [error_msg]}

    if ctx:
        await ctx.info(f"Starting path analysis: {actual_target_path}")
        await ctx.info(f"Using configuration file: {actual_config_path}")

    request_obj = FileAnalysisRequest(
        target_path=actual_target_path, config_path=actual_config_path
    )
    result = await handler.handle_file_path_analysis(request_obj)

    if ctx and result.vulnerabilities:
        await ctx.warning(
            f"Detected {len(result.vulnerabilities)} potential vulnerabilities"
        )

    return result.model_dump()


async def explain_vulnerabilities(
    analysis_file: str,
    format: str = "text",
    level: str = "brief",
    handler=None,
    ctx: Optional[Context] = None,
) -> Dict[str, Any]:
    """
    Explain vulnerability analysis results with natural language descriptions.

    Args:
        analysis_file: Path to the analysis results file (JSON format).
        format: Output format, either "text" or "markdown" (default: "text").
        level: Detail level, either "brief" or "detailed" (default: "brief").
        handler: Instance of LanalyzerMCPHandler.
        ctx: MCP context.

    Returns:
        Explanation results with natural language descriptions.
    """
    # Log original parameters to aid debugging
    debug(
        f"explain_vulnerabilities original parameters: analysis_file={analysis_file}, format={format}, level={level}"
    )

    actual_analysis_file = analysis_file
    actual_format = format
    actual_level = level

    # Handle nested parameter situations
    if isinstance(analysis_file, dict):
        warning(f"Nested parameter situation (analysis_file is dict): {analysis_file}")
        actual_analysis_file = analysis_file.get("analysis_file", actual_analysis_file)
        actual_format = analysis_file.get("format", actual_format)
        actual_level = analysis_file.get("level", actual_level)

    # Parameter validation
    if not isinstance(actual_analysis_file, str):
        error_msg = f"Analysis file path must be a string, received: {type(actual_analysis_file)}"
        if ctx:
            await ctx.error(error_msg)
        return {"success": False, "errors": [error_msg]}

    if actual_format not in ["text", "markdown"]:
        error_msg = f"Format must be 'text' or 'markdown', received: {actual_format}"
        if ctx:
            await ctx.error(error_msg)
        return {"success": False, "errors": [error_msg]}

    if actual_level not in ["brief", "detailed"]:
        error_msg = f"Level must be 'brief' or 'detailed', received: {actual_level}"
        if ctx:
            await ctx.error(error_msg)
        return {"success": False, "errors": [error_msg]}

    if ctx:
        await ctx.info(f"Explaining vulnerabilities from: {actual_analysis_file}")
        await ctx.info(f"Format: {actual_format}, Level: {actual_level}")

    request_obj = ExplainVulnerabilityRequest(
        analysis_file=actual_analysis_file, format=actual_format, level=actual_level
    )
    result = await handler.explain_vulnerabilities(request_obj)

    if ctx and result.success:
        await ctx.info(
            f"Generated explanation for {result.vulnerabilities_count} vulnerabilities"
        )
    elif ctx and not result.success:
        await ctx.error(f"Failed to explain vulnerabilities: {result.errors}")

    return result.model_dump()
