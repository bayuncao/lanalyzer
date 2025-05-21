#!/usr/bin/env python
"""
Tool implementations for MCP server.
"""

import logging
from typing import Dict, Any, Optional

from fastmcp import Context

from ..models import (
    AnalysisRequest,
    FileAnalysisRequest,
    ConfigurationRequest,
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
    logging.debug(
        f"analyze_file original parameters: file_path={file_path}, config_path={config_path}"
    )

    actual_file_path = file_path
    actual_config_path = config_path

    # Handle nested parameter situations where arguments might be passed as a single dictionary
    # Scenario 1: file_path is a dict containing all arguments
    if isinstance(file_path, dict):
        logging.warning(f"Nested parameter situation (file_path is dict): {file_path}")
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
