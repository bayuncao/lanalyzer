"""
Custom exceptions for MCP server.

This module provides specific exception classes for better error handling
and debugging in the MCP server implementation.
"""

from typing import Any, Dict, List, Optional


class MCPError(Exception):
    """Base exception class for MCP-related errors."""

    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for JSON serialization."""
        return {
            "error": self.__class__.__name__,
            "message": self.message,
            "error_code": self.error_code,
            "details": self.details,
        }


class MCPConfigurationError(MCPError):
    """Raised when there's a configuration-related error."""

    pass


class MCPAnalysisError(MCPError):
    """Raised when there's an error during analysis."""

    pass


class MCPValidationError(MCPError):
    """Raised when input validation fails."""

    def __init__(
        self,
        message: str,
        field_errors: Optional[List[Dict[str, str]]] = None,
        **kwargs,
    ):
        super().__init__(message, **kwargs)
        self.field_errors = field_errors or []

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary including field errors."""
        result = super().to_dict()
        result["field_errors"] = self.field_errors
        return result


class MCPTransportError(MCPError):
    """Raised when there's a transport-related error."""

    pass


class MCPInitializationError(MCPError):
    """Raised when server initialization fails."""

    pass


class MCPToolError(MCPError):
    """Raised when a tool execution fails."""

    def __init__(
        self,
        message: str,
        tool_name: Optional[str] = None,
        tool_args: Optional[Dict[str, Any]] = None,
        **kwargs,
    ):
        super().__init__(message, **kwargs)
        self.tool_name = tool_name
        self.tool_args = tool_args or {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary including tool information."""
        result = super().to_dict()
        result["tool_name"] = self.tool_name
        result["tool_args"] = self.tool_args
        return result


class MCPDependencyError(MCPError):
    """Raised when required dependencies are missing."""

    def __init__(
        self,
        message: str,
        missing_packages: Optional[List[str]] = None,
        install_command: Optional[str] = None,
        **kwargs,
    ):
        super().__init__(message, **kwargs)
        self.missing_packages = missing_packages or []
        self.install_command = install_command

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary including dependency information."""
        result = super().to_dict()
        result["missing_packages"] = self.missing_packages
        result["install_command"] = self.install_command
        return result


class MCPFileError(MCPError):
    """Raised when there's a file-related error."""

    def __init__(
        self,
        message: str,
        file_path: Optional[str] = None,
        operation: Optional[str] = None,
        **kwargs,
    ):
        super().__init__(message, **kwargs)
        self.file_path = file_path
        self.operation = operation

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary including file information."""
        result = super().to_dict()
        result["file_path"] = self.file_path
        result["operation"] = self.operation
        return result


def handle_exception(exc: Exception) -> Dict[str, Any]:
    """
    Convert any exception to a standardized error response.

    Args:
        exc: The exception to handle

    Returns:
        Dict containing error information
    """
    if isinstance(exc, MCPError):
        return exc.to_dict()

    # Handle common Python exceptions
    if isinstance(exc, FileNotFoundError):
        return MCPFileError(
            message=str(exc), error_code="FILE_NOT_FOUND", operation="read"
        ).to_dict()

    if isinstance(exc, PermissionError):
        return MCPFileError(
            message=str(exc),
            error_code="PERMISSION_DENIED",
        ).to_dict()

    if isinstance(exc, ValueError):
        return MCPValidationError(
            message=str(exc), error_code="INVALID_VALUE"
        ).to_dict()

    if isinstance(exc, ImportError):
        return MCPDependencyError(
            message=str(exc), error_code="MISSING_DEPENDENCY"
        ).to_dict()

    # Generic exception handling
    return MCPError(
        message=str(exc),
        error_code="INTERNAL_ERROR",
        details={"exception_type": exc.__class__.__name__},
    ).to_dict()
