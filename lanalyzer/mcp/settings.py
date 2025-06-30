"""
MCP Server configuration settings.

This module provides centralized configuration management for the MCP server,
replacing hardcoded values with configurable settings.
"""

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict


class TransportType(str, Enum):
    """Supported transport types for MCP server."""

    SSE = "sse"
    STREAMABLE_HTTP = "streamable-http"


class LogLevel(str, Enum):
    """Supported log levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


@dataclass
class MCPServerSettings:
    """Configuration settings for MCP server."""

    # Server basic settings
    name: str = "Lanalyzer"
    title: str = "Lanalyzer - Python Taint Analysis Tool"
    description: str = (
        "MCP server for Lanalyzer, providing taint analysis for Python code "
        "to detect security vulnerabilities."
    )

    # Network settings
    host: str = "127.0.0.1"
    port: int = 8000
    transport: TransportType = TransportType.SSE

    # Session settings (in seconds)
    session_keepalive_timeout: int = 120  # 2 minutes
    session_expiry_timeout: int = 1800  # 30 minutes
    initialization_timeout: float = 5.0  # 5 seconds

    # Logging settings
    log_level: LogLevel = LogLevel.INFO
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    # Debug settings
    debug: bool = False
    enable_request_logging: bool = False

    # Client connection settings
    max_retries: int = 3
    retry_delay: float = 1.0
    retry_backoff_factor: float = 1.5

    # Tool settings
    enable_tool_debugging: bool = False

    # JSON response settings (for streamable-http)
    json_response: bool = False

    # Additional options
    extra_options: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> "MCPServerSettings":
        """Create settings from environment variables."""
        return cls(
            host=os.getenv("MCP_HOST", "127.0.0.1"),
            port=int(os.getenv("MCP_PORT", "8000")),
            transport=TransportType(os.getenv("MCP_TRANSPORT", "sse")),
            debug=os.getenv("MCP_DEBUG", "false").lower() == "true",
            log_level=LogLevel(os.getenv("MCP_LOG_LEVEL", "INFO")),
            session_keepalive_timeout=int(os.getenv("MCP_KEEPALIVE_TIMEOUT", "120")),
            session_expiry_timeout=int(os.getenv("MCP_SESSION_TIMEOUT", "1800")),
            initialization_timeout=float(os.getenv("MCP_INIT_TIMEOUT", "5.0")),
            enable_request_logging=os.getenv("MCP_REQUEST_LOGGING", "false").lower()
            == "true",
            json_response=os.getenv("MCP_JSON_RESPONSE", "false").lower() == "true",
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert settings to dictionary."""
        result = {}
        for key, value in self.__dict__.items():
            if isinstance(value, Enum):
                result[key] = value.value
            else:
                result[key] = value
        return result

    def update_from_dict(self, data: Dict[str, Any]) -> None:
        """Update settings from dictionary."""
        for key, value in data.items():
            if hasattr(self, key):
                # Handle enum conversions
                if key == "transport" and isinstance(value, str):
                    setattr(self, key, TransportType(value))
                elif key == "log_level" and isinstance(value, str):
                    setattr(self, key, LogLevel(value))
                else:
                    setattr(self, key, value)


@dataclass
class MCPClientSettings:
    """Configuration settings for MCP client examples."""

    # Connection settings
    base_url_template: str = "http://{host}:{port}"
    sse_url_template: str = "http://{host}:{port}/sse"

    # Retry settings
    max_retries: int = 3
    retry_delay: float = 1.0
    retry_backoff_factor: float = 1.5

    # Timeout settings
    connection_timeout: float = 30.0
    request_timeout: float = 60.0

    @classmethod
    def from_server_settings(
        cls, server_settings: MCPServerSettings
    ) -> "MCPClientSettings":
        """Create client settings from server settings."""
        return cls(
            max_retries=server_settings.max_retries,
            retry_delay=server_settings.retry_delay,
            retry_backoff_factor=server_settings.retry_backoff_factor,
        )


# Default settings instance
DEFAULT_SETTINGS = MCPServerSettings()
