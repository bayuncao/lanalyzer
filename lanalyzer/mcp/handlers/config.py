"""
Configuration MCP handler for Lanalyzer.

This module implements the configuration handlers for MCP requests to Lanalyzer.
"""

import os
import json
import logging
from typing import Dict, List, Any, Optional

from lanalyzer.cli.config_utils import load_configuration, validate_configuration
from ..models import (
    ConfigurationRequest,
    ConfigurationResponse,
)
from .base import BaseMCPHandler

logger = logging.getLogger(__name__)


class ConfigMCPHandler(BaseMCPHandler):
    """Handles MCP protocol configuration requests for Lanalyzer."""

    async def handle_configuration_request(
        self, request: ConfigurationRequest
    ) -> ConfigurationResponse:
        """
        Handle a configuration request.

        Args:
            request: The configuration request

        Returns:
            ConfigurationResponse: The configuration response
        """
        try:
            if request.operation == "get":
                return await self._handle_get_config(request.config_path)
            elif request.operation == "validate":
                return await self._handle_validate_config(
                    request.config_path, request.config_data
                )
            elif request.operation == "create":
                return await self._handle_create_config(
                    request.config_data, request.config_path
                )
            else:
                return ConfigurationResponse(
                    success=False,
                    errors=[f"Unsupported operation: {request.operation}"],
                )
        except Exception as e:
            logger.exception("Error handling configuration request")
            return ConfigurationResponse(
                success=False,
                errors=[f"Configuration operation failed: {str(e)}"],
            )

    async def _handle_get_config(
        self, config_path: Optional[str]
    ) -> ConfigurationResponse:
        """
        Handle a request to get a configuration.

        Args:
            config_path: Path to the configuration file

        Returns:
            ConfigurationResponse: The configuration response
        """
        if not config_path:
            # Use default configuration path logic from config_utils or define a standard default
            # This path assumes a specific project structure.
            project_root = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "..")
            )
            config_path = os.path.join(
                project_root, "rules", "default_config.json"
            )  # Example default
            logger.info(f"No config path provided, using default: {config_path}")

        try:
            config = load_configuration(config_path, self.debug)
            return ConfigurationResponse(
                success=True,
                config=config,
            )
        except FileNotFoundError:
            return ConfigurationResponse(
                success=False,
                errors=[f"Configuration file not found: {config_path}"],
            )
        except Exception as e:
            logger.exception(f"Failed to load configuration from {config_path}")
            return ConfigurationResponse(
                success=False,
                errors=[f"Failed to load configuration from {config_path}: {str(e)}"],
            )

    async def _handle_validate_config(
        self, config_path: Optional[str], config_data: Optional[Dict[str, Any]]
    ) -> ConfigurationResponse:
        """
        Handle a request to validate a configuration.

        Args:
            config_path: Path to the configuration file
            config_data: Configuration data

        Returns:
            ConfigurationResponse: The configuration response
        """
        if config_path and not config_data:
            try:
                config_data = load_configuration(config_path, self.debug)
            except FileNotFoundError:
                return ConfigurationResponse(
                    success=False,
                    errors=[
                        f"Configuration file not found for validation: {config_path}"
                    ],
                )
            except Exception as e:
                logger.exception(
                    f"Failed to load configuration for validation from {config_path}"
                )
                return ConfigurationResponse(
                    success=False,
                    errors=[
                        f"Failed to load configuration for validation from {config_path}: {str(e)}"
                    ],
                )

        if not config_data:
            return ConfigurationResponse(
                success=False,
                errors=["No configuration data provided for validation"],
            )

        # Validate the configuration
        is_valid, issues = validate_configuration(config_data)

        return ConfigurationResponse(
            success=is_valid,
            config=config_data,
            errors=issues if not is_valid else [],  # Only return issues if not valid
            validation_result={"valid": is_valid, "issues": issues},
        )

    async def _handle_create_config(
        self, config_data: Optional[Dict[str, Any]], config_path: Optional[str]
    ) -> ConfigurationResponse:
        """
        Handle a request to create a configuration.

        Args:
            config_data: Configuration data
            config_path: Path to save the configuration file

        Returns:
            ConfigurationResponse: The configuration response
        """
        if not config_data:
            return ConfigurationResponse(
                success=False,
                errors=["No configuration data provided for creation"],
            )

        # Validate the configuration first
        is_valid, issues = validate_configuration(config_data)
        if not is_valid:
            return ConfigurationResponse(
                success=False,
                errors=["Invalid configuration data"] + issues,
                validation_result={"valid": is_valid, "issues": issues},
                config=config_data,
            )

        # If path is provided, save the configuration
        if config_path:
            try:
                # Ensure directory exists
                dir_name = os.path.dirname(config_path)
                if (
                    dir_name
                ):  # Check if dirname is not empty (e.g. for relative paths in cwd)
                    os.makedirs(dir_name, exist_ok=True)
                with open(config_path, "w", encoding="utf-8") as f:
                    json.dump(config_data, f, indent=2)
                logger.info(f"Configuration successfully saved to {config_path}")
            except Exception as e:
                logger.exception(f"Failed to save configuration to {config_path}")
                return ConfigurationResponse(
                    success=False,
                    errors=[f"Failed to save configuration: {str(e)}"],
                    config=config_data,
                )
        else:
            logger.info(
                "Configuration created (not saved to file as no path was provided)."
            )

        return ConfigurationResponse(
            success=True,
            config=config_data,
        )
