"""
Base MCP handler for Lanalyzer.

This module provides the base handler functionality for MCP requests to Lanalyzer.
"""

import logging
from typing import Dict, List, Any, Optional

from ..models import (
    ServerInfoResponse,
    VulnerabilityInfo,
)

logger = logging.getLogger(__name__)


class BaseMCPHandler:
    """Base class for MCP protocol handlers in Lanalyzer."""

    def __init__(self, debug: bool = False):
        """
        Initialize the base MCP handler.

        Args:
            debug: Whether to enable debug output
        """
        self.debug = debug
        # Should match Lanalyzer version, consider importing from __version__
        self.version = getattr(__import__("lanalyzer"), "__version__", "0.0.0")

    async def get_server_info(self) -> ServerInfoResponse:
        """
        Get information about the MCP server.

        Returns:
            ServerInfoResponse: Information about the server
        """
        return ServerInfoResponse(
            version=self.version,
            capabilities=[
                "analyze_code",
                "analyze_file",
                "analyze_path",
                "explain_vulnerabilities",
                "get_config",
                "validate_config",
                "create_config",
            ],
        )

    def _convert_vulnerabilities(
        self, vulnerabilities: List[Dict[str, Any]], display_file_path: str
    ) -> List[VulnerabilityInfo]:
        """
        Convert internal vulnerability representation to MCP format.

        Args:
            vulnerabilities: List of vulnerabilities from the tracker
            display_file_path: The file path to display in results

        Returns:
            List[VulnerabilityInfo]: List of vulnerability info
        """
        vuln_info_list = []

        for vuln in vulnerabilities:
            # Check if vuln is a dictionary type
            if not isinstance(vuln, dict):
                logger.warning(f"Skipping non-dict vulnerability: {type(vuln)}")
                continue

            try:
                # Extract file path from vulnerability
                file_path_in_vuln = vuln.get(
                    "file_path", vuln.get("file", display_file_path)
                )

                # Ensure all required fields have default values
                source_data = vuln.get("source", {}) or {}
                sink_data = vuln.get("sink", {}) or {}
                rule_value = vuln.get("rule", "Unknown")
                rule_name = (
                    rule_value
                    if isinstance(rule_value, str)
                    else rule_value.get("name", "Unknown")
                )
                rule_id = vuln.get("rule_id") if isinstance(rule_value, dict) else None

                # Create vulnerability info
                vuln_info = VulnerabilityInfo(
                    rule_name=rule_name,
                    rule_id=rule_id,
                    message=vuln.get(
                        "message",
                        vuln.get("description", "Potential security vulnerability"),
                    ),
                    severity=vuln.get("severity", "HIGH"),
                    source=source_data,
                    sink=sink_data,
                    file_path=file_path_in_vuln,
                    line=sink_data.get("location", {}).get(
                        "line", sink_data.get("line", 0)
                    ),
                    call_chain=vuln.get("call_chain"),
                    code_snippet=vuln.get("code_snippet"),
                )

                vuln_info_list.append(vuln_info)
            except Exception as e:
                logger.exception(f"Error converting vulnerability: {e} - Data: {vuln}")

        return vuln_info_list
