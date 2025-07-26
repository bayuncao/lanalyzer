"""
MCP request handlers for Lanalyzer.

This module provides the main entry point for MCP requests to Lanalyzer by
aggregating functionality from specialized handler modules.
"""

import logging

from .analysis import AnalysisMCPHandler
from .config import ConfigMCPHandler
from .explanation import ExplanationMCPHandler
from .vulnerability_report import VulnerabilityReportMCPHandler

logger = logging.getLogger(__name__)


class LanalyzerMCPHandler(
    ConfigMCPHandler,
    AnalysisMCPHandler,
    ExplanationMCPHandler,
    VulnerabilityReportMCPHandler,
):
    """
    Handles MCP protocol requests for Lanalyzer.

    This class aggregates functionality from specialized handler modules to provide
    a complete MCP request handling interface.
    """

    def __init__(self, debug: bool = False):
        """
        Initialize the MCP handler.

        Args:
            debug: Whether to enable debug output
        """
        ConfigMCPHandler.__init__(self, debug)
        AnalysisMCPHandler.__init__(self, debug)
        ExplanationMCPHandler.__init__(self, debug)
        VulnerabilityReportMCPHandler.__init__(self, debug)
        # Should match Lanalyzer version, consider importing from __version__
        self.version = getattr(__import__("lanalyzer"), "__version__", "0.0.0")
