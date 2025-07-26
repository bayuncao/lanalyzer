"""
Vulnerability report templates for MCP server.

This module provides templates and formatting utilities for generating
vulnerability reports in different formats (CVE, CNVD, etc.).
"""

from .base_template import BaseReportTemplate
from .cnvd_template import CNVDReportTemplate
from .cve_template import CVEReportTemplate

__all__ = [
    "BaseReportTemplate",
    "CVEReportTemplate",
    "CNVDReportTemplate",
]
