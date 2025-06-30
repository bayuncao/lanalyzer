"""
MCP data models for Lanalyzer (responses).

This module defines the Pydantic models used for MCP responses.
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from .requests import VulnerabilityInfo


class AnalysisResponse(BaseModel):
    success: bool = Field(..., description="Whether the analysis was successful")
    vulnerabilities: List[VulnerabilityInfo] = Field(
        default_factory=list, description="List of detected vulnerabilities"
    )
    errors: List[str] = Field(
        default_factory=list, description="List of errors encountered during analysis"
    )
    summary: Dict[str, Any] = Field(
        default_factory=dict, description="Summary of the analysis results"
    )


class ConfigurationResponse(BaseModel):
    success: bool = Field(..., description="Whether the operation was successful")
    config: Optional[Dict[str, Any]] = Field(None, description="The configuration data")
    errors: List[str] = Field(
        default_factory=list,
        description="List of errors encountered during the operation",
    )
    validation_result: Optional[Dict[str, Any]] = Field(
        None, description="Validation results if applicable"
    )


class ServerInfoResponse(BaseModel):
    name: str = Field("Lanalyzer MCP Server", description="The name of the server")
    version: str = Field(..., description="The server version")
    description: str = Field(
        "MCP server for Lanalyzer Python taint analysis",
        description="The server description",
    )
    capabilities: List[str] = Field(
        default_factory=list, description="List of server capabilities"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "Lanalyzer MCP Server",
                "version": "0.1.0",
                "description": "MCP server for Lanalyzer Python taint analysis",
                "capabilities": ["analyze_code", "get_config", "validate_config"],
            }
        }
    )


class ExplainVulnerabilityResponse(BaseModel):
    success: bool = Field(..., description="Whether the operation was successful")
    explanation: str = Field("", description="Vulnerability explanation text")
    vulnerabilities_count: int = Field(0, description="Number of vulnerabilities found")
    files_affected: List[str] = Field(
        default_factory=list, description="List of affected files"
    )
    errors: List[str] = Field(
        default_factory=list, description="List of error messages"
    )
