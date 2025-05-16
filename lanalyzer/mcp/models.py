"""
MCP data models for Lanalyzer.

This module defines the Pydantic models used for MCP requests and responses.
"""

from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class VulnerabilityInfo(BaseModel):
    """Vulnerability information model."""

    rule_name: str = Field(
        ..., description="The name of the rule that detected the vulnerability"
    )
    rule_id: Optional[str] = Field(
        None, description="The ID of the rule that detected the vulnerability"
    )
    message: str = Field(..., description="The vulnerability message")
    severity: str = Field("HIGH", description="The severity level of the vulnerability")

    source: Dict[str, Any] = Field(
        ..., description="Information about the vulnerability source"
    )
    sink: Dict[str, Any] = Field(
        ..., description="Information about the vulnerability sink"
    )

    file_path: str = Field(
        ..., description="The file path where the vulnerability was found"
    )
    line: int = Field(
        ..., description="The line number where the vulnerability was found"
    )

    call_chain: Optional[List[Dict[str, Any]]] = Field(
        None, description="The call chain information if available"
    )
    code_snippet: Optional[str] = Field(
        None, description="Code snippet around the vulnerability"
    )

    class Config:
        """Pydantic model configuration."""

        json_schema_extra = {
            "example": {
                "rule_name": "PickleDeserialization",
                "rule_id": "PICKLE-001",
                "message": "Potential insecure deserialization vulnerability",
                "severity": "HIGH",
                "source": {
                    "name": "user_input",
                    "line": 15,
                    "column": 10,
                    "value": "request.data",
                    "type": "UserInput",
                },
                "sink": {
                    "name": "pickle.loads",
                    "line": 20,
                    "column": 12,
                    "context": "pickle.loads(user_data)",
                },
                "file_path": "app/views.py",
                "line": 20,
                "call_chain": [
                    {"function": "process_data", "line": 10},
                    {"function": "deserialize", "line": 20},
                ],
                "code_snippet": "def deserialize(data):\n    return pickle.loads(data)  # Insecure!",
            }
        }


class AnalysisRequest(BaseModel):
    """Request model for code analysis."""

    code: str = Field(..., description="The code to analyze")
    file_path: str = Field(..., description="The file path to associate with the code")
    config_path: str = Field(..., description="Path to the configuration file")
    config: Optional[Dict[str, Any]] = Field(
        None, description="Configuration data (alternative to config_path)"
    )

    options: Dict[str, Any] = Field(
        default_factory=dict, description="Additional analysis options"
    )


class AnalysisResponse(BaseModel):
    """Response model for code analysis."""

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


class ConfigurationRequest(BaseModel):
    """Request model for configuration operations."""

    operation: str = Field(
        ..., description="The operation to perform (get, validate, create)"
    )
    config_path: Optional[str] = Field(
        None, description="Path to the configuration file"
    )
    config_data: Optional[Dict[str, Any]] = Field(
        None, description="Configuration data for create/validate operations"
    )


class ConfigurationResponse(BaseModel):
    """Response model for configuration operations."""

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
    """Response model for server information."""

    name: str = Field("Lanalyzer MCP Server", description="The name of the server")
    version: str = Field(..., description="The server version")
    description: str = Field(
        "MCP server for Lanalyzer Python taint analysis",
        description="The server description",
    )
    capabilities: List[str] = Field(
        default_factory=list, description="List of server capabilities"
    )

    class Config:
        """Pydantic model configuration."""

        json_schema_extra = {
            "example": {
                "name": "Lanalyzer MCP Server",
                "version": "0.1.0",
                "description": "MCP server for Lanalyzer Python taint analysis",
                "capabilities": ["analyze_code", "get_config", "validate_config"],
            }
        }


class FileAnalysisRequest(BaseModel):
    """Request model for file or directory analysis."""

    target_path: str = Field(..., description="Local file or directory path")
    config_path: str = Field(..., description="Configuration file path")
    output_path: Optional[str] = Field(None, description="Result output path")
    options: Dict[str, Any] = Field(
        default_factory=dict, description="Analysis options"
    )


class ExplainVulnerabilityRequest(BaseModel):
    """Request model for vulnerability explanation."""

    analysis_file: str = Field(..., description="Path to the analysis results file")
    format: str = Field("text", description="Explanation format: text, markdown")
    level: str = Field(
        "detailed", description="Explanation detail level: brief, detailed"
    )


class ExplainVulnerabilityResponse(BaseModel):
    """Response model for vulnerability explanation."""

    success: bool = Field(..., description="Whether the operation was successful")
    explanation: str = Field("", description="Vulnerability explanation text")
    vulnerabilities_count: int = Field(0, description="Number of vulnerabilities found")
    files_affected: List[str] = Field(
        default_factory=list, description="List of affected files"
    )
    errors: List[str] = Field(
        default_factory=list, description="List of error messages"
    )
