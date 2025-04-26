"""
MCP server implementation for Lanalyzer.

This module provides the Model Context Protocol (MCP) server implementation for Lanalyzer.
"""

import os
import json
import logging
import argparse
from typing import Dict, Any, Optional, Union, List

try:
    from fastapi import FastAPI, HTTPException, Body, Query, Request
    from fastapi.responses import JSONResponse
    from fastapi.middleware.cors import CORSMiddleware
    import uvicorn
    from pydantic import BaseModel, ValidationError, Field
except ImportError:
    raise ImportError(
        "MCP server requires additional dependencies. "
        "Please install with `pip install lanalyzer[mcp]`"
    )

from lanalyzer.mcp.handlers import LanalyzerMCPHandler
from lanalyzer.mcp.models import (
    AnalysisRequest,
    AnalysisResponse,
    ConfigurationRequest,
    ConfigurationResponse,
    ServerInfoResponse,
    FileAnalysisRequest,
    ExplainVulnerabilityRequest,
    ExplainVulnerabilityResponse,
)
from lanalyzer.__version__ import __version__


logger = logging.getLogger(__name__)


class MCPServer:
    """Model Context Protocol server for Lanalyzer."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8000,
        debug: bool = False,
    ):
        """
        Initialize the MCP server.

        Args:
            host: The host to bind to
            port: The port to bind to
            debug: Whether to enable debug output
        """
        self.host = host
        self.port = port
        self.debug = debug
        self.app = FastAPI(
            title="Lanalyzer MCP Server",
            description="Model Context Protocol (MCP) server for Lanalyzer Python taint analysis",
            version=__version__,
        )

        # Add CORS middleware
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

        # Initialize handler
        self.handler = LanalyzerMCPHandler(debug=debug)

        # Setup routes
        self._setup_routes()

    def _setup_routes(self) -> None:
        """Set up the API routes."""

        # Root MCP endpoint
        @self.app.get("/", response_model=ServerInfoResponse)
        async def root():
            """Get server information."""
            return await self.handler.get_server_info()

        # Analysis endpoint
        @self.app.post("/analyze", response_model=AnalysisResponse)
        async def analyze_code(request: AnalysisRequest):
            """
            Analyze code for security vulnerabilities.

            Args:
                request: Analysis request

            Returns:
                Analysis response
            """
            try:
                return await self.handler.handle_analysis_request(request)
            except Exception as e:
                logger.exception("Error handling analysis request")
                return AnalysisResponse(
                    success=False,
                    errors=[f"Analysis failed: {str(e)}"],
                )

        # File analysis endpoint
        @self.app.get("/analyze/file", response_model=AnalysisResponse)
        async def analyze_file(
            file_path: str = Query(..., description="Path to the file to analyze"),
            config_path: Optional[str] = Query(
                None, description="Path to the configuration file"
            ),
        ):
            """
            Analyze an existing file for security vulnerabilities.

            Args:
                file_path: Path to the file to analyze
                config_path: Optional path to the configuration file

            Returns:
                Analysis response
            """
            try:
                return await self.handler.handle_file_analysis_request(
                    file_path, config_path
                )
            except Exception as e:
                logger.exception(f"Error analyzing file {file_path}")
                return AnalysisResponse(
                    success=False,
                    errors=[f"Analysis failed: {str(e)}"],
                )

        # File path analysis endpoint
        @self.app.post("/analyze/path", response_model=AnalysisResponse)
        async def analyze_path(request: FileAnalysisRequest):
            """
            分析本地文件或目录中的安全漏洞。

            Args:
                request: 文件分析请求

            Returns:
                AnalysisResponse: 分析响应
            """
            try:
                return await self.handler.handle_file_path_analysis(request)
            except Exception as e:
                logger.exception("处理文件路径分析请求时出错")
                return AnalysisResponse(
                    success=False,
                    errors=[f"分析失败: {str(e)}"],
                )

        # Explain vulnerabilities endpoint
        @self.app.post("/explain", response_model=ExplainVulnerabilityResponse)
        async def explain_vulnerabilities(request: ExplainVulnerabilityRequest):
            """
            解释漏洞分析结果，生成自然语言说明。

            Args:
                request: 解释漏洞请求

            Returns:
                ExplainVulnerabilityResponse: 解释响应
            """
            try:
                return await self.handler.explain_vulnerabilities(request)
            except Exception as e:
                logger.exception("解释漏洞时出错")
                return ExplainVulnerabilityResponse(
                    success=False,
                    errors=[f"解释漏洞失败: {str(e)}"],
                )

        # Configuration endpoint
        @self.app.post("/configuration", response_model=ConfigurationResponse)
        async def handle_configuration(request: ConfigurationRequest):
            """
            Handle configuration operations.

            Args:
                request: Configuration request

            Returns:
                Configuration response
            """
            try:
                return await self.handler.handle_configuration_request(request)
            except Exception as e:
                logger.exception("Error handling configuration request")
                return ConfigurationResponse(
                    success=False,
                    errors=[f"Configuration operation failed: {str(e)}"],
                )

        # MCP protocol support endpoint - per MCP spec 2025-03-26
        @self.app.post("/.well-known/mcp/v1")
        async def mcp_endpoint_post(request: Request):
            """
            MCP protocol endpoint for POST requests.

            This is the standardized MCP endpoint as specified in the MCP protocol.

            Args:
                request: FastAPI request

            Returns:
                JSON response with MCP response
            """
            return await self._handle_mcp_request(request)

        @self.app.get("/.well-known/mcp/v1")
        async def mcp_endpoint_get():
            """
            MCP protocol endpoint for GET requests.

            This provides compatibility with clients that try GET requests first.

            Returns:
                Server info response
            """
            server_info = await self.handler.get_server_info()
            return JSONResponse(
                {
                    "type": "server_info_response",
                    "server": server_info.dict(),
                }
            )

    async def _handle_mcp_request(self, request: Request):
        """
        Handle MCP request.

        Args:
            request: FastAPI request

        Returns:
            JSON response with MCP response
        """
        try:
            # Parse the JSON body
            body = await request.json()

            # Extract the type field to determine the kind of request
            request_type = body.get("type")

            if request_type == "server_info":
                # Server info request
                server_info = await self.handler.get_server_info()
                return JSONResponse(
                    {
                        "type": "server_info_response",
                        "server": server_info.dict(),
                    }
                )

            elif request_type == "analyze":
                # Analysis request
                analysis_request = AnalysisRequest(
                    code=body.get("code", ""),
                    file_path=body.get("file_path", "unknown.py"),
                    config=body.get("config"),
                    options=body.get("options", {}),
                )

                response = await self.handler.handle_analysis_request(analysis_request)

                return JSONResponse(
                    {
                        "type": "analyze_response",
                        "success": response.success,
                        "vulnerabilities": [v.dict() for v in response.vulnerabilities],
                        "errors": response.errors,
                        "summary": response.summary,
                    }
                )

            elif request_type == "analyze_path":
                # File/directory path analysis request
                file_analysis_request = FileAnalysisRequest(
                    target_path=body.get("target_path", ""),
                    config_path=body.get("config_path"),
                    output_path=body.get("output_path"),
                    options=body.get("options", {}),
                )

                response = await self.handler.handle_file_path_analysis(
                    file_analysis_request
                )

                return JSONResponse(
                    {
                        "type": "analyze_path_response",
                        "success": response.success,
                        "vulnerabilities": [v.dict() for v in response.vulnerabilities],
                        "errors": response.errors,
                        "summary": response.summary,
                    }
                )

            elif request_type == "explain_vulnerabilities":
                # Explain vulnerabilities request
                explain_request = ExplainVulnerabilityRequest(
                    analysis_file=body.get("analysis_file", ""),
                    format=body.get("format", "text"),
                    level=body.get("level", "detailed"),
                )

                response = await self.handler.explain_vulnerabilities(explain_request)

                return JSONResponse(
                    {
                        "type": "explain_vulnerabilities_response",
                        "success": response.success,
                        "explanation": response.explanation,
                        "vulnerabilities_count": response.vulnerabilities_count,
                        "files_affected": response.files_affected,
                        "errors": response.errors,
                    }
                )

            elif request_type == "configuration":
                # Configuration request
                config_request = ConfigurationRequest(
                    operation=body.get("operation", ""),
                    config_path=body.get("config_path"),
                    config_data=body.get("config_data"),
                )

                response = await self.handler.handle_configuration_request(
                    config_request
                )

                return JSONResponse(
                    {
                        "type": "configuration_response",
                        "success": response.success,
                        "config": response.config,
                        "errors": response.errors,
                        "validation_result": response.validation_result,
                    }
                )

            else:
                # Unknown request type
                return JSONResponse(
                    {
                        "type": "error",
                        "error": f"Unsupported request type: {request_type}",
                    },
                    status_code=400,
                )

        except json.JSONDecodeError:
            return JSONResponse(
                {
                    "type": "error",
                    "error": "Invalid JSON in request body",
                },
                status_code=400,
            )
        except ValidationError as e:
            return JSONResponse(
                {
                    "type": "error",
                    "error": f"Invalid request parameters: {str(e)}",
                },
                status_code=400,
            )
        except Exception as e:
            logger.exception("Error handling MCP request")
            return JSONResponse(
                {
                    "type": "error",
                    "error": f"Internal server error: {str(e)}",
                },
                status_code=500,
            )

    def run(self) -> None:
        """Run the MCP server."""
        uvicorn.run(
            self.app,
            host=self.host,
            port=self.port,
            log_level="debug" if self.debug else "info",
        )


def create_parser() -> argparse.ArgumentParser:
    """
    Create the command-line argument parser for the MCP server.

    Returns:
        argparse.ArgumentParser: The argument parser
    """
    parser = argparse.ArgumentParser(
        description="Lanalyzer MCP Server - Model Context Protocol server for Lanalyzer"
    )

    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind the server to (default: 127.0.0.1)",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind the server to (default: 8000)",
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode",
    )

    return parser


def main() -> None:
    """
    Main entry point for the MCP server.

    This is used as the entry point for the `lanalyzer-mcp` command.
    """
    # Parse arguments
    parser = create_parser()
    args = parser.parse_args()

    # Configure logging
    logging_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=logging_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Print server info
    print(f"Starting Lanalyzer MCP Server v{__version__}")
    print(f"Binding to {args.host}:{args.port}")
    print(f"Debug mode: {args.debug}")

    # Run server
    server = MCPServer(
        host=args.host,
        port=args.port,
        debug=args.debug,
    )

    server.run()


if __name__ == "__main__":
    main()
