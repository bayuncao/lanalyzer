"""
Analysis MCP handler for Lanalyzer.

This module implements the analysis handlers for MCP requests to Lanalyzer.
"""

import json
import os
import subprocess
import sys
import tempfile
import time

from lanalyzer.analysis import EnhancedTaintTracker
from lanalyzer.cli.config_utils import load_configuration
from lanalyzer.logger import get_logger

from ..models import (
    AnalysisRequest,
    AnalysisResponse,
    FileAnalysisRequest,
    VulnerabilityInfo,
)
from .base import BaseMCPHandler

logger = get_logger(__name__)


class AnalysisMCPHandler(BaseMCPHandler):
    """Handles MCP protocol analysis requests for Lanalyzer."""

    async def handle_analysis_request(
        self, request: AnalysisRequest
    ) -> AnalysisResponse:
        """
        Handle a request to analyze code.

        Args:
            request: The analysis request

        Returns:
            AnalysisResponse: The analysis response
        """
        try:
            # Check if the configuration file path is valid
            if not request.config_path:
                return AnalysisResponse(
                    success=False,
                    errors=["Configuration file path cannot be empty"],
                )

            # Check if the configuration file exists
            if not os.path.exists(request.config_path):
                return AnalysisResponse(
                    success=False,
                    errors=[f"Configuration file not found: {request.config_path}"],
                )

            # Create a temporary file for the code
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".py", delete=False, encoding="utf-8"
            ) as temp_file:
                temp_file.write(request.code)
                temp_file_path = temp_file.name

            try:
                # Load configuration
                logger.debug(f"Using configuration file: {request.config_path}")
                config = load_configuration(request.config_path, self.debug)

                # Initialize tracker with config
                tracker = EnhancedTaintTracker(config, debug=self.debug)

                # Analyze the file
                vulnerabilities, _ = tracker.analyze_file(
                    temp_file_path
                )  # Ignore call_chains for now

                # Convert vulnerabilities to response format
                vuln_info_list = self._convert_vulnerabilities(
                    vulnerabilities, request.file_path
                )

                # Get analysis summary
                summary = tracker.get_summary()

                return AnalysisResponse(
                    success=True,
                    vulnerabilities=vuln_info_list,
                    summary=summary,
                )
            finally:
                # Clean up temporary file
                if os.path.exists(temp_file_path):
                    os.unlink(temp_file_path)

        except Exception as e:
            logger.exception("Error handling analysis request")
            return AnalysisResponse(
                success=False,
                errors=[f"Analysis failed: {str(e)}"],
            )

    async def handle_file_analysis_request(
        self, file_path: str, config_path: str
    ) -> AnalysisResponse:
        """
        Handle a request to analyze an existing file.
        Note: This method currently uses the CLI tool via subprocess.

        Args:
            file_path: Path to the file to analyze
            config_path: Path to the configuration file (required)

        Returns:
            AnalysisResponse: The analysis response
        """
        # Add debug log
        logger.debug(
            f"handle_file_analysis_request called: file_path={file_path}, config_path={config_path}"
        )
        logger.debug(f"config_path type: {type(config_path)}")

        try:
            # Check if the file exists
            if not os.path.exists(file_path):
                return AnalysisResponse(
                    success=False,
                    errors=[f"File not found: {file_path}"],
                )

            # Check if the configuration file exists
            if not os.path.exists(config_path):
                return AnalysisResponse(
                    success=False,
                    errors=[f"Configuration file not found: {config_path}"],
                )

            # Generate output file path
            base_name = os.path.splitext(os.path.basename(file_path))[0]
            output_dir = tempfile.mkdtemp(prefix="lanalyzer_mcp_")
            output_path = os.path.join(
                output_dir, f"analysis_{base_name}_{int(time.time())}.json"
            )

            # Generate temporary log file path
            log_file = os.path.join(output_dir, f"log_{int(time.time())}.txt")

            # Build command line
            cmd = [
                sys.executable,  # Use current python interpreter
                "-m",
                "lanalyzer",  # Run as module
                "analyze",  # Add analyze subcommand
                "--target",
                file_path,
                "--config",
                config_path,
                "--output",
                output_path,
                "--log-file",
                log_file,
            ]
            if self.debug:
                cmd.append("--debug")
            # Default to full output for MCP (no --minimal-output flag)

            if self.debug:
                logger.debug(f"Executing command: {' '.join(cmd)}")

            # Execute command
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
            )
            stdout, stderr = process.communicate()

            if process.returncode != 0:
                logger.error(f"Analysis failed, exit code: {process.returncode}")
                logger.error(f"Standard Output: {stdout}")
                logger.error(f"Error output: {stderr}")
                error_message = (
                    stderr or stdout or "Unknown error during CLI execution."
                )
                return AnalysisResponse(
                    success=False,
                    errors=[f"Analysis failed: {error_message}"],
                )

            # Read analysis results
            if os.path.exists(output_path):
                try:
                    with open(output_path, "r", encoding="utf-8") as f:
                        analysis_output = json.load(f)

                    if isinstance(analysis_output, list):
                        vulnerabilities_json = analysis_output
                    else:
                        vulnerabilities_json = analysis_output.get(
                            "vulnerabilities", []
                        )

                    vulnerabilities_info_list = []
                    for vuln_data in vulnerabilities_json:
                        try:
                            file_path_in_result = vuln_data.get("file", file_path)
                            source = vuln_data.get("source", {}) or {}
                            sink = vuln_data.get("sink", {}) or {}
                            rule_value = vuln_data.get("rule", "Unknown")
                            rule_name = (
                                rule_value
                                if isinstance(rule_value, str)
                                else rule_value.get("name", "Unknown")
                            )
                            rule_id = (
                                vuln_data.get("rule_id")
                                if isinstance(rule_value, dict)
                                else None
                            )
                            vuln_info = VulnerabilityInfo(
                                rule_name=rule_name,
                                rule_id=rule_id,
                                message=vuln_data.get(
                                    "message", "Potential security vulnerability"
                                ),
                                severity=vuln_data.get("severity", "HIGH"),
                                source=source,
                                sink=sink,
                                file_path=file_path_in_result,
                                line=sink.get("location", {}).get(
                                    "line", sink.get("line", 0)
                                ),
                                call_chain=vuln_data.get("call_chain"),
                                code_snippet=vuln_data.get("code_snippet"),
                            )
                            vulnerabilities_info_list.append(vuln_info)
                        except Exception as e:
                            logger.exception(
                                f"Error converting vulnerability information: {e} - Data: {vuln_data}"
                            )

                    summary = (
                        analysis_output.get(
                            "summary",
                            {
                                "files_analyzed": 1,  # Approximation if CLI doesn't provide detailed summary
                                "vulnerabilities_count": len(vulnerabilities_info_list),
                                "output_file": output_path,
                                "command": " ".join(cmd),
                            },
                        )
                        if isinstance(analysis_output, dict)
                        else {
                            "files_analyzed": 1,
                            "vulnerabilities_count": len(vulnerabilities_info_list),
                            "output_file": output_path,
                            "command": " ".join(cmd),
                        }
                    )

                    return AnalysisResponse(
                        success=True,
                        vulnerabilities=vulnerabilities_info_list,
                        summary=summary,
                    )

                except Exception as e:
                    logger.exception(f"Error reading analysis results: {e}")
                    return AnalysisResponse(
                        success=False,
                        errors=[f"Error reading analysis results: {str(e)}"],
                    )
                finally:
                    # Clean up temporary directory
                    if os.path.exists(output_dir):
                        try:
                            import shutil

                            shutil.rmtree(output_dir)
                        except Exception as e_rm:
                            logger.error(
                                f"Failed to remove temp directory {output_dir}: {e_rm}"
                            )

            else:
                logger.error(
                    f"Analysis output file not found: {output_path}. Stdout: {stdout}, Stderr: {stderr}"
                )
                return AnalysisResponse(
                    success=False,
                    errors=[
                        f"Analysis completed but output file not found: {output_path}. CLI stdout: {stdout}, stderr: {stderr}"
                    ],
                )

        except Exception as e:
            logger.exception(f"Error analyzing file {file_path}")
            return AnalysisResponse(
                success=False,
                errors=[f"Analysis failed: {str(e)}"],
            )

    async def handle_file_path_analysis(
        self, request: FileAnalysisRequest
    ) -> AnalysisResponse:
        """
        Handle file or directory analysis request using the command-line tool.

        Args:
            request: FileAnalysisRequest request object

        Returns:
            AnalysisResponse: Analysis response
        """
        try:
            target_path = request.target_path
            if not os.path.exists(target_path):
                return AnalysisResponse(
                    success=False,
                    errors=[f"Target path not found: {target_path}"],
                )

            # Check configuration file path
            config_path = request.config_path
            if not config_path:
                return AnalysisResponse(
                    success=False,
                    errors=["Configuration file path cannot be empty"],
                )

            # Check if configuration file exists
            if not os.path.exists(config_path):
                return AnalysisResponse(
                    success=False,
                    errors=[f"Configuration file not found: {config_path}"],
                )

            # Determine output file path
            output_dir = tempfile.mkdtemp(prefix="lanalyzer_mcp_")
            output_path_val = request.output_path
            if not output_path_val:
                # Generate output path based on target file name
                if os.path.isdir(target_path):
                    base_name = os.path.basename(target_path.rstrip("/\\"))
                else:
                    base_name = os.path.splitext(os.path.basename(target_path))[0]
                output_path_val = os.path.join(
                    output_dir, f"analysis_{base_name}_{int(time.time())}.json"
                )
            else:
                # If user specified an output_path, ensure its directory exists
                output_dir_user = os.path.dirname(output_path_val)
                if output_dir_user:
                    os.makedirs(output_dir_user, exist_ok=True)

            # Generate temporary log file path
            log_file = os.path.join(output_dir, f"log_{int(time.time())}.txt")

            # Build command line
            cmd = [
                sys.executable,
                "-m",
                "lanalyzer",
                "analyze",  # Add analyze subcommand
                "--target",
                target_path,
                "--config",
                config_path,
                "--output",
                output_path_val,
                "--log-file",
                log_file,
            ]
            if self.debug:
                cmd.append("--debug")
            # Use minimal_output setting from request
            if request.minimal_output:
                cmd.append("--minimal-output")

            if self.debug:
                logger.debug(f"Executing command: {' '.join(cmd)}")

            # Execute command
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
            )
            stdout, stderr = process.communicate()

            if process.returncode != 0:
                logger.error(f"Analysis failed, exit code: {process.returncode}")
                logger.error(f"Standard Output: {stdout}")
                logger.error(f"Error output: {stderr}")
                error_message = (
                    stderr or stdout or "Unknown error during CLI execution."
                )
                return AnalysisResponse(
                    success=False,
                    errors=[f"Analysis failed: {error_message}"],
                )

            # Read analysis results
            if os.path.exists(output_path_val):
                try:
                    with open(output_path_val, "r", encoding="utf-8") as f:
                        analysis_output = json.load(f)

                    if isinstance(analysis_output, list):
                        vulnerabilities_json = analysis_output
                    else:
                        vulnerabilities_json = analysis_output.get(
                            "vulnerabilities", []
                        )
                    vulnerabilities_info_list = []
                    for vuln_data in vulnerabilities_json:
                        try:
                            file_p = vuln_data.get("file", "")
                            source = vuln_data.get("source", {}) or {}
                            sink = vuln_data.get("sink", {}) or {}

                            vuln_info = VulnerabilityInfo(
                                rule_name=vuln_data.get("rule", "Unknown"),
                                rule_id=vuln_data.get("rule_id"),
                                message=vuln_data.get(
                                    "message", "Potential security vulnerability"
                                ),
                                severity=vuln_data.get("severity", "HIGH"),
                                source=source,
                                sink=sink,
                                file_path=file_p,
                                line=sink.get("location", {}).get(
                                    "line", sink.get("line", 0)
                                ),
                                call_chain=vuln_data.get("call_chain"),
                                code_snippet=vuln_data.get("code_snippet"),
                            )
                            vulnerabilities_info_list.append(vuln_info)
                        except Exception as e:
                            logger.exception(
                                f"Error converting vulnerability information: {e} - Data: {vuln_data}"
                            )

                    default_summary = {
                        "files_analyzed": len(
                            set(
                                v.file_path
                                for v in vulnerabilities_info_list
                                if v.file_path
                            )
                        )
                        or (1 if os.path.isfile(target_path) else 0),  # Best guess
                        "vulnerabilities_count": len(vulnerabilities_info_list),
                        "output_file": output_path_val,
                    }

                    if isinstance(analysis_output, list):
                        summary = default_summary
                    else:
                        summary = analysis_output.get("summary", default_summary)

                    return AnalysisResponse(
                        success=True,
                        vulnerabilities=vulnerabilities_info_list,
                        summary=summary,
                    )

                except Exception as e:
                    logger.exception(f"Error reading analysis results: {e}")
                    return AnalysisResponse(
                        success=False,
                        errors=[f"Error reading analysis results: {str(e)}"],
                    )
                finally:
                    # Clean up temporary directory
                    if not request.output_path and os.path.exists(output_dir):
                        try:
                            import shutil

                            shutil.rmtree(output_dir)
                        except Exception as e_rm:
                            logger.error(
                                f"Failed to remove temp directory {output_dir}: {e_rm}"
                            )
            else:
                logger.error(
                    f"Analysis output file not found: {output_path_val}. Stdout: {stdout}, Stderr: {stderr}"
                )
                return AnalysisResponse(
                    success=False,
                    errors=[
                        f"Analysis completed but output file not found: {output_path_val}. CLI stdout: {stdout}, stderr: {stderr}"
                    ],
                )

        except Exception as e:
            logger.exception(f"Error handling file path analysis request: {e}")
            return AnalysisResponse(
                success=False,
                errors=[f"Analysis failed: {str(e)}"],
            )
