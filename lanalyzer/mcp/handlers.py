"""
MCP request handlers for Lanalyzer.

This module implements the handlers for MCP requests to Lanalyzer.
"""

import os
import tempfile
import logging
import json
import subprocess
import time
from typing import Dict, List, Any, Optional

from lanalyzer.analysis.tracker import EnhancedTaintTracker
from lanalyzer.cli.config_utils import load_configuration, validate_configuration
from lanalyzer.mcp.models import (
    AnalysisRequest,
    AnalysisResponse,
    ConfigurationRequest,
    ConfigurationResponse,
    VulnerabilityInfo,
    ServerInfoResponse,
    FileAnalysisRequest,
    ExplainVulnerabilityRequest,
    ExplainVulnerabilityResponse,
)

logger = logging.getLogger(__name__)


class LanalyzerMCPHandler:
    """Handles MCP protocol requests for Lanalyzer."""

    def __init__(self, debug: bool = False):
        """
        Initialize the MCP handler.

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
                vulnerabilities = tracker.analyze_file(temp_file_path)

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
                "--target",
                file_path,
                "--config",
                config_path,
                "--format",
                "json",  # Ensure JSON output for parsing
                "--output",
                output_path,
                "--log-file",
                log_file,
            ]
            if self.debug:
                cmd.append("--debug")

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

                    # The CLI output is a dictionary with a "vulnerabilities" key
                    vulnerabilities_json = analysis_output.get("vulnerabilities", [])

                    # Convert results to VulnerabilityInfo objects
                    vulnerabilities_info_list = []
                    for vuln_data in vulnerabilities_json:
                        try:
                            file_path_in_result = vuln_data.get("file", file_path)
                            source = vuln_data.get("source", {}) or {}
                            sink = vuln_data.get("sink", {}) or {}

                            vuln_info = VulnerabilityInfo(
                                rule_name=vuln_data.get("rule", "Unknown"),
                                rule_id=vuln_data.get(
                                    "rule_id"
                                ),  # Assuming rule_id might exist
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

                    summary = analysis_output.get(
                        "summary",
                        {
                            "files_analyzed": 1,  # Approximation if CLI doesn't provide detailed summary
                            "vulnerabilities_count": len(vulnerabilities_info_list),
                            "output_file": output_path,
                            "command": " ".join(cmd),
                        },
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
                            # os.rmdir is for empty dirs, shutil.rmtree for non-empty
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
                rule_data = vuln.get("rule", {}) or {}

                # Create vulnerability info
                vuln_info = VulnerabilityInfo(
                    rule_name=rule_data.get("name", "Unknown Rule"),
                    rule_id=rule_data.get("id"),
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
                "--target",
                target_path,
                "--config",
                config_path,
                "--format",
                "json",
                "--output",
                output_path_val,
                "--log-file",
                log_file,
            ]
            if self.debug:
                cmd.append("--debug")

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

                    vulnerabilities_json = analysis_output.get("vulnerabilities", [])
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

                    summary = analysis_output.get(
                        "summary",
                        {
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
                        },
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
                    # Clean up the temp directory created for non-user-specified output
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

    async def explain_vulnerabilities(
        self, request: ExplainVulnerabilityRequest
    ) -> ExplainVulnerabilityResponse:
        """
        Explain vulnerability analysis results, generating natural language descriptions.

        Args:
            request: ExplainVulnerabilityRequest request object

        Returns:
            ExplainVulnerabilityResponse: Explanation response
        """
        try:
            analysis_file = request.analysis_file
            if not os.path.exists(analysis_file):
                return ExplainVulnerabilityResponse(
                    success=False,
                    errors=[f"Analysis results file not found: {analysis_file}"],
                )

            # Read analysis results
            with open(analysis_file, "r", encoding="utf-8") as f:
                # Assuming the file contains the direct list of vulnerabilities
                # or a structure like {"vulnerabilities": [...]}
                raw_data = json.load(f)
                vulnerabilities_list = []
                if isinstance(raw_data, list):
                    vulnerabilities_list = raw_data
                elif isinstance(raw_data, dict) and "vulnerabilities" in raw_data:
                    vulnerabilities_list = raw_data["vulnerabilities"]
                else:
                    # Try to infer if it's a single vulnerability object not in a list
                    if (
                        isinstance(raw_data, dict) and "rule" in raw_data
                    ):  # Simple check
                        vulnerabilities_list = [raw_data]
                    else:
                        logger.error(
                            f"Unexpected format in analysis results file: {analysis_file}"
                        )
                        return ExplainVulnerabilityResponse(
                            success=False,
                            errors=[
                                f"Unexpected format in analysis results file: {analysis_file}. Expected a list of vulnerabilities or a dict with a 'vulnerabilities' key."
                            ],
                        )

            if not vulnerabilities_list:
                return ExplainVulnerabilityResponse(
                    success=True,
                    explanation="No security vulnerabilities found in the provided report.",
                    vulnerabilities_count=0,
                    files_affected=[],
                )

            # Extract affected files
            files_affected = sorted(
                list(
                    set(
                        v.get("file", v.get("file_path", ""))
                        for v in vulnerabilities_list
                        if v.get("file", v.get("file_path", ""))
                    )
                )
            )

            # Create explanation text
            if request.format == "markdown":
                explanation = self._generate_markdown_explanation(
                    vulnerabilities_list, request.level
                )
            else:
                explanation = self._generate_text_explanation(
                    vulnerabilities_list, request.level
                )

            return ExplainVulnerabilityResponse(
                success=True,
                explanation=explanation,
                vulnerabilities_count=len(vulnerabilities_list),
                files_affected=files_affected,
            )

        except json.JSONDecodeError as e:
            logger.exception(
                f"Error decoding JSON from analysis file {analysis_file}: {e}"
            )
            return ExplainVulnerabilityResponse(
                success=False,
                errors=[
                    f"Error decoding JSON from analysis file {analysis_file}: {str(e)}"
                ],
            )
        except Exception as e:
            logger.exception(f"Error explaining vulnerabilities: {e}")
            return ExplainVulnerabilityResponse(
                success=False,
                errors=[f"Failed to explain vulnerabilities: {str(e)}"],
            )

    def _generate_text_explanation(
        self, vulnerabilities: List[Dict[str, Any]], level: str
    ) -> str:
        """
        Generate text format vulnerability explanation.

        Args:
            vulnerabilities: List of vulnerabilities
            level: Detail level, "brief" or "detailed"

        Returns:
            str: Text format vulnerability explanation
        """
        if not vulnerabilities:
            return "No security vulnerabilities found."

        files_affected = sorted(
            list(
                set(
                    v.get("file", v.get("file_path", "Unknown File"))
                    for v in vulnerabilities
                    if v.get("file", v.get("file_path"))
                )
            )
        )

        explanation = [
            f"Security Vulnerability Analysis Report",
            f"====================================",
            f"",
            f"Found {len(vulnerabilities)} potential security vulnerabilities, affecting {len(files_affected)} file(s).",
            f"",
        ]

        # Group vulnerabilities by file
        vulns_by_file: Dict[str, List[Dict[str, Any]]] = {}
        for vuln in vulnerabilities:
            file_key = vuln.get("file", vuln.get("file_path", "Unknown File"))
            if file_key not in vulns_by_file:
                vulns_by_file[file_key] = []
            vulns_by_file[file_key].append(vuln)

        # Generate report per file
        for file_path_key, file_vulns in vulns_by_file.items():
            explanation.append(f"File: {file_path_key}")
            explanation.append(f"{'-' * (len(file_path_key) + 6)}")

            for i, vuln in enumerate(file_vulns, 1):
                rule_name = vuln.get(
                    "rule_name", vuln.get("rule", "Unknown Vulnerability Type")
                )
                severity = vuln.get("severity", "Unknown")
                sink_info = vuln.get("sink", {})
                line_no = sink_info.get("location", {}).get(
                    "line", sink_info.get("line", "Unknown")
                )
                message = vuln.get(
                    "message", vuln.get("description", "No description provided.")
                )

                explanation.append(f"Vulnerability #{i}: {rule_name}")
                explanation.append(f"  Severity: {severity}")
                explanation.append(f"  Location: Line {line_no}")
                explanation.append(f"  Description: {message}")

                if level == "detailed":
                    # Add call chain information
                    call_chain = vuln.get("call_chain", [])
                    if call_chain:
                        explanation.append("  Call Chain:")
                        for j, call in enumerate(call_chain, 1):
                            func = call.get(
                                "function_name",
                                call.get("function", "Unknown Function"),
                            )
                            call_line = call.get(
                                "line_number", call.get("line", "Unknown")
                            )
                            call_type = call.get("type", "Unknown Type")
                            call_desc = call.get("description", "")

                            explanation.append(
                                f"    {j}. [{call_type.capitalize()}] {func} (Line {call_line})"
                            )
                            if call_desc:
                                explanation.append(f"       {call_desc}")
                    snippet = vuln.get("code_snippet")
                    if snippet:
                        explanation.append("  Code Snippet:")
                        for line_content in snippet.splitlines():
                            explanation.append(f"    | {line_content}")

                explanation.append("")

            explanation.append("")

        # Add remediation suggestions
        explanation.append("Remediation Suggestions:")
        explanation.append("------------------------")

        # Collect unique rule names or primary types for suggestions
        unique_rule_types = set()
        for v in vulnerabilities:
            rule_name_val = v.get("rule_name", v.get("rule", ""))
            if rule_name_val:
                # Try to get a general type, e.g., "PickleDeserialization" from "rules.python.pickle.PickleDeserialization"
                primary_type = rule_name_val.split(".")[-1]
                unique_rule_types.add(primary_type)

        if (
            "PickleDeserialization" in unique_rule_types
            or "UnsafeDeserialization" in unique_rule_types
        ):
            explanation.append("1. For unsafe deserialization issues (e.g., pickle):")
            explanation.append(
                "   - Avoid using pickle.loads() or similar functions on untrusted data, especially from network or user input."
            )
            explanation.append(
                "   - Consider using safer serialization formats like JSON if the data structure allows."
            )
            explanation.append(
                "   - If pickle must be used with untrusted data, implement a custom Unpickler that restricts loadable object types to only known safe types."
            )
            explanation.append("")

        if "SQLInjection" in unique_rule_types:
            explanation.append("2. For SQL injection issues:")
            explanation.append(
                "   - Use parameterized queries (prepared statements) with your database driver instead of string concatenation or formatting."
            )
            explanation.append(
                "   - Utilize Object-Relational Mapping (ORM) frameworks like SQLAlchemy, which often handle parameterization automatically."
            )
            explanation.append(
                "   - Validate and sanitize all user input before incorporating it into database queries, even when using ORMs or parameterized queries as an additional layer of defense."
            )
            explanation.append("")

        explanation.append("3. General Recommendations:")
        explanation.append(
            "   - Implement robust input validation for all data received from external sources."
        )
        explanation.append(
            "   - Adhere to the principle of least privilege for all system components and users."
        )
        explanation.append(
            "   - Implement comprehensive security logging and monitoring to detect and respond to suspicious activities."
        )
        explanation.append(
            "   - Keep all libraries and dependencies up to date to patch known vulnerabilities."
        )

        return "\n".join(explanation)

    def _generate_markdown_explanation(
        self, vulnerabilities: List[Dict[str, Any]], level: str
    ) -> str:
        """
        Generate Markdown format vulnerability explanation.

        Args:
            vulnerabilities: List of vulnerabilities
            level: Detail level, "brief" or "detailed"

        Returns:
            str: Markdown format vulnerability explanation
        """
        if not vulnerabilities:
            return "No security vulnerabilities found."

        files_affected = sorted(
            list(
                set(
                    v.get("file", v.get("file_path", "Unknown File"))
                    for v in vulnerabilities
                    if v.get("file", v.get("file_path"))
                )
            )
        )

        explanation = [
            f"# Security Vulnerability Analysis Report",
            f"",
            f"Found **{len(vulnerabilities)}** potential security vulnerabilities, affecting **{len(files_affected)}** file(s).",
            f"",
        ]

        # Group vulnerabilities by file
        vulns_by_file: Dict[str, List[Dict[str, Any]]] = {}
        for vuln in vulnerabilities:
            file_key = vuln.get("file", vuln.get("file_path", "Unknown File"))
            if file_key not in vulns_by_file:
                vulns_by_file[file_key] = []
            vulns_by_file[file_key].append(vuln)

        # Generate report per file
        for file_path_key, file_vulns in vulns_by_file.items():
            explanation.append(f"## File: `{file_path_key}`")

            for i, vuln in enumerate(file_vulns, 1):
                rule_name = vuln.get(
                    "rule_name", vuln.get("rule", "Unknown Vulnerability Type")
                )
                severity = vuln.get("severity", "Unknown").upper()
                sink_info = vuln.get("sink", {})
                line_no = sink_info.get("location", {}).get(
                    "line", sink_info.get("line", "Unknown")
                )
                message = vuln.get(
                    "message", vuln.get("description", "No description provided.")
                )

                severity_emoji = (
                    "🔴"
                    if severity == "HIGH"
                    else "🟠"
                    if severity == "MEDIUM"
                    else "🟡"
                    if severity == "LOW"
                    else "⚪"  # For INFO or UNKNOWN
                )

                explanation.append(
                    f"### {severity_emoji} Vulnerability #{i}: {rule_name}"
                )
                explanation.append(f"- **Severity**: {severity}")
                explanation.append(f"- **Location**: Line {line_no}")
                explanation.append(f"- **Description**: {message}")

                if level == "detailed":
                    # Add call chain information
                    call_chain = vuln.get("call_chain", [])
                    if call_chain:
                        explanation.append("\n  **Call Chain**:")
                        for j, call in enumerate(call_chain, 1):
                            func = call.get(
                                "function_name",
                                call.get("function", "Unknown Function"),
                            )
                            call_line = call.get(
                                "line_number", call.get("line", "Unknown")
                            )
                            call_type = call.get(
                                "type", "intermediate"
                            ).capitalize()  # e.g. source, sink, intermediate
                            call_desc = call.get("description", "")

                            type_icon = (
                                "🔍"
                                if call_type.lower() == "source"
                                else "🎯"
                                if call_type.lower() == "sink"
                                else "➡️"  # Using target/dartboard for sink  # Arrow for intermediate steps
                            )

                            explanation.append(
                                f"    {j}. {type_icon} **{func}** (Line {call_line}) - *{call_type}*"
                            )
                            if call_desc:
                                explanation.append(f"       - {call_desc}")
                    snippet = vuln.get("code_snippet")
                    if snippet:
                        explanation.append("  **Code Snippet**:")
                        explanation.append("  ```python")
                        explanation.extend(
                            [
                                f"  {line_content}"
                                for line_content in snippet.splitlines()
                            ]
                        )
                        explanation.append("  ```")

                explanation.append("")  # Adds a newline for better spacing in Markdown

        # Add remediation suggestions
        explanation.append("## Remediation Suggestions")

        unique_rule_types = set()
        for v in vulnerabilities:
            rule_name_val = v.get("rule_name", v.get("rule", ""))
            if rule_name_val:
                primary_type = rule_name_val.split(".")[-1]
                unique_rule_types.add(primary_type)

        if (
            "PickleDeserialization" in unique_rule_types
            or "UnsafeDeserialization" in unique_rule_types
        ):
            explanation.append(
                "### For unsafe deserialization issues (e.g., `pickle`):"
            )
            explanation.append(
                "- Avoid using `pickle.loads()` or similar functions on untrusted data, especially from network or user input."
            )
            explanation.append(
                "- Consider using safer serialization formats like JSON if the data structure allows."
            )
            explanation.append(
                "- If `pickle` must be used with untrusted data, implement a custom `Unpickler` that restricts loadable object types to only known safe types."
            )
            explanation.append("")

        if "SQLInjection" in unique_rule_types:
            explanation.append("### For SQL injection issues:")
            explanation.append(
                "- Use parameterized queries (prepared statements) with your database driver instead of string concatenation or formatting."
            )
            explanation.append(
                "- Utilize Object-Relational Mapping (ORM) frameworks like SQLAlchemy, which often handle parameterization automatically."
            )
            explanation.append(
                "- Validate and sanitize all user input before incorporating it into database queries, even when using ORMs or parameterized queries as an additional layer of defense."
            )
            explanation.append("")

        explanation.append("### General Recommendations:")
        explanation.append(
            "- Implement robust input validation for all data received from external sources."
        )
        explanation.append(
            "- Adhere to the principle of least privilege for all system components and users."
        )
        explanation.append(
            "- Implement comprehensive security logging and monitoring to detect and respond to suspicious activities."
        )
        explanation.append(
            "- Keep all libraries and dependencies up to date to patch known vulnerabilities."
        )

        return "\n".join(explanation)
