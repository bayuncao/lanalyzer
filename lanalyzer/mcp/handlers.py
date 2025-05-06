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
        self.version = "0.1.0"  # Should match Lanalyzer version

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
            # 检查配置文件路径是否有效
            if not request.config_path:
                return AnalysisResponse(
                    success=False,
                    errors=["配置文件路径不能为空"],
                )

            # 检查配置文件是否存在
            if not os.path.exists(request.config_path):
                return AnalysisResponse(
                    success=False,
                    errors=[f"配置文件不存在: {request.config_path}"],
                )

            # Create a temporary file for the code
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".py", delete=False
            ) as temp_file:
                temp_file.write(request.code)
                temp_file_path = temp_file.name

            try:
                # Load configuration
                logger.debug(f"使用配置文件: {request.config_path}")
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

        Args:
            file_path: Path to the file to analyze
            config_path: Path to the configuration file (required)

        Returns:
            AnalysisResponse: The analysis response
        """
        # 添加调试日志
        logger.debug(
            f"handle_file_analysis_request被调用: file_path={file_path}, config_path={config_path}"
        )
        logger.debug(f"config_path类型: {type(config_path)}")

        try:
            # 检查文件是否存在
            if not os.path.exists(file_path):
                return AnalysisResponse(
                    success=False,
                    errors=[f"文件不存在: {file_path}"],
                )

            # 检查配置文件是否存在
            if not os.path.exists(config_path):
                return AnalysisResponse(
                    success=False,
                    errors=[f"配置文件不存在: {config_path}"],
                )

            # 生成输出文件路径
            base_name = os.path.splitext(os.path.basename(file_path))[0]
            output_path = f"./analysis_{base_name}_{int(time.time())}.json"

            # 生成临时日志文件路径
            log_file = f"./log_{int(time.time())}.txt"

            # 构建命令行
            cmd = [
                "lanalyzer",
                "--target",
                file_path,
                "--config",
                config_path,
                "--pretty",
                "--output",
                output_path,
                "--log-file",
                log_file,
                "--debug",
            ]

            if self.debug:
                logger.debug(f"执行命令: {' '.join(cmd)}")

            # 执行命令
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            stdout, stderr = process.communicate()

            if process.returncode != 0:
                logger.error(f"分析失败，退出码: {process.returncode}")
                logger.error(f"错误输出: {stderr}")
                return AnalysisResponse(
                    success=False,
                    errors=[f"分析失败: {stderr}"],
                )

            # 读取分析结果
            if os.path.exists(output_path):
                try:
                    with open(output_path, "r", encoding="utf-8") as f:
                        vulnerabilities_json = json.load(f)

                    # 将结果转换为VulnerabilityInfo对象
                    vulnerabilities = []
                    for vuln in vulnerabilities_json:
                        try:
                            file_path_in_result = vuln.get("file", file_path)

                            source = vuln.get("source", {}) or {}
                            sink = vuln.get("sink", {}) or {}
                            rule = {"name": vuln.get("rule", "Unknown"), "id": None}

                            vuln_info = VulnerabilityInfo(
                                rule_name=rule["name"],
                                rule_id=rule["id"],
                                message=vuln.get("description", "潜在安全漏洞"),
                                severity=vuln.get("severity", "HIGH"),
                                source=source,
                                sink=sink,
                                file_path=file_path_in_result,
                                line=sink.get("line", 0),
                                call_chain=vuln.get("call_chain"),
                                code_snippet=None,
                            )
                            vulnerabilities.append(vuln_info)
                        except Exception as e:
                            logger.exception(f"转换漏洞信息时出错: {e}")

                    # 构建分析摘要
                    summary = {
                        "files_analyzed": 1,
                        "vulnerabilities_count": len(vulnerabilities),
                        "output_file": output_path,
                        "command": " ".join(cmd),
                    }

                    return AnalysisResponse(
                        success=True,
                        vulnerabilities=vulnerabilities,
                        summary=summary,
                    )

                except Exception as e:
                    logger.exception(f"读取分析结果时出错: {e}")
                    return AnalysisResponse(
                        success=False,
                        errors=[f"读取分析结果时出错: {str(e)}"],
                    )
            else:
                return AnalysisResponse(
                    success=False,
                    errors=[f"分析完成但未找到输出文件: {output_path}"],
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
            # Use default configuration
            config_path = os.path.join(
                os.path.dirname(__file__), "../../rules/pickle_analysis_config.json"
            )

        try:
            config = load_configuration(config_path, self.debug)
            return ConfigurationResponse(
                success=True,
                config=config,
            )
        except Exception as e:
            return ConfigurationResponse(
                success=False,
                errors=[f"Failed to load configuration: {str(e)}"],
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
            except Exception as e:
                return ConfigurationResponse(
                    success=False,
                    errors=[f"Failed to load configuration: {str(e)}"],
                )

        if not config_data:
            return ConfigurationResponse(
                success=False,
                errors=["No configuration data provided"],
            )

        # Validate the configuration
        is_valid, issues = validate_configuration(config_data)

        return ConfigurationResponse(
            success=is_valid,
            config=config_data,
            errors=issues,
            validation_result={"valid": is_valid, "issues": issues},
        )

    async def _handle_create_config(
        self, config_data: Dict[str, Any], config_path: Optional[str]
    ) -> ConfigurationResponse:
        """
        Handle a request to create a configuration.

        Args:
            config_data: Configuration data
            config_path: Path to save the configuration file

        Returns:
            ConfigurationResponse: The configuration response
        """
        # Validate the configuration first
        is_valid, issues = validate_configuration(config_data)
        if not is_valid:
            return ConfigurationResponse(
                success=False,
                errors=["Invalid configuration"] + issues,
                validation_result={"valid": is_valid, "issues": issues},
            )

        # If path is provided, save the configuration
        if config_path:
            try:
                os.makedirs(os.path.dirname(config_path), exist_ok=True)
                with open(config_path, "w") as f:
                    json.dump(config_data, f, indent=2)
            except Exception as e:
                return ConfigurationResponse(
                    success=False,
                    errors=[f"Failed to save configuration: {str(e)}"],
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
            # 检查vuln是否为字典类型
            if not isinstance(vuln, dict):
                logger.warning(f"Skipping non-dict vulnerability: {type(vuln)}")
                continue

            try:
                # Extract file path from vulnerability
                file_path = vuln.get("file_path", display_file_path)

                # 确保所有必需字段都有默认值
                source = vuln.get("source", {}) or {}
                sink = vuln.get("sink", {}) or {}
                rule = vuln.get("rule", {}) or {}

                # Create vulnerability info
                vuln_info = VulnerabilityInfo(
                    rule_name=rule.get("name", "Unknown"),
                    rule_id=rule.get("id"),
                    message=vuln.get("message", "Potential security vulnerability"),
                    severity=vuln.get("severity", "HIGH"),
                    source=source,
                    sink=sink,
                    file_path=file_path,
                    line=sink.get("line", 0),
                    call_chain=vuln.get("call_chain"),
                    code_snippet=vuln.get("code_snippet"),
                )

                vuln_info_list.append(vuln_info)
            except Exception as e:
                logger.exception(f"Error converting vulnerability: {e}")

        return vuln_info_list

    async def handle_file_path_analysis(
        self, request: FileAnalysisRequest
    ) -> AnalysisResponse:
        """
        处理文件或目录分析请求，使用命令行工具进行分析。

        Args:
            request: FileAnalysisRequest请求对象

        Returns:
            AnalysisResponse: 分析响应
        """
        try:
            target_path = request.target_path
            if not os.path.exists(target_path):
                return AnalysisResponse(
                    success=False,
                    errors=[f"目标路径不存在: {target_path}"],
                )

            # 检查配置文件路径
            config_path = request.config_path
            if not config_path:
                return AnalysisResponse(
                    success=False,
                    errors=["配置文件路径不能为空"],
                )

            # 检查配置文件是否存在
            if not os.path.exists(config_path):
                return AnalysisResponse(
                    success=False,
                    errors=[f"配置文件不存在: {config_path}"],
                )

            # 确定输出文件路径
            output_path = request.output_path
            if not output_path:
                # 生成基于目标文件名的输出路径
                if os.path.isdir(target_path):
                    base_name = os.path.basename(target_path.rstrip("/\\"))
                else:
                    base_name = os.path.splitext(os.path.basename(target_path))[0]
                output_path = f"./analysis_{base_name}_{int(time.time())}.json"

            # 生成临时日志文件路径
            log_file = f"./log_{int(time.time())}.txt"

            # 构建命令行
            cmd = [
                "lanalyzer",
                "--target",
                target_path,
                "--config",
                config_path,
                "--pretty",
                "--output",
                output_path,
                "--log-file",
                log_file,
                "--debug",
            ]

            if self.debug:
                logger.debug(f"执行命令: {' '.join(cmd)}")

            # 执行命令
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            stdout, stderr = process.communicate()

            if process.returncode != 0:
                logger.error(f"分析失败，退出码: {process.returncode}")
                logger.error(f"错误输出: {stderr}")
                return AnalysisResponse(
                    success=False,
                    errors=[f"分析失败: {stderr}"],
                )

            # 读取分析结果
            if os.path.exists(output_path):
                try:
                    with open(output_path, "r", encoding="utf-8") as f:
                        vulnerabilities_json = json.load(f)

                    # 将结果转换为VulnerabilityInfo对象
                    vulnerabilities = []
                    for vuln in vulnerabilities_json:
                        try:
                            file_path = vuln.get("file", "")

                            source = vuln.get("source", {}) or {}
                            sink = vuln.get("sink", {}) or {}
                            rule = {"name": vuln.get("rule", "Unknown"), "id": None}

                            vuln_info = VulnerabilityInfo(
                                rule_name=rule["name"],
                                rule_id=rule["id"],
                                message=vuln.get("description", "潜在安全漏洞"),
                                severity=vuln.get("severity", "HIGH"),
                                source=source,
                                sink=sink,
                                file_path=file_path,
                                line=sink.get("line", 0),
                                call_chain=vuln.get("call_chain"),
                                code_snippet=None,
                            )
                            vulnerabilities.append(vuln_info)
                        except Exception as e:
                            logger.exception(f"转换漏洞信息时出错: {e}")

                    # 构建分析摘要
                    summary = {
                        "files_analyzed": len(
                            set(v.file_path for v in vulnerabilities if v.file_path)
                        ),
                        "vulnerabilities_count": len(vulnerabilities),
                        "output_file": output_path,
                    }

                    return AnalysisResponse(
                        success=True,
                        vulnerabilities=vulnerabilities,
                        summary=summary,
                    )

                except Exception as e:
                    logger.exception(f"读取分析结果时出错: {e}")
                    return AnalysisResponse(
                        success=False,
                        errors=[f"读取分析结果时出错: {str(e)}"],
                    )
            else:
                return AnalysisResponse(
                    success=False,
                    errors=[f"分析完成但未找到输出文件: {output_path}"],
                )

        except Exception as e:
            logger.exception(f"处理文件路径分析请求时出错: {e}")
            return AnalysisResponse(
                success=False,
                errors=[f"分析失败: {str(e)}"],
            )

    async def explain_vulnerabilities(
        self, request: ExplainVulnerabilityRequest
    ) -> ExplainVulnerabilityResponse:
        """
        解释漏洞分析结果，生成自然语言说明。

        Args:
            request: ExplainVulnerabilityRequest请求对象

        Returns:
            ExplainVulnerabilityResponse: 解释响应
        """
        try:
            analysis_file = request.analysis_file
            if not os.path.exists(analysis_file):
                return ExplainVulnerabilityResponse(
                    success=False,
                    errors=[f"分析结果文件不存在: {analysis_file}"],
                )

            # 读取分析结果
            with open(analysis_file, "r", encoding="utf-8") as f:
                vulnerabilities = json.load(f)

            if not vulnerabilities:
                return ExplainVulnerabilityResponse(
                    success=True,
                    explanation="未发现任何安全漏洞。",
                    vulnerabilities_count=0,
                    files_affected=[],
                )

            # 提取受影响的文件
            files_affected = sorted(
                list(set(v.get("file", "") for v in vulnerabilities if v.get("file")))
            )

            # 创建解释文本
            if request.format == "markdown":
                explanation = self._generate_markdown_explanation(
                    vulnerabilities, request.level
                )
            else:
                explanation = self._generate_text_explanation(
                    vulnerabilities, request.level
                )

            return ExplainVulnerabilityResponse(
                success=True,
                explanation=explanation,
                vulnerabilities_count=len(vulnerabilities),
                files_affected=files_affected,
            )

        except Exception as e:
            logger.exception(f"解释漏洞时出错: {e}")
            return ExplainVulnerabilityResponse(
                success=False,
                errors=[f"解释漏洞失败: {str(e)}"],
            )

    def _generate_text_explanation(
        self, vulnerabilities: List[Dict[str, Any]], level: str
    ) -> str:
        """
        生成文本格式的漏洞解释。

        Args:
            vulnerabilities: 漏洞列表
            level: 详细程度，"brief" 或 "detailed"

        Returns:
            str: 文本格式的漏洞解释
        """
        if not vulnerabilities:
            return "未发现任何安全漏洞。"

        files_affected = sorted(
            list(set(v.get("file", "") for v in vulnerabilities if v.get("file")))
        )

        explanation = [
            f"安全漏洞分析报告",
            f"===================",
            f"",
            f"发现 {len(vulnerabilities)} 个潜在安全漏洞，涉及 {len(files_affected)} 个文件。",
            f"",
        ]

        # 按文件分组漏洞
        vulns_by_file = {}
        for vuln in vulnerabilities:
            file = vuln.get("file", "未知文件")
            if file not in vulns_by_file:
                vulns_by_file[file] = []
            vulns_by_file[file].append(vuln)

        # 按文件生成报告
        for file, file_vulns in vulns_by_file.items():
            explanation.append(f"文件: {file}")
            explanation.append(f"{'-' * 50}")

            for i, vuln in enumerate(file_vulns, 1):
                rule = vuln.get("rule", "未知漏洞类型")
                severity = vuln.get("severity", "未知")
                sink_line = vuln.get("sink", {}).get("line", "未知")
                description = vuln.get("description", "未提供描述")

                explanation.append(f"漏洞 #{i}: {rule}")
                explanation.append(f"严重性: {severity}")
                explanation.append(f"位置: 第 {sink_line} 行")
                explanation.append(f"描述: {description}")

                if level == "detailed":
                    # 添加调用链信息
                    call_chain = vuln.get("call_chain", [])
                    if call_chain:
                        explanation.append("\n调用链:")
                        for j, call in enumerate(call_chain, 1):
                            func = call.get("function", "未知函数")
                            line = call.get("line", "未知")
                            call_type = call.get("type", "未知")
                            call_desc = call.get("description", "")

                            explanation.append(
                                f"  {j}. [{call_type}] {func} (行 {line})"
                            )
                            if call_desc:
                                explanation.append(f"     {call_desc}")

                explanation.append("")

            explanation.append("")

        # 添加修复建议
        explanation.append("修复建议:")
        explanation.append("--------")

        vuln_types = set(
            v.get("rule", "").split()[0] for v in vulnerabilities if v.get("rule")
        )

        if (
            "UnsafeDeserialization" in vuln_types
            or "PickleDeserialization" in vuln_types
        ):
            explanation.append("1. 对于不安全的反序列化问题:")
            explanation.append("   - 避免对不可信数据使用pickle.loads()，尤其是来自网络或用户输入的数据")
            explanation.append("   - 考虑使用JSON等更安全的序列化格式")
            explanation.append("   - 如果必须使用pickle，实现自定义的unpickler限制可加载的对象类型")
            explanation.append("")

        if "SQLInjection" in vuln_types:
            explanation.append("2. 对于SQL注入问题:")
            explanation.append("   - 使用参数化查询替代字符串拼接")
            explanation.append("   - 使用ORM框架如SQLAlchemy")
            explanation.append("   - 对用户输入进行验证和转义")
            explanation.append("")

        explanation.append("3. 通用建议:")
        explanation.append("   - 对用户输入实施输入验证")
        explanation.append("   - 实现最小权限原则")
        explanation.append("   - 添加安全日志记录和监控")

        return "\n".join(explanation)

    def _generate_markdown_explanation(
        self, vulnerabilities: List[Dict[str, Any]], level: str
    ) -> str:
        """
        生成Markdown格式的漏洞解释。

        Args:
            vulnerabilities: 漏洞列表
            level: 详细程度，"brief" 或 "detailed"

        Returns:
            str: Markdown格式的漏洞解释
        """
        if not vulnerabilities:
            return "未发现任何安全漏洞。"

        files_affected = sorted(
            list(set(v.get("file", "") for v in vulnerabilities if v.get("file")))
        )

        explanation = [
            f"# 安全漏洞分析报告",
            f"",
            f"发现 **{len(vulnerabilities)}** 个潜在安全漏洞，涉及 **{len(files_affected)}** 个文件。",
            f"",
        ]

        # 按文件分组漏洞
        vulns_by_file = {}
        for vuln in vulnerabilities:
            file = vuln.get("file", "未知文件")
            if file not in vulns_by_file:
                vulns_by_file[file] = []
            vulns_by_file[file].append(vuln)

        # 按文件生成报告
        for file, file_vulns in vulns_by_file.items():
            explanation.append(f"## 文件: `{file}`")

            for i, vuln in enumerate(file_vulns, 1):
                rule = vuln.get("rule", "未知漏洞类型")
                severity = vuln.get("severity", "未知")
                sink_line = vuln.get("sink", {}).get("line", "未知")
                description = vuln.get("description", "未提供描述")

                severity_emoji = (
                    "🔴"
                    if severity.upper() == "HIGH"
                    else "🟠"
                    if severity.upper() == "MEDIUM"
                    else "🟡"
                )

                explanation.append(f"### 漏洞 #{i}: {rule} {severity_emoji}")
                explanation.append(f"- **严重性**: {severity}")
                explanation.append(f"- **位置**: 第 {sink_line} 行")
                explanation.append(f"- **描述**: {description}")

                if level == "detailed":
                    # 添加调用链信息
                    call_chain = vuln.get("call_chain", [])
                    if call_chain:
                        explanation.append("\n#### 调用链:")
                        for j, call in enumerate(call_chain, 1):
                            func = call.get("function", "未知函数")
                            line = call.get("line", "未知")
                            call_type = call.get("type", "未知")
                            call_desc = call.get("description", "")

                            type_icon = (
                                "🔍"
                                if call_type == "source"
                                else "❌"
                                if call_type == "sink"
                                else "📦"
                            )

                            explanation.append(
                                f"{j}. {type_icon} **{func}** (行 {line})"
                            )
                            if call_desc:
                                explanation.append(f"   - {call_desc}")

                explanation.append("")

        # 添加修复建议
        explanation.append("## 修复建议")

        vuln_types = set(
            v.get("rule", "").split()[0] for v in vulnerabilities if v.get("rule")
        )

        if (
            "UnsafeDeserialization" in vuln_types
            or "PickleDeserialization" in vuln_types
        ):
            explanation.append("### 对于不安全的反序列化问题:")
            explanation.append("- 避免对不可信数据使用`pickle.loads()`，尤其是来自网络或用户输入的数据")
            explanation.append("- 考虑使用JSON等更安全的序列化格式")
            explanation.append("- 如果必须使用pickle，实现自定义的unpickler限制可加载的对象类型")
            explanation.append("")

        if "SQLInjection" in vuln_types:
            explanation.append("### 对于SQL注入问题:")
            explanation.append("- 使用参数化查询替代字符串拼接")
            explanation.append("- 使用ORM框架如SQLAlchemy")
            explanation.append("- 对用户输入进行验证和转义")
            explanation.append("")

        explanation.append("### 通用建议:")
        explanation.append("- 对用户输入实施输入验证")
        explanation.append("- 实现最小权限原则")
        explanation.append("- 添加安全日志记录和监控")

        return "\n".join(explanation)
