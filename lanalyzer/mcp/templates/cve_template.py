"""
CVE vulnerability report template.

This module provides the CVE (Common Vulnerabilities and Exposures) report
template for generating standardized vulnerability reports.
"""

from typing import Any, Dict

from .base_template import BaseReportTemplate


class CVEReportTemplate(BaseReportTemplate):
    """
    CVE vulnerability report template.

    This class generates vulnerability reports following the CVE standard format.
    """

    # CVE-specific required fields
    TEMPLATE_REQUIRED_FIELDS = [
        "cve_id",
        "cvss_score",
        "cvss_vector",
        "affected_products",
        "vulnerability_type",
        "attack_vector",
        "attack_complexity",
        "privileges_required",
        "user_interaction",
        "scope",
        "confidentiality_impact",
        "integrity_impact",
        "availability_impact",
    ]

    # CVE report template
    CVE_TEMPLATE = """
# CVE漏洞报告

## 基本信息
- **CVE编号**: {cve_id}
- **漏洞标题**: {title}
- **发现日期**: {discovery_date}
- **严重程度**: {severity_formatted}
- **CVSS评分**: {cvss_score} ({cvss_vector})

## 漏洞描述
{description}

## 影响范围
- **受影响产品**: {affected_products}
- **受影响组件**: {affected_component}
- **漏洞类型**: {vulnerability_type}

## 技术细节
### 攻击向量分析
- **攻击向量**: {attack_vector}
- **攻击复杂度**: {attack_complexity}
- **所需权限**: {privileges_required}
- **用户交互**: {user_interaction}
- **影响范围**: {scope}

### 影响评估
- **机密性影响**: {confidentiality_impact}
- **完整性影响**: {integrity_impact}
- **可用性影响**: {availability_impact}

## 代码分析
### 漏洞位置
- **文件**: {affected_component}
- **行号**: {line_number}

### 代码片段
```python
{code_snippet}
```

### 数据流分析
{data_flow_analysis}

## 修复建议
{remediation_suggestions}

## 参考信息
- **CVE链接**: https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}
- **CVSS计算器**: https://www.first.org/cvss/calculator/3.1
- **报告生成时间**: {report_generation_time}
"""

    def format_report(self, data: Dict[str, Any]) -> str:
        """
        Format vulnerability data into a CVE report.

        Args:
            data: Dictionary containing vulnerability information

        Returns:
            Formatted CVE report string
        """
        # Validate required fields
        self.validate_data(data)

        # Extract and normalize vulnerability information
        vuln_info = self.extract_vulnerability_info(data)

        # Format severity
        severity_formatted = self.format_severity(data["severity"])

        # Generate data flow analysis
        data_flow_analysis = self._format_data_flow_analysis(vuln_info)

        # Generate remediation suggestions
        remediation_suggestions = self._generate_remediation_suggestions(data)

        # Format the report
        formatted_report = self.CVE_TEMPLATE.format(
            cve_id=data["cve_id"],
            title=vuln_info["title"],
            discovery_date=vuln_info["discovery_date"],
            severity_formatted=severity_formatted,
            cvss_score=data["cvss_score"],
            cvss_vector=data["cvss_vector"],
            description=vuln_info["description"],
            affected_products=data["affected_products"],
            affected_component=vuln_info["affected_component"],
            vulnerability_type=data["vulnerability_type"],
            attack_vector=data["attack_vector"],
            attack_complexity=data["attack_complexity"],
            privileges_required=data["privileges_required"],
            user_interaction=data["user_interaction"],
            scope=data["scope"],
            confidentiality_impact=data["confidentiality_impact"],
            integrity_impact=data["integrity_impact"],
            availability_impact=data["availability_impact"],
            line_number=vuln_info["line_number"],
            code_snippet=vuln_info["code_snippet"],
            data_flow_analysis=data_flow_analysis,
            remediation_suggestions=remediation_suggestions,
            report_generation_time=self.format_date(None),
        )

        return formatted_report.strip()

    def _format_data_flow_analysis(self, vuln_info: Dict[str, Any]) -> str:
        """
        Format data flow analysis section.

        Args:
            vuln_info: Normalized vulnerability information

        Returns:
            Formatted data flow analysis string
        """
        analysis_parts = []

        # Source information
        if "source_info" in vuln_info:
            source = vuln_info["source_info"]
            analysis_parts.append(f"**数据源**: {source['name']} (第{source['line']}行)")
            if source.get("type"):
                analysis_parts.append(f"**源类型**: {source['type']}")
            if source.get("value"):
                analysis_parts.append(f"**源值**: {source['value']}")

        # Sink information
        if "sink_info" in vuln_info:
            sink = vuln_info["sink_info"]
            analysis_parts.append(f"**数据汇**: {sink['name']} (第{sink['line']}行)")
            if sink.get("context"):
                analysis_parts.append(f"**汇上下文**: {sink['context']}")

        # Call chain
        if "call_chain" in vuln_info and vuln_info["call_chain"]:
            analysis_parts.append("**调用链**:")
            for i, step in enumerate(vuln_info["call_chain"], 1):
                function_name = step.get("function", "unknown")
                line = step.get("line", 0)
                analysis_parts.append(f"  {i}. {function_name} (第{line}行)")

        return "\n".join(analysis_parts) if analysis_parts else "暂无详细数据流分析信息"

    def _generate_remediation_suggestions(self, data: Dict[str, Any]) -> str:
        """
        Generate remediation suggestions based on vulnerability type.

        Args:
            data: Vulnerability data

        Returns:
            Remediation suggestions string
        """
        vuln_type = data.get("vulnerability_type", "").lower()

        suggestions = {
            "sql injection": [
                "使用参数化查询或预编译语句",
                "对用户输入进行严格的验证和过滤",
                "使用ORM框架避免直接SQL拼接",
                "实施最小权限原则",
            ],
            "command injection": [
                "避免直接执行用户输入的命令",
                "使用白名单验证允许的命令",
                "对特殊字符进行转义或过滤",
                "使用安全的API替代系统命令调用",
            ],
            "path traversal": [
                "验证和规范化文件路径",
                "使用白名单限制可访问的目录",
                "避免直接使用用户输入构造文件路径",
                "实施适当的访问控制",
            ],
            "deserialization": [
                "避免反序列化不可信的数据",
                "使用安全的序列化格式(如JSON)",
                "实施输入验证和类型检查",
                "使用白名单限制可反序列化的类",
            ],
        }

        # Find matching suggestions
        for key, suggestion_list in suggestions.items():
            if key in vuln_type:
                return "\n".join(f"- {suggestion}" for suggestion in suggestion_list)

        # Default suggestions
        return "\n".join(
            ["- 对所有用户输入进行严格验证", "- 实施适当的访问控制机制", "- 定期进行安全代码审查", "- 使用安全编码最佳实践"]
        )
