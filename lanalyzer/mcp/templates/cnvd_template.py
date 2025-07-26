"""
CNVD vulnerability report template.

This module provides the CNVD (China National Vulnerability Database) report
template for generating standardized vulnerability reports.
"""

from typing import Any, Dict

from .base_template import BaseReportTemplate


class CNVDReportTemplate(BaseReportTemplate):
    """
    CNVD vulnerability report template.

    This class generates vulnerability reports following the CNVD standard format.
    """

    # CNVD-specific required fields
    TEMPLATE_REQUIRED_FIELDS = [
        "cnvd_id",
        "cnnvd_id",
        "affected_products",
        "vulnerability_type",
        "threat_level",
        "exploit_difficulty",
        "remote_exploit",
        "local_exploit",
        "poc_available",
        "exploit_available",
        "vendor_patch",
        "third_party_patch",
    ]

    # CNVD report template
    CNVD_TEMPLATE = """
# CNVD漏洞报告

## 漏洞基本信息
- **CNVD编号**: {cnvd_id}
- **CNNVD编号**: {cnnvd_id}
- **漏洞名称**: {title}
- **发现时间**: {discovery_date}
- **危害等级**: {threat_level_formatted}
- **漏洞类型**: {vulnerability_type}

## 漏洞描述
{description}

## 影响产品
{affected_products}

## 漏洞分析
### 受影响组件
- **组件名称**: {affected_component}
- **漏洞位置**: 第{line_number}行

### 漏洞原理
{vulnerability_principle}

### 代码片段
```python
{code_snippet}
```

### 数据流追踪
{data_flow_tracking}

## 威胁评估
- **威胁等级**: {threat_level}
- **利用难度**: {exploit_difficulty}
- **远程利用**: {remote_exploit}
- **本地利用**: {local_exploit}
- **PoC可用性**: {poc_available}
- **Exploit可用性**: {exploit_available}

## 修复方案
### 厂商补丁
{vendor_patch}

### 第三方补丁
{third_party_patch}

### 临时缓解措施
{mitigation_measures}

### 修复建议
{fix_recommendations}

## 参考信息
- **CNVD链接**: https://www.cnvd.org.cn/flaw/show/{cnvd_id}
- **CNNVD链接**: https://www.cnnvd.org.cn/home/loophole/loopholeView?id={cnnvd_id}
- **报告生成时间**: {report_generation_time}

## 技术细节
### 漏洞验证
{vulnerability_verification}

### 影响范围
{impact_scope}

---
*本报告由Lanalyzer自动生成*
"""

    def format_report(self, data: Dict[str, Any]) -> str:
        """
        Format vulnerability data into a CNVD report.

        Args:
            data: Dictionary containing vulnerability information

        Returns:
            Formatted CNVD report string
        """
        # Validate required fields
        self.validate_data(data)

        # Extract and normalize vulnerability information
        vuln_info = self.extract_vulnerability_info(data)

        # Format threat level
        threat_level_formatted = self._format_threat_level(data["threat_level"])

        # Generate vulnerability principle analysis
        vulnerability_principle = self._generate_vulnerability_principle(
            data, vuln_info
        )

        # Generate data flow tracking
        data_flow_tracking = self._format_data_flow_tracking(vuln_info)

        # Generate mitigation measures
        mitigation_measures = self._generate_mitigation_measures(data)

        # Generate fix recommendations
        fix_recommendations = self._generate_fix_recommendations(data)

        # Generate vulnerability verification
        vulnerability_verification = self._generate_vulnerability_verification(
            vuln_info
        )

        # Generate impact scope
        impact_scope = self._generate_impact_scope(data, vuln_info)

        # Format the report
        formatted_report = self.CNVD_TEMPLATE.format(
            cnvd_id=data["cnvd_id"],
            cnnvd_id=data["cnnvd_id"],
            title=vuln_info["title"],
            discovery_date=vuln_info["discovery_date"],
            threat_level_formatted=threat_level_formatted,
            vulnerability_type=data["vulnerability_type"],
            description=vuln_info["description"],
            affected_products=data["affected_products"],
            affected_component=vuln_info["affected_component"],
            line_number=vuln_info["line_number"],
            vulnerability_principle=vulnerability_principle,
            code_snippet=vuln_info["code_snippet"],
            data_flow_tracking=data_flow_tracking,
            threat_level=data["threat_level"],
            exploit_difficulty=data["exploit_difficulty"],
            remote_exploit=data["remote_exploit"],
            local_exploit=data["local_exploit"],
            poc_available=data["poc_available"],
            exploit_available=data["exploit_available"],
            vendor_patch=data["vendor_patch"],
            third_party_patch=data["third_party_patch"],
            mitigation_measures=mitigation_measures,
            fix_recommendations=fix_recommendations,
            vulnerability_verification=vulnerability_verification,
            impact_scope=impact_scope,
            report_generation_time=self.format_date(None),
        )

        return formatted_report.strip()

    def _format_threat_level(self, threat_level: str) -> str:
        """
        Format threat level with appropriate styling.

        Args:
            threat_level: Threat level string

        Returns:
            Formatted threat level string
        """
        level_mapping = {"超危": "🔴 超危", "高危": "🟠 高危", "中危": "🟡 中危", "低危": "🟢 低危"}

        return level_mapping.get(threat_level, f"⚪ {threat_level}")

    def _generate_vulnerability_principle(
        self, data: Dict[str, Any], vuln_info: Dict[str, Any]
    ) -> str:
        """
        Generate vulnerability principle analysis.

        Args:
            data: Original vulnerability data
            vuln_info: Normalized vulnerability information

        Returns:
            Vulnerability principle analysis string
        """
        vuln_type = data.get("vulnerability_type", "").lower()

        principles = {
            "sql注入": "应用程序在构造SQL查询时直接拼接用户输入，未进行适当的参数化处理，导致攻击者可以注入恶意SQL代码。",
            "命令注入": "应用程序直接执行包含用户输入的系统命令，未对输入进行充分验证和过滤，使攻击者能够执行任意系统命令。",
            "路径遍历": "应用程序在处理文件路径时未进行充分验证，允许攻击者通过特殊字符序列访问系统中的任意文件。",
            "反序列化": "应用程序反序列化不可信的数据，可能导致远程代码执行或其他安全问题。",
        }

        for key, principle in principles.items():
            if key in vuln_type:
                return principle

        return f"该漏洞属于{data.get('vulnerability_type', '未知类型')}，具体原理需要进一步分析代码实现细节。"

    def _format_data_flow_tracking(self, vuln_info: Dict[str, Any]) -> str:
        """
        Format data flow tracking section.

        Args:
            vuln_info: Normalized vulnerability information

        Returns:
            Formatted data flow tracking string
        """
        tracking_parts = []

        # Source tracking
        if "source_info" in vuln_info:
            source = vuln_info["source_info"]
            tracking_parts.append(f"**污点源**: {source['name']} (第{source['line']}行)")
            if source.get("type"):
                tracking_parts.append(f"  - 源类型: {source['type']}")
            if source.get("value"):
                tracking_parts.append(f"  - 源数据: {source['value']}")

        # Sink tracking
        if "sink_info" in vuln_info:
            sink = vuln_info["sink_info"]
            tracking_parts.append(f"**污点汇**: {sink['name']} (第{sink['line']}行)")
            if sink.get("context"):
                tracking_parts.append(f"  - 汇上下文: {sink['context']}")

        # Call chain tracking
        if "call_chain" in vuln_info and vuln_info["call_chain"]:
            tracking_parts.append("**传播路径**:")
            for i, step in enumerate(vuln_info["call_chain"], 1):
                function_name = step.get("function", "unknown")
                line = step.get("line", 0)
                tracking_parts.append(f"  {i}. {function_name} (第{line}行)")

        return "\n".join(tracking_parts) if tracking_parts else "暂无详细数据流追踪信息"

    def _generate_mitigation_measures(self, data: Dict[str, Any]) -> str:
        """
        Generate temporary mitigation measures.

        Args:
            data: Vulnerability data

        Returns:
            Mitigation measures string
        """
        return "\n".join(
            [
                "- 限制对受影响组件的访问",
                "- 加强输入验证和过滤",
                "- 部署Web应用防火墙(WAF)",
                "- 监控异常访问行为",
                "- 及时应用安全补丁",
            ]
        )

    def _generate_fix_recommendations(self, data: Dict[str, Any]) -> str:
        """
        Generate fix recommendations.

        Args:
            data: Vulnerability data

        Returns:
            Fix recommendations string
        """
        return "\n".join(
            [
                "1. 立即修复代码中的安全缺陷",
                "2. 实施安全编码规范",
                "3. 进行全面的安全测试",
                "4. 建立安全开发生命周期(SDLC)",
                "5. 定期进行安全审计和渗透测试",
            ]
        )

    def _generate_vulnerability_verification(self, vuln_info: Dict[str, Any]) -> str:
        """
        Generate vulnerability verification information.

        Args:
            vuln_info: Normalized vulnerability information

        Returns:
            Vulnerability verification string
        """
        verification_steps = ["1. 代码审计确认漏洞存在", "2. 静态分析工具检测到安全缺陷", "3. 数据流分析验证污点传播路径"]

        if vuln_info.get("code_snippet"):
            verification_steps.append("4. 代码片段分析确认漏洞触发条件")

        return "\n".join(verification_steps)

    def _generate_impact_scope(
        self, data: Dict[str, Any], vuln_info: Dict[str, Any]
    ) -> str:
        """
        Generate impact scope analysis.

        Args:
            data: Original vulnerability data
            vuln_info: Normalized vulnerability information

        Returns:
            Impact scope analysis string
        """
        scope_parts = [
            f"**受影响文件**: {vuln_info['affected_component']}",
            f"**漏洞位置**: 第{vuln_info['line_number']}行",
            f"**威胁等级**: {data.get('threat_level', '中危')}",
        ]

        if data.get("affected_products"):
            scope_parts.append(f"**影响产品**: {data['affected_products']}")

        return "\n".join(scope_parts)
