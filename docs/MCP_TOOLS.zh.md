# Lanalyzer MCP 工具文档

本文档为 Lanalyzer 中所有模型上下文协议（MCP）工具提供全面的文档。这些工具使 AI 模型和应用程序能够通过标准化接口与 Lanalyzer 的安全分析功能进行交互。

## 概述

Lanalyzer 提供 8 个 MCP 工具，涵盖安全漏洞分析的完整工作流程：

1. **分析工具**：分析代码中的安全漏洞
   - `analyze_code` - 分析 Python 代码字符串
   - `analyze_file` - 分析单个 Python 文件  
   - `analyze_path` - 分析文件或整个目录/项目

2. **配置工具**：管理分析配置
   - `get_config` - 获取配置设置
   - `validate_config` - 验证配置数据
   - `create_config` - 创建新的配置文件

3. **解释工具**：生成人类可读的漏洞解释
   - `explain_vulnerabilities` - 生成自然语言解释

4. **报告生成工具**：生成标准化漏洞报告
   - `write_vulnerability_report` - 生成 CVE 或 CNVD 格式报告

## 工具详情

### 1. analyze_code

**用途**：使用 Lanalyzer 的污点分析引擎分析 Python 代码字符串中的安全漏洞。

**参数**：
- `code` (str, 必需): 要分析的 Python 源代码
- `file_path` (str, 必需): 用于报告的虚拟文件路径
- `config_path` (str, 必需): Lanalyzer 配置文件路径
- `ctx` (Context, 可选): 用于日志记录的 MCP 上下文

**返回值**：
```json
{
  "success": true,
  "vulnerabilities": [
    {
      "rule_type": "SQLInjection",
      "severity": "high", 
      "line": 5,
      "message": "潜在的 SQL 注入漏洞",
      "source": "user_input",
      "sink": "execute"
    }
  ],
  "summary": {"total_vulnerabilities": 1, "high_severity": 1},
  "errors": [],
  "call_chains": [...],
  "imports": {...}
}
```

**使用示例**：
```python
result = await client.call_tool("analyze_code", {
    "code": "user_input = input()\nquery = f\"SELECT * FROM users WHERE name = '{user_input}'\"",
    "file_path": "example.py",
    "config_path": "/path/to/config.json"
})
```

### 2. analyze_file

**用途**：分析 Python 文件中的安全漏洞。

**参数**：
- `file_path` (str, 必需): 要分析的 Python 文件路径
- `config_path` (str, 必需): Lanalyzer 配置文件路径
- `ctx` (Context, 可选): 用于日志记录的 MCP 上下文

**返回值**：与 `analyze_code` 相同格式

**使用示例**：
```python
result = await client.call_tool("analyze_file", {
    "file_path": "/path/to/vulnerable_script.py",
    "config_path": "/path/to/config.json"
})
```

### 3. analyze_path

**用途**：分析文件或目录路径中的安全漏洞。可以处理整个项目。

**参数**：
- `target_path` (str, 必需): 要分析的文件或目录路径
- `config_path` (str, 必需): Lanalyzer 配置文件路径  
- `ctx` (Context, 可选): 用于日志记录的 MCP 上下文

**返回值**：与 `analyze_code` 相同格式，但可能包含来自多个文件的漏洞

**使用示例**：
```python
# 分析整个项目
result = await client.call_tool("analyze_path", {
    "target_path": "/path/to/project",
    "config_path": "/path/to/config.json"
})
```

### 4. get_config

**用途**：从文件中获取 Lanalyzer 配置内容或获取默认配置。

**参数**：
- `config_path` (str, 可选): 配置文件路径（如果为 None，返回默认配置）
- `ctx` (Context, 可选): 用于日志记录的 MCP 上下文

**返回值**：
```json
{
  "success": true,
  "config": {
    "sources": ["input", "request.args", "request.form"],
    "sinks": ["execute", "eval", "subprocess.call"],
    "taint_propagation": {...},
    "rules": {...}
  },
  "config_path": "/path/to/config.json",
  "errors": []
}
```

### 5. validate_config

**用途**：验证 Lanalyzer 配置数据的正确性和完整性。

**参数**：
- `config_data` (dict, 可选): 要直接验证的配置数据
- `config_path` (str, 可选): 要验证的配置文件路径
- `ctx` (Context, 可选): 用于日志记录的 MCP 上下文

**返回值**：
```json
{
  "success": false,
  "errors": [
    "缺少必需字段：'sources'",
    "'sinks' 数组中的接收器格式无效"
  ],
  "warnings": ["发现已弃用字段 'old_setting'"],
  "config_path": "/path/to/config.json"
}
```

### 6. create_config

**用途**：使用提供的设置创建新的 Lanalyzer 配置文件。

**参数**：
- `config_data` (dict, 必需): 要写入的配置数据
- `config_path` (str, 可选): 保存配置的路径
- `ctx` (Context, 可选): 用于日志记录的 MCP 上下文

**返回值**：
```json
{
  "success": true,
  "config_path": "/path/to/new_config.json",
  "errors": [],
  "validation_errors": []
}
```

### 7. explain_vulnerabilities

**用途**：为漏洞分析结果生成自然语言解释。

**参数**：
- `analysis_file` (str, 必需): 分析结果 JSON 文件路径
- `format` (str, 可选): 输出格式 - "text" 或 "markdown"（默认："text"）
- `level` (str, 可选): 详细级别 - "brief" 或 "detailed"（默认："brief"）
- `ctx` (Context, 可选): 用于日志记录的 MCP 上下文

**返回值**：
```json
{
  "success": true,
  "explanation": "安全漏洞分析报告\n==================================\n发现 2 个潜在安全漏洞，影响 1 个文件...",
  "vulnerabilities_count": 2,
  "files_affected": ["/path/to/vulnerable_file.py"],
  "errors": []
}
```

## 常见工作流程示例

### 基本安全分析
```python
# 1. 分析文件
analysis_result = await client.call_tool("analyze_file", {
    "file_path": "app.py",
    "config_path": "security_config.json"
})

# 2. 生成解释
explanation = await client.call_tool("explain_vulnerabilities", {
    "analysis_file": analysis_result["summary"]["output_file"],
    "format": "markdown",
    "level": "detailed"
})
```

### 项目级分析
```python
# 分析整个项目
project_analysis = await client.call_tool("analyze_path", {
    "target_path": "/path/to/project",
    "config_path": "project_config.json"
})

# 获取详细解释
explanations = await client.call_tool("explain_vulnerabilities", {
    "analysis_file": project_analysis["summary"]["output_file"],
    "format": "markdown",
    "level": "detailed"
})
```

### 配置管理
```python
# 获取当前配置
current_config = await client.call_tool("get_config", {
    "config_path": "current_config.json"
})

# 验证修改后的配置
validation = await client.call_tool("validate_config", {
    "config_data": modified_config_data
})

# 如果有效则创建新配置
if validation["success"]:
    new_config = await client.call_tool("create_config", {
        "config_data": modified_config_data,
        "config_path": "new_config.json"
    })
```

## 错误处理

所有工具都返回一致的错误格式：
```json
{
  "success": false,
  "errors": ["错误消息 1", "错误消息 2"],
  "validation_errors": [...] // 用于验证相关工具
}
```

## 配置文件格式

Lanalyzer 配置文件应包含：
- `sources`: 污点源列表（用户输入点）
- `sinks`: 污点接收器列表（危险函数）
- `taint_propagation`: 污点在代码中流动的规则
- `rules`: 特定漏洞类型的检测规则

### 8. write_vulnerability_report

**用途**：基于 Lanalyzer 分析结果生成 CVE 或 CNVD 格式的标准化漏洞报告。

**参数**：
- `report_type` (str, 必需): 要生成的报告类型（"CVE" 或 "CNVD"）
- `vulnerability_data` (dict, 必需): 来自 Lanalyzer 的漏洞分析结果
- `additional_info` (dict, 可选): 报告生成的附加信息
- `ctx` (Context, 可选): 用于日志记录的 MCP 上下文
- `**kwargs`: 报告特定参数（见下文）

**CVE 报告参数**（当 report_type="CVE" 时必需）：
- `cve_id` (str): CVE 标识符（例如："CVE-2024-0001"）
- `cvss_score` (float): CVSS 评分（0.0-10.0）
- `cvss_vector` (str): CVSS 向量字符串
- `affected_products` (str): 受影响产品的描述
- `vulnerability_type` (str): 漏洞类型
- `attack_vector` (str): CVSS 攻击向量
- `attack_complexity` (str): CVSS 攻击复杂度
- `privileges_required` (str): CVSS 所需权限
- `user_interaction` (str): CVSS 用户交互
- `scope` (str): CVSS 影响范围
- `confidentiality_impact` (str): CVSS 机密性影响
- `integrity_impact` (str): CVSS 完整性影响
- `availability_impact` (str): CVSS 可用性影响

**CNVD 报告参数**（当 report_type="CNVD" 时必需）：
- `cnvd_id` (str): CNVD 标识符
- `cnnvd_id` (str): CNNVD 标识符
- `affected_products` (str): 受影响产品的描述
- `vulnerability_type` (str): 漏洞类型
- `threat_level` (str): 威胁等级（"超危"、"高危"、"中危"、"低危"）
- `exploit_difficulty` (str): 漏洞利用难度
- `remote_exploit` (str): 是否可远程利用
- `local_exploit` (str): 是否可本地利用
- `poc_available` (str): 是否有概念验证代码
- `exploit_available` (str): 是否有利用代码
- `vendor_patch` (str): 厂商补丁信息
- `third_party_patch` (str): 第三方补丁信息

**返回值**：
```json
{
  "success": true,
  "report_content": "# CVE漏洞报告\n\n## 基本信息\n- **CVE编号**: CVE-2024-0001...",
  "report_type": "CVE",
  "metadata": {
    "report_type": "CVE",
    "template_name": "CVEReportTemplate",
    "vulnerability_count": 1,
    "generation_timestamp": "2024-01-01",
    "cve_id": "CVE-2024-0001",
    "cvss_score": 7.5
  },
  "errors": [],
  "warnings": []
}
```

**使用示例**：
```python
# 生成 CVE 报告
result = await write_vulnerability_report(
    report_type="CVE",
    vulnerability_data={
        "rule_name": "SQLInjection",
        "message": "检测到潜在的 SQL 注入漏洞",
        "severity": "HIGH",
        "file_path": "/app/views.py",
        "line": 25,
        "source": {"name": "request.GET", "line": 20},
        "sink": {"name": "cursor.execute", "line": 25},
        "code_snippet": "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')"
    },
    cve_id="CVE-2024-0001",
    cvss_score=7.5,
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    affected_products="MyApp 1.0-2.0",
    vulnerability_type="SQL Injection",
    attack_vector="Network",
    attack_complexity="Low",
    privileges_required="None",
    user_interaction="None",
    scope="Unchanged",
    confidentiality_impact="High",
    integrity_impact="None",
    availability_impact="None"
)

# 生成 CNVD 报告
result = await write_vulnerability_report(
    report_type="CNVD",
    vulnerability_data={
        "rule_name": "CommandInjection",
        "message": "检测到命令注入漏洞",
        "severity": "HIGH",
        "file_path": "/app/utils.py",
        "line": 15
    },
    cnvd_id="CNVD-2024-0001",
    cnnvd_id="CNNVD-202400001",
    affected_products="MyApp 1.0",
    vulnerability_type="命令注入",
    threat_level="高危",
    exploit_difficulty="容易",
    remote_exploit="是",
    local_exploit="是",
    poc_available="是",
    exploit_available="否",
    vendor_patch="未发布",
    third_party_patch="无"
)
```

**错误处理**：
- 如果缺少必需参数，返回 `success: false` 并提供错误详情
- 验证报告类型和参数完整性
- 提供详细的错误消息以便故障排除

详细的配置示例请参见 Lanalyzer 主文档。
