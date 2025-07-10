# Lanalyzer MCP Tools Documentation

This document provides comprehensive documentation for all Model Context Protocol (MCP) tools available in Lanalyzer. These tools enable AI models and applications to interact with Lanalyzer's security analysis capabilities through a standardized interface.

## Overview

Lanalyzer provides 8 MCP tools that cover the complete workflow of security vulnerability analysis:

1. **Analysis Tools**: Analyze code for security vulnerabilities
   - `analyze_code` - Analyze Python code strings
   - `analyze_file` - Analyze individual Python files  
   - `analyze_path` - Analyze files or entire directories/projects

2. **Configuration Tools**: Manage analysis configurations
   - `get_config` - Retrieve configuration settings
   - `validate_config` - Validate configuration data
   - `create_config` - Create new configuration files

3. **Explanation Tools**: Generate human-readable vulnerability explanations
   - `explain_vulnerabilities` - Generate natural language explanations

4. **Report Generation Tools**: Generate standardized vulnerability reports
   - `write_vulnerability_report` - Generate CVE or CNVD format reports

## Tool Details

### 1. analyze_code

**Purpose**: Analyze Python code strings for security vulnerabilities using Lanalyzer's taint analysis engine.

**Parameters**:
- `code` (str, required): The Python source code to analyze
- `file_path` (str, required): Virtual file path for reporting purposes
- `config_path` (str, required): Path to Lanalyzer configuration file
- `ctx` (Context, optional): MCP context for logging

**Returns**:
```json
{
  "success": true,
  "vulnerabilities": [
    {
      "rule_type": "SQLInjection",
      "severity": "high", 
      "line": 5,
      "message": "Potential SQL injection vulnerability",
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

**Example Usage**:
```python
result = await client.call_tool("analyze_code", {
    "code": "user_input = input()\nquery = f\"SELECT * FROM users WHERE name = '{user_input}'\"",
    "file_path": "example.py",
    "config_path": "/path/to/config.json"
})
```

### 2. analyze_file

**Purpose**: Analyze a Python file for security vulnerabilities.

**Parameters**:
- `file_path` (str, required): Path to the Python file to analyze
- `config_path` (str, required): Path to Lanalyzer configuration file
- `ctx` (Context, optional): MCP context for logging

**Returns**: Same format as `analyze_code`

**Example Usage**:
```python
result = await client.call_tool("analyze_file", {
    "file_path": "/path/to/vulnerable_script.py",
    "config_path": "/path/to/config.json"
})
```

### 3. analyze_path

**Purpose**: Analyze a file or directory path for security vulnerabilities. Can process entire projects.

**Parameters**:
- `target_path` (str, required): Path to file or directory to analyze
- `config_path` (str, required): Path to Lanalyzer configuration file  
- `ctx` (Context, optional): MCP context for logging

**Returns**: Same format as `analyze_code` but may include vulnerabilities from multiple files

**Example Usage**:
```python
# Analyze entire project
result = await client.call_tool("analyze_path", {
    "target_path": "/path/to/project",
    "config_path": "/path/to/config.json"
})
```

### 4. get_config

**Purpose**: Retrieve Lanalyzer configuration content from a file or get default configuration.

**Parameters**:
- `config_path` (str, optional): Path to configuration file (if None, returns default)
- `ctx` (Context, optional): MCP context for logging

**Returns**:
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

**Purpose**: Validate Lanalyzer configuration data for correctness and completeness.

**Parameters**:
- `config_data` (dict, optional): Configuration data to validate directly
- `config_path` (str, optional): Path to configuration file to validate
- `ctx` (Context, optional): MCP context for logging

**Returns**:
```json
{
  "success": false,
  "errors": [
    "Missing required field: 'sources'",
    "Invalid sink format in 'sinks' array"
  ],
  "warnings": ["Deprecated field 'old_setting' found"],
  "config_path": "/path/to/config.json"
}
```

### 6. create_config

**Purpose**: Create a new Lanalyzer configuration file with provided settings.

**Parameters**:
- `config_data` (dict, required): Configuration data to write
- `config_path` (str, optional): Path where to save the configuration
- `ctx` (Context, optional): MCP context for logging

**Returns**:
```json
{
  "success": true,
  "config_path": "/path/to/new_config.json",
  "errors": [],
  "validation_errors": []
}
```

### 7. explain_vulnerabilities

**Purpose**: Generate natural language explanations for vulnerability analysis results.

**Parameters**:
- `analysis_file` (str, required): Path to analysis results JSON file
- `format` (str, optional): Output format - "text" or "markdown" (default: "text")
- `level` (str, optional): Detail level - "brief" or "detailed" (default: "brief")
- `ctx` (Context, optional): MCP context for logging

**Returns**:
```json
{
  "success": true,
  "explanation": "Security Vulnerability Analysis Report\n==================================\nFound 2 potential security vulnerabilities affecting 1 file(s)...",
  "vulnerabilities_count": 2,
  "files_affected": ["/path/to/vulnerable_file.py"],
  "errors": []
}
```

## Common Workflow Examples

### Basic Security Analysis
```python
# 1. Analyze a file
analysis_result = await client.call_tool("analyze_file", {
    "file_path": "app.py",
    "config_path": "security_config.json"
})

# 2. Generate explanation
explanation = await client.call_tool("explain_vulnerabilities", {
    "analysis_file": analysis_result["summary"]["output_file"],
    "format": "markdown",
    "level": "detailed"
})
```

### Project-wide Analysis
```python
# Analyze entire project
project_analysis = await client.call_tool("analyze_path", {
    "target_path": "/path/to/project",
    "config_path": "project_config.json"
})

# Get detailed explanations
explanations = await client.call_tool("explain_vulnerabilities", {
    "analysis_file": project_analysis["summary"]["output_file"],
    "format": "markdown",
    "level": "detailed"
})
```

### Configuration Management
```python
# Get current config
current_config = await client.call_tool("get_config", {
    "config_path": "current_config.json"
})

# Validate modified config
validation = await client.call_tool("validate_config", {
    "config_data": modified_config_data
})

# Create new config if valid
if validation["success"]:
    new_config = await client.call_tool("create_config", {
        "config_data": modified_config_data,
        "config_path": "new_config.json"
    })
```

## Error Handling

All tools return a consistent error format:
```json
{
  "success": false,
  "errors": ["Error message 1", "Error message 2"],
  "validation_errors": [...] // For validation-related tools
}
```

## Configuration File Format

Lanalyzer configuration files should contain:
- `sources`: List of taint sources (user input points)
- `sinks`: List of taint sinks (dangerous functions)
- `taint_propagation`: Rules for how taint flows through code
- `rules`: Detection rules for specific vulnerability types

### 8. write_vulnerability_report

**Purpose**: Generate standardized vulnerability reports in CVE or CNVD format based on Lanalyzer analysis results.

**Parameters**:
- `report_type` (str, required): Type of report to generate ("CVE" or "CNVD")
- `vulnerability_data` (dict, required): Vulnerability analysis results from Lanalyzer
- `additional_info` (dict, optional): Additional information for report generation
- `ctx` (Context, optional): MCP context for logging
- `**kwargs`: Report-specific parameters (see below)

**CVE Report Parameters** (required when report_type="CVE"):
- `cve_id` (str): CVE identifier (e.g., "CVE-2024-0001")
- `cvss_score` (float): CVSS score (0.0-10.0)
- `cvss_vector` (str): CVSS vector string
- `affected_products` (str): Description of affected products
- `vulnerability_type` (str): Type of vulnerability
- `attack_vector` (str): CVSS Attack Vector
- `attack_complexity` (str): CVSS Attack Complexity
- `privileges_required` (str): CVSS Privileges Required
- `user_interaction` (str): CVSS User Interaction
- `scope` (str): CVSS Scope
- `confidentiality_impact` (str): CVSS Confidentiality Impact
- `integrity_impact` (str): CVSS Integrity Impact
- `availability_impact` (str): CVSS Availability Impact

**CNVD Report Parameters** (required when report_type="CNVD"):
- `cnvd_id` (str): CNVD identifier
- `cnnvd_id` (str): CNNVD identifier
- `affected_products` (str): Description of affected products
- `vulnerability_type` (str): Type of vulnerability
- `threat_level` (str): Threat level ("超危", "高危", "中危", "低危")
- `exploit_difficulty` (str): Difficulty of exploiting the vulnerability
- `remote_exploit` (str): Whether remote exploitation is possible
- `local_exploit` (str): Whether local exploitation is possible
- `poc_available` (str): Whether proof-of-concept is available
- `exploit_available` (str): Whether exploit code is available
- `vendor_patch` (str): Vendor patch information
- `third_party_patch` (str): Third-party patch information

**Returns**:
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

**Example Usage**:
```python
# Generate CVE report
result = await write_vulnerability_report(
    report_type="CVE",
    vulnerability_data={
        "rule_name": "SQLInjection",
        "message": "Potential SQL injection vulnerability",
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

# Generate CNVD report
result = await write_vulnerability_report(
    report_type="CNVD",
    vulnerability_data={
        "rule_name": "CommandInjection",
        "message": "Command injection vulnerability detected",
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

**Error Handling**:
- Returns `success: false` with error details if required parameters are missing
- Validates report type and parameter completeness
- Provides detailed error messages for troubleshooting

See the main Lanalyzer documentation for detailed configuration examples.
