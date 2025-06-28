# Lanalyzer MCP Tools Documentation

This document provides comprehensive documentation for all Model Context Protocol (MCP) tools available in Lanalyzer. These tools enable AI models and applications to interact with Lanalyzer's security analysis capabilities through a standardized interface.

## Overview

Lanalyzer provides 7 MCP tools that cover the complete workflow of security vulnerability analysis:

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

See the main Lanalyzer documentation for detailed configuration examples.
