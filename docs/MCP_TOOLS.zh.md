# Lanalyzer MCP 工具文档

本文档为 Lanalyzer 中所有模型上下文协议（MCP）工具提供全面的文档。这些工具使 AI 模型和应用程序能够通过标准化接口与 Lanalyzer 的安全分析功能进行交互。

## 概述

Lanalyzer 提供 7 个 MCP 工具，涵盖安全漏洞分析的完整工作流程：

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

详细的配置示例请参见 Lanalyzer 主文档。
