[//]: # (横幅占位符 - 请替换为您的实际横幅图片URL)
![Lanalyzer 横幅](https://via.placeholder.com/1200x300.png?text=Lanalyzer+%E9%9D%99%E6%80%81%E5%88%86%E6%9E%90)

# Lanalyzer

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python Version](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![uv](https://img.shields.io/badge/uv-0.1.18+-purple.svg)](https://github.com/astral-sh/uv)
[![PyPI version](https://img.shields.io/pypi/v/lanalyzer.svg?logo=pypi&label=pypi&color=blue)](https://pypi.org/project/lanalyzer/)
[![Build Status](https://img.shields.io/github/actions/workflow/status/mxcrafts/lanalyzer/ci.yml?branch=main&style=flat-square)](https://github.com/mxcrafts/lanalyzer/actions)
[![Code Coverage](https://img.shields.io/codecov/c/github/mxcrafts/lanalyzer.svg?style=flat-square)](https://codecov.io/gh/mxcrafts/lanalyzer)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](CONTRIBUTING.md)
[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-orange.svg)](https://modelcontextprotocol.io/)

Lanalyzer 是一个高级的 Python 静态污点分析工具，旨在检测 Python 项目中的潜在安全漏洞。它通过分析从不受信任的数据源（Sources）到敏感操作点（Sinks）的数据流动，提供详细的风险洞察。

## 📖 目录

- [✨ 功能特点](#-功能特点)
- [🚀 开始使用](#-开始使用)
  - [前置要求](#前置要求)
  - [安装步骤](#安装步骤)
- [💻 使用方法](#-使用方法)
  - [基本分析](#基本分析)
  - [命令行选项](#命令行选项)
  - [示例](#示例)
- [🧩 MCP 模块使用指南](#-mcp-模块使用指南)
  - [安装 MCP 依赖](#安装-mcp-依赖)
  - [MCP 服务器启动方式](#mcp-服务器启动方式)
  - [MCP 服务器功能](#mcp-服务器功能)
  - [与 AI 工具集成](#与-ai-工具集成)
  - [在 Cursor 中使用](#在-cursor-中使用)
  - [MCP 命令行选项](#mcp-命令行选项)
  - [高级用法](#高级用法)
- [📊 分析结果格式](#-分析结果格式)
- [🤝 贡献](#-贡献)
- [📄 许可证](#-许可证)
- [📞 联系方式](#-联系方式)

## ✨ 功能特点

- **污点分析**：跟踪从数据源到汇聚点的数据流。
- **可定制规则**：支持自定义数据源、汇聚点、净化器和污点传播路径。
- **静态分析**：无需执行代码即可完成分析。
- **可扩展性**：轻松添加新规则，检测 SQL 注入、XSS 等漏洞。
- **详细报告**：生成包含漏洞详情和修复建议的全面分析报告。
- **命令行接口**：支持通过终端直接运行分析。

## 🚀 开始使用

### 前置要求
- Python 3.10 或更高版本
- [uv](https://github.com/astral-sh/uv)（推荐用于依赖管理）

### 安装步骤
1. 克隆仓库：
   ```bash
   git clone https://github.com/mxcrafts/lanalyzer.git
   cd lanalyzer
   ```

2. 创建虚拟环境并安装依赖：
   ```bash
   uv venv
   uv pip sync pyproject.toml --all-extras
   ```

3. 激活虚拟环境：
   ```bash
   source .venv/bin/activate
   ```

## 💻 使用方法

### 基本分析
对 Python 文件运行污点分析：
```bash
lanalyzer --target <目标文件> --config <配置文件> --pretty --output <输出文件> --log-file <日志文件> --debug
```

### 命令行选项
- `--target`：要分析的 Python 文件或目录的路径。
- `--config`：配置文件路径。
- `--output`：保存分析报告的路径。
- `--log-file`：保存日志文件的路径。
- `--pretty`：美化输出。
- `--detailed`：显示详细的分析统计信息。
- `--debug`：启用调试模式，显示详细日志。

### 示例
```bash
lanalyzer --target example.py --config rules/sql_injection.json --pretty --output example_analysis.json --log-file example_analysis.log --debug
```

## 🤝 贡献

欢迎贡献代码！请参阅 [CONTRIBUTING.md](CONTRIBUTING.md) 文件，了解如何为 Lanalyzer 做出贡献。

## 📄 许可证

本项目基于 GNU Affero General Public License v3.0 许可证开源。详情请参阅 [LICENSE](LICENSE) 文件。

## 📞 联系方式

### 联系方式

- Issues: [GitHub Issues](https://github.com/mxcrafts/ltrack/issues)
- Email: support@mx-crafts.com

## 🧩 MCP 模块使用指南

Lanalyzer 现在支持 Model Context Protocol (MCP)，可以作为 MCP 服务器运行，允许 AI 模型和工具通过标准接口访问污点分析功能。

### 安装 MCP 依赖

如果您使用的是 pip：

```bash
pip install "lanalyzer[mcp]"
```

如果您使用的是 uv：

```bash
uv pip install -e ".[mcp]"
```

### MCP 服务器启动方式

有多种方式可以启动 MCP 服务器：

1. **使用 lanalyzer 命令行工具**:

```bash
# 查看帮助信息
lanalyzer mcp --help

# 启动服务器
lanalyzer mcp run --host 0.0.0.0 --port 8000 --debug

# 使用 FastMCP 开发模式 (如适用，请验证此命令)
# lanalyzer mcp dev
```

2. **使用 Python 模块方式**:

```bash
# 查看帮助信息
python -m lanalyzer.mcp --help

# 启动服务器
python -m lanalyzer.mcp run --host 0.0.0.0 --port 8000 --debug
```

### MCP 服务器功能

MCP 服务器提供以下核心功能：

1. **代码分析**：分析 Python 代码字符串中的安全漏洞
2. **文件分析**：分析指定文件中的安全漏洞
3. **路径分析**：分析整个目录或项目中的安全漏洞
4. **漏洞解释**：提供对发现漏洞的详细解释
5. **配置管理**：获取、验证和创建分析配置

### 与 AI 工具集成

MCP 服务器可以与支持 MCP 协议的 AI 工具集成，例如：

```python
# 使用 FastMCP 客户端
from fastmcp import FastMCPClient

# 创建客户端连接到服务器
client = FastMCPClient("http://127.0.0.1:8000")

# 分析代码
result = client.call({
    "type": "analyze_code",
    "code": "user_input = input()\nquery = f"SELECT * FROM users WHERE name = '{user_input}'"",
    "file_path": "example.py",
    "config_path": "/path/to/config.json"
})

# 打印分析结果
print(result)
```

### 在 Cursor 中使用

如果您在 Cursor 编辑器中工作，可以直接要求 AI 使用 Lanalyzer 分析代码：

```
请使用 lanalyzer 分析当前文件中的安全漏洞，并解释可能的风险。
```

### MCP 命令行选项

MCP 服务器支持以下命令行选项：

- `--debug`: 启用调试模式，显示详细日志
- `--host`: 设置服务器监听地址（默认：127.0.0.1）
- `--port`: 设置服务器监听端口（默认：8000）

### 高级用法

#### 自定义配置

您可以使用 get_config、validate_config 和 create_config 工具来管理漏洞检测配置：

```python
# 获取默认配置
config = client.call({
    "type": "get_config"
})

# 创建新配置
result = client.call({
    "type": "create_config",
    "config_data": {...},  # 配置数据
    "config_path": "/path/to/save/config.json"  # 可选
})
```

#### 批量文件分析

分析整个项目或目录：

```python
result = client.call({
    "type": "analyze_path",
    "target_path": "/path/to/project",
    "config_path": "/path/to/config.json",
    "output_path": "/path/to/output.json"  # 可选
})
```

## 📊 分析结果格式

分析结果以 JSON 格式返回，具有以下结构：

### 根级字段

- **`vulnerabilities`** (数组): 检测到的漏洞列表
- **`call_chains`** (数组): 从源到汇的数据流路径
- **`summary`** (对象): 分析统计信息和概览
- **`imports`** (对象): 分析文件的导入信息

### 漏洞数组

每个漏洞对象包含：

- **`type`** (字符串): 漏洞类型（如 "UnsafeDeserialization"、"PathTraversal"、"CodeInjection"）
- **`severity`** (字符串): 风险级别（"High"、"Medium"、"Low"）
- **`detection_method`** (字符串): 漏洞检测方法（"sink_detection"、"taint_flow"）
- **`sink`** (对象): 危险操作的信息
  - **`name`** (字符串): 汇点类型名称
  - **`line`** (数字): 汇点所在行号
  - **`file`** (字符串): 包含汇点的文件路径
  - **`function_name`** (字符串): 包含汇点的函数
  - **`full_name`** (字符串): 汇点的完全限定名
- **`argument`** (字符串): 传递给汇点的参数
- **`argument_index`** (数字): 危险参数的索引（未知时为 -1）
- **`description`** (字符串): 漏洞的可读描述
- **`recommendation`** (字符串): 建议的缓解措施

### 调用链数组

每个调用链代表一个数据流路径：

- **`id`** (数字): 调用链的唯一标识符
- **`source`** (对象): 数据源信息
  - **`type`** (字符串): 源类型（如 "NetworkInput"、"UserInput"）
  - **`line`** (数字): 源的行号
  - **`file`** (字符串): 包含源的文件路径
  - **`function`** (字符串): 包含源的函数
- **`sink`** (对象): 数据汇信息
  - **`type`** (字符串): 汇类型（如 "PickleDeserialization"、"FileWrite"）
  - **`line`** (数字): 汇的行号
  - **`file`** (字符串): 包含汇的文件路径
  - **`function`** (字符串): 包含汇的函数
  - **`full_name`** (字符串): 汇的完全限定名
- **`tainted_variable`** (字符串): 携带污染数据的变量名
- **`vulnerability_type`** (字符串): 此流代表的漏洞类型
- **`flow_description`** (字符串): 数据流的可读描述
- **`path_analysis`** (对象): 流路径分析
  - **`path_length`** (数字): 流中的步骤数
  - **`confidence`** (数字): 置信度分数（0.0 到 1.0）
  - **`intermediate_steps`** (数字): 中间处理步骤数
  - **`complexity`** (字符串): 路径复杂度（"low"、"medium"、"high"）
- **`intermediate_nodes`** (数组): 中间处理步骤列表

### 摘要对象

- **`files_analyzed`** (数字): 处理的文件数
- **`functions_found`** (数字): 发现的函数总数
- **`tainted_variables`** (数字): 参与污点流的变量数
- **`sources_found`** (数字): 识别的数据源总数
- **`sinks_found`** (数字): 识别的数据汇总数
- **`vulnerabilities_found`** (数字): 检测到的漏洞总数
- **`imports`** (对象): 导入统计信息
  - **`total_imports`** (数字): 总导入语句数
  - **`unique_stdlib_modules`** (数字): 唯一标准库模块数
  - **`unique_third_party_modules`** (数字): 唯一第三方模块数
  - **`unique_functions`** (数字): 唯一导入函数数
  - **`unique_classes`** (数字): 唯一导入类数
  - **`stdlib_modules`** (数组): 标准库模块列表
  - **`third_party_modules`** (数组): 第三方模块列表
  - **`imported_functions`** (数组): 导入函数列表
  - **`imported_classes`** (数组): 导入类列表
- **`call_chains`** (对象): 调用链统计信息
  - **`total_paths`** (数字): 数据流路径总数
  - **`average_path_length`** (数字): 流路径平均长度
  - **`high_confidence_paths`** (数字): 高置信度路径数
  - **`complex_paths`** (数字): 复杂路径数
  - **`tracked_variables`** (数字): 流中跟踪的变量数
  - **`tracked_functions`** (数字): 流中涉及的函数数
  - **`data_flow_edges`** (数字): 总数据流连接数

### 导入对象

每个文件的导入信息：

- **`<文件路径>`** (对象): 每个分析文件的导入详情
  - **`total_imports`** (数字): 此文件中的总导入数
  - **`unique_modules`** (数字): 导入的唯一模块数
  - **`standard_library_modules`** (数组): 使用的标准库模块
  - **`third_party_modules`** (数组): 使用的第三方模块
  - **`imported_functions`** (数组): 导入的函数
  - **`imported_classes`** (数组): 导入的类
  - **`detailed_imports`** (数组): 详细导入信息
    - **`type`** (字符串): 导入类型（"import"、"from_import"）
    - **`module`** (字符串): 模块名
    - **`imported_name`** (字符串|null): 具体导入名称
    - **`alias`** (字符串|null): 导入别名
    - **`line`** (数字): 导入的行号
    - **`col`** (数字): 导入的列号
    - **`is_stdlib`** (布尔值): 是否为标准库模块
    - **`root_module`** (字符串): 根模块名

---

## 🌐 语言版本

- **English**: [README.md](README.md)
- **中文**: [README.zh.md](README.zh.md) (当前)
