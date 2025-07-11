![Lanalyzer](https://raw.githubusercontent.com/bayuncao/lanalyzer/0fe337cfa47121d987b692d621090ca678431c93/image/banner.png)

# Lanalyzer

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python Version](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![uv](https://img.shields.io/badge/uv-0.1.18+-purple.svg)](https://github.com/astral-sh/uv)
[![PyPI version](https://img.shields.io/pypi/v/lanalyzer.svg?logo=pypi&label=pypi&color=blue)](https://pypi.org/project/lanalyzer/)
[![Build Status](https://img.shields.io/github/actions/workflow/status/bayuncao/lanalyzer/ci.yml?branch=main&style=flat-square)](https://github.com/bayuncao/lanalyzer/actions)
[![Code Coverage](https://img.shields.io/codecov/c/github/bayuncao/lanalyzer.svg?style=flat-square)](https://codecov.io/gh/bayuncao/lanalyzer)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](CONTRIBUTING.md)
[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-orange.svg)](https://modelcontextprotocol.io/)

Lanalyzer 是一个高级的 Python 静态污点分析工具，旨在检测 Python 项目中的潜在安全漏洞。它通过分析从不受信任的数据源（Sources）到敏感操作点（Sinks）的数据流动，提供详细的风险洞察。

<p align="center">
  <a href="./README.md"><img alt="README in English" src="https://img.shields.io/badge/English-d9d9d9"></a>
  <a href="./README_CN.md"><img alt="简体中文版自述文件" src="https://img.shields.io/badge/简体中文-d9d9d9"></a>
</p>

## 📖 目录

- [Lanalyzer](#lanalyzer)
  - [📖 目录](#-目录)
  - [✨ 功能特点](#-功能特点)
  - [🚀 开始使用](#-开始使用)
    - [前置要求](#前置要求)
    - [安装步骤](#安装步骤)
      - [选项 1：从 PyPI 安装（推荐）](#选项-1从-pypi-安装推荐)
      - [选项 2：从源码安装](#选项-2从源码安装)
  - [💻 使用方法](#-使用方法)
    - [基本分析](#基本分析)
    - [命令行选项](#命令行选项)
    - [示例](#示例)
  - [🤝 贡献](#-贡献)
  - [📄 许可证](#-许可证)
  - [📞 联系方式](#-联系方式)
    - [联系方式](#联系方式)
  - [🧩 MCP 模块使用指南](#-mcp-模块使用指南)
    - [安装 MCP 依赖](#安装-mcp-依赖)
    - [MCP 服务器启动方式](#mcp-服务器启动方式)
    - [MCP 服务器功能](#mcp-服务器功能)
    - [与 AI 工具集成](#与-ai-工具集成)
    - [在 Cursor 中使用](#在-cursor-中使用)
    - [MCP 命令行选项](#mcp-命令行选项)
    - [高级用法](#高级用法)
      - [自定义配置](#自定义配置)
      - [批量文件分析](#批量文件分析)
  - [📊 分析结果格式](#-分析结果格式)

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

#### 选项 1：从 PyPI 安装（推荐）
```bash
# 使用 pip
pip install lanalyzer

# 作为工具安装（推荐）
uv tool install lanalyzer

# 使用 uv
uv add lanalyzer

# 包含 MCP 支持
uv add lanalyzer[mcp]
```

#### 选项 2：从源码安装
1. 克隆仓库：
   ```bash
   git clone https://github.com/bayuncao/lanalyzer.git
   cd lanalyzer
   ```

2. 安装依赖：
   ```bash
   # 安装基本依赖
   make install

   # 安装开发依赖
   make install-dev

   # 安装 MCP 支持
   make install-mcp

   # 安装所有依赖（开发 + MCP）
   make install-all
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
- `--minimal-output`：仅输出漏洞和调用链信息（默认：启用）。
- `--no-minimal-output`：输出完整的分析结果，包括摘要和导入信息。

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

- Issues: [GitHub Issues](https://github.com/bayuncao/ltrack/issues)
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
uv add lanalyzer[mcp]
```

### MCP 服务器启动方式

有多种方式可以启动 MCP 服务器：

1. **使用 lanalyzer 命令行工具**:

```bash
# 查看帮助信息
lanalyzer mcp --help

# 启动服务器（默认端口 8000）
lanalyzer mcp run --port 8000 --debug

# 使用开发模式
lanalyzer mcp dev
```

2. **使用 Python 模块方式**:

```bash
# 查看帮助信息
python -m lanalyzer.mcp --help

# 启动服务器（默认端口 8001）
python -m lanalyzer.mcp run --port 8001 --debug
```

3. **使用 Makefile（开发推荐）**:

```bash
# 启动 MCP 服务器
make mcp-server

# 启动 MCP 服务器（调试模式）
make mcp-server-debug

# 测试 MCP CLI
make mcp-test
```

### MCP 服务器功能

MCP 服务器提供以下核心功能：

1. **代码分析**：分析 Python 代码字符串中的安全漏洞
2. **文件分析**：分析指定文件中的安全漏洞
3. **路径分析**：分析整个目录或项目中的安全漏洞
4. **漏洞解释**：提供对发现漏洞的详细解释
5. **配置管理**：获取、验证和创建分析配置

详细的 MCP API 文档请参见 [MCP 工具参考](docs/MCP_TOOLS.md)。

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

**对于 `python -m lanalyzer.mcp run`**：
- `--debug`: 启用调试模式，显示详细日志
- `--host`: 设置服务器监听地址（默认：127.0.0.1）
- `--port`: 设置服务器监听端口（默认：8001）
- `--transport`: 传输协议（sse 或 streamable-http）

**对于 `lanalyzer mcp run`**：
- `--debug`: 启用调试模式
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

分析结果以 JSON 格式返回，包含以下主要部分：

- **`vulnerabilities`**: 检测到的安全漏洞列表
- **`call_chains`**: 从源到汇的数据流路径
- **`summary`**: 分析统计信息和概览
- **`imports`**: 分析文件的导入信息

详细格式规范请参见 [输出格式文档](docs/OUTPUT_FORMAT_CN.md)。