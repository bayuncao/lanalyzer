# LanaLyzer

LanaLyzer is an advanced Python static taint analysis tool designed to detect potential security vulnerabilities in Python projects. It identifies data flows from untrusted sources (Sources) to sensitive operations (Sinks) and provides detailed insights into potential risks.

## Features

- **Taint Analysis**: Tracks data flows from sources to sinks.
- **Customizable Rules**: Define your own sources, sinks, sanitizers, and taint propagation paths.
- **Static Analysis**: No need to execute the code.
- **Extensibility**: Easily add new rules for detecting vulnerabilities like SQL Injection, XSS, and more.
- **Detailed Reports**: Generate comprehensive analysis reports with vulnerability details and mitigation suggestions.
- **Command-Line Interface**: Run analyses directly from the terminal.

## Installation

### Prerequisites
- Python 3.10 or higher
- [Poetry](https://python-poetry.org/) (recommended for dependency management)

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/mxcrafts/lanalyzer.git
   cd lanalyzer
   ```

2. Install dependencies:
   ```bash
   poetry install
   ```

3. Activate the virtual environment:
   ```bash
   poetry shell
   ```

## Usage

### Basic Analysis
Run a taint analysis on a Python file:
```bash
python -m lanalyzer analyze <target_file> --config <config_file>
```

### Command-Line Options
- `--config`: Path to the configuration file.
- `--output`: Path to save the analysis report.
- `--pretty`: Pretty-print the output.
- `--detailed`: Show detailed analysis statistics.

### Example
```bash
python -m lanalyzer analyze example.py --config rules/sql_injection.json --pretty
```

## Contributing

We welcome contributions! Please see the [CONTRIBUTING.md](CONTRIBUTING.md) file for guidelines on how to contribute to LanaLyzer.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For questions or support, please open an issue on GitHub or email us at [lanalyzer@example.com](mailto:lanalyzer@example.com).

## Recent Updates

- Enhanced context analysis and call chain building: Fixed issues with source and sink association in taint analysis, prioritizing source finding within the same function to avoid incorrectly linking to identical statements in other functions.

## MCP支持

Lanalyzer现在支持[Model Context Protocol (MCP)](https://modelcontextprotocol.io/)，可以作为MCP服务器运行，允许AI代理通过标准接口访问污点分析功能。

### 安装MCP依赖

```bash
pip install lanalyzer[mcp]
```

### 启动MCP服务器

```bash
lanalyzer mcp --host 127.0.0.1 --port 8000
```

或者使用提供的脚本：

```bash
./lanalyzer_mcp.sh
```

### MCP服务器API

MCP服务器提供以下端点：

- `/.well-known/mcp/v1` - 标准MCP协议端点
- `/` - 服务器信息端点
- `/analyze` - 代码分析端点
- `/analyze/file` - 文件分析端点
- `/analyze/path` - 本地文件/目录分析端点
- `/explain` - 漏洞解释端点
- `/configuration` - 配置管理端点

### 文件分析和漏洞解释功能

Lanalyzer MCP服务器现在支持直接分析本地文件和目录，并提供友好的漏洞解释。

**分析本地文件或目录**：
```python
result = mcp_client.call({
    "type": "analyze_path",
    "target_path": "/path/to/your/file_or_directory.py",
    "config_path": "/path/to/config.json",  # 可选
    "output_path": "/path/to/output.json"   # 可选
})
```

**获取自然语言漏洞解释**：
```python
explanation = mcp_client.call({
    "type": "explain_vulnerabilities",
    "analysis_file": "/path/to/analysis_result.json",
    "format": "markdown", # 或 "text"
    "level": "detailed"   # 或 "brief"
})
```

**在Cursor中与AI聊天**：
现在您可以在Cursor中直接要求AI分析本地文件并解释漏洞，例如：
```
请使用lanalyzer分析examples/job.py文件中的安全漏洞，并以简洁的方式解释发现的问题
```

## Getting Started