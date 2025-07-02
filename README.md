![Lanalyzer](https://private-user-images.githubusercontent.com/126563545/461340415-4fede494-5b84-4928-b664-9303480021dd.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3NTE0Mjg5NjIsIm5iZiI6MTc1MTQyODY2MiwicGF0aCI6Ii8xMjY1NjM1NDUvNDYxMzQwNDE1LTRmZWRlNDk0LTViODQtNDkyOC1iNjY0LTkzMDM0ODAwMjFkZC5wbmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjUwNzAyJTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI1MDcwMlQwMzU3NDJaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT01NjZiYWFkZDg3NGU0ZjZlOTRmOWYxNThlM2UwNTMxM2VjY2M3NmRkZWQ4ZmUwMzUyZTQ5YjMyMjNkMjZlNGM4JlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCJ9.NxMO7JYy6-B_GO0McpCuRh3tTVAgu61xSCVf5wgYMU0)

# Lanalyzer

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python Version](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![uv](https://img.shields.io/badge/uv-0.1.18+-purple.svg)](https://github.com/astral-sh/uv)
[![PyPI version](https://img.shields.io/pypi/v/lanalyzer.svg?logo=pypi&label=pypi&color=blue)](https://pypi.org/project/lanalyzer/)
[![Build Status](https://img.shields.io/github/actions/workflow/status/mxcrafts/lanalyzer/ci.yml?branch=main&style=flat-square)](https://github.com/mxcrafts/lanalyzer/actions)
[![Code Coverage](https://img.shields.io/codecov/c/github/mxcrafts/lanalyzer.svg?style=flat-square)](https://codecov.io/gh/mxcrafts/lanalyzer)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](CONTRIBUTING.md)
[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-orange.svg)](https://modelcontextprotocol.io/)

Lanalyzer is an advanced Python static taint analysis tool designed to detect potential security vulnerabilities in Python projects. It identifies data flows from untrusted sources (Sources) to sensitive operations (Sinks) and provides detailed insights into potential risks.

<p align="center">
  <a href="./README.md"><img alt="README in English" src="https://img.shields.io/badge/English-d9d9d9"></a>
  <a href="./README.zh.md"><img alt="简体中文版自述文件" src="https://img.shields.io/badge/简体中文-d9d9d9"></a>
</p>

## 📖 Table of Contents

- [Lanalyzer](#lanalyzer)
  - [📖 Table of Contents](#-table-of-contents)
  - [✨ Features](#-features)
  - [🚀 Getting Started](#-getting-started)
    - [Prerequisites](#prerequisites)
    - [Installation](#installation)
      - [Option 1: Install from PyPI (Recommended)](#option-1-install-from-pypi-recommended)
      - [Option 2: Install from Source](#option-2-install-from-source)
  - [💻 Usage](#-usage)
    - [Basic Analysis](#basic-analysis)
    - [Command-Line Options](#command-line-options)
    - [Example](#example)
  - [🤝 Contributing](#-contributing)
  - [📄 License](#-license)
  - [📞 Contact](#-contact)
    - [Contact](#contact)
  - [🧩 Model Context Protocol (MCP) Support](#-model-context-protocol-mcp-support)
    - [Installing MCP Dependencies](#installing-mcp-dependencies)
    - [Starting the MCP Server](#starting-the-mcp-server)
    - [MCP Server Features](#mcp-server-features)
    - [Integration with AI Tools](#integration-with-ai-tools)
    - [Using in Cursor](#using-in-cursor)
    - [MCP Command-Line Options](#mcp-command-line-options)
    - [Advanced MCP Usage](#advanced-mcp-usage)
      - [Custom Configurations](#custom-configurations)
      - [Batch File Analysis](#batch-file-analysis)
  - [📊 Analysis Results Format](#-analysis-results-format)


## ✨ Features

- **Taint Analysis**: Tracks data flows from sources to sinks.
- **Customizable Rules**: Define your own sources, sinks, sanitizers, and taint propagation paths.
- **Static Analysis**: No need to execute the code.
- **Extensibility**: Easily add new rules for detecting vulnerabilities like SQL Injection, XSS, and more.
- **Detailed Reports**: Generate comprehensive analysis reports with vulnerability details and mitigation suggestions.
- **Command-Line Interface**: Run analyses directly from the terminal.

## 🚀 Getting Started

### Prerequisites
- Python 3.10 or higher
- [uv](https://github.com/astral-sh/uv) (recommended for dependency management)

### Installation

#### Option 1: Install from PyPI (Recommended)
```bash
# Using pip
pip install lanalyzer

# Using uv (recommended)
uv add lanalyzer

# With MCP support
uv add lanalyzer[mcp]
```

#### Option 2: Install from Source
1. Clone the repository:
   ```bash
   git clone https://github.com/mxcrafts/lanalyzer.git
   cd lanalyzer
   ```

2. Install dependencies:
   ```bash
   # Install basic dependencies
   make install

   # Install with development dependencies
   make install-dev

   # Install with MCP support
   make install-mcp

   # Install everything (dev + MCP)
   make install-all
   ```

## 💻 Usage

### Basic Analysis
Run a taint analysis on a Python file:
```bash
lanalyzer --target <target_file> --config <config_file> --pretty --output <output_file> --log-file <log_file> --debug
```

### Command-Line Options
- `--target`: Path to the Python file or directory to analyze.
- `--config`: Path to the configuration file.
- `--output`: Path to save the analysis report.
- `--log-file`: Path to save the log file.
- `--pretty`: Pretty-print the output.
- `--detailed`: Show detailed analysis statistics.
- `--debug`: Enable debug mode with detailed logging.

### Example
```bash
lanalyzer --target example.py --config rules/sql_injection.json --pretty --output example_analysis.json --log-file example_analysis.log --debug
```

## 🤝 Contributing

We welcome contributions! Please see the [CONTRIBUTING.md](CONTRIBUTING.md) file for guidelines on how to contribute to Lanalyzer.

For development setup, building, and publishing instructions, see [DEVELOPMENT.md](docs/DEVELOPMENT.md).

## 📄 License

This project is licensed under the GNU Affero General Public License v3.0. See the [LICENSE](LICENSE) file for details.

## 📞 Contact

### Contact

- Issues: [GitHub Issues](https://github.com/mxcrafts/ltrack/issues)
- Email: support@mx-crafts.com

## 🧩 Model Context Protocol (MCP) Support

Lanalyzer now supports the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/), allowing it to run as an MCP server that AI models and tools can use to access taint analysis functionality through a standard interface.

### Installing MCP Dependencies

If you're using pip:

```bash
pip install "lanalyzer[mcp]"
```

If you're using uv:

```bash
uv add lanalyzer[mcp]
```

### Starting the MCP Server

There are multiple ways to start the MCP server:

1. **Using Python Module**:

```bash
# View help information
python -m lanalyzer.mcp --help

# Start the server (default port 8001)
python -m lanalyzer.mcp run --port 8001 --debug
```

2. **Using the lanalyzer Command-Line Tool**:

```bash
# View help information
lanalyzer mcp --help

# Start the server (default port 8000)
lanalyzer mcp run --port 8000 --debug

# Use development mode
lanalyzer mcp dev
```

3. **Using Makefile (Recommended for Development)**:

```bash
# Start MCP server
make mcp-server

# Start MCP server with debug mode
make mcp-server-debug

# Test MCP CLI
make mcp-test
```

### MCP Server Features

The MCP server provides the following core functionalities:

1. **Code Analysis**: Analyze Python code strings for security vulnerabilities
2. **File Analysis**: Analyze specific files for security vulnerabilities
3. **Path Analysis**: Analyze entire directories or projects for security vulnerabilities
4. **Vulnerability Explanation**: Provide detailed explanations of discovered vulnerabilities
5. **Configuration Management**: Get, validate, and create analysis configurations

For detailed MCP API documentation, see [MCP Tools Reference](docs/MCP_TOOLS.md).

### Integration with AI Tools

The MCP server can be integrated with AI tools that support the MCP protocol:

```python
# Using the FastMCP client
from fastmcp import FastMCPClient

# Create a client connected to the server
client = FastMCPClient("http://127.0.0.1:8000")

# Analyze code
result = client.call({
    "type": "analyze_code",
    "code": "user_input = input()\nquery = f\"SELECT * FROM users WHERE name = '{user_input}'\"",
    "file_path": "example.py",
    "config_path": "/path/to/config.json"
})

# Print analysis results
print(result)
```

### Using in Cursor

If you're working in the Cursor editor, you can directly ask the AI to use Lanalyzer to analyze your code:

```
Please use lanalyzer to analyze the current file for security vulnerabilities and explain the potential risks.
```

### MCP Command-Line Options

The MCP server supports the following command-line options:

**For `python -m lanalyzer.mcp run`**:
- `--debug`: Enable debug mode with detailed logging
- `--host`: Set the server listening address (default: 127.0.0.1)
- `--port`: Set the server listening port (default: 8001)
- `--transport`: Transport protocol (sse or streamable-http)

**For `lanalyzer mcp run`**:
- `--debug`: Enable debug mode
- `--port`: Set the server listening port (default: 8000)

### Advanced MCP Usage

#### Custom Configurations

You can use the get_config, validate_config, and create_config tools to manage vulnerability detection configurations:

```python
# Get the default configuration
config = client.call({
    "type": "get_config"
})

# Create a new configuration
result = client.call({
    "type": "create_config",
    "config_data": {...},  # Configuration data
    "config_path": "/path/to/save/config.json"  # Optional
})
```

#### Batch File Analysis

Analyze an entire project or directory:

```python
result = client.call({
    "type": "analyze_path",
    "target_path": "/path/to/project",
    "config_path": "/path/to/config.json",
    "output_path": "/path/to/output.json"  # Optional
})
```

## 📊 Analysis Results Format

The analysis results are returned in JSON format with the following main sections:

- **`vulnerabilities`**: List of detected security vulnerabilities
- **`call_chains`**: Data flow paths from sources to sinks
- **`summary`**: Analysis statistics and overview
- **`imports`**: Import information for analyzed files

For detailed format specification, see [Output Format Documentation](docs/OUTPUT_FORMAT.md).