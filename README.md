[//]: # (Banner placeholder - replace with your actual banner URL)
![Lanalyzer Banner](https://via.placeholder.com/1200x300.png?text=Lanalyzer+Static+Analysis)

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

## 📖 Table of Contents

- [✨ Features](#-features)
- [🚀 Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [💻 Usage](#-usage)
  - [Basic Analysis](#basic-analysis)
  - [Command-Line Options](#command-line-options)
  - [Example](#example)
- [🧩 Model Context Protocol (MCP) Support](#-model-context-protocol-mcp-support)
  - [Installing MCP Dependencies](#installing-mcp-dependencies)
  - [Starting the MCP Server](#starting-the-mcp-server)
  - [MCP Server Features](#mcp-server-features)
  - [Integration with AI Tools](#integration-with-ai-tools)
  - [Using in Cursor](#using-in-cursor)
  - [MCP Command-Line Options](#mcp-command-line-options)
  - [Advanced MCP Usage](#advanced-mcp-usage)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)
- [📞 Contact](#-contact)


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
   uv sync

   # Install with development dependencies
   uv sync --group dev

   # Install with MCP support
   uv sync --extra mcp
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
uv pip install -e ".[mcp]"
```

### Starting the MCP Server

There are multiple ways to start the MCP server:

1. **Using Python Module**:

```bash
# View help information
python -m lanalyzer.mcp --help

# Start the server
python -m lanalyzer.mcp run --host 0.0.0.0 --port 8000 --debug
```

2. **Using the lanalyzer Command-Line Tool**:

```bash
# View help information
lanalyzer mcp --help

# Start the server
lanalyzer mcp run --host 0.0.0.0 --port 8000 --debug

# Use FastMCP development mode (if applicable, verify this command)
# lanalyzer mcp dev
```

### MCP Server Features

The MCP server provides the following core functionalities:

1. **Code Analysis**: Analyze Python code strings for security vulnerabilities
2. **File Analysis**: Analyze specific files for security vulnerabilities
3. **Path Analysis**: Analyze entire directories or projects for security vulnerabilities
4. **Vulnerability Explanation**: Provide detailed explanations of discovered vulnerabilities
5. **Configuration Management**: Get, validate, and create analysis configurations

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

- `--debug`: Enable debug mode with detailed logging
- `--host`: Set the server listening address (default: 127.0.0.1)
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

The analysis results are returned in JSON format with the following structure:

#### Root Level Fields

- **`vulnerabilities`** (Array): List of detected vulnerabilities
- **`call_chains`** (Array): Data flow paths from sources to sinks
- **`summary`** (Object): Analysis statistics and overview
- **`imports`** (Object): Import information for analyzed files

#### Vulnerabilities Array

Each vulnerability object contains:

- **`type`** (String): Vulnerability type (e.g., "UnsafeDeserialization", "PathTraversal", "CodeInjection")
- **`severity`** (String): Risk level ("High", "Medium", "Low")
- **`detection_method`** (String): How the vulnerability was detected ("sink_detection", "taint_flow")
- **`sink`** (Object): Information about the dangerous operation
  - **`name`** (String): Sink type name
  - **`line`** (Number): Line number where the sink occurs
  - **`file`** (String): File path containing the sink
  - **`function_name`** (String): Function containing the sink
  - **`full_name`** (String): Full qualified name of the sink
- **`argument`** (String): The argument passed to the sink
- **`argument_index`** (Number): Index of the dangerous argument (-1 if unknown)
- **`description`** (String): Human-readable description of the vulnerability
- **`recommendation`** (String): Suggested mitigation steps

#### Call Chains Array

Each call chain represents a data flow path:

- **`id`** (Number): Unique identifier for the call chain
- **`source`** (Object): Information about the data source
  - **`type`** (String): Source type (e.g., "NetworkInput", "UserInput")
  - **`line`** (Number): Line number of the source
  - **`file`** (String): File path containing the source
  - **`function`** (String): Function containing the source
- **`sink`** (Object): Information about the data sink
  - **`type`** (String): Sink type (e.g., "PickleDeserialization", "FileWrite")
  - **`line`** (Number): Line number of the sink
  - **`file`** (String): File path containing the sink
  - **`function`** (String): Function containing the sink
  - **`full_name`** (String): Full qualified name of the sink
- **`tainted_variable`** (String): Name of the variable carrying tainted data
- **`vulnerability_type`** (String): Type of vulnerability this flow represents
- **`flow_description`** (String): Human-readable description of the data flow
- **`path_analysis`** (Object): Analysis of the flow path
  - **`path_length`** (Number): Number of steps in the flow
  - **`confidence`** (Number): Confidence score (0.0 to 1.0)
  - **`intermediate_steps`** (Number): Number of intermediate processing steps
  - **`complexity`** (String): Path complexity ("low", "medium", "high")
- **`intermediate_nodes`** (Array): List of intermediate processing steps

#### Summary Object

- **`files_analyzed`** (Number): Number of files processed
- **`functions_found`** (Number): Total functions discovered
- **`tainted_variables`** (Number): Variables involved in taint flows
- **`sources_found`** (Number): Total data sources identified
- **`sinks_found`** (Number): Total data sinks identified
- **`vulnerabilities_found`** (Number): Total vulnerabilities detected
- **`imports`** (Object): Import statistics
  - **`total_imports`** (Number): Total import statements
  - **`unique_stdlib_modules`** (Number): Unique standard library modules
  - **`unique_third_party_modules`** (Number): Unique third-party modules
  - **`unique_functions`** (Number): Unique imported functions
  - **`unique_classes`** (Number): Unique imported classes
  - **`stdlib_modules`** (Array): List of standard library modules
  - **`third_party_modules`** (Array): List of third-party modules
  - **`imported_functions`** (Array): List of imported functions
  - **`imported_classes`** (Array): List of imported classes
- **`call_chains`** (Object): Call chain statistics
  - **`total_paths`** (Number): Total number of data flow paths
  - **`average_path_length`** (Number): Average length of flow paths
  - **`high_confidence_paths`** (Number): Number of high-confidence paths
  - **`complex_paths`** (Number): Number of complex paths
  - **`tracked_variables`** (Number): Variables tracked in flows
  - **`tracked_functions`** (Number): Functions involved in flows
  - **`data_flow_edges`** (Number): Total data flow connections

#### Imports Object

Per-file import information:

- **`<file_path>`** (Object): Import details for each analyzed file
  - **`total_imports`** (Number): Total imports in this file
  - **`unique_modules`** (Number): Unique modules imported
  - **`standard_library_modules`** (Array): Standard library modules used
  - **`third_party_modules`** (Array): Third-party modules used
  - **`imported_functions`** (Array): Functions imported
  - **`imported_classes`** (Array): Classes imported
  - **`detailed_imports`** (Array): Detailed import information
    - **`type`** (String): Import type ("import", "from_import")
    - **`module`** (String): Module name
    - **`imported_name`** (String|null): Specific imported name
    - **`alias`** (String|null): Import alias
    - **`line`** (Number): Line number of import
    - **`col`** (Number): Column number of import
    - **`is_stdlib`** (Boolean): Whether it's a standard library module
    - **`root_module`** (String): Root module name

---

## 🌐 Language Versions

- **English**: [README.md](README.md) (Current)
- **中文**: [README.zh.md](README.zh.md)
