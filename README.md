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

## Model Context Protocol (MCP) Support

LanaLyzer now supports the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/), allowing it to run as an MCP server that AI models and tools can use to access taint analysis functionality through a standard interface.

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
python -m lanalyzer.mcp run --host 127.0.0.1 --port 8000

# Use debug mode
python -m lanalyzer.mcp run --debug
```

2. **Using the lanalyzer Command-Line Tool**:

```bash
# View help information
lanalyzer mcp --help

# Start the server
lanalyzer mcp run --host 127.0.0.1 --port 8000

# Use FastMCP development mode
lanalyzer mcp dev
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

If you're working in the Cursor editor, you can directly ask the AI to use LanaLyzer to analyze your code:

```
Please use lanalyzer to analyze the current file for security vulnerabilities and explain the potential risks.
```

### Command-Line Options

The MCP server supports the following command-line options:

- `--debug`: Enable debug mode with detailed logging
- `--host`: Set the server listening address (default: 127.0.0.1)
- `--port`: Set the server listening port (default: 8000)

### Advanced Usage

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

## Getting Started