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

## Getting Started