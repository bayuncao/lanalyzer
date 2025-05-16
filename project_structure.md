# Lanalyzer Project Structure

## Main Directory Structure

- [x] **lanalyzer** - Main code directory
  - [x] **analysis** - Analysis related modules
  - [x] **cli** - Command line interface
  - [ ] **config** - Configuration related modules
  - [x] **logger** - Logging related modules
  - [ ] **mcp** - MCP(Model Control Panel) related modules
  - [ ] **models** - Data models
  - [ ] **output** - Output formatting related modules
  - [ ] **utils** - Utility functions
- [ ] **examples** - Example code
- [x] **rules** - Rule configuration files
- [ ] **logs** - Log files

## Project File Structure

### Rules Configuration Files

- [x] **rules/pickle_analysis_config.json** - Configuration for pickle deserialization analysis (Simplified)
- [x] **rules/eval_exec_analysis_config.json** - Configuration for eval/exec analysis
- [x] **rules/taint_rules_config.json** - Configuration for taint analysis rules

### Lanalyzer Core Module

- [ ] **lanalyzer/__init__.py** - Module initialization file
- [ ] **lanalyzer/__version__.py** - Version information
- [ ] **lanalyzer/main.py** - Main program entry

### Analysis Related Modules

- [ ] **lanalyzer/analysis/__init__.py**
- [ ] **lanalyzer/analysis/ast_parser.py** - AST parser
- [ ] **lanalyzer/analysis/base.py** - Base class
- [x] **lanalyzer/analysis/call_chain_builder.py** - Call chain builder
- [ ] **lanalyzer/analysis/callgraph.py** - Call graph related
- [x] **lanalyzer/analysis/chain_utils.py** - Chain utilities
- [x] **lanalyzer/analysis/control_flow_analyzer.py** - Control flow analyzer
- [x] **lanalyzer/analysis/data_flow_analyzer.py** - Data flow analyzer
- [ ] **lanalyzer/analysis/datastructures.py** - Data structures
- [ ] **lanalyzer/analysis/defuse.py** - Definition-use analysis
- [ ] **lanalyzer/analysis/pathsensitive.py** - Path-sensitive analysis
- [ ] **lanalyzer/analysis/tracker.py** - Tracker
- [ ] **lanalyzer/analysis/utils.py** - Utility functions
- [ ] **lanalyzer/analysis/visitor_base.py** - Visitor base class
- [ ] **lanalyzer/analysis/visitor_control.py** - Control visitor
- [ ] **lanalyzer/analysis/visitor_datastructure.py** - Data structure visitor
- [ ] **lanalyzer/analysis/visitor_function.py** - Function visitor
- [ ] **lanalyzer/analysis/visitor.py** - Visitor
- [ ] **lanalyzer/analysis/vulnerability_finder.py** - Vulnerability finder

### CLI Interface Module

- [x] **lanalyzer/cli/__init__.py** - Module initialization
- [x] **lanalyzer/cli/analysis_utils.py** - Analysis utilities
- [x] **lanalyzer/cli/config_utils.py** - Configuration utilities
- [x] **lanalyzer/cli/enhanced.py** - Enhanced functionality
- [x] **lanalyzer/cli/file_utils.py** - File utilities

### Configuration Module

- [ ] **lanalyzer/config/__init__.py**
- [ ] **lanalyzer/config/loader.py** - Configuration loader
- [ ] **lanalyzer/config/settings.py** - Settings

### Logger Module

- [x] **lanalyzer/logger/__init__.py** - Module initialization
- [x] **lanalyzer/logger/config.py** - Logger configuration
- [x] **lanalyzer/logger/core.py** - Logger core
- [ ] **lanalyzer/logger/decorators.py** - Logger decorators

### MCP Module

- [ ] **lanalyzer/mcp/__init__.py**
- [ ] **lanalyzer/mcp/__main__.py** - MCP entry point
- [ ] **lanalyzer/mcp/handlers.py** - Handlers
- [ ] **lanalyzer/mcp/mcpserver.py** - MCP commands
- [ ] **lanalyzer/mcp/models.py** - MCP models

### Data Model Module

- [ ] **lanalyzer/models/__init__.py**
- [ ] **lanalyzer/models/base.py** - Base models
- [ ] **lanalyzer/models/results.py** - Result models
- [ ] **lanalyzer/models/sink.py** - Sink models
- [ ] **lanalyzer/models/source.py** - Source models
- [ ] **lanalyzer/models/taint.py** - Taint models
- [ ] **lanalyzer/models/vulnerability.py** - Vulnerability models

### Output Module

- [ ] **lanalyzer/output/__init__.py**
- [ ] **lanalyzer/output/console_formatter.py** - Console formatter
- [ ] **lanalyzer/output/formatter.py** - Formatter base class
- [ ] **lanalyzer/output/json_formatter.py** - JSON formatter

### Utilities Module

- [ ] **lanalyzer/utils/__init__.py**
- [ ] **lanalyzer/utils/ast_utils.py** - AST utilities
- [ ] **lanalyzer/utils/fs_utils.py** - File system utilities

### Examples and Other Files

- [ ] **examples/__init__.py** - Examples initialization
- [ ] **examples/job.py** - Job example
- [ ] **examples/parallel_state.py** - Parallel state example
- [ ] **examples/rpc.py** - RPC example
- [ ] **examples/servicer.py** - Service provider example
- [ ] **examples/shm_broadcast.py** - Shared memory broadcast example
- [ ] **examples/utils.py** - Example utilities
- [ ] **mcp_client_example.py** - MCP client example
- [ ] **setup.py** - Installation script 