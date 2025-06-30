# Analysis Results Output Format

This document describes the detailed structure of the JSON output format returned by Lanalyzer's vulnerability analysis.

## Overview

The analysis results are returned in JSON format with the following main sections:

- **`vulnerabilities`**: List of detected security vulnerabilities
- **`call_chains`**: Data flow paths from sources to sinks  
- **`summary`**: Analysis statistics and overview
- **`imports`**: Import information for analyzed files

## Root Level Fields

```json
{
  "vulnerabilities": [...],
  "call_chains": [...],
  "summary": {...},
  "imports": {...}
}
```

## Vulnerabilities Array

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

### Example Vulnerability

```json
{
  "type": "UnsafeDeserialization",
  "severity": "High",
  "detection_method": "sink_detection",
  "sink": {
    "name": "PickleDeserialization",
    "line": 15,
    "file": "example.py",
    "function_name": "load_data",
    "full_name": "pickle.loads"
  },
  "argument": "user_data",
  "argument_index": 0,
  "description": "Unsafe deserialization of user-controlled data using pickle.loads",
  "recommendation": "Use safe serialization formats like JSON, or validate data before deserialization"
}
```

## Call Chains Array

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

### Example Call Chain

```json
{
  "id": 1,
  "source": {
    "type": "NetworkInput",
    "line": 5,
    "file": "example.py",
    "function": "handle_request"
  },
  "sink": {
    "type": "PickleDeserialization",
    "line": 15,
    "file": "example.py",
    "function": "load_data",
    "full_name": "pickle.loads"
  },
  "tainted_variable": "user_data",
  "vulnerability_type": "UnsafeDeserialization",
  "flow_description": "User input flows from network request to pickle deserialization",
  "path_analysis": {
    "path_length": 3,
    "confidence": 0.9,
    "intermediate_steps": 1,
    "complexity": "medium"
  },
  "intermediate_nodes": [
    {
      "line": 10,
      "function": "process_data",
      "operation": "assignment"
    }
  ]
}
```

## Summary Object

The summary provides overall analysis statistics:

- **`files_analyzed`** (Number): Number of files processed
- **`functions_found`** (Number): Total functions discovered
- **`tainted_variables`** (Number): Variables involved in taint flows
- **`sources_found`** (Number): Total data sources identified
- **`sinks_found`** (Number): Total data sinks identified
- **`vulnerabilities_found`** (Number): Total vulnerabilities detected
- **`imports`** (Object): Import statistics
- **`call_chains`** (Object): Call chain statistics

### Import Statistics

- **`total_imports`** (Number): Total import statements
- **`unique_stdlib_modules`** (Number): Unique standard library modules
- **`unique_third_party_modules`** (Number): Unique third-party modules
- **`unique_functions`** (Number): Unique imported functions
- **`unique_classes`** (Number): Unique imported classes
- **`stdlib_modules`** (Array): List of standard library modules
- **`third_party_modules`** (Array): List of third-party modules
- **`imported_functions`** (Array): List of imported functions
- **`imported_classes`** (Array): List of imported classes

### Call Chain Statistics

- **`total_paths`** (Number): Total number of data flow paths
- **`average_path_length`** (Number): Average length of flow paths
- **`high_confidence_paths`** (Number): Number of high-confidence paths
- **`complex_paths`** (Number): Number of complex paths
- **`tracked_variables`** (Number): Variables tracked in flows
- **`tracked_functions`** (Number): Functions involved in flows
- **`data_flow_edges`** (Number): Total data flow connections

## Imports Object

Per-file import information:

- **`<file_path>`** (Object): Import details for each analyzed file
  - **`total_imports`** (Number): Total imports in this file
  - **`unique_modules`** (Number): Unique modules imported
  - **`standard_library_modules`** (Array): Standard library modules used
  - **`third_party_modules`** (Array): Third-party modules used
  - **`imported_functions`** (Array): Functions imported
  - **`imported_classes`** (Array): Classes imported
  - **`detailed_imports`** (Array): Detailed import information

### Detailed Import Information

Each detailed import entry contains:

- **`type`** (String): Import type ("import", "from_import")
- **`module`** (String): Module name
- **`imported_name`** (String|null): Specific imported name
- **`alias`** (String|null): Import alias
- **`line`** (Number): Line number of import
- **`col`** (Number): Column number of import
- **`is_stdlib`** (Boolean): Whether it's a standard library module
- **`root_module`** (String): Root module name

## Complete Example

```json
{
  "vulnerabilities": [
    {
      "type": "UnsafeDeserialization",
      "severity": "High",
      "detection_method": "taint_flow",
      "sink": {
        "name": "PickleDeserialization",
        "line": 15,
        "file": "example.py",
        "function_name": "load_data",
        "full_name": "pickle.loads"
      },
      "argument": "user_data",
      "argument_index": 0,
      "description": "Unsafe deserialization of user-controlled data",
      "recommendation": "Use safe serialization formats like JSON"
    }
  ],
  "call_chains": [
    {
      "id": 1,
      "source": {
        "type": "NetworkInput",
        "line": 5,
        "file": "example.py",
        "function": "handle_request"
      },
      "sink": {
        "type": "PickleDeserialization",
        "line": 15,
        "file": "example.py",
        "function": "load_data",
        "full_name": "pickle.loads"
      },
      "tainted_variable": "user_data",
      "vulnerability_type": "UnsafeDeserialization",
      "flow_description": "Network input flows to pickle deserialization",
      "path_analysis": {
        "path_length": 2,
        "confidence": 0.95,
        "intermediate_steps": 0,
        "complexity": "low"
      },
      "intermediate_nodes": []
    }
  ],
  "summary": {
    "files_analyzed": 1,
    "functions_found": 3,
    "tainted_variables": 1,
    "sources_found": 1,
    "sinks_found": 1,
    "vulnerabilities_found": 1,
    "imports": {
      "total_imports": 3,
      "unique_stdlib_modules": 2,
      "unique_third_party_modules": 1,
      "stdlib_modules": ["pickle", "json"],
      "third_party_modules": ["requests"]
    },
    "call_chains": {
      "total_paths": 1,
      "average_path_length": 2.0,
      "high_confidence_paths": 1,
      "complex_paths": 0
    }
  },
  "imports": {
    "example.py": {
      "total_imports": 3,
      "unique_modules": 3,
      "standard_library_modules": ["pickle", "json"],
      "third_party_modules": ["requests"],
      "detailed_imports": [
        {
          "type": "import",
          "module": "pickle",
          "imported_name": null,
          "alias": null,
          "line": 1,
          "col": 0,
          "is_stdlib": true,
          "root_module": "pickle"
        }
      ]
    }
  }
}
```
