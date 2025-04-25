"""
Enhanced taint tracker implementation.
"""

import ast
import os
import traceback
import re
from typing import Any, Dict, List, Tuple, Set, Optional

from lanalyzer.analysis.ast_parser import ParentNodeVisitor

from .visitor import EnhancedTaintAnalysisVisitor


class EnhancedTaintTracker:
    """
    Enhanced taint tracker with advanced analysis capabilities.
    """

    def __init__(self, config: Dict[str, Any], debug: bool = False):
        """
        Initialize the enhanced taint tracker.

        Args:
            config: Configuration dictionary
            debug: Whether to enable debug output
        """
        self.config = config
        self.sources = config["sources"]
        self.sinks = config["sinks"]
        self.debug = debug
        self.analyzed_files = set()

        # Global tracking across multiple files
        self.all_functions = {}  # name -> CallGraphNode
        self.all_tainted_vars = {}  # name -> source_info
        self.global_call_graph = {}  # func_name -> list of called funcs

        # Track cross-module imports
        self.module_map = {}  # module_name -> file_path

    def analyze_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Analyze a file for taint vulnerabilities with enhanced tracking.

        Args:
            file_path: Path to the file to analyze

        Returns:
            List of enhanced vulnerability dictionaries
        """

        if not os.path.exists(file_path):
            if self.debug:
                print(f"❌ Error: File not found: {file_path}")
            return []

        if not file_path.endswith(".py"):
            if self.debug:
                print(f"⚠️ Skipping non-Python file: {file_path}")
            return []

        # Mark file as analyzed
        self.analyzed_files.add(file_path)

        if self.debug:
            print(f"\n🔍 Starting analysis of file: {file_path}")

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                code = f.read()
                # 存储当前文件内容，用于上下文显示
                self.current_file_contents = code

            # Parse the AST
            try:
                tree = ast.parse(code, filename=file_path)
            except SyntaxError as e:
                if self.debug:
                    print(f"Syntax error in {file_path}: {e}")
                return []

            # Add parent references to nodes
            parent_visitor = ParentNodeVisitor()
            parent_visitor.visit(tree)

            # Visit the AST with enhanced visitor
            visitor = EnhancedTaintAnalysisVisitor(
                parent_map=parent_visitor.parent_map,
                debug=self.debug,
                verbose=False,
                file_path=file_path,
            )
            # Set sources and sinks from the tracker
            visitor.sources = self.sources
            visitor.sinks = self.sinks
            visitor.visit(tree)

            # Update global call graph
            for func_name, func_node in visitor.functions.items():
                if func_name in self.all_functions:
                    # Merge information if function was seen before
                    existing = self.all_functions[func_name]
                    if func_node.ast_node:  # Prefer node with AST definition
                        existing.ast_node = func_node.ast_node
                        existing.file_path = func_node.file_path
                        existing.line_no = func_node.line_no

                    # Merge callers and callees
                    for caller in func_node.callers:
                        existing.add_caller(caller)
                    for callee in func_node.callees:
                        existing.add_callee(callee)

                    # Update tainted parameters and return status
                    existing.tainted_parameters.update(func_node.tainted_parameters)
                    existing.return_tainted = (
                        existing.return_tainted or func_node.return_tainted
                    )
                    existing.return_taint_sources.extend(func_node.return_taint_sources)
                else:
                    # Add new function to global tracking
                    self.all_functions[func_name] = func_node

            # Update global call graph relationships
            for func_name, func_node in visitor.functions.items():
                if func_name not in self.global_call_graph:
                    self.global_call_graph[func_name] = []

                for callee in func_node.callees:
                    if callee.name not in self.global_call_graph[func_name]:
                        self.global_call_graph[func_name].append(callee.name)

            # Find vulnerabilities with enhanced tracking
            vulnerabilities = self._find_enhanced_vulnerabilities(visitor, file_path)

            # Keep track of reported sink lines from full flows
            reported_sink_lines = {
                vuln.get("sink", {}).get("line", -1) for vuln in vulnerabilities
            }

            # Add new detection logic: treat standalone sinks as potential vulnerabilities
            if hasattr(visitor, "found_sinks") and visitor.found_sinks:
                if self.debug:
                    print(f"Found {len(visitor.found_sinks)} potential sinks")
                    # Check the source_lines attribute
                    if hasattr(visitor, "source_lines") and visitor.source_lines:
                        print(
                            f"✓ Visitor has source_lines attribute with {len(visitor.source_lines)} lines of source code"
                        )
                    else:
                        print(
                            "✗ Visitor does not have source_lines attribute or it is empty"
                        )

                for sink_info in visitor.found_sinks:
                    # Create a serializable copy of sink_info, removing the AST node
                    serializable_sink = {}
                    for key, value in sink_info.items():
                        if key != "node":  # Skip AST node
                            serializable_sink[key] = value

                    # Continue processing with the serializable sink_info
                    sink_line = serializable_sink.get("line", 0)

                    # Check if this sink has already been reported in a full flow
                    if sink_line in reported_sink_lines:
                        continue  # Skip if already reported via a full taint flow

                    # If this sink hasn't been reported, create a new vulnerability record
                    # (This block is reached only if the sink wasn't part of a full flow)
                    # Create a default "Unknown Source" source
                    unknown_source = {
                        "name": "UnknownSource",
                        "line": 0,
                        "col": 0,
                        "context": "auto_detected",
                        "description": "Automatically detected unknown source",
                    }

                    # Attempt to build a partial call chain based on sink location
                    partial_call_chain = self._build_partial_call_chain_for_sink(
                        visitor, serializable_sink
                    )

                    # Create vulnerability record
                    sink_vulnerability = {
                        "file": file_path,
                        "rule": f"Potential{serializable_sink.get('vulnerability_type', serializable_sink.get('name', 'Unknown'))}",
                        "source": unknown_source,
                        "sink": serializable_sink,  # Use the serializable version
                        "tainted_variable": "Unknown",
                        "severity": "Medium",  # Default to medium severity
                        "confidence": "Low",  # Confidence is low due to uncertain source
                        "description": f"Potential dangerous operation point {serializable_sink.get('name', 'Unknown')} found, but data source could not be determined",
                        "auto_detected": True,  # Mark as auto-detected vulnerability
                        "propagation_path": [],  # No propagation path (as source is unknown)
                        "call_chain": partial_call_chain,  # Use the generated partial chain
                    }

                    # Add extra sink-related info if available
                    if "tainted_args" in serializable_sink:
                        sink_vulnerability["tainted_arguments"] = serializable_sink[
                            "tainted_args"
                        ]

                    vulnerabilities.append(sink_vulnerability)
                    reported_sink_lines.add(sink_line)  # Mark as reported

                    if self.debug:
                        print(
                            f"Auto-detected potential vulnerability: {serializable_sink.get('name', 'Unknown')} at line {sink_line}"
                        )

            if self.debug:
                print(f"Enhanced analysis complete for {file_path}")
                print(
                    f"Found {len(vulnerabilities)} vulnerabilities with enhanced tracking"
                )
                print(
                    f"Tracked {len(visitor.def_use_chains)} variables with def-use chains"
                )
                print(
                    f"Identified {len(visitor.data_structures)} complex data structures"
                )

            self.visitor = visitor  # This line of code may be missing or misplaced in the original implementation
            return vulnerabilities

        except Exception as e:
            if self.debug:
                print(f"Error in enhanced analysis for {file_path}: {e}")
                traceback.print_exc()
            return []

    def _find_enhanced_vulnerabilities(
        self, visitor: EnhancedTaintAnalysisVisitor, file_path: str
    ) -> List[Dict[str, Any]]:
        """
        Find vulnerabilities using enhanced tracking information.

        Args:
            visitor: EnhancedTaintAnalysisVisitor instance
            file_path: Path to the analyzed file

        Returns:
            List of enhanced vulnerability dictionaries
        """
        vulnerabilities = []

        for sink in visitor.found_sinks:
            for tainted_arg in sink.get("tainted_args", []):
                arg_name, source_info = tainted_arg

                # Find matching rule
                for rule in self.config.get("rules", []):
                    source_name = source_info["name"]
                    sink_name = sink["name"]

                    if self._source_matches_rule(
                        source_name, rule
                    ) and self._sink_matches_rule(sink_name, rule):
                        # Get taint propagation chain for this vulnerability
                        propagation_chain = []
                        if isinstance(arg_name, str):
                            # Handle direct call arguments
                            if arg_name.startswith("direct_call_"):
                                # For direct call arguments, create a basic propagation chain
                                propagation_chain = [
                                    {
                                        "step_no": 1,
                                        "operation": "DirectCall",
                                        "description": f"Direct call from source to sink at line {sink.get('line', 0)}",
                                        "line": sink.get("line", 0),
                                        "var_name": arg_name,
                                    }
                                ]
                            else:
                                # For named arguments, get full propagation chain
                                if "=" in arg_name:
                                    # Handle keyword arguments
                                    parts = arg_name.split("=")
                                    arg_base_name = parts[0]
                                    value_name = parts[1]

                                    # Get chain for the value
                                    if value_name in visitor.variable_taint:
                                        propagation_chain = (
                                            visitor.get_taint_propagation_chain(
                                                value_name
                                            )
                                        )
                                        # Add parameter binding step
                                        propagation_chain.append(
                                            {
                                                "step_no": len(propagation_chain) + 1,
                                                "operation": "ParameterBinding",
                                                "description": f"Value '{value_name}' bound to parameter '{arg_base_name}' at line {sink.get('line', 0)}",
                                                "line": sink.get("line", 0),
                                                "var_name": arg_name,
                                            }
                                        )
                                    # Check data structures too
                                    elif value_name in visitor.data_structures:
                                        ds_chain = visitor.data_structures[
                                            value_name
                                        ].get_propagation_chain()
                                        propagation_chain.extend(ds_chain)
                                        # Add parameter binding step
                                        propagation_chain.append(
                                            {
                                                "step_no": len(propagation_chain) + 1,
                                                "operation": "DataStructureBinding",
                                                "description": f"Data structure '{value_name}' bound to parameter '{arg_base_name}' at line {sink.get('line', 0)}",
                                                "line": sink.get("line", 0),
                                                "var_name": arg_name,
                                            }
                                        )
                                else:
                                    # Regular variable
                                    arg_base_name = arg_name
                                    propagation_chain = (
                                        visitor.get_taint_propagation_chain(
                                            arg_base_name
                                        )
                                    )

                                    # Check for data structures as well
                                    if (
                                        arg_base_name in visitor.data_structures
                                        and not propagation_chain
                                    ):
                                        ds_chain = visitor.data_structures[
                                            arg_base_name
                                        ].get_propagation_chain()
                                        propagation_chain.extend(ds_chain)

                        # Get detailed call chain
                        call_chain = self._get_detailed_call_chain(
                            sink, visitor, source_info
                        )

                        # Format message with the actual source name
                        message = rule.get(
                            "message",
                            f"Tainted data from {source_name} flows to {sink_name}",
                        )
                        message = message.replace("{source}", source_name)

                        # Add a final step in the propagation chain showing sink usage
                        if propagation_chain:
                            propagation_chain.append(
                                {
                                    "step_no": len(propagation_chain) + 1,
                                    "operation": "SinkUsage",
                                    "description": f"Tainted data flows to {sink_name} sink at line {sink.get('line', 0)}",
                                    "line": sink.get("line", 0),
                                    "var_name": arg_name,
                                }
                            )

                        # Build enhanced vulnerability info
                        vulnerability = {
                            "rule": rule.get("name", "UnnamedRule"),
                            "message": message,
                            "file": file_path,
                            "source": {
                                "name": source_name,
                                "line": source_info.get("line", 0),
                                "col": source_info.get("col", 0),
                            },
                            "sink": {
                                "name": sink_name,
                                "line": sink.get("line", 0),
                                "col": sink.get("col", 0),
                            },
                            "tainted_variable": arg_name,
                            "propagation_chain": propagation_chain,
                            "call_chain": call_chain,
                        }

                        vulnerabilities.append(vulnerability)

        return vulnerabilities

    def _source_matches_rule(self, source_name: str, rule: Dict[str, Any]) -> bool:
        """
        Check if a source matches a rule.

        Args:
            source_name: Name of the source
            rule: Rule dictionary

        Returns:
            True if the source matches the rule, False otherwise
        """
        sources = rule.get("sources", [])
        return source_name in sources or "any" in sources

    def _sink_matches_rule(self, sink_name: str, rule: Dict[str, Any]) -> bool:
        """
        Check if a sink matches a rule.

        Args:
            sink_name: Name of the sink
            rule: Rule dictionary

        Returns:
            True if the sink matches the rule, False otherwise
        """
        sinks = rule.get("sinks", [])
        return sink_name in sinks or "any" in sinks

    def _get_detailed_call_chain(
        self,
        sink: Dict[str, Any],
        visitor: EnhancedTaintAnalysisVisitor,
        source_info: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        Get the detailed function call chain from source to sink.

        Args:
            sink: Sink dictionary
            visitor: EnhancedTaintAnalysisVisitor instance
            source_info: Source information dictionary

        Returns:
            List of dictionaries containing detailed function call chain information
        """
        call_chain = []
        source_line = source_info.get("line", 0)
        sink_line = sink.get("line", 0)
        source_name = source_info.get("name", "Unknown")
        sink_name = sink.get("name", "Unknown")

        if self.debug:
            print(
                f"Building call chain from source {source_name}(line {source_line}) to sink {sink_name}(line {sink_line})"
            )

        # 1. Find function containing the source
        source_func = None
        for func_name, func_node in visitor.functions.items():
            if func_node.line_no <= source_line <= func_node.end_line_no:
                source_func = func_node
                break

        # 2. Find function containing the sink
        sink_func = None
        for func_name, func_node in visitor.functions.items():
            if func_node.line_no <= sink_line <= func_node.end_line_no:
                sink_func = func_node
                break

        if self.debug:
            if source_func:
                print(
                    f"Found source function: {source_func.name} (lines {source_func.line_no}-{source_func.end_line_no})"
                )
            else:
                print(f"Could not find function containing source (line {source_line})")

            if sink_func:
                print(
                    f"Found sink function: {sink_func.name} (lines {sink_func.line_no}-{sink_func.end_line_no})"
                )
            else:
                print(f"Could not find function containing sink (line {sink_line})")

        # Get actual statement text for source and sink
        source_stmt_info = self._get_statement_at_line(
            visitor, source_line, context_lines=1
        )
        sink_stmt_info = self._get_statement_at_line(
            visitor, sink_line, context_lines=1
        )

        # 3. First add the specific sink statement with detailed information
        sink_operation = self._extract_operation_at_line(visitor, sink_line)
        if sink_operation:
            sink_stmt = {
                "function": sink_operation,
                "file": visitor.file_path,
                "line": sink_line,
                "statement": sink_stmt_info["statement"],
                "context_lines": [sink_line - 1, sink_line + 1],
                "type": "sink",
                "description": f"Unsafe {sink_name} operation, potentially leading to vulnerability",
            }
            call_chain.append(sink_stmt)

        # 4. Next add the specific source statement with detailed information
        source_operation = self._extract_operation_at_line(visitor, source_line)
        if source_operation:
            source_stmt = {
                "function": source_operation,
                "file": visitor.file_path,
                "line": source_line,
                "statement": source_stmt_info["statement"],
                "context_lines": [source_line - 1, source_line + 1],
                "type": "source",
                "description": f"Source of tainted data ({source_name})",
            }
            call_chain.append(source_stmt)

        # 5. If source and sink are in the same function, return detailed info
        if source_func and sink_func and source_func.name == sink_func.name:
            func_info = {
                "function": source_func.name,
                "file": source_func.file_path,
                "line": source_func.line_no,
                "statement": f"function {source_func.name}",
                "context_lines": [source_func.line_no, source_func.end_line_no],
                "type": "source+sink",
                "description": f"Contains both source {source_name}(line {source_line}) and sink {sink_name}(line {sink_line})",
            }
            call_chain.append(func_info)
            return call_chain

        # 6. Build the complete call chain from source to sink
        if source_func and sink_func:
            # Use Breadth-First Search (BFS) to find the path from source function to sink function
            queue = [(source_func, [source_func])]  # (current_node, path)
            visited = {source_func.name}
            max_depth = 20  # Prevent overly deep search
            found_path = None

            while queue and not found_path:
                current, path = queue.pop(0)

                # Check callees of the current node
                for callee in current.callees:
                    if callee.name == sink_func.name:
                        # Path found
                        found_path = path + [sink_func]
                        break

                    if callee.name not in visited and len(path) < max_depth:
                        visited.add(callee.name)
                        queue.append((callee, path + [callee]))

            # If path found, build the call chain with function and statement info
            if found_path:
                for i, func in enumerate(found_path):
                    # Determine node type
                    node_type = "intermediate"
                    description = "Intermediate function in the call chain"

                    if i == 0:
                        node_type = "source"
                        description = (
                            f"Contains source {source_name} at line {source_line}"
                        )
                    elif i == len(found_path) - 1:
                        node_type = "sink"
                        description = f"Contains sink {sink_name} at line {sink_line}"

                    # Find a representative line number for this function where it's called
                    line_num = func.line_no

                    # Try to find the actual call statement if this is an intermediate function
                    call_statement = ""

                    if i > 0 and i < len(found_path) - 1:
                        # This is an intermediate function - try to find where it's called
                        prev_func = found_path[i - 1]
                        for callee in prev_func.callees:
                            if callee.name == func.name and hasattr(
                                callee, "call_line"
                            ):
                                line_num = callee.call_line
                                call_statement = self._get_statement_at_line(
                                    visitor, line_num
                                )["statement"]
                                break

                    func_info = {
                        "function": func.name,
                        "file": func.file_path,
                        "line": line_num,
                        "statement": call_statement
                        if call_statement
                        else f"function {func.name}()",
                        "context_lines": [func.line_no, func.end_line_no],
                        "type": node_type,
                        "description": description,
                    }
                    call_chain.append(func_info)

                return call_chain

            # If direct path not found, try finding common callers...
            if not found_path and self.debug:
                print("No direct path found, trying to find common callers...")

            # Build reverse call graph (from callee to caller)
            reverse_call_graph = {}
            for func_name, func_node in visitor.functions.items():
                reverse_call_graph[func_name] = []

            for func_name, func_node in visitor.functions.items():
                for callee in func_node.callees:
                    if callee.name not in reverse_call_graph:
                        reverse_call_graph[callee.name] = []
                    reverse_call_graph[callee.name].append(func_name)

            # Use BFS to find common callers of source and sink functions
            source_callers = self._find_callers(
                source_func.name, reverse_call_graph, max_depth
            )
            sink_callers = self._find_callers(
                sink_func.name, reverse_call_graph, max_depth
            )

            common_callers = source_callers.intersection(sink_callers)

            if common_callers and self.debug:
                print(f"Found common callers: {common_callers}")

            # If common callers found, build path
            if common_callers:
                # Select a common caller
                common_caller = next(iter(common_callers))
                common_caller_node = None

                for func_name, func_node in visitor.functions.items():
                    if func_name == common_caller:
                        common_caller_node = func_node
                        break

                if common_caller_node:
                    # Try to extract call statements for both source and sink functions
                    source_call_stmt = ""
                    sink_call_stmt = ""

                    for callee in common_caller_node.callees:
                        if callee.name == source_func.name and hasattr(
                            callee, "call_line"
                        ):
                            source_call_stmt = self._get_statement_at_line(
                                visitor, callee.call_line
                            )["statement"]
                        elif callee.name == sink_func.name and hasattr(
                            callee, "call_line"
                        ):
                            sink_call_stmt = self._get_statement_at_line(
                                visitor, callee.call_line
                            )["statement"]

                    # Source function -> Common caller -> Sink function
                    call_chain = [
                        {
                            "function": source_func.name,
                            "file": source_func.file_path,
                            "line": source_func.line_no,
                            "statement": source_stmt_info["statement"],
                            "context_lines": [
                                source_func.line_no,
                                source_func.end_line_no,
                            ],
                            "type": "source",
                            "description": f"Contains source {source_name} at line {source_line}",
                        },
                        {
                            "function": common_caller_node.name,
                            "file": common_caller_node.file_path,
                            "line": common_caller_node.line_no,
                            "statement": f"function {common_caller_node.name}()",
                            "context_lines": [
                                common_caller_node.line_no,
                                common_caller_node.end_line_no,
                            ],
                            "type": "intermediate",
                            "description": "Common caller of source and sink functions",
                            "calls": [
                                {
                                    "function": source_func.name,
                                    "statement": source_call_stmt,
                                },
                                {
                                    "function": sink_func.name,
                                    "statement": sink_call_stmt,
                                },
                            ],
                        },
                        {
                            "function": sink_func.name,
                            "file": sink_func.file_path,
                            "line": sink_func.line_no,
                            "statement": sink_stmt_info["statement"],
                            "context_lines": [sink_func.line_no, sink_func.end_line_no],
                            "type": "sink",
                            "description": f"Contains sink {sink_name} at line {sink_line}",
                        },
                    ]
                    return call_chain

        # 7. If full call chain cannot be built, but source or sink function exists, add them
        if source_func:
            source_func_info = {
                "function": source_func.name,
                "file": source_func.file_path,
                "line": source_func.line_no,
                "statement": source_stmt_info["statement"],
                "context_lines": [source_func.line_no, source_func.end_line_no],
                "type": "source",
                "description": f"Contains source {source_name} at line {source_line}",
            }
            call_chain.append(source_func_info)

        if sink_func:
            sink_func_info = {
                "function": sink_func.name,
                "file": sink_func.file_path,
                "line": sink_func.line_no,
                "statement": sink_stmt_info["statement"],
                "context_lines": [sink_func.line_no, sink_func.end_line_no],
                "type": "sink",
                "description": f"Contains sink {sink_name} at line {sink_line}",
            }
            call_chain.append(sink_func_info)

        return call_chain

    def _find_callers(
        self, func_name: str, reverse_call_graph: Dict[str, List[str]], max_depth: int
    ) -> Set[str]:
        """
        Use BFS to find all functions that call the specified function.

        Args:
            func_name: Name of the function to find callers for
            reverse_call_graph: Reverse call graph
            max_depth: Maximum search depth

        Returns:
            Set of function names that call this function
        """
        callers = set()
        visited = {func_name}
        queue = [(func_name, 0)]  # (function_name, depth)

        while queue:
            current, depth = queue.pop(0)

            if depth >= max_depth:
                continue

            # Get all callers of the current function
            current_callers = reverse_call_graph.get(current, [])

            for caller in current_callers:
                callers.add(caller)

                if caller not in visited:
                    visited.add(caller)
                    queue.append((caller, depth + 1))

        return callers

    def analyze_multiple_files(self, file_paths: List[str]) -> List[Dict[str, Any]]:
        """
        Analyze multiple files with cross-file taint tracking.

        Args:
            file_paths: List of file paths to analyze

        Returns:
            List of vulnerability dictionaries across all files
        """
        all_vulnerabilities = []

        # First pass: analyze each file individually
        for file_path in file_paths:
            if self.debug:
                print(f"Analyzing {file_path}")
            vulnerabilities = self.analyze_file(file_path)
            all_vulnerabilities.extend(vulnerabilities)

        # Second pass: propagate taint across function calls
        if self.debug:
            print("Propagating taint across function calls...")
        self._propagate_taint_across_functions()

        # Third pass: re-analyze files with updated taint information
        additional_vulnerabilities = []
        for file_path in file_paths:
            if self.debug:
                print(f"Re-analyzing {file_path} with cross-function taint information")
            vulnerabilities = self.analyze_file(file_path)

            # Only add new vulnerabilities not in the original set
            for vuln in vulnerabilities:
                if vuln not in all_vulnerabilities:
                    additional_vulnerabilities.append(vuln)

        all_vulnerabilities.extend(additional_vulnerabilities)

        if self.debug:
            print(f"Total vulnerabilities found: {len(all_vulnerabilities)}")

        return all_vulnerabilities

    def _propagate_taint_across_functions(self) -> None:
        """
        Propagate taint information across function calls.
        """
        # Iteratively propagate taint until fixpoint
        changed = True
        iterations = 0
        max_iterations = 10  # Prevent infinite loops

        while changed and iterations < max_iterations:
            iterations += 1
            changed = False

            # For each function that returns tainted data
            for func_name, func_node in self.all_functions.items():
                if func_node.return_tainted:
                    # For each caller of this function
                    for caller in func_node.callers:
                        # Check if caller is not already marked as returning tainted data
                        if not caller.return_tainted:
                            caller.return_tainted = True
                            caller.return_taint_sources.extend(
                                func_node.return_taint_sources
                            )
                            changed = True
                            if self.debug:
                                print(
                                    f"Propagated taint from {func_name} to caller {caller.name}"
                                )

        if self.debug:
            if iterations == max_iterations:
                print(
                    f"Warning: Reached maximum iterations ({max_iterations}) in taint propagation"
                )
            else:
                print(f"Taint propagation converged after {iterations} iterations")

    def check_sink_patterns(self, file_path: str) -> List[Tuple[str, int]]:
        """
        Check for sink patterns in a file.

        Args:
            file_path: Path to the file to check

        Returns:
            List of (pattern, line_number) tuples for sink patterns found
        """
        if not os.path.exists(file_path) or not file_path.endswith(".py"):
            return []

        sink_patterns = []
        for sink in self.sinks:
            if "pattern" in sink:
                sink_patterns.append(sink["pattern"])

        if not sink_patterns:
            return []

        found_patterns = []
        try:
            with open(file_path, "r") as f:
                for i, line in enumerate(f, 1):
                    for pattern in sink_patterns:
                        if pattern in line:
                            found_patterns.append((pattern, i))
                            if self.debug:
                                print(
                                    f"Found sink pattern '{pattern}' in {file_path} at line {i}"
                                )
        except Exception as e:
            if self.debug:
                print(f"Error checking sink patterns in {file_path}: {e}")

        return found_patterns

    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the analysis.

        Returns:
            Dictionary with summary information
        """
        return {
            "files_analyzed": len(self.analyzed_files),
            "functions_analyzed": len(self.all_functions),
            "function_call_relationships": sum(
                len(callees) for callees in self.global_call_graph.values()
            ),
            "functions_returning_tainted_data": sum(
                1 for f in self.all_functions.values() if f.return_tainted
            ),
        }

    def get_detailed_summary(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Get a detailed summary of the analysis with statistics about propagation chains.

        Args:
            vulnerabilities: List of vulnerability dictionaries

        Returns:
            Dictionary with detailed summary information
        """
        # Basic summary
        summary = self.get_summary()

        # Propagation statistics
        total_prop_steps = 0
        max_prop_steps = 0
        min_prop_steps = float("inf")
        vuln_with_prop = 0

        # Call chain statistics
        total_call_steps = 0
        max_call_steps = 0
        min_call_steps = float("inf")
        vuln_with_calls = 0

        # Source-sink statistics
        source_counts = {}
        sink_counts = {}
        source_sink_pairs = {}

        for vuln in vulnerabilities:
            # Count sources
            source_name = vuln.get("source", {}).get("name", "Unknown")
            source_counts[source_name] = source_counts.get(source_name, 0) + 1

            # Count sinks
            sink_name = vuln.get("sink", {}).get("name", "Unknown")
            sink_counts[sink_name] = sink_counts.get(sink_name, 0) + 1

            # Count source-sink pairs
            pair = f"{source_name} -> {sink_name}"
            source_sink_pairs[pair] = source_sink_pairs.get(pair, 0) + 1

            # Propagation statistics
            prop_chain = vuln.get("propagation_chain", [])
            if prop_chain:
                vuln_with_prop += 1
                steps = len(prop_chain)
                total_prop_steps += steps
                max_prop_steps = max(max_prop_steps, steps)
                min_prop_steps = min(min_prop_steps, steps)

            # Call chain statistics
            call_chain = vuln.get("call_chain", [])
            if call_chain:
                vuln_with_calls += 1
                steps = len(call_chain)
                total_call_steps += steps
                max_call_steps = max(max_call_steps, steps)
                min_call_steps = min(min_call_steps, steps)

        # Calculate averages
        avg_prop_steps = total_prop_steps / vuln_with_prop if vuln_with_prop > 0 else 0
        avg_call_steps = (
            total_call_steps / vuln_with_calls if vuln_with_calls > 0 else 0
        )

        # Add statistics to summary
        summary.update(
            {
                "vulnerabilities_found": len(vulnerabilities),
                "vulnerabilities_with_propagation": vuln_with_prop,
                "average_propagation_steps": round(avg_prop_steps, 2),
                "max_propagation_steps": max_prop_steps,
                "min_propagation_steps": min_prop_steps
                if min_prop_steps != float("inf")
                else 0,
                "vulnerabilities_with_call_chains": vuln_with_calls,
                "average_call_chain_length": round(avg_call_steps, 2),
                "max_call_chain_length": max_call_steps,
                "min_call_chain_length": min_call_steps
                if min_call_steps != float("inf")
                else 0,
                "source_counts": source_counts,
                "sink_counts": sink_counts,
                "source_sink_pairs": source_sink_pairs,
            }
        )

        return summary

    def print_detailed_vulnerability(self, vulnerability: Dict[str, Any]) -> None:
        """
        Print a detailed vulnerability report with enhanced call chain information.

        Args:
            vulnerability: The vulnerability dictionary
        """
        print("\n" + "=" * 80)
        print(f"VULNERABILITY REPORT: {vulnerability.get('rule', 'Unknown Rule')}")
        print("=" * 80)

        # Print file info
        file_path = vulnerability.get("file", "Unknown file")
        print(f"File: {file_path}")

        # Print source info
        source = vulnerability.get("source", {})
        source_name = source.get("name", "Unknown")
        source_line = source.get("line", 0)
        print(f"Source: {source_name} at line {source_line}")

        # Print sink info
        sink = vulnerability.get("sink", {})
        sink_name = sink.get("name", "Unknown")
        sink_line = sink.get("line", 0)
        print(f"Sink: {sink_name} at line {sink_line}")

        # Print tainted variable
        tainted_var = vulnerability.get("tainted_variable", "Unknown")
        print(f"Tainted Variable: {tainted_var}")

        # Print severity and confidence
        severity = vulnerability.get("severity", "Unknown")
        confidence = vulnerability.get("confidence", "Unknown")
        print(f"Severity: {severity}")
        print(f"Confidence: {confidence}")

        # Print description
        description = vulnerability.get("description", "No description available")
        print(f"\nDescription: {description}")

        # Print enhanced call chain information
        call_chain = vulnerability.get("call_chain", [])
        if call_chain:
            print("\nCall Chain:")
            for i, call_item in enumerate(call_chain):
                # 增强的调用链显示
                call_type = call_item.get("type", "unknown")
                call_func = call_item.get("function", "Unknown")
                call_line = call_item.get("line", 0)
                call_file = call_item.get("file", "Unknown")

                # 使用彩色输出区分不同类型的调用链节点
                type_colors = {
                    "source": "\033[92m",  # 绿色
                    "sink": "\033[91m",  # 红色
                    "intermediate": "\033[94m",  # 蓝色
                    "source+sink": "\033[93m",  # 黄色
                    "sink_container": "\033[95m",  # 紫色
                    "related_path": "\033[96m",  # 青色
                }
                color = type_colors.get(call_type, "\033[0m")
                reset = "\033[0m"

                # 打印带颜色的标题行
                title = f"{color}[{i+1}] {call_type.upper()}: {call_func} @ {os.path.basename(call_file)}:{call_line}{reset}"
                print(f"\n  {title}")

                # 打印语句（如果有）
                if "statement" in call_item:
                    statement = call_item["statement"]
                    print(f"      Statement: {statement}")

                # 打印上下文行（如果有）
                if "context_lines" in call_item and call_item["context_lines"]:
                    context_start, context_end = call_item["context_lines"]
                    print(f"      Context: Lines {context_start}-{context_end}")

                    # 如果有源代码，尝试显示上下文代码
                    if (
                        hasattr(self, "current_file_contents")
                        and self.current_file_contents
                    ):
                        # 在当前文件内容中提取上下文
                        try:
                            context_lines = self.current_file_contents.splitlines()[
                                context_start - 1 : context_end
                            ]
                            if context_lines:
                                print("      Code:")
                                for i, line in enumerate(context_lines, context_start):
                                    # 高亮当前行
                                    if i == call_line:
                                        print(f"      > {i}: {line}")
                                    else:
                                        print(f"        {i}: {line}")
                        except Exception as e:
                            if self.debug:
                                print(f"Error displaying context: {str(e)}")

                # 打印描述
                description = call_item.get("description", "")
                if description:
                    print(f"      Description: {description}")

                # 打印调用信息（如果有）
                if "calls" in call_item:
                    print("      Calls:")
                    for call in call_item["calls"]:
                        func_name = call.get("function", "unknown")
                        statement = call.get("statement", "")
                        print(f"        -> {func_name}: {statement}")

        # Print propagation path
        propagation_path = vulnerability.get("propagation_path", [])
        if propagation_path:
            print("\nPropagation Path:")
            for step in propagation_path:
                print(f"  {step}")

        print("=" * 80 + "\n")

    def _build_partial_call_chain_for_sink(
        self, visitor: EnhancedTaintAnalysisVisitor, sink_info: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Build a more complete call chain, providing rich calling context even without an explicit source.
        This is used for auto-detected vulnerabilities where the full data source path cannot be determined.

        Args:
            visitor: Visitor instance containing analysis results
            sink_info: Sink information dictionary

        Returns:
            List of dictionaries representing the call chain
        """
        call_chain = []
        # 用于去重的集合
        added_sources = set()  # 记录已添加的源点，格式为 "line:statement"

        sink_line = sink_info.get("line", 0)
        sink_name = sink_info.get("name", "Unknown Sink")
        vulnerability_type = sink_info.get(
            "vulnerability_type", f"{sink_name} Vulnerability"
        )

        if self.debug:
            print(
                f"[DEBUG] Building call chain for sink '{sink_name}' (line {sink_line})"
            )

        if not sink_line:
            if self.debug:
                print("[DEBUG] Sink line number is 0 or missing")
            return []

        # Step 1: Get the exact statement at the sink line
        sink_stmt_info = self._get_statement_at_line(
            visitor, sink_line, context_lines=2
        )

        # Step 2: Find the direct sink operation (the actual dangerous call)
        sink_operation = self._extract_operation_at_line(visitor, sink_line)
        sink_entry = None
        if sink_operation:
            # If direct operation is found, create sink entry (but don't add to chain yet)
            sink_entry = {
                "function": sink_operation,
                "file": visitor.file_path,
                "line": sink_line,
                "statement": sink_stmt_info["statement"],
                "context_lines": [sink_line - 2, sink_line + 2]
                if sink_line > 2
                else [1, sink_line + 2],
                "type": "sink",
                "description": f"Unsafe {sink_name} operation, potentially leading to {vulnerability_type}",
            }

        # Step 3: Find function containing the sink
        sink_function_node = self._find_function_containing_line(visitor, sink_line)

        # 记录汇聚点所在的函数范围，用于优先在同一函数内查找源点
        sink_function_range = None
        if sink_function_node:
            sink_function_range = (
                sink_function_node.line_no,
                sink_function_node.end_line_no,
            )

        # 创建容器函数信息，但先不添加到调用链
        sink_container_entry = None
        if sink_function_node:
            file_path = getattr(sink_function_node, "file_path", visitor.file_path)

            # Find where this function is defined (to provide context)
            func_def_start = sink_function_node.line_no
            func_def_end = getattr(
                sink_function_node, "end_line_no", func_def_start + 1
            )

            # Try to get the function definition statement
            func_def_stmt = ""
            if (
                hasattr(visitor, "source_lines")
                and visitor.source_lines
                and func_def_start > 0
                and func_def_start <= len(visitor.source_lines)
            ):
                func_def_stmt = visitor.source_lines[func_def_start - 1].strip()

            sink_container_entry = {
                "function": sink_function_node.name,
                "file": file_path,
                "line": sink_function_node.line_no,
                "statement": func_def_stmt
                if func_def_stmt
                else f"function {sink_function_node.name}",
                "context_lines": [func_def_start, func_def_end],
                "type": "sink_container",
                "description": f"Function containing sink {sink_name}, at line {sink_line}",
            }

        # Step 4: Try to find tainted variables used in the sink
        tainted_vars_in_sink = self._find_tainted_vars_in_sink(visitor, sink_line)

        # 按函数内/函数外分类源点
        same_function_sources = []  # 同函数内的源点
        other_sources = []  # 其他函数的源点
        parser_sources = []  # 命令行参数源点

        # Step 5: If we found tainted variables, try to find their source statements
        if (
            tainted_vars_in_sink
            and hasattr(visitor, "tainted")
            and hasattr(visitor, "source_statements")
        ):
            for var_name in tainted_vars_in_sink:
                # 检查变量是否被污染以及是否有源点信息
                if var_name in visitor.tainted:
                    source_info = visitor.tainted.get(var_name)
                    if source_info and "line" in source_info:
                        source_line = source_info.get("line", 0)
                        source_name = source_info.get("name", "Unknown")

                        # 获取源语句的详细信息
                        if source_line > 0:
                            source_stmt_info = self._get_statement_at_line(
                                visitor, source_line, context_lines=1
                            )
                            source_operation = self._extract_operation_at_line(
                                visitor, source_line
                            )

                            # 创建源语句信息
                            source_stmt = {
                                "function": source_operation or f"Source of {var_name}",
                                "file": visitor.file_path,
                                "line": source_line,
                                "statement": source_info.get(
                                    "statement", source_stmt_info["statement"]
                                ),
                                "context_lines": [source_line - 1, source_line + 1],
                                "type": "source",
                                "description": f"Source of tainted data ({source_name}) assigned to variable {var_name}",
                            }

                            # 去重处理
                            source_key = f"{source_line}:{source_stmt['statement']}"
                            if source_key not in added_sources:
                                added_sources.add(source_key)

                                # 判断源点是否在同一函数内
                                if (
                                    sink_function_range
                                    and sink_function_range[0]
                                    <= source_line
                                    <= sink_function_range[1]
                                ):
                                    same_function_sources.append(source_stmt)
                                else:
                                    other_sources.append(source_stmt)

                            if self.debug:
                                print(
                                    f"[DEBUG] Added source statement for var {var_name} at line {source_line}"
                                )

        # 步骤 6: 搜索函数内可能的源语句，优先考虑同一函数内的源
        found_source_in_function = len(same_function_sources) > 0
        if (
            not found_source_in_function
            and sink_function_node
            and hasattr(visitor, "source_lines")
        ):
            # 从配置文件中收集所有源模式，优先处理高优先级源（如NetworkInput）
            source_patterns = []
            high_priority_patterns = []

            for source_config in self.sources:
                patterns = source_config.get("patterns", [])
                source_name = source_config.get("name", "UnknownSource")
                priority = source_config.get("priority", "normal")

                # 将高优先级的源模式单独收集
                if priority == "high":
                    for pattern in patterns:
                        high_priority_patterns.append((pattern, source_name))
                else:
                    for pattern in patterns:
                        source_patterns.append((pattern, source_name))

            # 优先级排序：先检查高优先级模式
            all_sorted_patterns = high_priority_patterns + source_patterns

            # 在函数内搜索可能的源语句
            if sink_function_range:
                start_line, end_line = sink_function_range
                # 创建一个源语句列表
                potential_sources = []

                # 在函数内搜索可能的源语句
                for line_idx in range(
                    start_line, min(end_line, len(visitor.source_lines))
                ):
                    if line_idx == sink_line:
                        continue  # 跳过汇聚点所在行

                    line = (
                        visitor.source_lines[line_idx - 1]
                        if line_idx > 0 and line_idx <= len(visitor.source_lines)
                        else ""
                    )
                    if not line:
                        continue

                    # 检查是否含有配置文件中定义的源模式
                    for pattern, source_name in all_sorted_patterns:
                        # 将星号通配符转换为正则表达式
                        if "*" in pattern:
                            pattern_regex = pattern.replace(".", "\\.").replace(
                                "*", ".*"
                            )
                            pattern_match = re.search(pattern_regex, line)
                            matches = bool(pattern_match)
                        else:
                            matches = pattern in line

                        if matches:
                            # 检查是否是变量赋值模式
                            if "=" in line and line.index("=") < line.find(pattern):
                                var_name = line.split("=")[0].strip()
                                # 检查sink语句是否使用该变量
                                sink_stmt = sink_stmt_info["statement"]
                                if var_name in sink_stmt:
                                    potential_sources.append(
                                        {
                                            "line": line_idx,
                                            "statement": line.strip(),
                                            "var": var_name,
                                            "in_same_function": True,
                                            "source_name": source_name,
                                            "pattern": pattern,
                                        }
                                    )
                                    break  # 找到一个匹配就跳出内循环

                # 如果在同一函数内找到了源，添加到调用链
                if potential_sources:
                    # 按行号排序，优先选择距离sink最近但在sink之前的源
                    potential_sources.sort(
                        key=lambda x: sink_line - x["line"]
                        if x["line"] < sink_line
                        else float("inf")
                    )
                    for src in potential_sources:
                        if src["line"] < sink_line:  # 优先选择在sink之前的源
                            source_stmt = {
                                "function": f"{src['var']} = {src['statement'].split('=')[1].strip()}"
                                if "=" in src["statement"]
                                else src["statement"],
                                "file": visitor.file_path,
                                "line": src["line"],
                                "statement": src["statement"],
                                "context_lines": [src["line"] - 1, src["line"] + 1],
                                "type": "source",
                                "description": f"Source of tainted data ({src['source_name']}) assigned to variable {src['var']}",
                            }

                            # 去重处理
                            source_key = f"{src['line']}:{source_stmt['statement']}"
                            if source_key not in added_sources:
                                added_sources.add(source_key)
                                same_function_sources.append(source_stmt)
                                found_source_in_function = True
                                if self.debug:
                                    print(
                                        f"[DEBUG] Found source using pattern '{src['pattern']}' at line {src['line']}"
                                    )

        # 步骤 7: 如果在同一函数内没有找到源，则搜索所有潜在的源点
        if not found_source_in_function and hasattr(visitor, "var_assignments"):
            potential_sources = []

            # 从配置文件中获取源类型和模式
            source_type_patterns = {}
            for source_config in self.sources:
                source_name = source_config.get("name", "UnknownSource")
                patterns = source_config.get("patterns", [])
                for pattern in patterns:
                    source_type_patterns[pattern] = source_name

            # 遍历所有赋值语句，查找可能的源点
            for var_name, assign_info in visitor.var_assignments.items():
                if "line" in assign_info:
                    # 如果已经找到过这一行的源，跳过
                    line_no = assign_info["line"]
                    if any(
                        source["line"] == line_no
                        for source in same_function_sources + other_sources
                    ):
                        continue

                    stmt = self._get_statement_at_line(visitor, line_no)["statement"]

                    # 检查是否匹配任何配置文件中的源模式
                    matched_source_type = None
                    matched_pattern = None

                    for pattern, source_type in source_type_patterns.items():
                        # 处理通配符
                        if "*" in pattern:
                            pattern_regex = pattern.replace(".", "\\.").replace(
                                "*", ".*"
                            )
                            if re.search(pattern_regex, stmt):
                                matched_source_type = source_type
                                matched_pattern = pattern
                                break
                        elif pattern in stmt:
                            matched_source_type = source_type
                            matched_pattern = pattern
                            break

                    if matched_source_type:
                        # 判断是否在同一个函数内
                        in_same_function = False
                        if (
                            sink_function_range
                            and sink_function_range[0]
                            <= line_no
                            <= sink_function_range[1]
                        ):
                            in_same_function = True

                        is_command_line = "CommandLineArgs" in matched_source_type

                        potential_sources.append(
                            {
                                "var": var_name,
                                "line": line_no,
                                "statement": stmt,
                                "in_same_function": in_same_function,
                                "is_parser": is_command_line,
                                "source_name": matched_source_type,
                                "pattern": matched_pattern,
                            }
                        )

            # 添加潜在源，优先选择同一函数内的源
            if potential_sources:
                # 首先按是否在同一函数内排序，然后按行号接近sink排序
                potential_sources.sort(
                    key=lambda x: (
                        not x.get("in_same_function", False),
                        abs(x["line"] - sink_line),
                    )
                )

                # 将潜在源分类
                for src in potential_sources:
                    # 去重处理
                    source_key = f"{src['line']}:{src['statement']}"
                    if source_key in added_sources:
                        continue

                    source_stmt = {
                        "function": f"{src['var'] if 'var' in src else ''} = {src['statement'].split('=')[1].strip()}"
                        if "=" in src["statement"]
                        else src["statement"],
                        "file": visitor.file_path,
                        "line": src["line"],
                        "statement": src["statement"],
                        "context_lines": [src["line"] - 1, src["line"] + 1],
                        "type": "source",
                        "description": f"Source of tainted data ({src.get('source_name', 'Unknown')}) assigned to variable {src['var']}",
                    }

                    added_sources.add(source_key)

                    if src.get("is_parser", False):
                        parser_sources.append(source_stmt)
                    elif src.get("in_same_function", False):
                        same_function_sources.append(source_stmt)
                    else:
                        other_sources.append(source_stmt)

                    if self.debug:
                        print(
                            f"[DEBUG] Found source using pattern '{src.get('pattern', 'unknown')}' at line {src['line']}"
                        )

        # 构建最终调用链，按照优先级顺序
        final_call_chain = []

        # 1. 同一函数内的源点（最高优先级）
        for entry in same_function_sources:
            final_call_chain.append(entry)

        # 2. 命令行参数源点
        for entry in parser_sources:
            final_call_chain.append(entry)

        # 3. 其他函数中的源点（仅当同函数内无源点时添加）
        if not same_function_sources:
            for entry in other_sources:
                final_call_chain.append(entry)

        # 4. 容器函数
        if sink_container_entry:
            final_call_chain.append(sink_container_entry)

        # 5. 汇聚点
        if sink_entry:
            final_call_chain.append(sink_entry)

        # 对于同类型的源点，按照行号排序
        if len(same_function_sources) > 1:
            # 对同函数内源点按距离汇聚点的位置排序（近→远）
            same_function_sources_sorted = sorted(
                same_function_sources, key=lambda x: abs(x["line"] - sink_line)
            )

            # 清除原来添加的同函数内源点
            final_call_chain = [
                e for e in final_call_chain if e not in same_function_sources
            ]

            # 将排序后的同函数内源点插入到调用链最前面
            for entry in reversed(same_function_sources_sorted):
                final_call_chain.insert(0, entry)

        if self.debug:
            print(f"[DEBUG] Built call chain with {len(final_call_chain)} nodes")
            source_count = len([e for e in final_call_chain if e["type"] == "source"])
            print(f"[DEBUG] Sources in call chain: {source_count}")

        return final_call_chain

    def _find_tainted_vars_in_sink(
        self, visitor: EnhancedTaintAnalysisVisitor, sink_line: int
    ) -> List[str]:
        """
        查找在sink语句中使用的污点变量

        Args:
            visitor: 访问者实例
            sink_line: sink语句所在行号

        Returns:
            包含在sink中使用的污点变量名的列表
        """
        tainted_vars = []

        # 检查visitor是否有源代码行
        if not hasattr(visitor, "source_lines") or not visitor.source_lines:
            return tainted_vars

        # 获取sink行的源代码
        if sink_line <= 0 or sink_line > len(visitor.source_lines):
            return tainted_vars

        sink_code = visitor.source_lines[sink_line - 1]

        # 提取变量名
        if hasattr(visitor, "tainted"):
            # 检查每个污点变量是否在sink代码中使用
            for var_name in visitor.tainted:
                # 变量名前后必须有非字母数字字符或行首尾，以避免部分匹配
                # 例如，避免将"a"匹配到"abc"中
                import re

                pattern = r"(^|[^\w])" + re.escape(var_name) + r"([^\w]|$)"
                if re.search(pattern, sink_code):
                    tainted_vars.append(var_name)
                    if self.debug:
                        print(
                            f"[DEBUG] Found tainted variable {var_name} used in sink at line {sink_line}"
                        )

        return tainted_vars

    def _find_function_containing_line(
        self, visitor: EnhancedTaintAnalysisVisitor, line: int
    ) -> Optional[Any]:
        """
        Find the function node containing the specified line.

        Args:
            visitor: Visitor instance
            line: Line number

        Returns:
            The function node containing the line, or None if not found
        """
        for func_name, func_node in visitor.functions.items():
            # Ensure the node has necessary attributes
            if not hasattr(func_node, "line_no") or not hasattr(
                func_node, "end_line_no"
            ):
                continue

            # Check if the line number is valid
            if not isinstance(func_node.line_no, int) or not isinstance(
                func_node.end_line_no, int
            ):
                continue

            # Check if the line is within the function's range
            if func_node.line_no <= line <= func_node.end_line_no:
                return func_node

        return None

    def _extract_operation_at_line(
        self, visitor: EnhancedTaintAnalysisVisitor, line: int
    ) -> Optional[str]:
        """
        Attempt to extract the actual operation name for the specified line.

        Args:
            visitor: Visitor instance
            line: Line number

        Returns:
            Operation name, or None if not found
        """
        # Check if raw source code is available
        if not hasattr(visitor, "source_lines") or not visitor.source_lines:
            if self.debug:
                print(
                    f"[Warning] Visitor lacks source_lines attribute or it is empty, cannot extract operation for line {line}"
                )
            return None

        # Ensure line number is within valid range
        if line <= 0 or line > len(visitor.source_lines):
            if self.debug:
                print(
                    f"[Warning] Line number {line} is out of range (1-{len(visitor.source_lines)})"
                )
            return None

        # Get line content
        line_content = visitor.source_lines[line - 1].strip()

        # More detailed extraction of the operation by checking full statement
        if "=" in line_content:
            # Handle assignment cases: extract the right side of the assignment
            operation = line_content.split("=", 1)[1].strip()
        else:
            # For non-assignment statements, use the full statement
            operation = line_content

        # Clean up the operation string
        # Remove trailing semicolons, comments, etc.
        operation = re.sub(r"[;].*$", "", operation)
        operation = re.sub(r"#.*$", "", operation)
        operation = operation.strip()

        # Common dangerous function name patterns
        dangerous_patterns = {
            "PickleDeserialization": [
                "pickle.loads",
                "pickle.load",
                "cPickle.loads",
                "cPickle.load",
            ],
            "CommandExecution": [
                "os.system",
                "subprocess.run",
                "subprocess.Popen",
                "exec(",
                "eval(",
            ],
            "SQLInjection": [
                "execute(",
                "executemany(",
                "cursor.execute",
                "raw_connection",
            ],
            "PathTraversal": ["open(", "os.path.join", "os.makedirs", "os.listdir"],
            "XSS": ["render_template", "render", "html"],
        }

        # Attempt to find matching dangerous patterns
        sink_type = None
        matched_pattern = None

        for sink_name, patterns in dangerous_patterns.items():
            for pattern in patterns:
                if pattern in operation:
                    sink_type = sink_name
                    matched_pattern = pattern
                    break
            if sink_type:
                break

        if sink_type and matched_pattern:
            # Return the exact operation instead of just the pattern
            return operation

        # If no dangerous pattern found but operation is not empty, return the operation
        if operation:
            return operation

        return None

    def _get_statement_at_line(
        self, visitor: EnhancedTaintAnalysisVisitor, line: int, context_lines: int = 0
    ) -> Dict[str, Any]:
        """
        Extract the statement at the given line with optional context lines.

        Args:
            visitor: The visitor instance
            line: The line number to extract
            context_lines: Number of lines of context to include before and after

        Returns:
            Dictionary with statement text and context information
        """
        if not hasattr(visitor, "source_lines") or not visitor.source_lines:
            return {"statement": "", "context_start": line, "context_end": line}

        if line <= 0 or line > len(visitor.source_lines):
            return {"statement": "", "context_start": line, "context_end": line}

        # Extract main statement
        statement = visitor.source_lines[line - 1].strip()

        # Determine context range
        start_line = max(1, line - context_lines)
        end_line = min(len(visitor.source_lines), line + context_lines)

        # Extract context if requested
        context = []
        if context_lines > 0:
            for i in range(start_line, end_line + 1):
                if i == line:
                    # Mark the actual statement line (could be used for highlighting)
                    context.append(f"{i}: {visitor.source_lines[i-1].rstrip()}")
                else:
                    context.append(f"{i}: {visitor.source_lines[i-1].rstrip()}")

        return {
            "statement": statement,
            "context_lines": context if context_lines > 0 else None,
            "context_start": start_line,
            "context_end": end_line,
        }

    def _find_related_functions(
        self, visitor: EnhancedTaintAnalysisVisitor, sink_name: str
    ) -> List[Any]:
        """
        Find functions related to the given sink.

        Args:
            visitor: Visitor instance
            sink_name: Sink name

        Returns:
            List of related function nodes
        """
        related_functions = []

        # 1. Use sink definitions from the config file to find related function patterns
        related_patterns = []

        # Find patterns related to sink_name in the config file
        for sink in self.sinks:
            if sink.get("name") == sink_name:
                # 首先查看是否有专门的related_patterns字段
                if "related_patterns" in sink:
                    related_patterns.extend(sink.get("related_patterns", []))
                    if self.debug:
                        print(
                            f"Found related_patterns in config for {sink_name}: {related_patterns}"
                        )

                # 否则，从patterns提取关键词
                for pattern in sink.get("patterns", []):
                    # Extract the base function name part from the pattern
                    if "." in pattern:
                        func_part = pattern.split(".")[-1]
                        related_patterns.append(func_part)
                    elif "(" in pattern:
                        func_part = pattern.split("(")[0]
                        related_patterns.append(func_part)
                    else:
                        related_patterns.append(pattern)
                break

        # If no related patterns found in config, use the sink name itself as a basis
        if not related_patterns:
            # Use words from sink_name as search patterns
            words = re.findall(r"[A-Za-z]+", sink_name)
            for word in words:
                if (
                    len(word) > 3
                ):  # Only use longer words to avoid mismatches from short words
                    related_patterns.append(word.lower())

            if self.debug:
                print(
                    f"No patterns found in config for {sink_name}, using words: {related_patterns}"
                )

        # 2. Find similar functions through AST analysis
        # First, find functions similar to the pattern names
        for func_name, func_node in visitor.functions.items():
            for pattern in related_patterns:
                # Check if function name contains pattern (case-insensitive)
                if pattern.lower() in func_name.lower():
                    if self.debug:
                        print(
                            f"Found related function {func_name} matching pattern {pattern}"
                        )
                    related_functions.append(func_node)
                    break

        # 3. Find functions that call similar functions
        call_related_functions = []
        for func_node in list(
            related_functions
        ):  # Use a copy to avoid modifying while iterating
            # Find other functions that call the current function
            for caller in func_node.callers:
                if (
                    caller not in related_functions
                    and caller not in call_related_functions
                ):
                    call_related_functions.append(caller)

        # Merge directly related functions and call-relation related functions
        related_functions.extend(call_related_functions)

        # 4. Limit the number of returned results to avoid excessive length
        return related_functions[:5]
