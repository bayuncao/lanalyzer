"""
Simplified taint analysis visitor.

This module consolidates all visitor functionality into a single, comprehensive class
that replaces the complex mixin-based approach.
"""

import ast
from typing import Any, Dict, List, Optional

from lanalyzer.logger import debug

from ..flow.call_chain_tracker import CallChainTracker
from ..import_tracker import ImportTracker
from ..source_sink_classifier import SourceSinkClassifier
from .ast_processor import ASTProcessor


class TaintAnalysisVisitor(ast.NodeVisitor):
    """
    Comprehensive taint analysis visitor that combines all functionality.

    This class replaces the complex mixin-based visitor pattern with a single,
    unified implementation that handles:
    - Source and sink detection
    - Taint propagation
    - Function call tracking
    - Data structure analysis
    - Control flow analysis
    """

    def __init__(
        self,
        parent_map: Optional[Dict[ast.AST, ast.AST]] = None,
        debug_mode: bool = False,
        verbose: bool = False,
        file_path: Optional[str] = None,
        source_lines: Optional[List[str]] = None,
    ):
        """
        Initialize the taint analysis visitor.

        Args:
            parent_map: Dictionary mapping AST nodes to their parents
            debug_mode: Whether to enable debug output
            verbose: Whether to enable verbose output
            file_path: Path to the file being analyzed
            source_lines: List of source code lines
        """
        super().__init__()

        # Basic configuration
        self.parent_map = parent_map or {}
        self.debug = debug_mode
        self.verbose = verbose
        self.file_path = file_path
        self.source_lines = source_lines

        # AST processor for utility functions
        self.ast_processor = ASTProcessor(debug_mode)

        # Analysis results
        self.found_sources: List[Dict[str, Any]] = []
        self.found_sinks: List[Dict[str, Any]] = []
        self.found_vulnerabilities: List[Dict[str, Any]] = []

        # Taint tracking
        self.tainted: Dict[str, Any] = {}
        self.variable_taint: Dict[str, Any] = {}
        self.source_statements: Dict[str, Any] = {}

        # Function and call tracking
        self.functions: Dict[str, Any] = {}
        self.current_function: Optional[Any] = None
        self.call_locations: List[Any] = []
        self.var_assignments: Dict[str, List[Dict[str, Any]]] = {}

        # Cross-function analysis for parameter tracking
        self.function_calls_with_tainted_args: Dict[str, List[Dict[str, Any]]] = {}
        self.function_definitions: Dict[str, Dict[str, Any]] = {}
        self.pending_parameter_taints: List[Dict[str, Any]] = []

        # Data structure tracking
        self.data_structures: Dict[str, Any] = {}

        # Control flow tracking
        self.def_use_chains: Dict[str, Any] = {}
        self.path_constraints: List[Any] = []

        # Path-sensitive analysis
        self.path_analyzer: Optional[Any] = None
        self.current_path_node: Optional[Any] = None
        self.path_sensitive_enabled: bool = False

        # Import and classification handling
        self.import_tracker = ImportTracker(debug_mode=self.debug)
        self.import_aliases = self.import_tracker.import_aliases
        self.from_imports = self.import_tracker.from_imports
        self.direct_imports = self.import_tracker.direct_imports

        # Source/Sink classifier
        self.classifier = SourceSinkClassifier(self)

        # Call chain tracker for enhanced taint analysis
        self.call_chain_tracker = CallChainTracker(file_path, debug=debug_mode)

    def enable_path_sensitive_analysis(self, enable: bool = True) -> None:
        """
        Enable or disable path-sensitive analysis.

        Args:
            enable: Whether to enable path-sensitive analysis
        """
        self.path_sensitive_enabled = enable
        if enable and self.path_analyzer is None:
            # Import here to avoid circular imports
            from ..models.path import PathSensitiveAnalyzer

            self.path_analyzer = PathSensitiveAnalyzer(debug=self.debug)

    def visit_Module(self, node: ast.Module) -> None:
        """Visit module node and initialize path-sensitive analysis if enabled."""
        if self.debug:
            debug(
                f"\n========== Starting analysis of file: {self.file_path} ==========\n"
            )

        # Initialize path-sensitive analysis if enabled
        if self.path_sensitive_enabled and self.path_analyzer:
            # Initialize path analysis with the module as root
            self.current_path_node = self.path_analyzer.initialize_analysis(node)
            if self.debug:
                debug("[VISITOR] Initialized path-sensitive analysis")

        self.generic_visit(node)

        if self.debug:
            debug(
                f"\n========== Finished analysis of file: {self.file_path} =========="
            )
            debug(f"Found {len(self.found_sinks)} sinks")
            debug(f"Found {len(self.found_sources)} sources")

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit a function definition node."""
        if self.debug:
            debug(f"[VISITOR] Enter function: {node.name}")

        # Create function node representation
        func_info = {
            "name": node.name,
            "node": node,
            "line": getattr(node, "lineno", 0),
            "args": [arg.arg for arg in node.args.args],
            "is_async": False,
        }

        self.functions[node.name] = func_info
        # Store function definition for cross-function analysis
        self.function_definitions[node.name] = func_info

        previous_function = self.current_function
        self.current_function = func_info

        # Check if this function has pending parameter taints from previous calls
        self._apply_pending_parameter_taints(node.name)

        # Apply reverse inference: analyze sinks in this function to infer parameter sources
        self._apply_reverse_inference(node.name, func_info)

        # Visit function body
        self.generic_visit(node)

        # Restore previous function context
        self.current_function = previous_function

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Visit an async function definition node."""
        if self.debug:
            debug(f"[VISITOR] Enter async function: {node.name}")

        # Create function node representation
        func_info = {
            "name": node.name,
            "node": node,
            "line": getattr(node, "lineno", 0),
            "args": [arg.arg for arg in node.args.args],
            "is_async": True,
        }

        self.functions[node.name] = func_info
        # Store function definition for cross-function analysis
        self.function_definitions[node.name] = func_info

        previous_function = self.current_function
        self.current_function = func_info

        # Check if this function has pending parameter taints from previous calls
        self._apply_pending_parameter_taints(node.name)

        # Apply reverse inference: analyze sinks in this function to infer parameter sources
        self._apply_reverse_inference(node.name, func_info)

        # Visit function body
        self.generic_visit(node)

        # Restore previous function context
        self.current_function = previous_function

    def visit_Call(self, node: ast.Call) -> None:
        """Visit a function call node with enhanced error handling."""
        try:
            func_name, full_name = self.ast_processor.get_func_name_with_module(
                node.func
            )
            line_no = getattr(node, "lineno", 0)
            col_offset = getattr(node, "col_offset", 0)
        except Exception as e:
            if self.debug:
                debug(f"[VISITOR] Error processing call node: {e}")
            self.generic_visit(node)
            return

        if self.debug:
            current_func_name = (
                getattr(self.current_function, "name", "GlobalScope")
                if self.current_function
                else "GlobalScope"
            )
            debug(
                f"[VISITOR] Call to {func_name} (full: {full_name}) at line {line_no} in {current_func_name}"
            )

        # Track function calls
        call_info = {
            "name": func_name,
            "full_name": full_name,
            "line": line_no,
            "col": col_offset,
            "node": node,
            "function": self.current_function,
        }
        self.call_locations.append(call_info)

        # Check for data flow patterns (like in-place modification)
        if func_name:
            self._check_data_flow_patterns(
                node, func_name, full_name, line_no, col_offset
            )

        # Check for sources
        if func_name and self._is_source(func_name, full_name):
            self._handle_source(node, func_name, full_name, line_no, col_offset)

        # Check for sinks
        if func_name and self._is_sink(func_name, full_name):
            self._handle_sink(node, func_name, full_name, line_no, col_offset)

        # Cross-function analysis: track calls with tainted arguments
        if func_name:
            self._track_function_call_with_tainted_args(
                node, func_name, full_name, line_no, col_offset
            )

        # Continue visiting child nodes with error handling
        try:
            self.generic_visit(node)
        except Exception as e:
            if self.debug:
                debug(f"[VISITOR] Error in generic_visit for Call node: {e}")

    def visit_Await(self, node: ast.Await) -> None:
        """Visit an await expression."""
        if self.debug:
            debug(f"[VISITOR] Await expression at line {getattr(node, 'lineno', 0)}")

        # Check if the awaited expression is tainted
        if hasattr(node, "value") and isinstance(node.value, ast.Call):
            # This is await func_call()
            func_name, full_name = self.ast_processor.get_func_name_with_module(
                node.value.func
            )
            line_no = getattr(node, "lineno", 0)
            col_offset = getattr(node, "col_offset", 0)

            # Track as async call
            call_info = {
                "name": func_name,
                "full_name": full_name,
                "line": line_no,
                "col": col_offset,
                "node": node.value,
                "function": self.current_function,
                "is_async": True,
            }
            self.call_locations.append(call_info)

            # Check for sources and sinks in async calls
            if func_name and self._is_source(func_name, full_name):
                self._handle_source(
                    node.value, func_name, full_name, line_no, col_offset
                )

            if func_name and self._is_sink(func_name, full_name):
                self._handle_sink(node.value, func_name, full_name, line_no, col_offset)

        # Continue visiting child nodes
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        """Visit a subscript node (e.g., sys.argv[1])."""
        # Check if this is accessing a source like sys.argv
        if isinstance(node.value, ast.Attribute):
            attr_name = self._get_attribute_name(node.value)
            if attr_name and self._is_source_attribute(attr_name):
                line_no = getattr(node, "lineno", 0)
                col_offset = getattr(node, "col_offset", 0)

                if self.debug:
                    debug(
                        f"[VISITOR] Found source attribute access: {attr_name} at line {line_no}"
                    )

                # Create source info
                source_type = self.classifier.source_type("", attr_name)
                source_info = {
                    "name": source_type,
                    "line": line_no,
                    "col": col_offset,
                    "node": node,
                }

                self.found_sources.append(source_info)

                # Track taint propagation for subscript access
                self._track_subscript_taint(node, source_info)

        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        """Visit an attribute node (e.g., os.environ)."""
        attr_name = self._get_attribute_name(node)
        if attr_name and self._is_source_attribute(attr_name):
            line_no = getattr(node, "lineno", 0)
            col_offset = getattr(node, "col_offset", 0)

            if self.debug:
                debug(
                    f"[VISITOR] Found source attribute: {attr_name} at line {line_no}"
                )

            # Create source info
            source_type = self.classifier.source_type("", attr_name)
            source_info = {
                "name": source_type,
                "line": line_no,
                "col": col_offset,
                "node": node,
            }

            self.found_sources.append(source_info)

            # Track taint propagation for attribute access
            self._track_attribute_taint(node, source_info)

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Visit an assignment node to track variable assignments."""
        line_no = getattr(node, "lineno", 0)

        # Track variable assignments for data flow analysis
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id

                # Initialize assignment tracking for this variable
                if var_name not in self.var_assignments:
                    self.var_assignments[var_name] = []

                # Get statement text
                statement = ""
                if self.source_lines and 1 <= line_no <= len(self.source_lines):
                    statement = self.source_lines[line_no - 1].strip()

                assignment_info = {
                    "line": line_no,
                    "statement": statement,
                    "node": node,
                    "target": target,
                    "value": node.value,
                }

                self.var_assignments[var_name].append(assignment_info)

                # Check if assigned value is tainted
                if isinstance(node.value, ast.Name) and node.value.id in self.tainted:
                    self.tainted[var_name] = self.tainted[node.value.id]
                    if self.debug:
                        debug(
                            f"[VISITOR] Propagated taint from {node.value.id} to {var_name}"
                        )
                else:
                    # Check for taint in complex expressions
                    taint_info = self._check_expression_taint(node.value)
                    if taint_info:
                        self.tainted[var_name] = taint_info
                        if self.debug:
                            debug(
                                f"[VISITOR] Marked variable {var_name} as tainted from complex expression"
                            )

        self.generic_visit(node)

    def _is_source(self, func_name: str, full_name: Optional[str] = None) -> bool:
        """Check if function is a taint source."""
        return self.classifier.is_source(func_name, full_name)

    def _is_sink(self, func_name: str, full_name: Optional[str] = None) -> bool:
        """Check if function is a taint sink."""
        return self.classifier.is_sink(func_name, full_name)

    def _handle_source(
        self,
        node: ast.Call,
        func_name: str,
        full_name: Optional[str],
        line_no: int,
        col_offset: int,
    ) -> None:
        """Handle detection of a taint source."""
        source_type = self.classifier.source_type(func_name, full_name)

        source_info = {
            "name": source_type,
            "line": line_no,
            "col": col_offset,
            "node": node,
        }

        self.found_sources.append(source_info)

        if self.debug:
            debug(f"[VISITOR] Found source: {source_type} at line {line_no}")

        # Track source in call chain
        source_node = self.call_chain_tracker.track_source(node, source_info)

        # Track taint propagation
        self._track_assignment_taint(node, source_info, source_node)

    def _handle_sink(
        self,
        node: ast.Call,
        func_name: str,
        full_name: Optional[str],
        line_no: int,
        col_offset: int,
    ) -> None:
        """Handle detection of a taint sink."""
        sink_type = self.classifier.sink_type(func_name, full_name)
        vulnerability_type = self.classifier.sink_vulnerability_type(sink_type)

        sink_info = {
            "name": sink_type,
            "line": line_no,
            "col": col_offset,
            "node": node,
            "vulnerability_type": vulnerability_type,
            "function_name": func_name,
            "full_name": full_name,
        }

        self.found_sinks.append(sink_info)

        if self.debug:
            debug(f"[VISITOR] Found sink: {sink_type} at line {line_no}")

        # Track sink in call chain
        sink_node = self.call_chain_tracker.track_sink(node, sink_info)

        # Always report sink as potential vulnerability (sink-first approach)
        self._report_sink_vulnerability(node, sink_type, sink_info)

        # Also check sink arguments for tainted data (traditional approach)
        self._check_sink_args(node, sink_type, sink_info, sink_node)

    def _track_assignment_taint(
        self, node: ast.Call, source_info: Dict[str, Any], source_node=None
    ) -> None:
        """Track taint propagation from source assignments."""
        # Find the assignment target if this call is part of an assignment
        parent = self.parent_map.get(node)
        if isinstance(parent, ast.Assign):
            for target in parent.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    self.tainted[var_name] = source_info

                    # Track assignment in call chain
                    if source_node:
                        self.call_chain_tracker.track_assignment(
                            var_name,
                            getattr(parent, "lineno", 0),
                            getattr(parent, "col_offset", 0),
                            source_node,
                        )

                    if self.debug:
                        debug(
                            f"[VISITOR] Marked variable {var_name} as tainted from {source_info['name']}"
                        )

    def _check_sink_args(
        self, node: ast.Call, sink_type: str, sink_info: Dict[str, Any], sink_node=None
    ) -> None:
        """Check sink arguments for tainted data."""
        if self.debug:
            debug(
                f"[VISITOR] Checking sink args for {sink_type} at line {sink_info.get('line', 0)}"
            )

        for i, arg in enumerate(node.args):
            taint_info = None
            tainted_var = None

            if self.debug:
                debug(f"[VISITOR] Checking arg {i}: {type(arg).__name__}")

            if isinstance(arg, ast.Name) and arg.id in self.tainted:
                # Simple variable reference
                taint_info = self.tainted[arg.id]
                tainted_var = arg.id
                if self.debug:
                    debug(f"[VISITOR] Found tainted variable: {arg.id}")
            else:
                # Complex expression - check for taint
                taint_info = self._check_expression_taint(arg)
                if taint_info:
                    tainted_var = self._describe_argument(arg)
                    if self.debug:
                        debug(
                            f"[VISITOR] Found tainted complex expression: {tainted_var}"
                        )
                elif self.debug:
                    debug("[VISITOR] No taint found in complex expression")

            if taint_info:
                # Check path reachability if path-sensitive analysis is enabled
                is_reachable = True
                if self.path_sensitive_enabled and self.current_path_node:
                    is_reachable = self.current_path_node.is_reachable()
                    if self.debug:
                        debug(
                            f"[VISITOR] Path reachability check: {is_reachable} for sink at line {sink_info.get('line', 0)}"
                        )

                # Only report vulnerability if path is reachable
                if is_reachable:
                    # Found tainted data flowing to sink
                    vulnerability = {
                        "source": taint_info,
                        "sink": sink_info,
                        "tainted_var": tainted_var,
                        "arg_index": i,
                        "path_reachable": is_reachable,
                    }

                    # Add path constraint information if available
                    if self.path_sensitive_enabled and self.current_path_node:
                        vulnerability[
                            "path_constraints"
                        ] = self.current_path_node.get_constraint_summary()

                    # Create detailed taint path if we have call chain tracking
                    if sink_node and hasattr(self, "call_chain_tracker"):
                        # Try to find the source node for this tainted variable
                        source_node = None

                        # First, check current chain for source nodes
                        source_nodes = [
                            node
                            for node in self.call_chain_tracker.current_chain
                            if node.node_type == "source"
                        ]
                        if source_nodes:
                            source_node = source_nodes[0]
                        else:
                            # If no source in current chain, create a source node from taint_info
                            if taint_info:
                                source_node = self.call_chain_tracker.create_source_node_from_taint(
                                    taint_info
                                )

                        if source_node:
                            taint_path = self.call_chain_tracker.create_taint_path(
                                source_node, sink_node, tainted_var
                            )
                            vulnerability["taint_path"] = taint_path

                            if self.debug:
                                debug(
                                    f"[VISITOR] Created taint path from {source_node.function_name} to {sink_node.function_name}"
                                )

                    self.found_vulnerabilities.append(vulnerability)
                elif self.debug:
                    debug(
                        f"[VISITOR] Filtered out unreachable vulnerability: {tainted_var} -> {sink_type}"
                    )

                if self.debug:
                    debug(
                        f"[VISITOR] Found vulnerability: {tainted_var} flows to {sink_type}"
                    )

    def _report_sink_vulnerability(
        self, node: ast.Call, sink_type: str, sink_info: Dict[str, Any]
    ) -> None:
        """Report a sink as a potential vulnerability (sink-first approach)."""
        # Create a vulnerability entry for the sink regardless of taint flow
        vulnerability = {
            "source": {
                "name": "PotentialSource",
                "line": sink_info.get("line", 0),
                "file": self.file_path,
            },
            "sink": sink_info,
            "tainted_var": "unknown",
            "arg_index": -1,
            "detection_type": "sink_only",  # Mark this as sink-only detection
        }

        # Check if any arguments might be from user input or external sources
        for i, arg in enumerate(node.args):
            arg_description = self._describe_argument(arg)
            if arg_description:
                vulnerability["tainted_var"] = arg_description
                vulnerability["arg_index"] = i
                break

        self.found_vulnerabilities.append(vulnerability)

        if self.debug:
            debug(
                f"[VISITOR] Reported sink-only vulnerability: {sink_type} at line {sink_info.get('line', 0)}"
            )

    def _describe_argument(self, arg: ast.expr) -> str:
        """Describe an argument for sink-only vulnerability reporting."""
        if isinstance(arg, ast.Name):
            return arg.id
        elif isinstance(arg, ast.Str):
            return f"string_literal: {arg.s[:50]}..."
        elif isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return f"string_literal: {arg.value[:50]}..."
        elif isinstance(arg, ast.Call):
            if hasattr(arg.func, "id"):
                return f"call_result: {arg.func.id}()"
            elif hasattr(arg.func, "attr"):
                return f"call_result: {arg.func.attr}()"
        elif isinstance(arg, ast.Attribute):
            return self._get_attribute_name(arg) or "attribute_access"
        elif isinstance(arg, ast.Subscript):
            if isinstance(arg.value, ast.Name):
                return f"{arg.value.id}[...]"
            elif isinstance(arg.value, ast.Attribute):
                attr_name = self._get_attribute_name(arg.value)
                return f"{attr_name}[...]" if attr_name else "subscript_access"

        return f"{type(arg).__name__.lower()}_expression"

    def _get_attribute_name(self, node: ast.Attribute) -> Optional[str]:
        """Get the full attribute name (e.g., 'sys.argv' from sys.argv)."""
        parts = []
        current = node

        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value

        if isinstance(current, ast.Name):
            parts.append(current.id)
            return ".".join(reversed(parts))

        return None

    def _is_source_attribute(self, attr_name: str) -> bool:
        """Check if an attribute name matches a source pattern."""
        return self.classifier.is_source("", attr_name)

    def _track_subscript_taint(
        self, node: ast.Subscript, source_info: Dict[str, Any]
    ) -> None:
        """Track taint propagation from subscript access."""
        # Find the assignment target if this subscript is part of an assignment
        parent = self.parent_map.get(node)
        if isinstance(parent, ast.Assign):
            for target in parent.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    self.tainted[var_name] = source_info
                    if self.debug:
                        debug(
                            f"[VISITOR] Marked variable {var_name} as tainted from subscript {source_info['name']}"
                        )

    def _track_attribute_taint(
        self, node: ast.Attribute, source_info: Dict[str, Any]
    ) -> None:
        """Track taint propagation from attribute access."""
        # Find the assignment target if this attribute is part of an assignment
        parent = self.parent_map.get(node)
        if isinstance(parent, ast.Assign):
            for target in parent.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    self.tainted[var_name] = source_info
                    if self.debug:
                        debug(
                            f"[VISITOR] Marked variable {var_name} as tainted from attribute {source_info['name']}"
                        )

    def _check_expression_taint(self, expr: ast.expr) -> Optional[Dict[str, Any]]:
        """Check if an expression contains tainted data."""
        if isinstance(expr, ast.Name):
            # Simple variable reference
            return self.tainted.get(expr.id)

        elif isinstance(expr, ast.Subscript):
            # Check if subscript access is from a tainted source
            if isinstance(expr.value, ast.Attribute):
                attr_name = self._get_attribute_name(expr.value)
                if attr_name and self._is_source_attribute(attr_name):
                    # This is a source like sys.argv[1]
                    source_type = self.classifier.source_type("", attr_name)
                    return {
                        "name": source_type,
                        "line": getattr(expr, "lineno", 0),
                        "col": getattr(expr, "col_offset", 0),
                        "node": expr,
                    }
            elif isinstance(expr.value, ast.Name):
                # Check if the base variable is tainted (e.g., buffer[i])
                base_taint = self.tainted.get(expr.value.id)
                if base_taint:
                    return base_taint
            # Check if the base value is tainted (recursive check)
            return self._check_expression_taint(expr.value)

        elif isinstance(expr, ast.Attribute):
            # Check if attribute access is from a source
            attr_name = self._get_attribute_name(expr)
            if attr_name and self._is_source_attribute(attr_name):
                source_type = self.classifier.source_type("", attr_name)
                return {
                    "name": source_type,
                    "line": getattr(expr, "lineno", 0),
                    "col": getattr(expr, "col_offset", 0),
                    "node": expr,
                }
            # Check if the base value is tainted (e.g., buffer.cpu() where buffer is tainted)
            base_taint = self._check_expression_taint(expr.value)
            if base_taint:
                return base_taint

        elif isinstance(expr, ast.Call):
            # Check if function call arguments are tainted
            # This handles cases like bytes(tainted_data)
            for arg in expr.args:
                arg_taint = self._check_expression_taint(arg)
                if arg_taint:
                    return arg_taint
            # Check if the function itself is tainted (e.g., tainted_func())
            func_taint = self._check_expression_taint(expr.func)
            if func_taint:
                return func_taint

        elif isinstance(expr, ast.IfExp):
            # Conditional expression: check both branches
            test_taint = self._check_expression_taint(expr.test)
            body_taint = self._check_expression_taint(expr.body)
            orelse_taint = self._check_expression_taint(expr.orelse)

            # If any part is tainted, the whole expression is tainted
            # Prioritize body and orelse over test
            return body_taint or orelse_taint or test_taint

        elif isinstance(expr, ast.BinOp):
            # Binary operation: check both operands
            left_taint = self._check_expression_taint(expr.left)
            right_taint = self._check_expression_taint(expr.right)
            return left_taint or right_taint

        elif isinstance(expr, ast.Call):
            # Function call: check if it's a source
            func_name, full_name = self.ast_processor.get_func_name_with_module(
                expr.func
            )
            if func_name and self._is_source(func_name, full_name):
                source_type = self.classifier.source_type(func_name, full_name)
                return {
                    "name": source_type,
                    "line": getattr(expr, "lineno", 0),
                    "col": getattr(expr, "col_offset", 0),
                    "node": expr,
                }
            # Check arguments for taint
            for arg in expr.args:
                arg_taint = self._check_expression_taint(arg)
                if arg_taint:
                    return arg_taint

        # For other expression types, return None (not tainted)
        return None

    # Import handling methods
    def visit_Import(self, node: ast.Import) -> None:
        """Handle import statements."""
        self.import_tracker.visit_Import(node)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Handle from-import statements."""
        self.import_tracker.visit_ImportFrom(node)
        self.generic_visit(node)

    # Cross-function analysis methods
    def _track_function_call_with_tainted_args(
        self,
        node: ast.Call,
        func_name: str,
        full_name: Optional[str],
        line_no: int,
        col_offset: int,
    ) -> None:
        """Track function calls that have tainted arguments for cross-function analysis."""
        tainted_args = []

        # Check each argument for taint
        for i, arg in enumerate(node.args):
            taint_info = self._check_expression_taint(arg)
            if taint_info:
                tainted_args.append(
                    {"index": i, "taint_info": taint_info, "arg_node": arg}
                )

        # If we found tainted arguments, record this call
        if tainted_args:
            call_info = {
                "function_name": func_name,
                "full_name": full_name,
                "line": line_no,
                "col": col_offset,
                "tainted_args": tainted_args,
                "call_node": node,
            }

            if func_name not in self.function_calls_with_tainted_args:
                self.function_calls_with_tainted_args[func_name] = []
            self.function_calls_with_tainted_args[func_name].append(call_info)

            if self.debug:
                debug(
                    f"[VISITOR] Tracked call to {func_name} with {len(tainted_args)} tainted arguments at line {line_no}"
                )

            # If we haven't seen the function definition yet, store as pending
            if func_name not in self.function_definitions:
                self.pending_parameter_taints.append(
                    {"function_name": func_name, "call_info": call_info}
                )
            else:
                # Apply parameter taints immediately
                self._apply_parameter_taints_for_function(func_name, call_info)

    def _apply_pending_parameter_taints(self, func_name: str) -> None:
        """Apply pending parameter taints when a function definition is encountered."""
        # Find and apply any pending taints for this function
        pending_to_remove = []
        for i, pending in enumerate(self.pending_parameter_taints):
            if pending["function_name"] == func_name:
                self._apply_parameter_taints_for_function(
                    func_name, pending["call_info"]
                )
                pending_to_remove.append(i)

        # Remove processed pending taints
        for i in reversed(pending_to_remove):
            del self.pending_parameter_taints[i]

    def _apply_parameter_taints_for_function(
        self, func_name: str, call_info: Dict[str, Any]
    ) -> None:
        """Apply parameter taints for a specific function call."""
        if func_name not in self.function_definitions:
            return

        func_def = self.function_definitions[func_name]
        param_names = func_def["args"]
        func_node = func_def["node"]

        # Apply taint to each tainted parameter
        for tainted_arg in call_info["tainted_args"]:
            param_index = tainted_arg["index"]
            if param_index < len(param_names):
                param_name = param_names[param_index]
                taint_info = tainted_arg["taint_info"]

                # Mark the parameter as tainted
                self.tainted[param_name] = taint_info

                if self.debug:
                    debug(
                        f"[VISITOR] Marked parameter {param_name} of function {func_name} as tainted from cross-function analysis"
                    )

        # Re-check all sinks in this function now that parameters are tainted
        self._recheck_sinks_in_function(func_node)

    def _recheck_sinks_in_function(self, func_node: ast.FunctionDef) -> None:
        """Re-check all sinks in a function after parameters have been tainted."""
        if self.debug:
            debug(
                f"[VISITOR] Re-checking sinks in function {func_node.name} after parameter tainting"
            )

        # Walk through the function body to find all Call nodes
        for node in ast.walk(func_node):
            if isinstance(node, ast.Call):
                func_name, full_name = self.ast_processor.get_func_name_with_module(
                    node.func
                )
                if func_name and self._is_sink(func_name, full_name):
                    line_no = getattr(node, "lineno", 0)
                    col_offset = getattr(node, "col_offset", 0)

                    # Check if any arguments are now tainted
                    for i, arg in enumerate(node.args):
                        taint_info = self._check_expression_taint(arg)
                        if taint_info:
                            if self.debug:
                                debug(
                                    f"[VISITOR] Found tainted argument in {func_name} at line {line_no} after cross-function analysis"
                                )

                            # Create a call chain for this tainted flow
                            self._create_call_chain_from_cross_function_analysis(
                                taint_info,
                                node,
                                func_name,
                                full_name,
                                line_no,
                                col_offset,
                                i,
                            )
                            break

    def _create_call_chain_from_cross_function_analysis(
        self,
        source_info: Dict[str, Any],
        sink_node: ast.Call,
        sink_func_name: str,
        sink_full_name: str,
        line_no: int,
        col_offset: int,
        arg_index: int,
    ) -> None:
        """Create a call chain from cross-function analysis."""
        # Create vulnerability info for this cross-function flow
        sink_type = self.classifier.sink_type(sink_func_name, sink_full_name)

        vulnerability = {
            "source": source_info,
            "sink": {
                "name": sink_type,
                "line": line_no,
                "col": col_offset,
                "node": sink_node,
                "function_name": sink_func_name,
                "full_name": sink_full_name,
                "vulnerability_type": "UnsafeDeserialization",
            },
            "tainted_var": self._describe_argument(sink_node.args[arg_index]),
            "arg_index": arg_index,
        }

        self.found_vulnerabilities.append(vulnerability)

        if self.debug:
            debug(
                f"[VISITOR] Created call chain from cross-function analysis: {source_info['name']} -> {sink_func_name}"
            )

    def _apply_reverse_inference(
        self, func_name: str, func_info: Dict[str, Any]
    ) -> None:
        """Apply reverse inference: analyze sinks to infer parameter sources."""
        if self.debug:
            debug(f"[VISITOR] Applying reverse inference for function {func_name}")

        param_names = func_info["args"]
        func_node = func_info["node"]
        inferred_sources = []

        # Walk through the function body to find all sink calls
        for node in ast.walk(func_node):
            if isinstance(node, ast.Call):
                (
                    sink_func_name,
                    sink_full_name,
                ) = self.ast_processor.get_func_name_with_module(node.func)
                if sink_func_name and self._is_sink(sink_func_name, sink_full_name):
                    # Analyze each argument of the sink call
                    for i, arg in enumerate(node.args):
                        source_param = self._trace_to_function_parameter(
                            arg, param_names
                        )
                        if source_param is not None:
                            if self.debug:
                                debug(
                                    f"[VISITOR] Reverse inference: sink {sink_func_name} uses source {source_param}"
                                )

                            if source_param == "tainted_variable":
                                # Already tainted variable, create call chain directly
                                self._create_call_chain_for_tainted_variable(
                                    arg, node, sink_func_name, sink_full_name
                                )
                            elif source_param not in inferred_sources:
                                # Infer this parameter as a potential NetworkInput source
                                inferred_sources.append(source_param)
                                self._mark_parameter_as_inferred_source(
                                    source_param, func_info, node
                                )

        if inferred_sources and self.debug:
            debug(
                f"[VISITOR] Inferred {len(inferred_sources)} parameters as potential sources: {inferred_sources}"
            )

    def _trace_to_function_parameter(
        self, arg_node: ast.AST, param_names: List[str]
    ) -> Optional[str]:
        """Trace an argument back to a function parameter or tainted variable."""
        return self._trace_to_source_recursive(arg_node, param_names, set())

    def _trace_to_source_recursive(
        self, node: ast.AST, param_names: List[str], visited: set
    ) -> Optional[str]:
        """Recursively trace a node back to a source (parameter or tainted variable)."""
        # Avoid infinite recursion
        node_id = id(node)
        if node_id in visited:
            return None
        visited.add(node_id)

        if isinstance(node, ast.Name):
            # Direct parameter usage: sink(param)
            if node.id in param_names:
                return node.id
            # Check if this variable is tainted
            elif node.id in self.tainted:
                return "tainted_variable"

        elif isinstance(node, ast.Attribute):
            # Attribute access: sink(param.attr) or sink(var.attr)
            base_source = self._trace_to_source_recursive(
                node.value, param_names, visited
            )
            if base_source:
                return base_source

        elif isinstance(node, ast.Subscript):
            # Subscript access: sink(param[key]) or sink(var[key])
            base_source = self._trace_to_source_recursive(
                node.value, param_names, visited
            )
            if base_source:
                return base_source

        elif isinstance(node, ast.Call):
            # Method calls: sink(var.method()) or sink(func(var))
            if isinstance(node.func, ast.Attribute):
                # Method call: var.method()
                base_source = self._trace_to_source_recursive(
                    node.func.value, param_names, visited
                )
                if base_source:
                    return base_source

            # Check arguments of function calls
            for arg in node.args:
                arg_source = self._trace_to_source_recursive(arg, param_names, visited)
                if arg_source:
                    return arg_source

        return None

    def _mark_parameter_as_inferred_source(
        self, param_name: str, func_info: Dict[str, Any], sink_node: ast.Call
    ) -> None:
        """Mark a function parameter as an inferred NetworkInput source."""
        # Create source info for the inferred source
        source_info = {
            "name": "NetworkInput",
            "line": func_info["line"],
            "col": 0,
            "node": func_info["node"],
            "inferred": True,  # Mark as inferred rather than explicit
        }

        # Mark the parameter as tainted
        self.tainted[param_name] = source_info

        if self.debug:
            debug(
                f"[VISITOR] Marked parameter {param_name} as inferred NetworkInput source"
            )

        # Re-check all sinks in this function now that the parameter is tainted
        self._recheck_sinks_in_function(func_info["node"])

    def _create_call_chain_for_tainted_variable(
        self,
        arg_node: ast.AST,
        sink_node: ast.Call,
        sink_func_name: str,
        sink_full_name: str,
    ) -> None:
        """Create a call chain for a sink that uses an already tainted variable."""
        # Find the tainted variable name
        tainted_var_name = self._get_variable_name_from_node(arg_node)
        if not tainted_var_name or tainted_var_name not in self.tainted:
            return

        source_info = self.tainted[tainted_var_name]
        line_no = getattr(sink_node, "lineno", 0)
        col_offset = getattr(sink_node, "col_offset", 0)

        # Create vulnerability info for this tainted flow
        sink_type = self.classifier.sink_type(sink_func_name, sink_full_name)

        vulnerability = {
            "source": source_info,
            "sink": {
                "name": sink_type,
                "line": line_no,
                "col": col_offset,
                "node": sink_node,
                "function_name": sink_func_name,
                "full_name": sink_full_name,
                "vulnerability_type": "UnsafeDeserialization",
            },
            "tainted_var": self._describe_argument(arg_node),
            "arg_index": 0,  # Simplified
        }

        self.found_vulnerabilities.append(vulnerability)

        if self.debug:
            debug(
                f"[VISITOR] Created call chain for tainted variable: {source_info['name']} -> {sink_func_name}"
            )

    def _get_variable_name_from_node(self, node: ast.AST) -> Optional[str]:
        """Extract the base variable name from a complex expression."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return self._get_variable_name_from_node(node.value)
        elif isinstance(node, ast.Subscript):
            return self._get_variable_name_from_node(node.value)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                return self._get_variable_name_from_node(node.func.value)
        return None

    def _check_data_flow_patterns(
        self,
        node: ast.Call,
        func_name: str,
        full_name: Optional[str],
        line_no: int,
        col_offset: int,
    ) -> None:
        """Check for configured data flow patterns like in-place modification."""
        if not hasattr(self.classifier, "config") or not self.classifier.config:
            return

        data_flow_patterns = self.classifier.config.get("data_flow_patterns", {})

        # Check in-place modification patterns
        in_place_patterns = data_flow_patterns.get("in_place_modification", {}).get(
            "patterns", []
        )

        for pattern in in_place_patterns:
            function_patterns = pattern.get("function_patterns", [])
            modifies_parameter = pattern.get("modifies_parameter", 0)
            source_type = pattern.get("source_type", "NetworkInput")

            # Check if this function matches any pattern
            if self._matches_function_pattern(func_name, full_name, function_patterns):
                if self.debug:
                    debug(
                        f"[VISITOR] Found in-place modification pattern: {func_name} modifies parameter {modifies_parameter}"
                    )

                # Mark the specified parameter as tainted
                if modifies_parameter < len(node.args):
                    arg = node.args[modifies_parameter]
                    if isinstance(arg, ast.Name):
                        var_name = arg.id

                        # Create source info for the in-place modification
                        source_info = {
                            "name": source_type,
                            "line": line_no,
                            "col": col_offset,
                            "node": node,
                            "pattern_matched": True,
                        }

                        self.tainted[var_name] = source_info

                        if self.debug:
                            debug(
                                f"[VISITOR] Marked variable {var_name} as tainted from in-place modification {func_name}"
                            )

    def _matches_function_pattern(
        self, func_name: str, full_name: Optional[str], patterns: List[str]
    ) -> bool:
        """Check if a function name matches any of the given patterns."""
        import fnmatch

        for pattern in patterns:
            # Check against function name
            if fnmatch.fnmatch(func_name, pattern):
                return True

            # Check against full name if available
            if full_name and fnmatch.fnmatch(full_name, pattern):
                return True

            # Check if pattern is contained in full name
            if full_name and pattern.replace("*", "") in full_name:
                return True

        return False

    # Path-sensitive analysis methods for control flow nodes

    def visit_If(self, node: ast.If) -> None:
        """Visit If node and handle path-sensitive analysis."""
        if (
            self.path_sensitive_enabled
            and self.path_analyzer
            and self.current_path_node
        ):
            from lanalyzer.logger import debug

            # Create path nodes for then and else branches
            then_node = self.path_analyzer.enter_conditional(node.test, "then")

            # Visit then branch
            previous_path_node = self.current_path_node
            self.current_path_node = then_node

            if self.debug:
                debug(
                    f"[VISITOR] Entering 'then' branch at line {getattr(node, 'lineno', 0)}"
                )

            for stmt in node.body:
                self.visit(stmt)

            # Handle else branch if it exists
            if node.orelse:
                else_node = self.path_analyzer.enter_conditional(node.test, "else")
                self.current_path_node = else_node

                if self.debug:
                    debug(
                        f"[VISITOR] Entering 'else' branch at line {getattr(node, 'lineno', 0)}"
                    )

                for stmt in node.orelse:
                    self.visit(stmt)

            # Restore previous path node
            self.current_path_node = previous_path_node
        else:
            # Fallback to standard visiting
            self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        """Visit While node and handle path-sensitive analysis."""
        if (
            self.path_sensitive_enabled
            and self.path_analyzer
            and self.current_path_node
        ):
            from lanalyzer.logger import debug

            # Create path node for loop body
            loop_node = self.path_analyzer.enter_conditional(node.test, "loop")

            # Visit loop body
            previous_path_node = self.current_path_node
            self.current_path_node = loop_node

            if self.debug:
                debug(
                    f"[VISITOR] Entering while loop at line {getattr(node, 'lineno', 0)}"
                )

            for stmt in node.body:
                self.visit(stmt)

            # Handle else clause if it exists
            if node.orelse:
                else_node = self.path_analyzer.enter_conditional(node.test, "loop_else")
                self.current_path_node = else_node

                if self.debug:
                    debug(
                        f"[VISITOR] Entering while-else branch at line {getattr(node, 'lineno', 0)}"
                    )

                for stmt in node.orelse:
                    self.visit(stmt)

            # Restore previous path node
            self.current_path_node = previous_path_node
        else:
            # Fallback to standard visiting
            self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        """Visit For node and handle path-sensitive analysis."""
        if (
            self.path_sensitive_enabled
            and self.path_analyzer
            and self.current_path_node
        ):
            from lanalyzer.logger import debug

            # Create path node for loop body
            # For loops don't have a simple test condition, so we use the iterator
            loop_node = self.path_analyzer.enter_conditional(node.iter, "for_loop")

            # Visit loop body
            previous_path_node = self.current_path_node
            self.current_path_node = loop_node

            if self.debug:
                debug(
                    f"[VISITOR] Entering for loop at line {getattr(node, 'lineno', 0)}"
                )

            for stmt in node.body:
                self.visit(stmt)

            # Handle else clause if it exists
            if node.orelse:
                else_node = self.path_analyzer.enter_conditional(node.iter, "for_else")
                self.current_path_node = else_node

                if self.debug:
                    debug(
                        f"[VISITOR] Entering for-else branch at line {getattr(node, 'lineno', 0)}"
                    )

                for stmt in node.orelse:
                    self.visit(stmt)

            # Restore previous path node
            self.current_path_node = previous_path_node
        else:
            # Fallback to standard visiting
            self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        """Visit Try node and handle path-sensitive analysis."""
        if (
            self.path_sensitive_enabled
            and self.path_analyzer
            and self.current_path_node
        ):
            from lanalyzer.logger import debug

            # Visit try body
            if self.debug:
                debug(
                    f"[VISITOR] Entering try block at line {getattr(node, 'lineno', 0)}"
                )

            for stmt in node.body:
                self.visit(stmt)

            # Visit exception handlers
            for handler in node.handlers:
                if self.debug:
                    debug(
                        f"[VISITOR] Entering except block at line {getattr(handler, 'lineno', 0)}"
                    )

                for stmt in handler.body:
                    self.visit(stmt)

            # Visit else clause if it exists
            if node.orelse:
                if self.debug:
                    debug(
                        f"[VISITOR] Entering try-else block at line {getattr(node, 'lineno', 0)}"
                    )

                for stmt in node.orelse:
                    self.visit(stmt)

            # Visit finally clause if it exists
            if node.finalbody:
                if self.debug:
                    debug(
                        f"[VISITOR] Entering finally block at line {getattr(node, 'lineno', 0)}"
                    )

                for stmt in node.finalbody:
                    self.visit(stmt)
        else:
            # Fallback to standard visiting
            self.generic_visit(node)
