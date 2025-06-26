"""
Simplified taint analysis visitor.

This module consolidates all visitor functionality into a single, comprehensive class
that replaces the complex mixin-based approach.
"""

import ast
import copy
from typing import Any, Dict, List, Optional, Set

from lanalyzer.logger import debug, error
from ..import_tracker import ImportTracker
from ..source_sink_classifier import SourceSinkClassifier
from .ast_processor import ASTProcessor
from ..flow.call_chain_tracker import CallChainTracker


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
        
        # Data structure tracking
        self.data_structures: Dict[str, Any] = {}
        
        # Control flow tracking
        self.def_use_chains: Dict[str, Any] = {}
        self.path_constraints: List[Any] = []
        
        # Import and classification handling
        self.import_tracker = ImportTracker(debug_mode=self.debug)
        self.import_aliases = self.import_tracker.import_aliases
        self.from_imports = self.import_tracker.from_imports
        self.direct_imports = self.import_tracker.direct_imports
        
        # Source/Sink classifier
        self.classifier = SourceSinkClassifier(self)

        # Call chain tracker for enhanced taint analysis
        self.call_chain_tracker = CallChainTracker(file_path, debug=debug_mode)

    def visit_Module(self, node: ast.Module) -> None:
        """Visit a module node and initialize analysis."""
        if self.debug:
            debug(f"\n========== Starting analysis of file: {self.file_path} ==========\n")
        
        self.generic_visit(node)
        
        if self.debug:
            debug(f"\n========== Finished analysis of file: {self.file_path} ==========")
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
        }
        
        self.functions[node.name] = func_info
        previous_function = self.current_function
        self.current_function = func_info
        
        # Visit function body
        self.generic_visit(node)
        
        # Restore previous function context
        self.current_function = previous_function

    def visit_Call(self, node: ast.Call) -> None:
        """Visit a function call node."""
        func_name, full_name = self.ast_processor.get_func_name_with_module(node.func)
        line_no = getattr(node, "lineno", 0)
        col_offset = getattr(node, "col_offset", 0)

        if self.debug:
            current_func_name = getattr(self.current_function, "name", "GlobalScope") if self.current_function else "GlobalScope"
            debug(f"[VISITOR] Call to {func_name} (full: {full_name}) at line {line_no} in {current_func_name}")

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

        # Check for sources
        if func_name and self._is_source(func_name, full_name):
            self._handle_source(node, func_name, full_name, line_no, col_offset)

        # Check for sinks
        if func_name and self._is_sink(func_name, full_name):
            self._handle_sink(node, func_name, full_name, line_no, col_offset)

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
                    debug(f"[VISITOR] Found source attribute access: {attr_name} at line {line_no}")

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
                debug(f"[VISITOR] Found source attribute: {attr_name} at line {line_no}")

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
                        debug(f"[VISITOR] Propagated taint from {node.value.id} to {var_name}")
                else:
                    # Check for taint in complex expressions
                    taint_info = self._check_expression_taint(node.value)
                    if taint_info:
                        self.tainted[var_name] = taint_info
                        if self.debug:
                            debug(f"[VISITOR] Marked variable {var_name} as tainted from complex expression")

        self.generic_visit(node)

    def _is_source(self, func_name: str, full_name: Optional[str] = None) -> bool:
        """Check if function is a taint source."""
        return self.classifier.is_source(func_name, full_name)

    def _is_sink(self, func_name: str, full_name: Optional[str] = None) -> bool:
        """Check if function is a taint sink."""
        return self.classifier.is_sink(func_name, full_name)

    def _handle_source(self, node: ast.Call, func_name: str, full_name: Optional[str], line_no: int, col_offset: int) -> None:
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

    def _handle_sink(self, node: ast.Call, func_name: str, full_name: Optional[str], line_no: int, col_offset: int) -> None:
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

    def _track_assignment_taint(self, node: ast.Call, source_info: Dict[str, Any], source_node=None) -> None:
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
                            getattr(parent, 'lineno', 0),
                            getattr(parent, 'col_offset', 0),
                            source_node
                        )

                    if self.debug:
                        debug(f"[VISITOR] Marked variable {var_name} as tainted from {source_info['name']}")

    def _check_sink_args(self, node: ast.Call, sink_type: str, sink_info: Dict[str, Any], sink_node=None) -> None:
        """Check sink arguments for tainted data."""
        if self.debug:
            debug(f"[VISITOR] Checking sink args for {sink_type} at line {sink_info.get('line', 0)}")

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
                        debug(f"[VISITOR] Found tainted complex expression: {tainted_var}")
                elif self.debug:
                    debug(f"[VISITOR] No taint found in complex expression")

            if taint_info:
                # Found tainted data flowing to sink
                vulnerability = {
                    "source": taint_info,
                    "sink": sink_info,
                    "tainted_var": tainted_var,
                    "arg_index": i,
                }
                self.found_vulnerabilities.append(vulnerability)

                # Create detailed taint path if we have call chain tracking
                if sink_node and hasattr(self, 'call_chain_tracker'):
                    # Find the source node for this tainted variable
                    source_nodes = [node for node in self.call_chain_tracker.current_chain
                                  if node.node_type == "source"]
                    if source_nodes:
                        taint_path = self.call_chain_tracker.create_taint_path(
                            source_nodes[0], sink_node, tainted_var
                        )
                        vulnerability["taint_path"] = taint_path

                if self.debug:
                    debug(f"[VISITOR] Found vulnerability: {tainted_var} flows to {sink_type}")

    def _report_sink_vulnerability(self, node: ast.Call, sink_type: str, sink_info: Dict[str, Any]) -> None:
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
            debug(f"[VISITOR] Reported sink-only vulnerability: {sink_type} at line {sink_info.get('line', 0)}")

    def _describe_argument(self, arg: ast.expr) -> str:
        """Describe an argument for sink-only vulnerability reporting."""
        if isinstance(arg, ast.Name):
            return arg.id
        elif isinstance(arg, ast.Str):
            return f"string_literal: {arg.s[:50]}..."
        elif isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return f"string_literal: {arg.value[:50]}..."
        elif isinstance(arg, ast.Call):
            if hasattr(arg.func, 'id'):
                return f"call_result: {arg.func.id}()"
            elif hasattr(arg.func, 'attr'):
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

    def _track_subscript_taint(self, node: ast.Subscript, source_info: Dict[str, Any]) -> None:
        """Track taint propagation from subscript access."""
        # Find the assignment target if this subscript is part of an assignment
        parent = self.parent_map.get(node)
        if isinstance(parent, ast.Assign):
            for target in parent.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    self.tainted[var_name] = source_info
                    if self.debug:
                        debug(f"[VISITOR] Marked variable {var_name} as tainted from subscript {source_info['name']}")

    def _track_attribute_taint(self, node: ast.Attribute, source_info: Dict[str, Any]) -> None:
        """Track taint propagation from attribute access."""
        # Find the assignment target if this attribute is part of an assignment
        parent = self.parent_map.get(node)
        if isinstance(parent, ast.Assign):
            for target in parent.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    self.tainted[var_name] = source_info
                    if self.debug:
                        debug(f"[VISITOR] Marked variable {var_name} as tainted from attribute {source_info['name']}")

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
            func_name, full_name = self.ast_processor.get_func_name_with_module(expr.func)
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
