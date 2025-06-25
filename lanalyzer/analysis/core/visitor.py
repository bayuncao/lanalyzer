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
        
        # Track taint propagation
        self._track_assignment_taint(node, source_info)

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
        }
        
        self.found_sinks.append(sink_info)
        
        if self.debug:
            debug(f"[VISITOR] Found sink: {sink_type} at line {line_no}")
        
        # Check sink arguments for tainted data
        self._check_sink_args(node, sink_type, sink_info)

    def _track_assignment_taint(self, node: ast.Call, source_info: Dict[str, Any]) -> None:
        """Track taint propagation from source assignments."""
        # Find the assignment target if this call is part of an assignment
        parent = self.parent_map.get(node)
        if isinstance(parent, ast.Assign):
            for target in parent.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    self.tainted[var_name] = source_info
                    if self.debug:
                        debug(f"[VISITOR] Marked variable {var_name} as tainted from {source_info['name']}")

    def _check_sink_args(self, node: ast.Call, sink_type: str, sink_info: Dict[str, Any]) -> None:
        """Check sink arguments for tainted data."""
        for i, arg in enumerate(node.args):
            if isinstance(arg, ast.Name) and arg.id in self.tainted:
                # Found tainted data flowing to sink
                vulnerability = {
                    "source": self.tainted[arg.id],
                    "sink": sink_info,
                    "tainted_var": arg.id,
                    "arg_index": i,
                }
                self.found_vulnerabilities.append(vulnerability)

                if self.debug:
                    debug(f"[VISITOR] Found vulnerability: {arg.id} flows to {sink_type}")

    # Import handling methods
    def visit_Import(self, node: ast.Import) -> None:
        """Handle import statements."""
        self.import_tracker.visit_Import(node)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Handle from-import statements."""
        self.import_tracker.visit_ImportFrom(node)
        self.generic_visit(node)
