"""
Enhanced AST visitor for taint analysis - Base Visitor.
"""

import ast
import os
from typing import Callable, Dict, Optional, Tuple

from lanalyzer.analysis.ast_parser import TaintVisitor

from .pathsensitive import PathNode


class EnhancedTaintVisitor(TaintVisitor):
    """
    Enhanced taint visitor with additional features:
    1. Cross-function call taint tracking
    2. Complex data structure taint propagation
    3. Definition-use chain analysis
    4. Path-sensitive analysis
    """

    def __init__(
        self,
        parent_map=None,
        debug: bool = False,
        verbose: bool = False,
        file_path: Optional[str] = None,
    ):
        """
        Initialize the enhanced taint visitor.

        Args:
            parent_map: Dictionary mapping AST nodes to their parents
            debug: Whether to enable debug output
            verbose: Whether to enable verbose output
            file_path: Path to the file being analyzed
        """
        super().__init__(parent_map, debug, verbose)
        self.file_path = file_path
        self.source_lines = None  # Will store source code lines

        # If file path is provided, try to load the source code
        if file_path and os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    self.source_lines = f.readlines()
                if self.debug:
                    print(
                        f"Loaded {len(self.source_lines)} lines of source code from {file_path}"
                    )
            except Exception as e:
                if self.debug:
                    print(f"Failed to load source code: {str(e)}")

        # For compatibility with the updated TaintVisitor, which uses "tainted"
        # instead of "variable_taint". This makes variable_taint an alias to tainted.
        self.variable_taint = self.tainted if hasattr(self, "tainted") else {}

        # Initialize sources and sinks from the tracker
        self.sources = []
        self.sinks = []

        # Call graph related
        self.functions = {}  # name -> CallGraphNode
        self.current_function = None  # Current function being analyzed
        self.call_locations = []  # Stack of call locations

        # Complex data structures
        self.data_structures = {}  # name -> DataStructureNode

        # Definition-use chains
        self.def_use_chains = {}  # name -> DefUseChain

        # Path-sensitive analysis
        self.path_root = None  # Root of the path tree
        self.current_path = None  # Current path being analyzed
        self.path_constraints = []  # Stack of path constraints

        # Track taint propagation path
        self.taint_propagation_paths = {}  # var_name -> list of propagation steps

        # Function return taint tracking
        self.function_returns_tainted = {}  # function_name -> bool

        # Cross-module imports
        self.module_imports = {}  # imported_name -> (module, original_name)

        # Enhanced file handle tracking
        self.file_handle_operations = {}  # handle_name -> list of operations

        # Improved taint tracking for complex operations
        self.operation_taint_rules = self._initialize_operation_taint_rules()

        # Increased initialization debug info
        if self.debug:
            print(
                f"Creating EnhancedTaintVisitor instance for analyzing file: {self.file_path}"
            )

    def _initialize_operation_taint_rules(self) -> Dict[str, Callable]:
        """Initialize rules for how taint propagates through different operations."""
        rules = {}

        # String operations that propagate taint
        string_propagating_methods = [
            "strip",
            "lstrip",
            "rstrip",
            "upper",
            "lower",
            "title",
            "capitalize",
            "swapcase",
            "replace",
            "format",
            "join",
            "split",
            "rsplit",
            "splitlines",
            "partition",
            "rpartition",
        ]

        for method in string_propagating_methods:
            rules[f"str.{method}"] = lambda node, source_info: source_info

        # List/dict operations that propagate taint
        container_propagating_methods = ["copy", "items", "keys", "values"]
        for method in container_propagating_methods:
            rules[f"dict.{method}"] = lambda node, source_info: source_info
            rules[f"list.{method}"] = lambda node, source_info: source_info

        return rules

    def visit_Module(self, node: ast.Module) -> None:
        """Visit a module node and initialize path analysis."""
        # Add filename debug info
        if self.debug:
            print(
                f"\n========== Starting analysis of file: {self.file_path} ==========\n"
            )

        self.path_root = PathNode(node)
        self.current_path = self.path_root
        super().generic_visit(node)

        # Print file info again upon analysis completion
        if self.debug:
            print(
                f"\n========== Completed analysis of file: {self.file_path} =========="
            )
            print(f"Found {len(self.found_sinks)} sinks")
            print(f"Found {len(self.found_sources)} sources")

    def visit_Name(self, node: ast.Name) -> None:
        """Visit a name node to track variable uses."""
        # Update def-use chains for variable uses
        if isinstance(node.ctx, ast.Load) and node.id in self.def_use_chains:
            self.def_use_chains[node.id].add_use(node, getattr(node, "lineno", 0))

        # Continue visiting
        self.generic_visit(node)

    def _get_func_name_with_module(self, node) -> Tuple[str, Optional[str]]:
        """Enhanced version of _get_func_name_with_module to handle more cases."""
        # Use parent method first
        func_name, full_name = super()._get_func_name_with_module(node)

        # Handle additional import cases
        if not full_name and func_name in self.module_imports:
            module, original_name = self.module_imports[func_name]
            full_name = f"{module}.{original_name}"

        return func_name, full_name
