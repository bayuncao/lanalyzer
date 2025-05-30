"""
Enhanced AST visitor for taint analysis.
This is the main aggregation file that imports and combines all visitor components.
"""

from typing import Optional
import os
import ast

from lanalyzer.logger import debug, warning, error

from .visitor_base import EnhancedTaintVisitor
from .visitor_function import FunctionVisitorMixin
from .visitor_datastructure import DataStructureVisitorMixin
from .visitor_control import ControlFlowVisitorMixin

import importlib

# Dynamically import analysis submodules
for module_name in ["callgraph", "datastructures", "defuse", "pathsensitive"]:
    globals()[module_name] = importlib.import_module(
        f".{module_name}", package="lanalyzer.analysis"
    )


class EnhancedTaintAnalysisVisitor(
    EnhancedTaintVisitor,
    FunctionVisitorMixin,
    DataStructureVisitorMixin,
    ControlFlowVisitorMixin,
):
    """
    This class combines all the visitor mixins to create a complete taint analysis visitor.

    - EnhancedTaintVisitor: Base visitor with core functionality
    - FunctionVisitorMixin: Function definition and call tracking
    - DataStructureVisitorMixin: Complex data structure tracking
    - ControlFlowVisitorMixin: Control flow analysis
    """

    def visit_ClassDef(self, node: ast.ClassDef):
        """
        Directly implement the visit_ClassDef method to ensure that intra-class method calls are correctly identified and processed.
        """
        debug(f"[FORCE] Visiting class definition: {node.name}")

        # Save the previous class context
        previous_class = getattr(self, "current_class", None)
        self.current_class = node.name

        # Initialize class method mapping
        if not hasattr(self, "class_methods"):
            self.class_methods = {}

        # Create method mapping for the current class
        if self.current_class not in self.class_methods:
            self.class_methods[self.current_class] = {
                "methods": set(),  # All method names in the class
                "calls": {},  # Inter-method call relationships
            }

        # Process class members
        for item in node.body:
            item_type = type(item).__name__
            item_name = getattr(item, "name", None)
            debug(
                f"[FORCE] Class {self.current_class} member: type={item_type}, name={item_name}"
            )

            # Set parent node reference
            if not hasattr(item, "parent"):
                item.parent = node  # type: ignore

            # Mark class method
            if isinstance(item, ast.FunctionDef):
                debug(f"[FORCE] Found class method: {self.current_class}.{item.name}")
                self.class_methods[self.current_class]["methods"].add(item.name)

                # Important: Set the class information to which the method belongs
                if not hasattr(item, "class_name"):
                    item.class_name = self.current_class  # type: ignore

                # New: Check for calls to other class methods within the method body
                for stmt in item.body:
                    # Handle direct calls like self.method()
                    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                        call_node = stmt.value
                        if (
                            isinstance(call_node.func, ast.Attribute)
                            and isinstance(call_node.func.value, ast.Name)
                            and call_node.func.value.id == "self"
                        ):
                            called_method_name = call_node.func.attr
                            if (
                                called_method_name
                                in self.class_methods[self.current_class]["methods"]
                            ):
                                # Record method call relationship
                                self.class_methods[self.current_class][
                                    "calls"
                                ].setdefault(item.name, {}).setdefault(
                                    called_method_name, []
                                ).append(
                                    getattr(stmt, "lineno", 0)
                                )
                                debug(
                                    f"[FORCE] Recording intra-class method call: {self.current_class}.{item.name} calls {self.current_class}.{called_method_name} at line {getattr(stmt, 'lineno', 0)}"
                                )

                    # Recursively check more complex structures (e.g., calls within If statements)
                    for subnode in ast.walk(stmt):
                        if (
                            isinstance(subnode, ast.Call)
                            and isinstance(subnode.func, ast.Attribute)
                            and isinstance(subnode.func.value, ast.Name)
                            and subnode.func.value.id == "self"
                        ):
                            called_method_name = subnode.func.attr
                            # Ensure it's a call to a known method of the current class
                            if (
                                called_method_name
                                in self.class_methods[self.current_class]["methods"]
                            ):
                                # Record method call relationship
                                self.class_methods[self.current_class][
                                    "calls"
                                ].setdefault(item.name, {}).setdefault(
                                    called_method_name, []
                                ).append(
                                    getattr(subnode, "lineno", 0)
                                )
                                debug(
                                    f"[FORCE] Recording intra-class method call (in walk): {self.current_class}.{item.name} calls {self.current_class}.{called_method_name} at line {getattr(subnode, 'lineno', 0)}"
                                )

        # Visit class members
        super().generic_visit(node)  # Use super() for MRO consistency

        # Output class method call relationships for debugging
        if self.debug and self.current_class in self.class_methods:
            methods = self.class_methods[self.current_class]["methods"]
            calls = self.class_methods[self.current_class]["calls"]
            debug(f"[FORCE] Methods of class {self.current_class}: {methods}")
            debug(
                f"[FORCE] Method call relationships of class {self.current_class}: {calls}"
            )

        # Restore the previous class context
        self.current_class = previous_class

    def visit_Module(self, node: ast.Module):
        """
        Directly implement the visit_Module method to ensure all top-level definitions are correctly processed.
        """
        debug(
            f"[FORCE] Starting module analysis: {getattr(self, 'file_path', 'Unknown File')}"
        )

        # Initialize path analysis
        self.path_root = self.pathsensitive.PathNode(node)
        self.current_path = self.path_root

        # Set parent node reference for each top-level definition in the module
        for child in node.body:
            if not hasattr(child, "parent"):
                child.parent = node  # type: ignore

        # Continue processing module content
        super().generic_visit(node)  # Use super() for MRO consistency

        # Output analysis result statistics
        if self.debug:
            function_count = len(getattr(self, "functions", {}))
            debug(
                f"[FORCE] Module analysis complete, found {function_count} functions."
            )
            debug(
                f"[FORCE] Class method relationships: {getattr(self, 'class_methods', {})}"
            )

    def __init__(
        self,
        parent_map=None,  # Consider type hinting for parent_map
        debug_mode: bool = False,
        verbose: bool = False,
        file_path: Optional[str] = None,
    ):
        """Initialize the complete taint analysis visitor."""
        self.callgraph = globals()["callgraph"]
        self.datastructures = globals()["datastructures"]
        self.defuse = globals()["defuse"]
        self.pathsensitive = globals()["pathsensitive"]

        super().__init__(parent_map, debug_mode, verbose, file_path)
        if not hasattr(self, "source_lines") or not self.source_lines:
            if file_path and os.path.exists(file_path):
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        self.source_lines = f.readlines()
                    if self.debug:
                        debug(
                            f"Loaded {len(self.source_lines)} lines of source code from {file_path} into EnhancedTaintAnalysisVisitor"
                        )
                except Exception as e:
                    if self.debug:
                        error(
                            f"Failed to load source code in EnhancedTaintAnalysisVisitor for {file_path}: {str(e)}"
                        )
            elif file_path:
                if self.debug:
                    warning(
                        f"Source file not found for EnhancedTaintAnalysisVisitor: {file_path}"
                    )
            # else:
            #    if self.debug:
            #        warning("No file_path provided to EnhancedTaintAnalysisVisitor, source lines not loaded.")

        if self.debug:
            debug(
                f"[FORCE] EnhancedTaintAnalysisVisitor initialized for file: {file_path if file_path else 'No file specified'}"
            )
            if hasattr(self, "source_lines") and self.source_lines:
                debug(
                    f"Successfully loaded source code lines: {len(self.source_lines)} lines"
                )
            elif (
                file_path
            ):  # Only warn if a file_path was given but lines weren't loaded
                warning(f"Warning: Failed to load source code lines from {file_path}")

    def visit(self, node: ast.AST):
        if self.debug:
            node_type = type(node).__name__
            node_name_attr = getattr(node, "name", None)
            node_id_attr = getattr(node, "id", None)  # For ast.Name nodes
            node_identifier = (
                node_name_attr if node_name_attr is not None else node_id_attr
            )

            line_info = f" (line {node.lineno})" if hasattr(node, "lineno") else ""

            debug(
                f"[FORCE] EnhancedTaintAnalysisVisitor visiting node: {node_type}{line_info}, name/id='{node_identifier if node_identifier else 'N/A'}'"
            )
        return super().visit(node)
