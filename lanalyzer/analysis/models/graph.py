"""
Graph-based data structures for analysis.

This module consolidates CallGraphNode, DataStructureNode, and DefUseChain
into a single file for better organization and reduced complexity.
"""

import ast
from typing import Any, Dict, List, Optional, Set


class CallGraphNode:
    """
    Represents a node in the call graph, corresponding to a function or method.
    """

    def __init__(
        self,
        name: str,
        ast_node: Optional[ast.FunctionDef] = None,
        file_path: Optional[str] = None,
        line_no: int = 0,
        end_line_no: int = 0,
    ):
        self.name: str = name
        self.ast_node: Optional[ast.FunctionDef] = ast_node
        self.file_path: Optional[str] = file_path
        self.line_no: int = line_no
        self.end_line_no: int = end_line_no if end_line_no > 0 else line_no

        # Call relationships
        self.callers: List["CallGraphNode"] = []  # Functions that call this function
        self.callees: List["CallGraphNode"] = []  # Functions that this function calls

        # Function metadata
        self.parameters: List[str] = []  # Parameter names
        self.tainted_parameters: Set[int] = set()  # Tainted parameter indices
        self.return_tainted: bool = False  # Whether function returns tainted data
        self.return_taint_sources: List[Any] = []  # Sources of return taint

        # Call point information
        self.call_line: int = 0  # Most recent call line
        self.call_points: List[Dict[str, Any]] = []  # All call points
        self.is_self_method_call: bool = False  # Whether it's a self.method() call
        self.self_method_name: Optional[str] = None  # Method name if self call

    def add_caller(self, caller: "CallGraphNode") -> None:
        """Add a caller to this node if not already present."""
        if caller not in self.callers:
            self.callers.append(caller)

    def add_callee(self, callee: "CallGraphNode") -> None:
        """Add a callee to this node if not already present."""
        if callee not in self.callees:
            self.callees.append(callee)

    def add_call_point(self, line_no: int, statement: str, caller_name: str) -> None:
        """Add detailed call point information."""
        call_point = {"line": line_no, "statement": statement, "caller": caller_name}
        self.call_points.append(call_point)
        self.call_line = line_no  # Update most recent call line

    def __repr__(self) -> str:
        return f"CallGraphNode(name='{self.name}', file='{self.file_path}', line={self.line_no})"


class DataStructureNode:
    """
    Represents a node in a data structure, such as a dictionary or list.
    Used for tracking taint propagation through complex data structures.
    """

    def __init__(self, name: str, node_type: str):
        self.name = name
        self.node_type = node_type  # 'dict', 'list', 'tuple', 'object', etc.

        # Taint tracking
        self.tainted = False
        self.tainted_keys: Set[Any] = set()  # For dictionaries
        self.tainted_indices: Set[int] = set()  # For lists/tuples
        self.tainted_attributes: Set[str] = set()  # For objects

        # Source and propagation tracking
        self.source_info: Optional[Dict[str, Any]] = None
        self.propagation_history: List[str] = []

        # Structure relationships
        self.parent_structures: Set[str] = set()
        self.child_structures: Set[str] = set()

    def mark_tainted(
        self, source_info: Dict[str, Any], propagation_step: Optional[str] = None
    ) -> None:
        """Mark the data structure as tainted with the given source info."""
        self.tainted = True
        self.source_info = source_info
        if propagation_step:
            self.add_propagation_step(propagation_step)

    def add_tainted_key(
        self,
        key: Any,
        source_info: Optional[Dict[str, Any]] = None,
        propagation_step: Optional[str] = None,
    ) -> None:
        """Add a tainted key for dictionaries."""
        self.tainted_keys.add(key)
        if source_info:
            self.source_info = source_info
            self.tainted = True
        if propagation_step:
            self.add_propagation_step(f"Key '{key}' tainted: {propagation_step}")

    def add_tainted_index(
        self,
        index: int,
        source_info: Optional[Dict[str, Any]] = None,
        propagation_step: Optional[str] = None,
    ) -> None:
        """Add a tainted index for lists and tuples."""
        self.tainted_indices.add(index)
        if source_info:
            self.source_info = source_info
            self.tainted = True
        if propagation_step:
            self.add_propagation_step(f"Index {index} tainted: {propagation_step}")

    def add_tainted_attribute(
        self,
        attr: str,
        source_info: Optional[Dict[str, Any]] = None,
        propagation_step: Optional[str] = None,
    ) -> None:
        """Add a tainted attribute for objects."""
        self.tainted_attributes.add(attr)
        if source_info:
            self.source_info = source_info
            self.tainted = True
        if propagation_step:
            self.add_propagation_step(f"Attribute '{attr}' tainted: {propagation_step}")

    def add_propagation_step(self, step: str) -> None:
        """Add a step to the propagation history."""
        if step not in self.propagation_history:
            self.propagation_history.append(step)

    def add_parent_structure(self, parent_name: str) -> None:
        """Add a parent data structure."""
        self.parent_structures.add(parent_name)

    def add_child_structure(self, child_name: str) -> None:
        """Add a child data structure."""
        self.child_structures.add(child_name)

    def is_key_tainted(self, key: Any) -> bool:
        """Check if a specific key is tainted."""
        return self.tainted and (
            len(self.tainted_keys) == 0 or key in self.tainted_keys
        )

    def is_index_tainted(self, index: int) -> bool:
        """Check if a specific index is tainted."""
        return self.tainted and (
            len(self.tainted_indices) == 0 or index in self.tainted_indices
        )

    def is_attribute_tainted(self, attr: str) -> bool:
        """Check if a specific attribute is tainted."""
        return self.tainted and (
            len(self.tainted_attributes) == 0 or attr in self.tainted_attributes
        )

    def __repr__(self) -> str:
        return f"DataStructureNode(name='{self.name}', type='{self.node_type}', tainted={self.tainted})"


class DefUseChain:
    """
    Represents a definition-use chain for a variable.
    Used for tracking variable definitions and uses throughout the code.
    """

    def __init__(self, name: str):
        self.name = name
        self.definitions: List[tuple[ast.AST, int]] = []  # (ast_node, line_no) pairs
        self.uses: List[tuple[ast.AST, int]] = []  # (ast_node, line_no) pairs

        # Taint tracking
        self.tainted = False
        self.taint_sources: List[Any] = []

    def add_definition(self, node: ast.AST, line_no: int) -> None:
        """Add a definition site for this variable."""
        self.definitions.append((node, line_no))

    def add_use(self, node: ast.AST, line_no: int) -> None:
        """Add a use site for this variable."""
        self.uses.append((node, line_no))

    def mark_tainted(self, source_info: Any) -> None:
        """Mark variable as tainted with the given source info."""
        self.tainted = True
        if source_info not in self.taint_sources:
            self.taint_sources.append(source_info)

    def __repr__(self) -> str:
        return f"DefUseChain(name='{self.name}', tainted={self.tainted}, defs={len(self.definitions)}, uses={len(self.uses)})"
