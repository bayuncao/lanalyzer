"""
Path-sensitive analysis for enhanced taint tracking.
"""

import ast
from typing import Any, Dict, List, Optional


class PathNode:
    """
    Represents a node in the path-sensitive analysis.
    """

    def __init__(self, ast_node: ast.AST, parent: Optional["PathNode"] = None):
        self.ast_node = ast_node
        self.parent = parent
        self.children = []
        self.constraints = []  # Conditions that must be true to reach this node
        self.variable_taint = {}  # State of tainted variables at this node

    def add_child(self, child: "PathNode") -> None:
        self.children.append(child)
        child.parent = self

    def add_constraint(self, constraint_type: str, condition: ast.AST) -> None:
        """Add a path constraint to this node."""
        self.constraints.append((constraint_type, condition))

    def is_reachable(self) -> bool:
        """
        Check if this path is reachable based on constraints.
        This is a simplified version and would need constraint solving in practice.
        """
        # For now, assume all paths are reachable
        return True

    def get_path_to_root(self) -> List["PathNode"]:
        """Get the path from this node to the root."""
        path = [self]
        current = self.parent
        while current:
            path.append(current)
            current = current.parent
        return path[::-1]  # Reverse to get root-to-node order

    def get_variable_state(self, variable_name: str) -> Optional[Dict[str, Any]]:
        """Get the taint state of a variable at this node."""
        if variable_name in self.variable_taint:
            return self.variable_taint[variable_name]

        # Check parent nodes if not found in current node
        current = self.parent
        while current:
            if variable_name in current.variable_taint:
                return current.variable_taint[variable_name]
            current = current.parent

        return None

    def __repr__(self) -> str:
        return f"PathNode(ast_type='{type(self.ast_node).__name__}', constraints={len(self.constraints)})"
