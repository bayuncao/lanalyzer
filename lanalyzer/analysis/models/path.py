"""
Path-sensitive analysis models.

This module contains data structures for path-sensitive analysis,
including PathNode for tracking execution paths and constraints.
"""

import ast
from typing import Any, Dict, List, Optional, Tuple


class PathNode:
    """
    Represents a node in the path-sensitive analysis.

    Each PathNode corresponds to a point in the program execution
    where the analysis state might differ based on the path taken.
    """

    def __init__(self, ast_node: ast.AST, parent: Optional["PathNode"] = None):
        self.ast_node = ast_node
        self.parent = parent
        self.children: List["PathNode"] = []

        # Path constraints (conditions that must be true to reach this node)
        self.constraints: List[Tuple[str, ast.AST]] = []

        # Variable taint state at this node
        self.variable_taint: Dict[str, Any] = {}

    def add_child(self, child: "PathNode") -> None:
        """Add a child node to this path node."""
        self.children.append(child)
        child.parent = self

    def add_constraint(self, constraint_type: str, condition: ast.AST) -> None:
        """
        Add a path constraint to this node.

        Args:
            constraint_type: Type of constraint ('then', 'else', 'loop', etc.)
            condition: AST node representing the condition
        """
        self.constraints.append((constraint_type, condition))

    def is_reachable(self) -> bool:
        """
        Check if this path is reachable based on constraints.

        This is a simplified version. In a full implementation,
        this would involve constraint solving to determine satisfiability.

        Returns:
            True if the path is potentially reachable, False otherwise
        """
        # For now, assume all paths are reachable
        # TODO: Implement proper constraint solving
        return True

    def get_path_to_root(self) -> List["PathNode"]:
        """
        Get the path from this node to the root.

        Returns:
            List of PathNodes from root to this node
        """
        path = [self]
        current = self.parent
        while current:
            path.append(current)
            current = current.parent
        return path[::-1]  # Reverse to get root-to-node order

    def get_variable_state(self, variable_name: str) -> Optional[Dict[str, Any]]:
        """
        Get the taint state of a variable at this node.

        Args:
            variable_name: Name of the variable to check

        Returns:
            Taint state dictionary if variable is tainted, None otherwise
        """
        # Check current node first
        if variable_name in self.variable_taint:
            return self.variable_taint[variable_name]

        # Check parent nodes if not found in current node
        current = self.parent
        while current:
            if variable_name in current.variable_taint:
                return current.variable_taint[variable_name]
            current = current.parent

        return None

    def set_variable_state(
        self, variable_name: str, taint_info: Dict[str, Any]
    ) -> None:
        """
        Set the taint state of a variable at this node.

        Args:
            variable_name: Name of the variable
            taint_info: Taint information dictionary
        """
        self.variable_taint[variable_name] = taint_info

    def get_all_constraints(self) -> List[Tuple[str, ast.AST]]:
        """
        Get all constraints from root to this node.

        Returns:
            List of all constraints along the path
        """
        all_constraints = []
        path = self.get_path_to_root()

        for node in path:
            all_constraints.extend(node.constraints)

        return all_constraints

    def get_constraint_summary(self) -> str:
        """
        Get a human-readable summary of constraints.

        Returns:
            String describing the path constraints
        """
        constraints = self.get_all_constraints()
        if not constraints:
            return "No constraints"

        constraint_strs = []
        for constraint_type, condition in constraints:
            # Simple string representation of the condition
            if hasattr(ast, "unparse"):
                condition_str = ast.unparse(condition)
            else:
                condition_str = str(condition)

            constraint_strs.append(f"{constraint_type}: {condition_str}")

        return " AND ".join(constraint_strs)

    def __repr__(self) -> str:
        ast_type = type(self.ast_node).__name__
        constraint_count = len(self.constraints)
        return f"PathNode(ast_type='{ast_type}', constraints={constraint_count})"


class PathSensitiveAnalyzer:
    """
    Analyzer for path-sensitive taint analysis.

    This class manages the creation and traversal of PathNodes
    during the analysis process.
    """

    def __init__(self, debug: bool = False):
        self.debug = debug
        self.root_node: Optional[PathNode] = None
        self.current_node: Optional[PathNode] = None
        self.all_paths: List[List[PathNode]] = []

    def initialize_analysis(self, root_ast: ast.AST) -> PathNode:
        """
        Initialize path-sensitive analysis with the root AST node.

        Args:
            root_ast: Root AST node (usually Module)

        Returns:
            Root PathNode
        """
        self.root_node = PathNode(root_ast)
        self.current_node = self.root_node
        return self.root_node

    def enter_conditional(self, condition: ast.AST, branch_type: str) -> PathNode:
        """
        Enter a conditional branch (if/else, loop, etc.).

        Args:
            condition: AST node representing the condition
            branch_type: Type of branch ('then', 'else', 'loop', etc.)

        Returns:
            New PathNode for the branch
        """
        if not self.current_node:
            raise RuntimeError("No current node - analysis not initialized")

        branch_node = PathNode(condition, self.current_node)
        branch_node.add_constraint(branch_type, condition)
        self.current_node.add_child(branch_node)

        return branch_node

    def exit_conditional(self) -> Optional[PathNode]:
        """
        Exit the current conditional branch.

        Returns:
            Parent PathNode, or None if at root
        """
        if not self.current_node:
            return None

        return self.current_node.parent

    def get_all_leaf_paths(self) -> List[List[PathNode]]:
        """
        Get all paths from root to leaf nodes.

        Returns:
            List of paths, where each path is a list of PathNodes
        """
        if not self.root_node:
            return []

        paths = []
        self._collect_paths(self.root_node, [], paths)
        return paths

    def _collect_paths(
        self,
        node: PathNode,
        current_path: List[PathNode],
        all_paths: List[List[PathNode]],
    ) -> None:
        """Recursively collect all paths from current node to leaves."""
        current_path = current_path + [node]

        if not node.children:
            # Leaf node - add complete path
            all_paths.append(current_path)
        else:
            # Continue to children
            for child in node.children:
                self._collect_paths(child, current_path, all_paths)

    def find_paths_with_variable(self, variable_name: str) -> List[List[PathNode]]:
        """
        Find all paths where a specific variable is tainted.

        Args:
            variable_name: Name of the variable to search for

        Returns:
            List of paths containing the tainted variable
        """
        all_paths = self.get_all_leaf_paths()
        matching_paths = []

        for path in all_paths:
            for node in path:
                if node.get_variable_state(variable_name):
                    matching_paths.append(path)
                    break

        return matching_paths
