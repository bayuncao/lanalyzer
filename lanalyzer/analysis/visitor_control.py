"""
Enhanced AST visitor for taint analysis - Control flow operations.
"""

import ast
import copy

from .visitor_base import EnhancedTaintVisitor


class ControlFlowVisitorMixin:
    """Mixin for control flow-related visit methods."""

    def visit_If(self: "EnhancedTaintVisitor", node: ast.If) -> None:
        """Visit if statements for path-sensitive analysis."""
        if_path = self.pathsensitive.PathNode(node, self.current_path)
        self.current_path.add_child(if_path)
        old_path = self.current_path
        old_taint = copy.deepcopy(self.variable_taint)
        then_path = self.pathsensitive.PathNode(node.body, if_path)
        if_path.add_child(then_path)
        then_path.add_constraint("then", node.test)
        self.current_path = then_path
        for stmt in node.body:
            self.visit(stmt)
        self.variable_taint = copy.deepcopy(old_taint)
        if node.orelse:
            else_path = self.pathsensitive.PathNode(node.orelse, if_path)
            if_path.add_child(else_path)
            else_path.add_constraint("else", node.test)
            self.current_path = else_path
            for stmt in node.orelse:
                self.visit(stmt)
        self.current_path = old_path
