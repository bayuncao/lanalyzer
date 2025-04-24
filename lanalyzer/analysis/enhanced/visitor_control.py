"""
Enhanced AST visitor for taint analysis - Control flow operations.
"""

import ast
import copy
from typing import Dict, Any, List

from .visitor_base import EnhancedTaintVisitor


class ControlFlowVisitorMixin:
    """Mixin for control flow-related visit methods."""

    def visit_If(self: "EnhancedTaintVisitor", node: ast.If) -> None:
        """Visit if statements for path-sensitive analysis."""
        # Create path nodes for if conditions
        if_path = self.pathsensitive.PathNode(node, self.current_path)
        self.current_path.add_child(if_path)

        # Save current path
        old_path = self.current_path
        old_taint = copy.deepcopy(self.variable_taint)

        # Handle "then" branch
        then_path = self.pathsensitive.PathNode(node.body, if_path)
        if_path.add_child(then_path)
        then_path.add_constraint("then", node.test)
        self.current_path = then_path

        # Visit then branch
        for stmt in node.body:
            self.visit(stmt)

        # Restore state for "else" branch (if any)
        self.variable_taint = copy.deepcopy(old_taint)

        if node.orelse:
            else_path = self.pathsensitive.PathNode(node.orelse, if_path)
            if_path.add_child(else_path)
            else_path.add_constraint("else", node.test)
            self.current_path = else_path

            # Visit else branch
            for stmt in node.orelse:
                self.visit(stmt)

        # Restore original path
        self.current_path = old_path

        # Don't call generic_visit as we've handled the children manually
        
    def get_taint_propagation_chain(self: "EnhancedTaintVisitor", var_name: str) -> List[Dict[str, Any]]:
        """Get the complete taint propagation chain for a variable."""
        if var_name not in self.variable_taint:
            return []

        propagation_chain = []
        current_info = self.variable_taint[var_name]

        # Add initial source
        propagation_chain.append(
            {
                "var_name": var_name,
                "source_type": current_info.get("name", "Unknown"),
                "line": current_info.get("line", 0),
                "col": current_info.get("col", 0),
                "operation": "Source",
                "description": f"Variable originates from {current_info.get('name', 'Unknown')} source",
            }
        )

        # Add propagation path if available
        if "propagation_path" in current_info:
            for i, step in enumerate(current_info["propagation_path"]):
                propagation_chain.append(
                    {
                        "step_no": i + 1,
                        "operation": "Propagation",
                        "description": step,
                        "var_name": var_name,
                    }
                )

        # Add def-use information if available
        if var_name in self.def_use_chains:
            chain = self.def_use_chains[var_name]

            # Include all definitions with context
            for i, (def_node, line_no) in enumerate(chain.definitions):
                # Get more context about the definition
                context = "Unknown assignment"
                if isinstance(def_node, ast.Assign):
                    if isinstance(def_node.value, ast.Name):
                        context = f"Assigned from variable {def_node.value.id}"
                    elif isinstance(def_node.value, ast.Call):
                        if isinstance(def_node.value.func, ast.Name):
                            context = f"Assigned from function call {def_node.value.func.id}()"
                        elif isinstance(def_node.value.func, ast.Attribute):
                            if isinstance(def_node.value.func.value, ast.Name):
                                context = f"Assigned from method call {def_node.value.func.value.id}.{def_node.value.func.attr}()"

                propagation_chain.append(
                    {
                        "step_no": len(propagation_chain),
                        "operation": "Definition",
                        "description": f"Defined at line {line_no} via {context}",
                        "line": line_no,
                        "var_name": var_name,
                    }
                )

            # Include all uses with context
            for i, (use_node, line_no) in enumerate(chain.uses):
                # Get more context about the use
                context = "Unknown usage"
                if hasattr(use_node, "parent"):
                    parent = use_node.parent
                    if isinstance(parent, ast.Call) and parent.func == use_node:
                        context = f"Used as function name in call at line {line_no}"
                    elif isinstance(parent, ast.Call):
                        for i, arg in enumerate(parent.args):
                            if arg == use_node:
                                if isinstance(parent.func, ast.Name):
                                    context = f"Used as argument {i+1} in call to {parent.func.id}() at line {line_no}"
                                elif isinstance(parent.func, ast.Attribute):
                                    if isinstance(parent.func.value, ast.Name):
                                        context = f"Used as argument {i+1} in call to {parent.func.value.id}.{parent.func.attr}() at line {line_no}"

                propagation_chain.append(
                    {
                        "step_no": len(propagation_chain),
                        "operation": "Usage",
                        "description": f"Used at line {line_no}: {context}",
                        "line": line_no,
                        "var_name": var_name,
                    }
                )

        # Sort the propagation chain by line number where available
        propagation_chain.sort(
            key=lambda x: x.get("line", 0) if x.get("line", 0) > 0 else float("inf")
        )

        return propagation_chain 