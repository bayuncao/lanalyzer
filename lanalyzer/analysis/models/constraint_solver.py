"""
Simple constraint solver for path-sensitive analysis.

This module provides a lightweight constraint propagation algorithm
for determining path reachability in static analysis.
"""

import ast
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class ConstraintType(Enum):
    """Types of constraints supported by the solver."""

    BOOLEAN = "boolean"  # x == True, x is None
    COMPARISON = "comparison"  # x > 0, len(x) > 5
    MEMBERSHIP = "membership"  # x in list, hasattr(x, 'attr')
    TYPE_CHECK = "type_check"  # isinstance(x, str)
    LOGICAL = "logical"  # and, or, not


class Constraint:
    """
    Represents a single constraint in the path analysis.

    A constraint consists of:
    - constraint_type: The type of constraint (boolean, comparison, etc.)
    - variable: The variable being constrained (if applicable)
    - operator: The operation being performed
    - value: The value being compared against
    - ast_node: The original AST node for complex analysis
    """

    def __init__(
        self,
        constraint_type: ConstraintType,
        variable: Optional[str] = None,
        operator: Optional[str] = None,
        value: Any = None,
        ast_node: Optional[ast.AST] = None,
        negated: bool = False,
    ):
        self.constraint_type = constraint_type
        self.variable = variable
        self.operator = operator
        self.value = value
        self.ast_node = ast_node
        self.negated = negated

    def __repr__(self) -> str:
        neg_str = "NOT " if self.negated else ""
        if self.variable and self.operator and self.value is not None:
            return f"{neg_str}{self.variable} {self.operator} {self.value}"
        elif self.variable:
            return f"{neg_str}{self.variable}"
        else:
            return f"{neg_str}{self.constraint_type.value}"


class ConstraintSolver:
    """
    Simple constraint propagation solver for path reachability analysis.

    This solver uses basic constraint propagation techniques to determine
    if a set of constraints is satisfiable, which helps determine if a
    code path is reachable.
    """

    def __init__(self, debug: bool = False):
        self.debug = debug
        self.variable_domains: Dict[str, Set[Any]] = {}
        self.constraints: List[Constraint] = []

    def add_constraint(self, constraint: Constraint) -> None:
        """Add a constraint to the solver."""
        self.constraints.append(constraint)

        # Initialize variable domain if needed
        if constraint.variable and constraint.variable not in self.variable_domains:
            self.variable_domains[constraint.variable] = set()

    def is_satisfiable(self, constraints: List[Constraint]) -> bool:
        """
        Check if a list of constraints is satisfiable.

        Args:
            constraints: List of constraints to check

        Returns:
            True if constraints are satisfiable, False otherwise
        """
        # Check for boolean constant constraints first
        for constraint in constraints:
            if (
                constraint.constraint_type == ConstraintType.BOOLEAN
                and constraint.variable is None
            ):
                # This is a boolean constant constraint (True/False)
                if constraint.operator == "constant":
                    expected_value = constraint.value
                    if constraint.negated:
                        expected_value = not expected_value

                    # If we have a False constant constraint, the path is unsatisfiable
                    if not expected_value:
                        if self.debug:
                            print(
                                f"[CONSTRAINT_SOLVER] Found unsatisfiable boolean constant: {constraint}"
                            )
                        return False

        # Check for obvious contradictions in variable constraints
        variable_constraints = {}
        for constraint in constraints:
            if constraint.variable:
                if constraint.variable not in variable_constraints:
                    variable_constraints[constraint.variable] = []
                variable_constraints[constraint.variable].append(constraint)

        # Check for contradictory constraints on the same variable
        for var, var_constraints in variable_constraints.items():
            if self._has_contradictory_constraints(var_constraints):
                return False

        # If no obvious contradictions, assume satisfiable
        return True

    def _propagate_constraints(self) -> bool:
        """
        Apply constraint propagation algorithm.

        Returns:
            True if constraints are consistent, False if contradiction found
        """
        changed = True
        iterations = 0
        max_iterations = 100  # Prevent infinite loops

        while changed and iterations < max_iterations:
            changed = False
            iterations += 1

            for constraint in self.constraints:
                if self._apply_constraint(constraint):
                    changed = True

                # Check for contradictions
                if self._has_contradiction():
                    if self.debug:
                        print(
                            f"Contradiction found after applying constraint: {constraint}"
                        )
                    return False

        return True

    def _apply_constraint(self, constraint: Constraint) -> bool:
        """
        Apply a single constraint and update variable domains.

        Args:
            constraint: The constraint to apply

        Returns:
            True if domains were modified, False otherwise
        """
        if constraint.constraint_type == ConstraintType.BOOLEAN:
            return self._apply_boolean_constraint(constraint)
        elif constraint.constraint_type == ConstraintType.COMPARISON:
            return self._apply_comparison_constraint(constraint)
        elif constraint.constraint_type == ConstraintType.MEMBERSHIP:
            return self._apply_membership_constraint(constraint)
        elif constraint.constraint_type == ConstraintType.TYPE_CHECK:
            return self._apply_type_constraint(constraint)
        elif constraint.constraint_type == ConstraintType.LOGICAL:
            return self._apply_logical_constraint(constraint)

        return False

    def _apply_boolean_constraint(self, constraint: Constraint) -> bool:
        """Apply boolean constraints like x == True, x is None."""
        if not constraint.variable:
            return False

        var_domain = self.variable_domains[constraint.variable]

        if constraint.operator == "==" or constraint.operator == "is":
            target_value = constraint.value
            if constraint.negated:
                # x != True means x can be anything except True
                # For negated constraints, we assume the domain is satisfiable
                # unless we have explicit contradictions
                return False  # No domain change needed for negated constraints
            else:
                # x == True means x can only be True
                if not var_domain or target_value not in var_domain:
                    var_domain.clear()
                    var_domain.add(target_value)
                    return True
        elif constraint.operator == "truthiness":
            # Variable truthiness test
            if constraint.negated:
                # Variable is falsy - could be False, None, 0, [], etc.
                return False  # Assume satisfiable
            else:
                # Variable is truthy - could be True, non-zero numbers, non-empty collections, etc.
                return False  # Assume satisfiable

        return False

    def _apply_comparison_constraint(self, constraint: Constraint) -> bool:
        """Apply comparison constraints like x > 0, len(x) > 5."""
        # For simplicity, we'll handle basic numeric comparisons
        if not constraint.variable or constraint.value is None:
            return False

        # This is a simplified implementation
        # In practice, you'd want more sophisticated domain handling
        return False

    def _apply_membership_constraint(self, constraint: Constraint) -> bool:
        """Apply membership constraints like x in list, hasattr(x, 'attr')."""
        if not constraint.variable:
            return False

        # Simplified implementation for common cases
        if constraint.operator == "in":
            # For 'x in collection', we can't easily propagate without knowing collection
            return False
        elif constraint.operator == "hasattr":
            # For hasattr(x, 'attr'), we assume it's satisfiable
            return False

        return False

    def _apply_type_constraint(self, constraint: Constraint) -> bool:
        """Apply type constraints like isinstance(x, str)."""
        if not constraint.variable:
            return False

        # Simplified type constraint handling
        var_domain = self.variable_domains[constraint.variable]

        if constraint.operator == "isinstance":
            target_type = constraint.value
            if constraint.negated:
                # Remove instances of target_type from domain
                # This is simplified - in practice you'd need type hierarchy
                return False
            else:
                # Keep only instances of target_type
                # This is simplified - in practice you'd need type hierarchy
                return False

        return False

    def _apply_logical_constraint(self, constraint: Constraint) -> bool:
        """Apply logical constraints like and, or, not."""
        # Logical constraints are typically handled at a higher level
        # by combining multiple constraints
        return False

    def _has_contradiction(self) -> bool:
        """Check if current variable domains contain contradictions."""
        for var, domain in self.variable_domains.items():
            # Only check for contradictions if domain has been explicitly constrained
            # Empty domain at initialization is not a contradiction
            if len(domain) == 0 and hasattr(self, "_domain_constrained"):
                if var in getattr(self, "_domain_constrained", set()):
                    return True

        return False

    def _has_contradictory_constraints(self, constraints: List[Constraint]) -> bool:
        """
        Check if a list of constraints on the same variable are contradictory.

        Args:
            constraints: List of constraints for the same variable

        Returns:
            True if constraints are contradictory, False otherwise
        """
        # Simple contradiction detection
        # Look for x == A and x == B where A != B
        equality_values = []

        for constraint in constraints:
            if constraint.constraint_type == ConstraintType.BOOLEAN:
                if constraint.operator == "==" and not constraint.negated:
                    equality_values.append(constraint.value)
                elif constraint.operator == "==" and constraint.negated:
                    # x != A is not directly contradictory with x == B unless A == B
                    pass

        # If we have multiple different equality constraints, that's a contradiction
        if len(set(equality_values)) > 1:
            return True

        return False


def parse_ast_to_constraint(
    ast_node: ast.AST, branch_type: str
) -> Optional[Constraint]:
    """
    Parse an AST node into a constraint.

    Args:
        ast_node: The AST node to parse
        branch_type: The type of branch ('then', 'else', 'loop', etc.)

    Returns:
        Constraint object if parsing successful, None otherwise
    """
    negated = branch_type == "else"

    if isinstance(ast_node, ast.Compare):
        return _parse_comparison(ast_node, negated)
    elif isinstance(ast_node, ast.Call):
        return _parse_call(ast_node, negated)
    elif isinstance(ast_node, ast.Name):
        return _parse_name(ast_node, negated)
    elif isinstance(ast_node, ast.Constant):
        return _parse_constant(ast_node, negated)
    elif isinstance(ast_node, ast.BoolOp):
        return _parse_bool_op(ast_node, negated)

    return None


def _parse_comparison(ast_node: ast.Compare, negated: bool) -> Optional[Constraint]:
    """Parse comparison nodes like x > 0, x == None."""
    if len(ast_node.comparators) != 1 or len(ast_node.ops) != 1:
        return None

    left = ast_node.left
    op = ast_node.ops[0]
    right = ast_node.comparators[0]

    # Extract variable name from left side
    if isinstance(left, ast.Name):
        variable = left.id
    else:
        return None

    # Extract operator
    op_map = {
        ast.Eq: "==",
        ast.NotEq: "!=",
        ast.Lt: "<",
        ast.LtE: "<=",
        ast.Gt: ">",
        ast.GtE: ">=",
        ast.Is: "is",
        ast.IsNot: "is not",
        ast.In: "in",
        ast.NotIn: "not in",
    }

    operator = op_map.get(type(op))
    if not operator:
        return None

    # Extract value from right side
    if isinstance(right, ast.Constant):
        value = right.value
    elif isinstance(right, ast.Name):
        value = right.id  # Variable reference
    else:
        return None

    # Determine constraint type
    if operator in ["==", "!=", "is", "is not"]:
        constraint_type = ConstraintType.BOOLEAN
    elif operator in ["<", "<=", ">", ">="]:
        constraint_type = ConstraintType.COMPARISON
    elif operator in ["in", "not in"]:
        constraint_type = ConstraintType.MEMBERSHIP
    else:
        return None

    return Constraint(
        constraint_type=constraint_type,
        variable=variable,
        operator=operator,
        value=value,
        ast_node=ast_node,
        negated=negated,
    )


def _parse_call(ast_node: ast.Call, negated: bool) -> Optional[Constraint]:
    """Parse function calls like isinstance(x, str), hasattr(x, 'attr')."""
    if isinstance(ast_node.func, ast.Name):
        func_name = ast_node.func.id

        if func_name == "isinstance" and len(ast_node.args) == 2:
            # isinstance(x, type)
            if isinstance(ast_node.args[0], ast.Name):
                variable = ast_node.args[0].id
                # For simplicity, we'll store the type as a string
                if isinstance(ast_node.args[1], ast.Name):
                    type_name = ast_node.args[1].id
                else:
                    return None

                return Constraint(
                    constraint_type=ConstraintType.TYPE_CHECK,
                    variable=variable,
                    operator="isinstance",
                    value=type_name,
                    ast_node=ast_node,
                    negated=negated,
                )

        elif func_name == "hasattr" and len(ast_node.args) == 2:
            # hasattr(x, 'attr')
            if isinstance(ast_node.args[0], ast.Name) and isinstance(
                ast_node.args[1], ast.Constant
            ):
                variable = ast_node.args[0].id
                attr_name = ast_node.args[1].value

                return Constraint(
                    constraint_type=ConstraintType.MEMBERSHIP,
                    variable=variable,
                    operator="hasattr",
                    value=attr_name,
                    ast_node=ast_node,
                    negated=negated,
                )

    return None


def _parse_name(ast_node: ast.Name, negated: bool) -> Optional[Constraint]:
    """Parse name nodes like x (truthiness test)."""
    variable = ast_node.id

    return Constraint(
        constraint_type=ConstraintType.BOOLEAN,
        variable=variable,
        operator="truthiness",
        value=True,
        ast_node=ast_node,
        negated=negated,
    )


def _parse_constant(ast_node: ast.Constant, negated: bool) -> Optional[Constraint]:
    """Parse constant nodes like True, False."""
    value = ast_node.value

    if isinstance(value, bool):
        return Constraint(
            constraint_type=ConstraintType.BOOLEAN,
            variable=None,
            operator="constant",
            value=value,
            ast_node=ast_node,
            negated=negated,
        )

    return None


def _parse_bool_op(ast_node: ast.BoolOp, negated: bool) -> Optional[Constraint]:
    """Parse boolean operations like and, or."""
    # For now, we'll return a logical constraint placeholder
    # Complex logical operations would need special handling
    return Constraint(
        constraint_type=ConstraintType.LOGICAL,
        variable=None,
        operator="and" if isinstance(ast_node.op, ast.And) else "or",
        value=None,
        ast_node=ast_node,
        negated=negated,
    )
