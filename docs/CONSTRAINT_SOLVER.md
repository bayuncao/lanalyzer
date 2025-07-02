# Constraint Solver for Path-Sensitive Analysis

This document describes the constraint propagation algorithm implemented in lanalyzer for path-sensitive analysis.

## Overview

The constraint solver is designed to determine whether execution paths in code are reachable by analyzing the satisfiability of path constraints. This improves the accuracy of taint analysis by eliminating impossible execution paths.

## Features

### Supported Constraint Types

1. **Boolean Constraints**
   - Equality: `x == True`, `x == False`
   - Identity: `x is None`, `x is not None`
   - Truthiness: `if x:` (variable truthiness tests)

2. **Comparison Constraints**
   - Numeric comparisons: `x > 0`, `x <= 5`, `x >= 10`
   - String comparisons: `name == "admin"`

3. **Membership Constraints**
   - Collection membership: `x in list`, `key in dict`
   - Attribute existence: `hasattr(obj, 'attr')`

4. **Type Constraints**
   - Type checking: `isinstance(x, str)`, `isinstance(obj, MyClass)`

5. **Logical Combinations**
   - Boolean operations: `and`, `or`, `not`
   - Branch negation: `else` branches automatically negate conditions

### Algorithm

The constraint solver uses a simplified constraint propagation approach:

1. **Constraint Collection**: Gather all constraints along an execution path
2. **AST Parsing**: Convert AST nodes to constraint objects
3. **Contradiction Detection**: Check for obvious contradictions
4. **Satisfiability**: Return whether the constraint set is satisfiable

## Usage

### Basic Usage

```python
from lanalyzer.analysis.models.constraint_solver import ConstraintSolver, Constraint, ConstraintType

# Create a constraint solver
solver = ConstraintSolver()

# Create constraints
constraint1 = Constraint(
    constraint_type=ConstraintType.BOOLEAN,
    variable="x",
    operator="==",
    value=5
)

constraint2 = Constraint(
    constraint_type=ConstraintType.BOOLEAN,
    variable="x", 
    operator="==",
    value=10
)

# Check satisfiability
result = solver.is_satisfiable([constraint1, constraint2])
print(result)  # False - contradictory constraints
```

### Integration with PathNode

```python
from lanalyzer.analysis.models.path import PathNode, PathSensitiveAnalyzer
import ast

# Create path-sensitive analyzer
analyzer = PathSensitiveAnalyzer()
root_ast = ast.Module(body=[], type_ignores=[])
root_node = analyzer.initialize_analysis(root_ast)

# Add conditional branch
condition_code = "x > 0"
condition_tree = ast.parse(condition_code, mode='eval')
branch_node = analyzer.enter_conditional(condition_tree.body, "then")

# Check if path is reachable
is_reachable = branch_node.is_reachable()
print(f"Path reachable: {is_reachable}")

# Get constraint summary
summary = branch_node.get_constraint_summary()
print(f"Constraints: {summary}")
```

### AST Constraint Parsing

```python
from lanalyzer.analysis.models.constraint_solver import parse_ast_to_constraint
import ast

# Parse different types of conditions
test_cases = [
    "x == 5",                    # Boolean constraint
    "x > 0",                     # Comparison constraint  
    "isinstance(x, str)",        # Type constraint
    "hasattr(obj, 'attr')",      # Membership constraint
    "x",                         # Truthiness test
]

for code in test_cases:
    tree = ast.parse(code, mode='eval')
    constraint = parse_ast_to_constraint(tree.body, "then")
    if constraint:
        print(f"{code} -> {constraint}")
```

## Implementation Details

### Constraint Representation

Each constraint is represented by a `Constraint` object with:
- `constraint_type`: The type of constraint (boolean, comparison, etc.)
- `variable`: The variable being constrained
- `operator`: The operation being performed
- `value`: The value being compared against
- `ast_node`: The original AST node for complex analysis
- `negated`: Whether the constraint is negated (from else branches)

### Satisfiability Algorithm

The current implementation uses a heuristic-based approach:

1. **Group constraints by variable**
2. **Check for obvious contradictions** (e.g., `x == 5` and `x == 10`)
3. **Assume satisfiable** if no contradictions found

This approach is designed for performance in static analysis scenarios where:
- Most paths are actually reachable
- Complex constraint solving is not required
- False positives are acceptable, false negatives are not

### Performance Characteristics

- **Time Complexity**: O(n) where n is the number of constraints
- **Space Complexity**: O(n) for constraint storage
- **Scalability**: Designed for analyzing large codebases efficiently

## Limitations

1. **Simplified Logic**: Does not perform full constraint solving
2. **Limited Type System**: Basic type constraint handling
3. **No Arithmetic**: Does not solve arithmetic constraints
4. **Heuristic-Based**: May miss some contradictions

## Future Enhancements

Potential improvements for more sophisticated constraint solving:

1. **Domain Tracking**: Track possible values for each variable
2. **Arithmetic Constraints**: Handle numeric relationships
3. **Type Hierarchy**: Support inheritance and type relationships
4. **SMT Integration**: Optional integration with Z3 for complex cases
5. **Constraint Simplification**: Reduce constraint sets before solving

## Examples

See `examples/constraint_solver_demo.py` for comprehensive examples demonstrating:
- Basic constraint solving
- AST parsing
- Path-sensitive analysis
- Real-world scenarios

## Testing

Run the constraint solver tests:

```bash
python -m pytest tests/test_constraint_solver.py -v
```

The test suite covers:
- Constraint creation and representation
- AST parsing for different node types
- Satisfiability checking
- Integration with PathNode
- Real-world scenarios
