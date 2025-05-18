"""
AST utility functions for LanaLyzer.

Provides basic utility functions for working with Python Abstract Syntax Trees (AST).
General utility functions not specific to analysis modules.
"""

import ast
import os
from typing import Any, Dict, List, Optional, Set, Tuple

from lanalyzer.logger import error


def parse_file(file_path: str, encoding: str = "utf-8") -> Optional[ast.Module]:
    """
    Parse a Python file into an AST.

    Args:
        file_path: Path to the Python file
        encoding: File encoding (default: utf-8)

    Returns:
        AST Module node representing the file

    Raises:
        SyntaxError: If the file contains syntax errors
        FileNotFoundError: If the file doesn't exist
        PermissionError: If the file can't be read
    """
    if not os.path.exists(file_path):
        error(f"Error: File not found: {file_path}")
        return None

    try:
        with open(file_path, "r", encoding=encoding) as f:
            source_code = f.read()
        return ast.parse(source_code, filename=file_path)
    except SyntaxError as e:
        error(f"Syntax error in {file_path}: {str(e)}")
        return None
    except UnicodeDecodeError as e:
        error(f"Error decoding {file_path} with encoding {encoding}: {str(e)}")
        return None
    except Exception as e:
        error(f"Error parsing {file_path}: {str(e)}")
        return None


def get_function_definitions(tree: ast.Module) -> Dict[str, ast.FunctionDef]:
    """
    Get all function definitions in an AST.

    Args:
        tree: AST to search for function definitions

    Returns:
        Dictionary mapping function names to their FunctionDef nodes
    """
    functions = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            functions[node.name] = node

    return functions


def get_class_definitions(tree: ast.Module) -> Dict[str, ast.ClassDef]:
    """
    Get all class definitions in an AST.

    Args:
        tree: AST to search for class definitions

    Returns:
        Dictionary mapping class names to their ClassDef nodes
    """
    classes = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            classes[node.name] = node

    return classes


def get_call_names(tree: ast.Module) -> Set[str]:
    """
    Get all function call names in an AST.

    Args:
        tree: AST to search for function calls

    Returns:
        Set of function call names
    """
    call_names = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                call_names.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                call_names.add(node.func.attr)

    return call_names


def get_function_parameters(func_def: ast.FunctionDef) -> List[str]:
    """
    Get the parameter names of a function.

    Args:
        func_def: FunctionDef node

    Returns:
        List of parameter names
    """
    params = []

    for arg in func_def.args.args:
        params.append(arg.arg)

    if func_def.args.vararg:
        params.append(func_def.args.vararg.arg)

    if func_def.args.kwarg:
        params.append(func_def.args.kwarg.arg)

    for arg in func_def.args.kwonlyargs:
        params.append(arg.arg)

    return params


def get_function_local_variables(func_def: ast.FunctionDef) -> Set[str]:
    """
    Get all local variables defined in a function.

    Args:
        func_def: FunctionDef node

    Returns:
        Set of local variable names
    """
    local_vars = set()

    # Add parameters
    for param in get_function_parameters(func_def):
        local_vars.add(param)

    # Add variables that are assigned to
    for node in ast.walk(func_def):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    local_vars.add(target.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            local_vars.add(node.target.id)
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
            local_vars.add(node.target.id)
        elif isinstance(node, ast.For) and isinstance(node.target, ast.Name):
            local_vars.add(node.target.id)
        elif isinstance(node, ast.With):
            for item in node.items:
                if isinstance(item.optional_vars, ast.Name):
                    local_vars.add(item.optional_vars.id)

    return local_vars


def find_function_calls(tree: ast.Module, function_name: str) -> List[ast.Call]:
    """
    Find all calls to a specific function in an AST.

    Args:
        tree: AST to search
        function_name: Name of the function to find calls for

    Returns:
        List of Call nodes representing calls to the function
    """
    calls = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == function_name:
                calls.append(node)
            elif (
                isinstance(node.func, ast.Attribute) and node.func.attr == function_name
            ):
                calls.append(node)

    return calls


def get_assignment_targets(tree: ast.Module) -> Dict[str, List[ast.Assign]]:
    """
    Get all assignment targets in an AST.

    Args:
        tree: AST to search for assignments

    Returns:
        Dictionary mapping variable names to the Assign nodes that target them
    """
    assignments = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    if target.id not in assignments:
                        assignments[target.id] = []
                    assignments[target.id].append(node)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id not in assignments:
                assignments[node.target.id] = []
            assignments[node.target.id].append(node)  # type: ignore

    return assignments


def get_import_names(tree: ast.Module) -> Dict[str, str]:
    """
    Get all import names in an AST.

    Args:
        tree: AST to search for imports

    Returns:
        Dictionary mapping imported names to their module paths
    """
    imports = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for name in node.names:
                imports[name.asname or name.name] = name.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for name in node.names:
                if name.name == "*":
                    continue  # Can't track * imports statically
                imports[name.asname or name.name] = f"{module}.{name.name}"

    return imports


def get_function_calls_with_args(
    tree: ast.Module,
) -> List[Tuple[str, List[Any], Dict[str, Any]]]:
    """
    Get all function calls with their arguments.

    Args:
        tree: AST to search for function calls

    Returns:
        List of tuples (function_name, args, kwargs)
    """
    calls = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = None
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr

            if func_name:
                # Get positional args
                args = []
                for arg in node.args:
                    if isinstance(arg, ast.Constant):
                        args.append(arg.value)
                    elif isinstance(arg, ast.Name):
                        args.append(arg.id)
                    else:
                        args.append("complex_expression")

                # Get keyword args
                kwargs = {}
                for kwarg in node.keywords:
                    key = kwarg.arg
                    if key is None:  # For **kwargs
                        continue
                    if isinstance(kwarg.value, ast.Constant):
                        kwargs[key] = kwarg.value.value
                    elif isinstance(kwarg.value, ast.Name):
                        kwargs[key] = kwarg.value.id
                    else:
                        kwargs[key] = "complex_expression"

                calls.append((func_name, args, kwargs))

    return calls


def find_source_locations(tree: ast.Module, pattern: str) -> List[Tuple[int, int]]:
    """
    Find source locations (line, col) in the code that match a text pattern.

    Args:
        tree: AST of the code to search
        pattern: Text pattern to search for

    Returns:
        List of (line, col) tuples for locations matching the pattern
    """
    source_lines = ast.unparse(tree).split("\n")
    locations = []

    for i, line in enumerate(source_lines):
        col = line.find(pattern)
        if col != -1:
            # AST line numbers are 1-indexed
            locations.append((i + 1, col))

    return locations


def get_node_source_code(node: ast.AST, source_code: str) -> str:
    """
    Extract the source code for a given AST node.

    Args:
        node: AST node
        source_code: Complete source code string

    Returns:
        Source code for the AST node or empty string if not available
    """
    if not hasattr(node, "lineno") or not hasattr(node, "end_lineno"):
        return ""

    source_lines = source_code.splitlines()

    # AST line numbers are 1-indexed, but list indices are 0-indexed
    start_line = node.lineno - 1
    end_line = getattr(node, "end_lineno", node.lineno) - 1  # type: ignore

    if start_line >= len(source_lines) or end_line >= len(source_lines):
        return ""  # Should not happen with valid AST nodes from parsed code

    start_col = getattr(node, "col_offset", 0)
    end_col = getattr(node, "end_col_offset", len(source_lines[end_line]))  # type: ignore

    if start_line == end_line:
        return source_lines[start_line][start_col:end_col]
    else:
        result = [source_lines[start_line][start_col:]]
        for i in range(start_line + 1, end_line):
            result.append(source_lines[i])
        result.append(source_lines[end_line][:end_col])
        return "\n".join(result)


def extract_call_targets(node: ast.Call) -> List[str]:
    """
    Extract possible function names from a Call node.

    Args:
        node: Call node to extract from

    Returns:
        List of function names that may be called
    """
    if isinstance(node.func, ast.Name):
        # Direct call to a function by name
        return [node.func.id]

    elif isinstance(node.func, ast.Attribute):
        # Method call or dotted access
        attr_chain = []
        current = node.func

        # Build the chain from right to left (e.g., "a.b.func" -> ["func", "b", "a"])
        while isinstance(current, ast.Attribute):
            attr_chain.append(current.attr)
            current = current.value

        if isinstance(current, ast.Name):
            attr_chain.append(current.id)

        results = []
        current_chain_str = ""

        # Build up from right to left
        for part in reversed(attr_chain):
            if current_chain_str:
                current_chain_str = part + "." + current_chain_str
            else:
                current_chain_str = part
            results.append(current_chain_str)

        return results

    return []


def extract_function_calls(ast_node: ast.AST) -> Set[str]:
    """
    Extract all function calls from an AST node.

    Args:
        ast_node: AST node to extract from

    Returns:
        Set of function call names found
    """

    class CallVisitor(ast.NodeVisitor):
        def __init__(self):
            self.calls: Set[str] = set()

        def visit_Call(self, node: ast.Call):
            targets = extract_call_targets(node)
            self.calls.update(targets)
            self.generic_visit(node)

    visitor = CallVisitor()
    visitor.visit(ast_node)
    return visitor.calls


def contains_sink_patterns(code: str, sink_patterns: List[str]) -> bool:
    """
    Check if code contains any sink patterns.

    Args:
        code: Code to check
        sink_patterns: List of sink patterns to check for

    Returns:
        True if any sink pattern is found, False otherwise
    """
    for pattern in sink_patterns:
        if pattern in code:
            return True
    return False
