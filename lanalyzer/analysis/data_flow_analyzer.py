"""
Data flow analysis for taint analysis call chains.
"""

import re
from typing import Any, Dict, List, Set

from lanalyzer.analysis.visitor import EnhancedTaintAnalysisVisitor


class DataFlowAnalyzer:
    """Analyze data flow between taint sources and sinks."""

    def __init__(self, builder):
        """Initialize with reference to parent builder."""
        self.builder = builder
        self.tracker = builder.tracker
        self.debug = builder.debug

    def find_data_flow_steps(
        self,
        visitor: EnhancedTaintAnalysisVisitor,
        var_name: str,
        source_line: int,
        sink_line: int,
        sink_arg_expressions: List[str],
        data_flow_path: List[Dict[str, Any]],
        added_sources: Set[str],
    ) -> None:
        """
        Find data flow paths from source variable to sink parameters, including variable assignments and transformations.

        Args:
            visitor: Visitor instance
            var_name: Source variable name
            source_line: Line number of source
            sink_line: Line number of sink
            sink_arg_expressions: Parameter expressions in sink
            data_flow_path: List to collect data flow paths
            added_sources: Set of already added sources
        """
        if not hasattr(visitor, "source_lines") or not visitor.source_lines:
            return

        # Build variable usage mapping
        var_usage_map = {}

        # Find all usage points of the variable
        # First collect all relevant assignment statements
        assignments = []
        for line_num in range(source_line + 1, sink_line):
            if line_num > len(visitor.source_lines):
                break

            line = visitor.source_lines[line_num - 1].strip()
            # Check if variable appears in this line
            if var_name in line:
                # If it's an assignment statement and variable is on the right side
                if "=" in line and var_name in line.split("=", 1)[1]:
                    left_side = line.split("=", 1)[0].strip()
                    # Avoid handling cases like var_name1 = var_name2
                    if var_name != left_side and left_side.isidentifier():
                        var_usage_map[left_side] = {
                            "line": line_num,
                            "statement": line,
                            "from_var": var_name,
                        }
                        assignments.append(
                            {
                                "line": line_num,
                                "statement": line,
                                "from_var": var_name,
                                "to_var": left_side,
                            }
                        )

                # Check array index access
                # For example, var2 = var_name[1]
                elif "[" in line and "]" in line and "=" in line:
                    left_side = line.split("=", 1)[0].strip()
                    right_side = line.split("=", 1)[1].strip()
                    # Check if var_name is the base of array index access
                    array_access_pattern = r"{}(?:\s*\[[^\]]+\])".format(
                        re.escape(var_name)
                    )
                    if re.search(array_access_pattern, right_side):
                        # Extract detailed information about index access
                        index_info = self.extract_index_access_info(
                            right_side, var_name
                        )

                        var_usage_map[left_side] = {
                            "line": line_num,
                            "statement": line,
                            "from_var": var_name,
                            "is_array_access": True,
                            "index_info": index_info,
                        }
                        assignments.append(
                            {
                                "line": line_num,
                                "statement": line,
                                "from_var": var_name,
                                "to_var": left_side,
                                "is_array_access": True,
                                "index_info": index_info,
                            }
                        )

        # Sort assignment statements by line number
        assignments.sort(key=lambda x: x["line"])

        # Only add data flow paths that lead to the final sink
        relevant_assignments = []

        # Check if variables used in sink parameters are in our tracked data flow
        for expr in sink_arg_expressions:
            # Check if it contains index access
            if "[" in expr and "]" in expr:
                array_var_match = re.match(r"([a-zA-Z_][a-zA-Z0-9_]*)\s*\[", expr)
                if array_var_match:
                    array_var = array_var_match.group(1)

                    # Extract more details about index access
                    index_info = self.extract_index_access_info(expr, array_var)

                    # Build data flow graph and find path from source variable to variable used in sink
                    visited = set([var_name])
                    path = self.find_var_path(
                        var_name, array_var, var_usage_map, visited
                    )

                    if path:
                        # Convert path to data flow steps
                        for step_var in path[1:]:  # Skip the source variable itself
                            step_info = var_usage_map[step_var]

                            # Enhance data flow description
                            step_desc = (
                                f"Data flow: {step_info['from_var']} → {step_var}"
                            )

                            if step_info.get("is_array_access"):
                                step_index_info = step_info.get("index_info", {})
                                if step_index_info:
                                    index_value = step_index_info.get("index", "?")
                                    step_desc += f" (array element access at index {index_value})"
                                else:
                                    step_desc += " (array element access)"

                            # If this is the variable flowing directly to sink, add more context
                            if step_var == array_var:
                                if index_info.get("is_index_access"):
                                    index_value = index_info.get("index")
                                    index_type = index_info.get("index_type", "unknown")

                                    if index_type == "integer":
                                        step_desc += f" → Final step: {step_var}[{index_value}] used in sink"
                                    else:
                                        step_desc += f" → Final step: {step_var}[{index_value}] used in sink"

                            flow_step = {
                                "function": f"Data flow: {step_info['statement']}",
                                "file": visitor.file_path,
                                "line": step_info["line"],
                                "statement": step_info["statement"],
                                "context_lines": [
                                    step_info["line"] - 1,
                                    step_info["line"] + 1,
                                ],
                                "type": "data_flow",
                                "description": step_desc,
                            }

                            source_key = f"{step_info['line']}:{step_info['statement']}"
                            if source_key not in added_sources:
                                relevant_assignments.append(flow_step)
                    elif var_name == array_var:
                        # Case of direct flow from source variable to sink
                        index_value = index_info.get("index", "?")
                        step_desc = f"Data flow: {var_name}[{index_value}] used directly in sink"

                        # Find the nearest source variable statement for context
                        source_stmt = ""
                        for line_num in range(source_line, sink_line):
                            if line_num > len(visitor.source_lines):
                                break
                            line = visitor.source_lines[line_num - 1].strip()
                            if (
                                var_name in line
                                and "=" in line
                                and line.split("=")[0].strip() == var_name
                            ):
                                source_stmt = line
                                break

                        if source_stmt:
                            flow_step = {
                                "function": "Data flow: Direct use of source variable",
                                "file": visitor.file_path,
                                "line": source_line,
                                "statement": source_stmt,
                                "context_lines": [source_line - 1, source_line + 1],
                                "type": "data_flow",
                                "description": step_desc,
                            }

                            source_key = f"{source_line}:{source_stmt}"
                            if source_key not in added_sources:
                                relevant_assignments.append(flow_step)

        # Sort by line number and add to data flow path
        relevant_assignments.sort(key=lambda x: x["line"])
        for assignment in relevant_assignments:
            data_flow_path.append(assignment)

    def find_var_path(
        self,
        start_var: str,
        target_var: str,
        var_map: Dict[str, Dict[str, Any]],
        visited: Set[str],
    ) -> List[str]:
        """
        Use breadth-first search to find a path from start variable to target variable

        Args:
            start_var: Starting variable name
            target_var: Target variable name
            var_map: Variable mapping relationships
            visited: Set of visited variables

        Returns:
            List of variable names representing path from start_var to target_var, or empty list if no path exists
        """
        if start_var == target_var:
            return [start_var]

        queue = [(start_var, [start_var])]

        while queue:
            current_var, path = queue.pop(0)

            # Find all variables derived from current_var
            for var_name, info in var_map.items():
                if info.get("from_var") == current_var and var_name not in visited:
                    new_path = path + [var_name]

                    if var_name == target_var:
                        return new_path

                    visited.add(var_name)
                    queue.append((var_name, new_path))

        return []  # No path found

    def extract_index_access_info(self, expr: str, var_name: str) -> Dict[str, Any]:
        """
        Extract index access information from expression.
        For example, extract index value "1" from "message[1]", and base variable "message".

        Args:
            expr: Expression containing index access
            var_name: Base variable name

        Returns:
            Dictionary containing index access information
        """
        result = {
            "base_var": var_name,
            "full_expr": expr.strip(),
            "index": None,
            "is_index_access": False,
        }

        # Match index access pattern
        index_match = re.search(r"{}\s*\[(.*?)\]".format(re.escape(var_name)), expr)
        if index_match:
            result["is_index_access"] = True
            result["index"] = index_match.group(1).strip()

            # Try to determine index type (e.g., number, string, etc.)
            index_val = result["index"]
            if index_val.isdigit() or (
                index_val.startswith("-") and index_val[1:].isdigit()
            ):
                result["index_type"] = "integer"
                result["index_value"] = int(index_val)
            elif (index_val.startswith('"') and index_val.endswith('"')) or (
                index_val.startswith("'") and index_val.endswith("'")
            ):
                result["index_type"] = "string"
                result["index_value"] = index_val.strip("'\"")
            else:
                result["index_type"] = "variable"

        return result
