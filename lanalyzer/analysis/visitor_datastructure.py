"""
Enhanced AST visitor for taint analysis - Data structure related operations.
"""

import ast
import copy

from .visitor_base import EnhancedTaintVisitor
from .datastructures import DataStructureNode


class DataStructureVisitorMixin:
    """Mixin for data structure-related visit methods."""

    def _track_data_structure_operations(
        self: "EnhancedTaintVisitor", node: ast.Call, func_name: str, full_name: str
    ) -> None:
        """Track taint propagation through data structure operations."""
        # Handle dictionary, list, and object operations
        if isinstance(node.func, ast.Attribute) and isinstance(
            node.func.value, ast.Name
        ):
            obj_name = node.func.value.id
            attr_name = node.func.attr

            # Check if this is an operation on a tainted container
            if obj_name in self.variable_taint:
                # Dictionary methods
                if attr_name in ["get", "pop", "items", "keys", "values"]:
                    # Find the assignment this call is part of, if any
                    if hasattr(node, "parent") and isinstance(node.parent, ast.Assign):
                        for target in node.parent.targets:
                            if isinstance(target, ast.Name):
                                # Propagate taint to target variable
                                self.variable_taint[target.id] = self.variable_taint[
                                    obj_name
                                ]

                                # Create complex data structure node if needed
                                if obj_name not in self.data_structures:
                                    self.data_structures[obj_name] = DataStructureNode(
                                        obj_name, "dict"
                                    )
                                    self.data_structures[obj_name].tainted = True
                                    self.data_structures[
                                        obj_name
                                    ].source_info = self.variable_taint[obj_name]

                                if self.debug:
                                    print(
                                        f"Propagated taint from dict {obj_name} to {target.id} via {attr_name}"
                                    )

    def _track_container_methods(self: "EnhancedTaintVisitor", node: ast.Call) -> None:
        """Track taint propagation through container methods like list.append, dict.update, etc."""
        if isinstance(node.func, ast.Attribute) and isinstance(
            node.func.value, ast.Name
        ):
            container_name = node.func.value.id
            method_name = node.func.attr

            # Check if this container is in our data structures
            if container_name in self.data_structures:
                container = self.data_structures[container_name]
                lineno = getattr(node, "lineno", 0)

                # Handle dictionary methods
                if container.node_type == "dict":
                    if method_name == "update" and node.args:
                        # dict.update() method - check if argument is tainted
                        arg = node.args[0]
                        if isinstance(arg, ast.Name) and arg.id in self.variable_taint:
                            # Mark entire dict as tainted
                            container.mark_tainted(
                                self.variable_taint[arg.id],
                                f"Dictionary updated with tainted data from '{arg.id}' at line {lineno}",
                            )
                            if self.debug:
                                print(
                                    f"Dictionary {container_name} tainted by update() with {arg.id}"
                                )

                    elif method_name == "setdefault" and len(node.args) >= 2:
                        # dict.setdefault(key, default) - check if default value is tainted
                        key = node.args[0]
                        default = node.args[1]

                        if (
                            isinstance(default, ast.Name)
                            and default.id in self.variable_taint
                        ):
                            # Mark specific key as tainted
                            key_value = None
                            if isinstance(key, ast.Constant):
                                key_value = key.value
                            elif isinstance(key, ast.Name):
                                key_value = key.id

                            if key_value is not None:
                                container.add_tainted_key(
                                    key_value,
                                    self.variable_taint[default.id],
                                    f"Key set with tainted default value from '{default.id}' at line {lineno}",
                                )
                                if self.debug:
                                    print(
                                        f"Dictionary {container_name} key '{key_value}' tainted by setdefault()"
                                    )

                # Handle list methods
                elif container.node_type == "list":
                    if method_name == "append" and node.args:
                        # list.append() method - check if argument is tainted
                        arg = node.args[0]
                        if isinstance(arg, ast.Name) and arg.id in self.variable_taint:
                            # Get current list length (approximate)
                            idx = (
                                len(container.tainted_indices)
                                if container.tainted
                                else 0
                            )

                            # Mark the appended index as tainted
                            container.add_tainted_index(
                                idx,
                                self.variable_taint[arg.id],
                                f"List appended with tainted data from '{arg.id}' at line {lineno}",
                            )
                            if self.debug:
                                print(
                                    f"List {container_name} index {idx} tainted by append() with {arg.id}"
                                )

                    elif method_name == "extend" and node.args:
                        # list.extend() method - check if argument is tainted
                        arg = node.args[0]
                        if isinstance(arg, ast.Name):
                            if arg.id in self.variable_taint:
                                # Mark entire list as tainted
                                container.mark_tainted(
                                    self.variable_taint[arg.id],
                                    f"List extended with tainted data from '{arg.id}' at line {lineno}",
                                )
                                if self.debug:
                                    print(
                                        f"List {container_name} tainted by extend() with {arg.id}"
                                    )
                            elif arg.id in self.data_structures:
                                # Propagate taint from another data structure
                                other_container = self.data_structures[arg.id]
                                if other_container.tainted:
                                    container.mark_tainted(
                                        other_container.source_info,
                                        f"List extended with tainted data structure '{arg.id}' at line {lineno}",
                                    )
                                    # Link the two containers
                                    container.add_parent_structure(arg.id)
                                    other_container.add_child_structure(container_name)
                                    if self.debug:
                                        print(
                                            f"List {container_name} tainted by extend() with tainted data structure {arg.id}"
                                        )

                    elif method_name == "insert" and len(node.args) >= 2:
                        # list.insert(index, value) - check if value is tainted
                        value = node.args[1]
                        if (
                            isinstance(value, ast.Name)
                            and value.id in self.variable_taint
                        ):
                            # Mark entire list as tainted since we don't know the exact index in static analysis
                            container.mark_tainted(
                                self.variable_taint[value.id],
                                f"List inserted with tainted data from '{value.id}' at line {lineno}",
                            )
                            if self.debug:
                                print(
                                    f"List {container_name} tainted by insert() with {value.id}"
                                )

    def _track_complex_data_assignments(
        self: "EnhancedTaintVisitor", node: ast.Assign
    ) -> None:
        """Track taint in complex data structure assignments with enhanced propagation tracking."""
        # Handle dictionary assignments
        if isinstance(node.value, ast.Dict):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    dict_name = target.id

                    # Check if any key/value is tainted
                    tainted_dict = False
                    tainted_keys = set()

                    for i, (key, value) in enumerate(
                        zip(node.value.keys, node.value.values)
                    ):
                        # Check if value is tainted
                        if (
                            isinstance(value, ast.Name)
                            and value.id in self.variable_taint
                        ):
                            tainted_dict = True
                            key_repr = "unknown"
                            if isinstance(key, ast.Constant):
                                key_repr = repr(key.value)
                                tainted_keys.add(key.value)
                            elif isinstance(key, ast.Name):
                                key_repr = key.id
                                tainted_keys.add(key.id)

                    if tainted_dict:
                        # Create data structure entry
                        self.data_structures[dict_name] = DataStructureNode(
                            dict_name, "dict"
                        )
                        dict_node = self.data_structures[dict_name]

                        # Mark with taint information
                        dict_taint_info = {
                            "name": "ComplexDataStructure",
                            "line": getattr(node, "lineno", 0),
                            "col": getattr(node, "col_offset", 0),
                        }

                        # Add tainted keys
                        for key in tainted_keys:
                            dict_node.add_tainted_key(key, dict_taint_info)

                        # Mark the entire dictionary as tainted
                        dict_node.mark_tainted(
                            dict_taint_info,
                            f"Dictionary created with tainted values at line {getattr(node, 'lineno', 0)}",
                        )

                        # Update variable taint tracking
                        self.variable_taint[dict_name] = dict_taint_info

                        if self.debug:
                            print(
                                f"Created tainted dictionary {dict_name} with tainted keys {tainted_keys}"
                            )

        # Handle list assignments with enhanced tracking
        elif isinstance(node.value, ast.List):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    list_name = target.id

                    # Check if any element is tainted
                    tainted_list = False
                    tainted_indices = set()

                    for i, elt in enumerate(node.value.elts):
                        if isinstance(elt, ast.Name) and elt.id in self.variable_taint:
                            tainted_list = True
                            tainted_indices.add(i)

                    if tainted_list:
                        # Create data structure entry
                        self.data_structures[list_name] = DataStructureNode(
                            list_name, "list"
                        )
                        list_node = self.data_structures[list_name]

                        # Mark with taint information
                        list_taint_info = {
                            "name": "ComplexDataStructure",
                            "line": getattr(node, "lineno", 0),
                            "col": getattr(node, "col_offset", 0),
                        }

                        # Add tainted indices
                        for idx in tainted_indices:
                            list_node.add_tainted_index(idx, list_taint_info)

                        # Mark the entire list as tainted
                        list_node.mark_tainted(
                            list_taint_info,
                            f"List created with tainted values at line {getattr(node, 'lineno', 0)}",
                        )

                        # Update variable taint tracking
                        self.variable_taint[list_name] = list_taint_info

                        if self.debug:
                            print(
                                f"Created tainted list {list_name} with tainted indices {tainted_indices}"
                            )

    def visit_Subscript(self: "EnhancedTaintVisitor", node: ast.Subscript) -> None:
        """Visit subscript operations on complex data structures."""
        # Track taint propagation through subscripts
        if isinstance(node.value, ast.Name):
            var_name = node.value.id

            # Check if accessing a tainted data structure
            if var_name in self.data_structures:
                data_struct = self.data_structures[var_name]

                # For dictionary access with constant key
                if data_struct.node_type == "dict" and isinstance(
                    node.slice, ast.Constant
                ):
                    if data_struct.is_key_tainted(node.slice.value):
                        # Propagate taint if this is part of an assignment
                        if hasattr(node, "parent") and isinstance(
                            node.parent, ast.Assign
                        ):
                            for target in node.parent.targets:
                                if isinstance(target, ast.Name):
                                    self.variable_taint[
                                        target.id
                                    ] = data_struct.source_info
                                    if self.debug:
                                        print(
                                            f"Propagated taint from {var_name}[{node.slice.value}] to {target.id}"
                                        )

                # For list access with constant index
                elif data_struct.node_type == "list" and isinstance(
                    node.slice, ast.Constant
                ):
                    if data_struct.is_index_tainted(node.slice.value):
                        # Propagate taint if this is part of an assignment
                        if hasattr(node, "parent") and isinstance(
                            node.parent, ast.Assign
                        ):
                            for target in node.parent.targets:
                                if isinstance(target, ast.Name):
                                    self.variable_taint[
                                        target.id
                                    ] = data_struct.source_info
                                    if self.debug:
                                        print(
                                            f"Propagated taint from {var_name}[{node.slice.value}] to {target.id}"
                                        )

        # Continue visiting
        self.generic_visit(node)

    def visit_Assign(self: "EnhancedTaintVisitor", node: ast.Assign) -> None:
        """Enhanced assignment visitor with improved taint tracking."""
        # Call parent method first
        super().visit_Assign(node)

        # Update def-use chains
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                if var_name not in self.def_use_chains:
                    self.def_use_chains[var_name] = self.defuse.DefUseChain(var_name)
                self.def_use_chains[var_name].add_definition(
                    node, getattr(node, "lineno", 0)
                )

                # Check if variable is tainted and update chain
                if var_name in self.variable_taint:
                    self.def_use_chains[var_name].tainted = True
                    if (
                        self.variable_taint[var_name]
                        not in self.def_use_chains[var_name].taint_sources
                    ):
                        self.def_use_chains[var_name].taint_sources.append(
                            self.variable_taint[var_name]
                        )

        # Track complex data structure assignments
        self._track_complex_data_assignments(node)

        # Add path constraint for assignment
        if self.current_path:
            assign_path = self.pathsensitive.PathNode(node, self.current_path)
            self.current_path.add_child(assign_path)
            # Copy current variable taint state to this path node
            assign_path.variable_taint = copy.deepcopy(self.variable_taint)
