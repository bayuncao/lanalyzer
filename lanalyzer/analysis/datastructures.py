"""
Complex data structure analysis for enhanced taint tracking.
"""

from typing import Any, Dict, Optional


class DataStructureNode:
    """
    Represents a node in a data structure, such as a dictionary or list.
    """

    def __init__(self, name: str, node_type: str):
        self.name = name
        self.node_type = node_type
        self.tainted = False
        self.tainted_keys = set()
        self.tainted_indices = set()
        self.tainted_attributes = set()
        self.source_info = None
        self.propagation_history = []
        self.parent_structures = set()
        self.child_structures = set()

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
