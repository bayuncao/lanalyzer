"""
Enhanced taint tracker - refactored version.

This module provides the main orchestrator for taint analysis,
consolidating functionality from the original tracker while
simplifying the architecture.
"""

import ast
import os
from typing import Any, Dict, List, Optional, Set, Type, TypeVar

from lanalyzer.logger import debug as log_debug, info, error
from lanalyzer.models import AnalysisResults, Vulnerability
from .ast_processor import ASTProcessor
from .visitor import TaintAnalysisVisitor

T = TypeVar("T", bound="EnhancedTaintTracker")


class EnhancedTaintTracker:
    """
    Enhanced taint tracker for analyzing Python code.
    
    This class orchestrates the entire taint analysis process,
    from AST parsing to vulnerability detection.
    """

    def __init__(self, config: Dict[str, Any], debug: bool = False):
        """
        Initialize the enhanced taint tracker.
        
        Args:
            config: Configuration dictionary with sources, sinks, and rules
            debug: Whether to enable debug output
        """
        self.config = config
        self.debug = debug
        
        # Extract configuration
        self.sources: List[Dict[str, Any]] = config.get("sources", [])
        self.sinks: List[Dict[str, Any]] = config.get("sinks", [])
        self.rules: List[Dict[str, Any]] = config.get("rules", [])
        
        # Analysis state
        self.analyzed_files: Set[str] = set()
        self.current_file_contents: Optional[str] = None
        
        # Global tracking across multiple files
        self.all_functions: Dict[str, Any] = {}
        self.all_tainted_vars: Dict[str, Any] = {}
        self.global_call_graph: Dict[str, List[str]] = {}
        self.module_map: Dict[str, str] = {}
        
        # Core components
        self.ast_processor = ASTProcessor(debug)
        
        # Store last visitor for inspection
        self.visitor: Optional[TaintAnalysisVisitor] = None

    @classmethod
    def from_config(cls: Type[T], config: Dict[str, Any], debug: bool = False) -> T:
        """
        Create an enhanced taint tracker instance from a configuration dictionary.
        
        Args:
            config: Configuration dictionary
            debug: Whether to enable debug output
            
        Returns:
            Initialized EnhancedTaintTracker instance
        """
        return cls(config, debug)

    def analyze_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Analyze a single Python file for taint vulnerabilities.
        
        Args:
            file_path: Path to the Python file to analyze
            
        Returns:
            List of vulnerability dictionaries
        """
        if not os.path.exists(file_path):
            if self.debug:
                log_debug(f"File not found: {file_path}")
            return []

        if file_path in self.analyzed_files:
            if self.debug:
                log_debug(f"File already analyzed: {file_path}")
            return []

        self.analyzed_files.add(file_path)

        if self.debug:
            log_debug(f"Analyzing file: {file_path}")

        try:
            # Parse the file
            tree, source_lines, parent_map = self.ast_processor.parse_file(file_path)
            
            if tree is None:
                return []

            # Store current file contents for context display
            if source_lines:
                self.current_file_contents = "".join(source_lines)

            # Create and configure visitor
            visitor = TaintAnalysisVisitor(
                parent_map=parent_map,
                debug_mode=self.debug,
                verbose=False,
                file_path=file_path,
                source_lines=source_lines,
            )
            
            # Configure visitor with sources and sinks
            visitor.classifier.configure(self.sources, self.sinks)
            
            # Visit the AST
            visitor.visit(tree)
            
            # Store visitor for potential inspection
            self.visitor = visitor
            
            # Update global state
            self._update_global_state(visitor, file_path)
            
            # Convert vulnerabilities to standard format
            vulnerabilities = self._convert_vulnerabilities(visitor)
            
            if self.debug:
                log_debug(f"Found {len(vulnerabilities)} vulnerabilities in {file_path}")
            
            return vulnerabilities

        except Exception as e:
            if self.debug:
                log_debug(f"Error analyzing {file_path}: {e}")
                import traceback
                log_debug(traceback.format_exc())
            return []

    def analyze_multiple_files(self, file_paths: List[str]) -> List[Dict[str, Any]]:
        """
        Analyze multiple Python files with cross-file taint propagation.
        
        Args:
            file_paths: List of file paths to analyze
            
        Returns:
            List of vulnerability dictionaries from all files
        """
        all_vulnerabilities = []
        processed_vulnerabilities_set = set()

        # First pass: analyze each file individually
        for file_path in file_paths:
            if self.debug:
                log_debug(f"Initial analysis pass for: {file_path}")
            
            vulnerabilities = self.analyze_file(file_path)
            
            for vuln in vulnerabilities:
                # Create a hashable representation for deduplication
                vuln_tuple = tuple(sorted(vuln.items()))
                if vuln_tuple not in processed_vulnerabilities_set:
                    all_vulnerabilities.append(vuln)
                    processed_vulnerabilities_set.add(vuln_tuple)

        # Second pass: propagate taint across function calls
        if self.debug:
            log_debug("Propagating taint information across all analyzed functions...")
        
        self._propagate_taint_across_functions()

        return all_vulnerabilities

    def get_summary(self) -> Dict[str, Any]:
        """
        Get analysis summary statistics.
        
        Returns:
            Dictionary containing analysis summary
        """
        summary = {
            "files_analyzed": len(self.analyzed_files),
            "functions_found": len(self.all_functions),
            "tainted_variables": len(self.all_tainted_vars),
        }
        
        if self.visitor:
            summary.update({
                "sources_found": len(self.visitor.found_sources),
                "sinks_found": len(self.visitor.found_sinks),
                "vulnerabilities_found": len(self.visitor.found_vulnerabilities),
            })
        
        return summary

    def _update_global_state(self, visitor: TaintAnalysisVisitor, file_path: str) -> None:
        """Update global analysis state with visitor results."""
        # Update global functions
        for func_name, func_info in visitor.functions.items():
            qualified_name = f"{file_path}::{func_name}"
            self.all_functions[qualified_name] = func_info

        # Update global tainted variables
        for var_name, taint_info in visitor.tainted.items():
            qualified_name = f"{file_path}::{var_name}"
            self.all_tainted_vars[qualified_name] = taint_info

        # Update module mapping
        self.module_map[os.path.basename(file_path).replace(".py", "")] = file_path

    def _convert_vulnerabilities(self, visitor: TaintAnalysisVisitor) -> List[Dict[str, Any]]:
        """Convert visitor vulnerabilities to standard format."""
        vulnerabilities = []
        
        for vuln in visitor.found_vulnerabilities:
            source_info = vuln.get("source", {})
            sink_info = vuln.get("sink", {})
            
            vulnerability = {
                "type": sink_info.get("vulnerability_type", "Unknown"),
                "severity": "High",  # Default severity
                "source": {
                    "name": source_info.get("name", "Unknown"),
                    "line": source_info.get("line", 0),
                    "file": visitor.file_path,
                },
                "sink": {
                    "name": sink_info.get("name", "Unknown"),
                    "line": sink_info.get("line", 0),
                    "file": visitor.file_path,
                },
                "tainted_variable": vuln.get("tainted_var", ""),
                "description": f"Tainted data from {source_info.get('name', 'source')} flows to {sink_info.get('name', 'sink')}",
            }
            
            vulnerabilities.append(vulnerability)
        
        return vulnerabilities

    def _propagate_taint_across_functions(self) -> None:
        """Propagate taint information across function boundaries."""
        # This is a simplified version of cross-function taint propagation
        # In a full implementation, this would analyze call graphs and
        # propagate taint through function parameters and return values
        
        if self.debug:
            log_debug("Cross-function taint propagation not yet implemented in refactored version")
        
        # TODO: Implement cross-function taint propagation
        # This would involve:
        # 1. Building a complete call graph
        # 2. Analyzing function parameters and return values
        # 3. Propagating taint through function calls
        # 4. Detecting vulnerabilities across function boundaries
