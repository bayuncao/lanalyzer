"""
Enhanced AST visitor for taint analysis.
This is the main aggregation file that imports and combines all visitor components.
"""

import ast
from typing import Any, Dict, List, Optional, Tuple
import os

from lanalyzer.analysis.enhanced.ast_parser import TaintVisitor

from .callgraph import CallGraphNode
from .datastructures import DataStructureNode
from .defuse import DefUseChain
from .pathsensitive import PathNode

from .visitor_base import EnhancedTaintVisitor
from .visitor_function import FunctionVisitorMixin
from .visitor_datastructure import DataStructureVisitorMixin
from .visitor_control import ControlFlowVisitorMixin

import importlib

# Create dynamic imports to avoid circular references
for module_name in ['callgraph', 'datastructures', 'defuse', 'pathsensitive']:
    globals()[module_name] = importlib.import_module(f'.{module_name}', package='lanalyzer.analysis.enhanced')


class EnhancedTaintAnalysisVisitor(
    EnhancedTaintVisitor, 
    FunctionVisitorMixin,
    DataStructureVisitorMixin,
    ControlFlowVisitorMixin
):
    """
    This class combines all the visitor mixins to create a complete taint analysis visitor.
    
    - EnhancedTaintVisitor: Base visitor with core functionality
    - FunctionVisitorMixin: Function definition and call tracking
    - DataStructureVisitorMixin: Complex data structure tracking
    - ControlFlowVisitorMixin: Control flow analysis
    """
    
    def __init__(
        self,
        parent_map=None,
        debug: bool = False,
        verbose: bool = False,
        file_path: Optional[str] = None,
    ):
        """Initialize the complete taint analysis visitor."""
        # Setup module references to avoid circular imports
        self.callgraph = globals()['callgraph']
        self.datastructures = globals()['datastructures']
        self.defuse = globals()['defuse']
        self.pathsensitive = globals()['pathsensitive']
        
        # Initialize the base visitor
        super().__init__(parent_map, debug, verbose, file_path)
        
        # 确保file_path被设置，并且源代码行已加载
        if not hasattr(self, 'source_lines') or not self.source_lines:
            if file_path and os.path.exists(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        self.source_lines = f.readlines()
                    if self.debug:
                        print(f"在EnhancedTaintAnalysisVisitor中加载了 {len(self.source_lines)} 行源代码从 {file_path}")
                except Exception as e:
                    if self.debug:
                        print(f"在EnhancedTaintAnalysisVisitor中无法加载源代码: {str(e)}")
        
        if self.debug:
            print(f"初始化完整污点分析访问者用于文件: {file_path}")
            if hasattr(self, 'source_lines') and self.source_lines:
                print(f"成功加载源代码行: {len(self.source_lines)} 行")
            else:
                print(f"警告: 未能加载源代码行")
