"""
Core analysis engine for Lanalyzer.

This package contains the fundamental components for AST processing,
visitor pattern implementation, and taint tracking.
"""

from .ast_processor import ASTProcessor, ParentNodeVisitor
from .visitor import TaintAnalysisVisitor
from .tracker import EnhancedTaintTracker

__all__ = [
    "ASTProcessor",
    "ParentNodeVisitor", 
    "TaintAnalysisVisitor",
    "EnhancedTaintTracker",
]
