"""
Core analysis engine for Lanalyzer.

This package contains the fundamental components for AST processing,
visitor pattern implementation, and taint tracking.
"""

from .ast_processor import ASTProcessor, ParentNodeVisitor
from .tracker import EnhancedTaintTracker
from .visitor import TaintAnalysisVisitor

__all__ = [
    "ASTProcessor",
    "ParentNodeVisitor",
    "TaintAnalysisVisitor",
    "EnhancedTaintTracker",
]
