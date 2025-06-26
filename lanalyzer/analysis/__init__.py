"""
Taint analysis module for LanaLyzer.

This package provides advanced taint analysis with the following capabilities:

1. Cross-function taint propagation - Tracks how tainted data flows between functions
2. Complex data structure analysis - Monitors taint in dictionaries, lists, and objects
3. Path-sensitive analysis - Considers conditional branches in code execution
4. Complete propagation chain tracking - Records all steps in taint flow
5. Detailed call graph construction - Maps relationships between all functions

## Refactored Architecture

The analysis module has been refactored for better organization:
- `core/` - Core analysis engine (AST processing, visitor, tracker)
- `flow/` - Data and control flow analysis
- `models/` - Data structures (call graph, data structures, path analysis)
- `utils/` - Utilities and formatters
"""

# Common components
from lanalyzer.analysis.base import BaseAnalyzer

# New refactored components (primary imports)
from lanalyzer.analysis.core import (
    ASTProcessor,
    ParentNodeVisitor,
    TaintAnalysisVisitor,
    EnhancedTaintTracker,
)
from lanalyzer.analysis.models import (
    CallGraphNode,
    DataStructureNode,
    DefUseChain,
    PathNode,
)
from lanalyzer.analysis.flow import (
    FlowAnalyzer,
    CallChainBuilder,
)
from lanalyzer.analysis.utils import (
    AnalysisHelpers,
    DescriptionFormatter,
)

# Backward compatibility imports
# These maintain compatibility with existing code while using the new implementations
try:
    # Try to import from old locations for backward compatibility
    from lanalyzer.analysis.visitor import EnhancedTaintAnalysisVisitor
except ImportError:
    # Use new implementation if old one doesn't exist
    EnhancedTaintAnalysisVisitor = TaintAnalysisVisitor

# Backward compatibility aliases
EnhancedTaintVisitor = TaintAnalysisVisitor  # Alias for old name

# Import functions from utils package
from lanalyzer.utils.ast_utils import (
    contains_sink_patterns,
    extract_call_targets,
    extract_function_calls,
)
from lanalyzer.utils.ast_utils import parse_file as parse_ast
from lanalyzer.utils.fs_utils import get_python_files_in_directory as get_python_files

# Legacy component aliases for backward compatibility
try:
    from lanalyzer.analysis.chain_utils import ChainUtils
except ImportError:
    # Create a compatibility wrapper if old module doesn't exist
    class ChainUtils:
        def __init__(self, builder):
            self.builder = builder
            self.helpers = AnalysisHelpers(builder.debug if hasattr(builder, 'debug') else False)

try:
    from lanalyzer.analysis.control_flow_analyzer import ControlFlowAnalyzer
except ImportError:
    # Use new FlowAnalyzer as compatibility wrapper
    ControlFlowAnalyzer = FlowAnalyzer

try:
    from lanalyzer.analysis.data_flow_analyzer import DataFlowAnalyzer
except ImportError:
    # Use new FlowAnalyzer as compatibility wrapper
    DataFlowAnalyzer = FlowAnalyzer

from lanalyzer.logger import info, error


def analyze_file(
    target_path: str,
    config_path: str,
    output_path: str = None,
    pretty: bool = False,
    debug: bool = False,
    detailed: bool = False,
):
    """
    Analyze a file or directory for taint vulnerabilities using enhanced analysis.

    Args:
        target_path: Path to the file or directory to analyze
        config_path: Path to the configuration file
        output_path: Path to write the results to (optional)
        pretty: Whether to format the JSON output for readability
        debug: Whether to print debug information
        detailed: Whether to include detailed propagation chains

    Returns:
        Tuple of (vulnerabilities, summary)
    """
    import json
    import os

    # Load configuration
    try:
        with open(config_path, "r") as f:
            config = json.load(f)
    except Exception as e:
        error(f"Error loading configuration: {e}")
        return [], {}

    # Set up enhanced tracker
    tracker = EnhancedTaintTracker(config, debug=debug)

    # Analyze targets
    vulnerabilities = []
    if os.path.isdir(target_path):
        file_paths = []
        for root, _, files in os.walk(target_path):
            for file in files:
                if file.endswith(".py"):
                    file_paths.append(os.path.join(root, file))

        # Use cross-file analysis for directories
        vulnerabilities = tracker.analyze_multiple_files(file_paths)
    else:
        # Single file analysis
        vulnerabilities = tracker.analyze_file(target_path)

    # Get summary (use new method name)
    summary = tracker.get_summary()

    # Write results to output file if specified
    if output_path:
        result_data = {
            "vulnerabilities": vulnerabilities,
            "summary": summary,
            "imports": tracker.all_imports  # Add detailed import information
        }

        with open(output_path, "w") as f:
            if pretty:
                json.dump(result_data, f, indent=2)
            else:
                json.dump(result_data, f)

    # Print statistics if requested
    if detailed:
        info("\n" + "=" * 80)
        info("ENHANCED TAINT ANALYSIS SUMMARY")
        info("-" * 80)
        info(f"Files analyzed: {summary.get('files_analyzed', 0)}")
        info(f"Functions found: {summary.get('functions_found', 0)}")
        info(f"Sources found: {summary.get('sources_found', 0)}")
        info(f"Sinks found: {summary.get('sinks_found', 0)}")
        info(f"Vulnerabilities found: {summary.get('vulnerabilities_found', len(vulnerabilities))}")
        info(f"Tainted variables: {summary.get('tainted_variables', 0)}")
        info("=" * 80)

    return vulnerabilities, summary


# Legacy call chain builder for backward compatibility
try:
    from lanalyzer.analysis.call_chain_builder import CallChainBuilder as LegacyCallChainBuilder
except ImportError:
    # Use new CallChainBuilder if legacy doesn't exist
    LegacyCallChainBuilder = CallChainBuilder

# Provide alias for old function name for backward compatibility
enhanced_analyze_file = analyze_file

__all__ = [
    # Main analysis classes (new refactored)
    "EnhancedTaintTracker",
    "TaintAnalysisVisitor",
    "ASTProcessor",
    "ParentNodeVisitor",

    # Backward compatibility classes
    "EnhancedTaintAnalysisVisitor",
    "EnhancedTaintVisitor",

    # Data structures
    "CallGraphNode",
    "DataStructureNode",
    "DefUseChain",
    "PathNode",

    # Flow analysis
    "FlowAnalyzer",
    "CallChainBuilder",

    # Utilities
    "AnalysisHelpers",
    "DescriptionFormatter",

    # Public API functions
    "analyze_file",
    "enhanced_analyze_file",  # Compatibility alias

    # Base components
    "BaseAnalyzer",
    "parse_ast",
    "get_python_files",
    "extract_call_targets",
    "extract_function_calls",
    "contains_sink_patterns",

    # Legacy compatibility
    "ChainUtils",
    "ControlFlowAnalyzer",
    "DataFlowAnalyzer",
    "LegacyCallChainBuilder",
]
