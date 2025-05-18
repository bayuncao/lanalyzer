"""
Taint analysis module for LanaLyzer.

This package provides advanced taint analysis with the following capabilities:

1. Cross-function taint propagation - Tracks how tainted data flows between functions
2. Complex data structure analysis - Monitors taint in dictionaries, lists, and objects
3. Path-sensitive analysis - Considers conditional branches in code execution
4. Complete propagation chain tracking - Records all steps in taint flow
5. Detailed call graph construction - Maps relationships between all functions
"""

# Common components
from lanalyzer.analysis.base import BaseAnalyzer

# Core analysis components
from lanalyzer.analysis.callgraph import CallGraphNode
from lanalyzer.analysis.datastructures import DataStructureNode
from lanalyzer.analysis.defuse import DefUseChain
from lanalyzer.analysis.pathsensitive import PathNode
from lanalyzer.analysis.tracker import EnhancedTaintTracker
from lanalyzer.analysis.visitor import EnhancedTaintAnalysisVisitor


# For backward compatibility
from lanalyzer.analysis.visitor import (
    EnhancedTaintAnalysisVisitor as EnhancedTaintVisitor,
)

# Import functions we have migrated from the utils package
from lanalyzer.utils.ast_utils import (
    contains_sink_patterns,
    extract_call_targets,
    extract_function_calls,
)
from lanalyzer.utils.ast_utils import parse_file as parse_ast
from lanalyzer.utils.fs_utils import get_python_files_in_directory as get_python_files

from lanalyzer.analysis.call_chain_builder import CallChainBuilder
from lanalyzer.analysis.chain_utils import ChainUtils
from lanalyzer.analysis.control_flow_analyzer import ControlFlowAnalyzer
from lanalyzer.analysis.data_flow_analyzer import DataFlowAnalyzer

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

    # Get detailed summary
    summary = tracker.get_detailed_summary(vulnerabilities)

    # Write results to output file if specified
    if output_path:
        result_data = {"vulnerabilities": vulnerabilities, "summary": summary}

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
        info(f"Files analyzed: {summary['files_analyzed']}")
        info(f"Functions analyzed: {summary['functions_analyzed']}")
        info(f"Vulnerabilities found: {summary['vulnerabilities_found']}")
        info(
            f"Vulnerabilities with propagation chains: {summary['vulnerabilities_with_propagation']}"
        )
        info(f"Average propagation steps: {summary['average_propagation_steps']}")
        info(
            f"Vulnerabilities with call chains: {summary['vulnerabilities_with_call_chains']}"
        )
        info(f"Average call chain length: {summary['average_call_chain_length']}")
        info("-" * 80)
        info("SOURCES:")
        for source, count in summary["source_counts"].items():
            info(f"  {source}: {count}")
        info("SINKS:")
        for sink, count in summary["sink_counts"].items():
            info(f"  {sink}: {count}")
        info("-" * 80)
        info("SOURCE -> SINK FLOWS:")
        for pair, count in summary["source_sink_pairs"].items():
            info(f"  {pair}: {count}")
        info("=" * 80)

    return vulnerabilities, summary


# Provide alias for old function name for backward compatibility
enhanced_analyze_file = analyze_file

__all__ = [
    # Main analysis classes
    "EnhancedTaintTracker",
    "EnhancedTaintAnalysisVisitor",
    "EnhancedTaintVisitor",  # Backward compatibility
    # Helper data structures
    "CallGraphNode",
    "DataStructureNode",
    "DefUseChain",
    "PathNode",
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
    "CallChainBuilder",
    "ChainUtils",
    "ControlFlowAnalyzer",
    "DataFlowAnalyzer",
    "LegacyCallChainBuilder",
]
