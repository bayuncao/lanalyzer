"""
Analysis Utilities Module - Provides analysis execution and report generation functionalities.
"""

import datetime
import os
import time
import traceback
from typing import Any, Dict, List

from lanalyzer.analysis.tracker import EnhancedTaintTracker


def analyze_files_with_logging(
    tracker: EnhancedTaintTracker, files: List[str], debug: bool = False
) -> List[Dict[str, Any]]:
    """
    Analyze multiple files with detailed logging.

    Args:
        tracker: Taint analyzer instance
        files: List of files to analyze
        debug: Whether to enable debug mode

    Returns:
        List of found vulnerabilities
    """
    all_vulnerabilities = []
    total_files = len(files)
    start_time = time.time()

    print(f"\n[Analysis] Starting analysis of {total_files} files")
    print(f"[Analysis] Start time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Log configuration info - use tracker.config instead of direct access to rules
    print(f"[Config] Source types: {[s['name'] for s in tracker.sources]}")
    print(f"[Config] Sink types: {[s['name'] for s in tracker.sinks]}")
    print(f"[Config] Number of rules: {len(tracker.config.get('rules', []))}")

    # Log sink patterns of special interest
    sink_patterns = []
    for sink in tracker.sinks:
        sink_patterns.extend(sink.get("patterns", []))
    print(f"[Config] Sink patterns: {sink_patterns}")

    # Special focus on sinks within `with open` context
    with_open_sinks = [p for p in sink_patterns if "load" in p or "loads" in p]
    if with_open_sinks:
        print(f"[Config] Special focus on sinks in 'with open' context: {with_open_sinks}")

    for idx, file_path in enumerate(files, 1):
        file_start_time = time.time()

        try:
            # Print analysis progress
            progress = f"[{idx}/{total_files}]"
            print(f"\n{progress} {'='*50}")
            print(f"{progress} Starting analysis of file: {file_path}")
            print(f"{progress} {'='*50}")

            # Print file information
            if os.path.exists(file_path):
                file_size = os.path.getsize(file_path)
                print(f"{progress} File size: {file_size} bytes")

                # Calculate file line count
                try:
                    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                        line_count = content.count("\n") + 1

                    print(f"{progress} File line count: {line_count}")

                except Exception as e:
                    print(f"{progress} Error reading file content: {e}")

            # Record current time before execution
            analysis_start = time.time()
            print(f"{progress} Starting AST analysis...")

            # Analyze file, continue processing regardless of success
            try:
                file_vulnerabilities = tracker.analyze_file(file_path)
            except Exception as e:
                print(f"{progress} Exception during analysis: {e}")
                if debug:
                    print(traceback.format_exc())
                file_vulnerabilities = []  # Set to empty list on error

            # Record analysis results
            file_end_time = time.time()
            analysis_duration = file_end_time - file_start_time
            ast_analysis_time = file_end_time - analysis_start

            print(f"{progress} Analysis complete, total time: {analysis_duration:.2f} seconds")
            print(f"{progress} AST analysis time: {ast_analysis_time:.2f} seconds")
            print(f"{progress} Number of vulnerabilities found: {len(file_vulnerabilities)}")

            # Modified part: Force analysis even if no visitor
            sources_count = 0
            sinks_count = 0
            
            # Attempt to get source and sink info, but don't block processing
            if hasattr(tracker, "visitor") and tracker.visitor:
                sources_count = (
                    len(tracker.visitor.found_sources)
                    if hasattr(tracker.visitor, "found_sources")
                    else 0
                )
                sinks_count = (
                    len(tracker.visitor.found_sinks)
                    if hasattr(tracker.visitor, "found_sinks")
                    else 0
                )
                
                print(f"{progress} Number of sources found: {sources_count}")
                print(f"{progress} Number of sinks found: {sinks_count}")

                # Log file handles related to `with open`
                if hasattr(tracker.visitor, "file_handles"):
                    file_handles = tracker.visitor.file_handles
                    print(f"{progress} Number of tracked file handles: {len(file_handles)}")

                    # Log details for each file handle
                    if file_handles:
                        print(f"{progress} File handle details:")
                        for handle, info in file_handles.items():
                            from_with = info.get("from_with", False)
                            mode = info.get("mode", "unknown")
                            source = info.get("source_var", "unknown")
                            print(
                                f"{progress}   - {handle}: from_with={from_with}, mode={mode}, source={source}"
                            )
            else:
                # Continue analysis even without visitor
                print(f"{progress} Note: No visitor information available for this file. Skipping detailed analysis but continuing processing.")
                
                # Custom analysis logic can be added here, independent of the visitor
                # Example: Use regex or other methods to find potential issues
                try:
                    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                        # Simple example: Check for specific sensitive function calls
                        for pattern in tracker.sinks:
                            for sink_pattern in pattern.get("patterns", []):
                                if sink_pattern in content:
                                    print(f"{progress} Potential sink pattern found in file: {sink_pattern}")
                except Exception as e:
                    print(f"{progress} Could not read file content for alternative analysis: {e}")

            if file_vulnerabilities:
                print(f"{progress} Vulnerability details:")
                for i, vuln in enumerate(file_vulnerabilities, 1):
                    rule = vuln.get("rule", "Unknown")
                    source_name = vuln.get("source", {}).get("name", "Unknown")
                    source_line = vuln.get("source", {}).get("line", 0)
                    sink_name = vuln.get("sink", {}).get("name", "Unknown")
                    sink_line = vuln.get("sink", {}).get("line", 0)
                    tainted_var = vuln.get("tainted_variable", "Unknown")
                    
                    # Check if it's an auto-detected vulnerability
                    is_auto_detected = vuln.get("auto_detected", False)
                    
                    if is_auto_detected:
                        print(
                            f"{progress}   {i}. {rule}: [Auto-detected] {sink_name}(line {sink_line}), no specific source found"
                        )
                    else:
                        print(
                            f"{progress}   {i}. {rule}: {source_name}(line {source_line}) -> {sink_name}(line {sink_line}), tainted variable: {tainted_var}"
                        )
                        
                    # Check if it's a sink in `with open` context - Modified code for robust check
                    is_with_open_sink = (
                        "with open" in source_name or "FileRead" in source_name
                    )

                    # Only check file_handles if tracker.visitor exists
                    if (
                        hasattr(tracker, "visitor")
                        and tracker.visitor
                        and hasattr(tracker.visitor, "file_handles")
                    ):
                        is_with_open_sink = is_with_open_sink or (
                            tainted_var in tracker.visitor.file_handles
                            and tracker.visitor.file_handles[tainted_var].get(
                                "from_with", False
                            )
                        )

                    if is_with_open_sink:
                        print(f"{progress}      ⚠️ Note: This is a sink point within a 'with open' context!")

            all_vulnerabilities.extend(file_vulnerabilities)

        except Exception as e:
            print(f"{progress} Error analyzing file: {e}")
            if debug:
                print(traceback.format_exc())

    # Print summary
    end_time = time.time()
    total_duration = end_time - start_time
    print(f"\n[Analysis] Analysis complete, total time: {total_duration:.2f} seconds")
    print(f"[Analysis] Average time per file: {total_duration/total_files:.2f} seconds")
    print(f"[Analysis] Total vulnerabilities found: {len(all_vulnerabilities)}")

    # Count vulnerability types
    vuln_types = {}
    auto_detected_vulns = 0

    for vuln in all_vulnerabilities:
        rule = vuln.get("rule", "Unknown")
        is_auto_detected = vuln.get("auto_detected", False)
        
        if is_auto_detected:
            auto_detected_vulns += 1
        
        vuln_types[rule] = vuln_types.get(rule, 0) + 1

    if vuln_types:
        print("[Analysis] Vulnerability type statistics:")
        for rule, count in sorted(vuln_types.items(), key=lambda x: x[1], reverse=True):
            print(f"  - {rule}: {count}")
        
        # Display count of auto-detected vulnerabilities
        if auto_detected_vulns > 0:
            print(f"[Analysis] Auto-detected potential vulnerabilities: {auto_detected_vulns}")

    # Special count for vulnerabilities in `with open` context
    with_open_vulns = []
    for vuln in all_vulnerabilities:
        source_name = vuln.get("source", {}).get("name", "")
        tainted_var = vuln.get("tainted_variable", "")
        if "with open" in source_name or "FileRead" in source_name:
            with_open_vulns.append(vuln)

    if with_open_vulns:
        print(f"[Analysis] Found {len(with_open_vulns)} file operation related vulnerabilities")
        for i, vuln in enumerate(with_open_vulns, 1):
            file = vuln.get("file", "Unknown")
            sink_line = vuln.get("sink", {}).get("line", 0)
            rule = vuln.get("rule", "Unknown")
            print(f"  {i}. {os.path.basename(file)}:{sink_line} - {rule}")

    print(f"[Analysis] End time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    return all_vulnerabilities


def print_summary(
    summary: Dict[str, Any], vulnerabilities: List[Dict[str, Any]]
) -> None:
    """
    Print a detailed summary of the analysis results.

    Args:
        summary: Analysis summary dictionary
        vulnerabilities: List of vulnerability dictionaries
    """
    print("\n" + "=" * 60)
    print("ENHANCED TAINT ANALYSIS RESULTS")
    print("-" * 60)
    print(f"Files analyzed: {summary.get('files_analyzed', 0)}")
    print(f"Functions analyzed: {summary.get('functions_analyzed', 0)}")
    print(f"Vulnerabilities found: {len(vulnerabilities)}")

    if len(vulnerabilities) > 0:
        print("-" * 60)
        print("VULNERABILITIES BY TYPE:")
        rules = {}
        for vuln in vulnerabilities:
            rule = vuln.get("rule", "Unknown")
            rules[rule] = rules.get(rule, 0) + 1

        for rule, count in sorted(rules.items(), key=lambda x: x[1], reverse=True):
            print(f"  {rule}: {count}")

        print("\nTOP 5 AFFECTED FILES:")
        files = {}
        for vuln in vulnerabilities:
            file = vuln.get("file", "Unknown")
            files[file] = files.get(file, 0) + 1

        for file, count in sorted(files.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {os.path.basename(file)}: {count}")

    print("=" * 60)


def print_detailed_summary(detailed_summary: Dict[str, Any]) -> None:
    """Print detailed analysis summary with advanced statistics."""
    print("\n" + "=" * 60)
    print("DETAILED ANALYSIS STATISTICS")
    print("-" * 60)

    print(f"Files analyzed: {detailed_summary.get('files_analyzed', 0)}")
    print(f"Functions analyzed: {detailed_summary.get('functions_analyzed', 0)}")
    print(f"Vulnerabilities found: {detailed_summary.get('vulnerabilities_found', 0)}")

    
    print("\nPROPAGATION STATISTICS:")
    print(
        f"Vulnerabilities with propagation chains: {detailed_summary.get('vulnerabilities_with_propagation', 0)}"
    )
    print(
        f"Average propagation steps: {detailed_summary.get('average_propagation_steps', 0)}"
    )
    print(f"Max propagation steps: {detailed_summary.get('max_propagation_steps', 0)}")
    print(f"Min propagation steps: {detailed_summary.get('min_propagation_steps', 0)}")

    print("\nCALL CHAIN STATISTICS:")
    print(
        f"Vulnerabilities with call chains: {detailed_summary.get('vulnerabilities_with_call_chains', 0)}"
    )
    print(
        f"Average call chain length: {detailed_summary.get('average_call_chain_length', 0)}"
    )
    print(f"Max call chain length: {detailed_summary.get('max_call_chain_length', 0)}")
    print(f"Min call chain length: {detailed_summary.get('min_call_chain_length', 0)}")

    source_counts = detailed_summary.get("source_counts", {})
    if source_counts:
        print("\nSOURCE TYPE STATISTICS:")
        for source, count in sorted(
            source_counts.items(), key=lambda x: x[1], reverse=True
        ):
            print(f"  {source}: {count}")

    
    sink_counts = detailed_summary.get("sink_counts", {})
    if sink_counts:
        print("\nSINK TYPE STATISTICS:")
        for sink, count in sorted(
            sink_counts.items(), key=lambda x: x[1], reverse=True
        ):
            print(f"  {sink}: {count}")

    
    source_sink_pairs = detailed_summary.get("source_sink_pairs", {})
    if source_sink_pairs:
        print("\nTOP SOURCE-SINK PAIRS:")
        for pair, count in sorted(
            source_sink_pairs.items(), key=lambda x: x[1], reverse=True
        )[
            :10
        ]:  
            print(f"  {pair}: {count}")

    print("=" * 60) 