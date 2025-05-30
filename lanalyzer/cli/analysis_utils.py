"""
Analysis Utilities Module - Provides analysis execution and report generation functionalities.
"""

import datetime
import os
import time
import traceback
from typing import Any, Dict, List

from lanalyzer.analysis.tracker import EnhancedTaintTracker
from lanalyzer.logger import info, warning, error


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

    info(f"\n[Analysis] Starting analysis of {total_files} files")
    info(
        f"[Analysis] Start time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    info(f"[Config] Source types: {[s['name'] for s in tracker.sources]}")
    info(f"[Config] Sink types: {[s['name'] for s in tracker.sinks]}")
    info(f"[Config] Number of rules: {len(tracker.config.get('rules', []))}")

    sink_patterns = []
    for sink in tracker.sinks:
        sink_patterns.extend(sink.get("patterns", []))
    info(f"[Config] Sink patterns: {sink_patterns}")

    with_open_sinks = [p for p in sink_patterns if "load" in p or "loads" in p]
    if with_open_sinks:
        info(
            f"[Config] Special focus on sinks in 'with open' context: {with_open_sinks}"
        )

    for idx, file_path in enumerate(files, 1):
        file_start_time = time.time()

        try:
            progress = f"[{idx}/{total_files}]"
            info(f"\n{progress} {'='*50}")
            info(f"{progress} Starting analysis of file: {file_path}")
            info(f"{progress} {'='*50}")

            if os.path.exists(file_path):
                file_size = os.path.getsize(file_path)
                info(f"{progress} File size: {file_size} bytes")

                try:
                    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                        line_count = content.count("\n") + 1

                    info(f"{progress} File line count: {line_count}")

                except Exception as e:
                    error(f"{progress} Error reading file content: {e}")

            analysis_start = time.time()
            info(f"{progress} Starting AST analysis...")

            try:
                file_vulnerabilities = tracker.analyze_file(file_path)
            except Exception as e:
                error(f"{progress} Exception during analysis: {e}")
                if debug:
                    error(traceback.format_exc())
                file_vulnerabilities = []

            file_end_time = time.time()
            analysis_duration = file_end_time - file_start_time
            ast_analysis_time = file_end_time - analysis_start

            info(
                f"{progress} Analysis complete, total time: {analysis_duration:.2f} seconds"
            )
            info(f"{progress} AST analysis time: {ast_analysis_time:.2f} seconds")
            info(
                f"{progress} Number of vulnerabilities found: {len(file_vulnerabilities)}"
            )

            sources_count = 0
            sinks_count = 0

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

                info(f"{progress} Number of sources found: {sources_count}")
                info(f"{progress} Number of sinks found: {sinks_count}")

                if hasattr(tracker.visitor, "file_handles"):
                    file_handles = tracker.visitor.file_handles
                    info(
                        f"{progress} Number of tracked file handles: {len(file_handles)}"
                    )

                    if file_handles:
                        info(f"{progress} File handle details:")
                        for handle, info_data in file_handles.items():
                            from_with = info_data.get("from_with", False)
                            mode = info_data.get("mode", "unknown")
                            source = info_data.get("source_var", "unknown")
                            info(
                                f"{progress}   - {handle}: from_with={from_with}, mode={mode}, source={source}"
                            )
            else:
                warning(
                    f"{progress} Note: No visitor information available for this file. Skipping detailed analysis but continuing processing."
                )

                try:
                    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                        for pattern in tracker.sinks:
                            for sink_pattern in pattern.get("patterns", []):
                                if sink_pattern in content:
                                    info(
                                        f"{progress} Potential sink pattern found in file: {sink_pattern}"
                                    )
                except Exception as e:
                    error(
                        f"{progress} Could not read file content for alternative analysis: {e}"
                    )

            if file_vulnerabilities:
                info(f"{progress} Vulnerability details:")
                for i, vuln in enumerate(file_vulnerabilities, 1):
                    rule = vuln.get("rule", "Unknown")
                    source_name = vuln.get("source", {}).get("name", "Unknown")
                    source_line = vuln.get("source", {}).get("line", 0)
                    sink_name = vuln.get("sink", {}).get("name", "Unknown")
                    sink_line = vuln.get("sink", {}).get("line", 0)
                    tainted_var = vuln.get("tainted_variable", "Unknown")

                    is_auto_detected = vuln.get("auto_detected", False)

                    if is_auto_detected:
                        info(
                            f"{progress}   {i}. {rule}: [Auto-detected] {sink_name}(line {sink_line}), no specific source found"
                        )
                    else:
                        info(
                            f"{progress}   {i}. {rule}: {source_name}(line {source_line}) -> {sink_name}(line {sink_line}), tainted variable: {tainted_var}"
                        )

                    is_with_open_sink = (
                        "with open" in source_name or "FileRead" in source_name
                    )

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
                        warning(
                            f"{progress}      ⚠️ Note: This is a sink point within a 'with open' context!"
                        )

            all_vulnerabilities.extend(file_vulnerabilities)

        except Exception as e:
            error(f"{progress} Error analyzing file: {e}")
            if debug:
                error(traceback.format_exc())

    end_time = time.time()
    total_duration = end_time - start_time
    info(f"\n[Analysis] Analysis complete, total time: {total_duration:.2f} seconds")
    info(f"[Analysis] Average time per file: {total_duration/total_files:.2f} seconds")
    info(f"[Analysis] Total vulnerabilities found: {len(all_vulnerabilities)}")

    vuln_types = {}
    auto_detected_vulns = 0

    for vuln in all_vulnerabilities:
        rule = vuln.get("rule", "Unknown")
        is_auto_detected = vuln.get("auto_detected", False)

        if is_auto_detected:
            auto_detected_vulns += 1

        vuln_types[rule] = vuln_types.get(rule, 0) + 1

    if vuln_types:
        info("[Analysis] Vulnerability type statistics:")
        for rule, count in sorted(vuln_types.items(), key=lambda x: x[1], reverse=True):
            info(f"  - {rule}: {count}")

        if auto_detected_vulns > 0:
            info(
                f"[Analysis] Auto-detected potential vulnerabilities: {auto_detected_vulns}"
            )

    with_open_vulns = []
    for vuln in all_vulnerabilities:
        source_name = vuln.get("source", {}).get("name", "")
        tainted_var = vuln.get("tainted_variable", "")
        if "with open" in source_name or "FileRead" in source_name:
            with_open_vulns.append(vuln)

    if with_open_vulns:
        info(
            f"[Analysis] Found {len(with_open_vulns)} file operation related vulnerabilities"
        )
        for i, vuln in enumerate(with_open_vulns, 1):
            file = vuln.get("file", "Unknown")
            sink_line = vuln.get("sink", {}).get("line", 0)
            rule = vuln.get("rule", "Unknown")
            info(f"  {i}. {os.path.basename(file)}:{sink_line} - {rule}")

    info(
        f"[Analysis] End time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

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
    info("\n" + "=" * 60)
    info("ENHANCED TAINT ANALYSIS RESULTS")
    info("-" * 60)
    info(f"Files analyzed: {summary.get('files_analyzed', 0)}")
    info(f"Functions analyzed: {summary.get('functions_analyzed', 0)}")
    info(f"Vulnerabilities found: {len(vulnerabilities)}")

    if len(vulnerabilities) > 0:
        info("-" * 60)
        info("VULNERABILITIES BY TYPE:")
        rules = {}
        for vuln in vulnerabilities:
            rule = vuln.get("rule", "Unknown")
            rules[rule] = rules.get(rule, 0) + 1

        for rule, count in sorted(rules.items(), key=lambda x: x[1], reverse=True):
            info(f"  {rule}: {count}")

        info("\nTOP 5 AFFECTED FILES:")
        files = {}
        for vuln in vulnerabilities:
            file = vuln.get("file", "Unknown")
            files[file] = files.get(file, 0) + 1

        for file, count in sorted(files.items(), key=lambda x: x[1], reverse=True)[:5]:
            info(f"  {os.path.basename(file)}: {count}")

    info("=" * 60)


def print_detailed_summary(detailed_summary: Dict[str, Any]) -> None:
    """Print detailed analysis summary with advanced statistics."""
    info("\n" + "=" * 60)
    info("DETAILED ANALYSIS STATISTICS")
    info("-" * 60)

    info(f"Files analyzed: {detailed_summary.get('files_analyzed', 0)}")
    info(f"Functions analyzed: {detailed_summary.get('functions_analyzed', 0)}")
    info(f"Vulnerabilities found: {detailed_summary.get('vulnerabilities_found', 0)}")

    info("\nPROPAGATION STATISTICS:")
    info(
        f"Vulnerabilities with propagation chains: {detailed_summary.get('vulnerabilities_with_propagation', 0)}"
    )
    info(
        f"Average propagation steps: {detailed_summary.get('average_propagation_steps', 0)}"
    )
    info(f"Max propagation steps: {detailed_summary.get('max_propagation_steps', 0)}")
    info(f"Min propagation steps: {detailed_summary.get('min_propagation_steps', 0)}")

    info("\nCALL CHAIN STATISTICS:")
    info(
        f"Vulnerabilities with call chains: {detailed_summary.get('vulnerabilities_with_call_chains', 0)}"
    )
    info(
        f"Average call chain length: {detailed_summary.get('average_call_chain_length', 0)}"
    )
    info(f"Max call chain length: {detailed_summary.get('max_call_chain_length', 0)}")
    info(f"Min call chain length: {detailed_summary.get('min_call_chain_length', 0)}")

    source_counts = detailed_summary.get("source_counts", {})
    if source_counts:
        info("\nSOURCE TYPE STATISTICS:")
        for source, count in sorted(
            source_counts.items(), key=lambda x: x[1], reverse=True
        ):
            info(f"  {source}: {count}")

    sink_counts = detailed_summary.get("sink_counts", {})
    if sink_counts:
        info("\nSINK TYPE STATISTICS:")
        for sink, count in sorted(
            sink_counts.items(), key=lambda x: x[1], reverse=True
        ):
            info(f"  {sink}: {count}")

    source_sink_pairs = detailed_summary.get("source_sink_pairs", {})
    if source_sink_pairs:
        info("\nTOP SOURCE-SINK PAIRS:")
        for pair, count in sorted(
            source_sink_pairs.items(), key=lambda x: x[1], reverse=True
        )[:10]:
            info(f"  {pair}: {count}")

    info("=" * 60)
