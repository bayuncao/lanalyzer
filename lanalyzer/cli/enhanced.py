#!/usr/bin/env python3
"""
Enhanced CLI module for LAnaLyzer.

Provides the command-line interface for enhanced taint analysis with 
complete propagation and call chains.
"""

import sys
import os

from lanalyzer.analysis.tracker import EnhancedTaintTracker
from lanalyzer.cli.log_utils import LogTee, get_timestamp
from lanalyzer.cli.file_utils import list_target_files, gather_target_files
from lanalyzer.cli.config_utils import load_configuration, save_output
from lanalyzer.cli.analysis_utils import (
    analyze_files_with_logging, 
    print_summary, 
    print_detailed_summary
)


def enhanced_cli_main() -> int:
    """
    Main entry point for the Lanalyzer enhanced CLI.

    Returns:
        Exit code
    """
    from lanalyzer.cli.base import create_parser

    parser = create_parser()

    args = parser.parse_args()

    # Set log file
    log_file = None
    original_stdout = sys.stdout
    original_stderr = sys.stderr

    if args.log_file:
        try:
            log_file = open(args.log_file, "w", encoding="utf-8")
            # Redirect stdout and stderr to the log file
            sys.stdout = LogTee(sys.stdout, log_file)
            sys.stderr = LogTee(sys.stderr, log_file)
            print(f"[Log] Started logging to file: {args.log_file}")
            print(f"[Log] Time: {get_timestamp()}")
        except Exception as e:
            print(f"[Error] Failed to open log file {args.log_file}: {e}")
            # Restore standard output
            sys.stdout = original_stdout
            sys.stderr = original_stderr

    try:
        # Add mandatory debug output to help identify issues
        print("[Start] Lanalyzer enhanced mode starting")
        print(f"[Args] Target: {args.target}")
        print(f"[Args] Config: {args.config}")
        print(f"[Args] Output: {args.output}")
        print(f"[Args] Debug Mode: {args.debug}")
        print(f"[Args] Log File: {args.log_file}")

        # If list-files is enabled, just list the files to be analyzed
        if args.list_files:
            list_target_files(args.target)
            return 0

        # Load configuration
        config = load_configuration(args.config, args.debug)

        # List files to be analyzed
        target_files = gather_target_files(args.target)
        if args.debug:
            print(f"[File List] The following {len(target_files)} files will be analyzed:")
            for idx, file_path in enumerate(target_files, 1):
                print(f"  {idx}. {file_path}")

        # Run analysis
        tracker = EnhancedTaintTracker(config, debug=args.debug)

        # Use the enhanced analysis function with detailed logging support
        vulnerabilities = analyze_files_with_logging(
            tracker, target_files, debug=args.debug
        )

        # Save results
        if args.output:
            save_output(vulnerabilities, args.output, args.pretty, args.debug)

        # Get summary
        summary = tracker.get_summary()
        detailed_summary = tracker.get_detailed_summary(vulnerabilities)

        # Print basic summary
        print_summary(summary, vulnerabilities)

        # Print detailed summary
        print_detailed_summary(detailed_summary)

        # Print detailed vulnerability information
        if vulnerabilities and args.verbose:
            print("\n" + "=" * 60)
            print("DETAILED VULNERABILITY INFORMATION")
            print("-" * 60)
            for i, vuln in enumerate(vulnerabilities, 1):
                print(f"\nVulnerability #{i}:")
                tracker.print_detailed_vulnerability(vuln)

        return 0

    except Exception as e:
        if args.debug:
            import traceback
            traceback.print_exc()
        else:
            print(f"Error during analysis: {e}")
        return 1

    finally:
        # Close log file and restore standard output
        if log_file:
            print(f"[Log] End time: {get_timestamp()}")
            print("[Log] Logging complete")
            sys.stdout = original_stdout
            sys.stderr = original_stderr
            log_file.close()


# Create a direct execution function to avoid module import issues
def main():
    """
    Entry point function when the module is executed directly from the command line.
    This method can avoid module import warnings.
    """
    sys.exit(enhanced_cli_main())


if __name__ == "__main__":
    main()
