"""
Base analyzer module for LanaLyzer.

Provides the abstract base class for all analyzers.
"""

import abc
import os
import time
from typing import (
    Any,
    Dict,
    List,
    Type,
    TypeVar,
    Set,
)  # Added Set for self.analyzed_files

from lanalyzer.models import AnalysisResults, Vulnerability
from lanalyzer.utils.fs_utils import get_python_files_in_directory
from lanalyzer.logger import debug, info

# Type variable for better type hinting
T = TypeVar("T", bound="BaseAnalyzer")


class BaseAnalyzer(abc.ABC):
    """
    Abstract base class for all code analyzers.

    Provides common interface and functionality for taint and other analysis types.
    """

    def __init__(
        self, config: Dict[str, Any], debug: bool = False, verbose: bool = False
    ):
        """
        Initialize the analyzer.

        Args:
            config: Configuration dictionary with analysis settings
            debug: Whether to enable debug output
            verbose: Whether to enable verbose output
        """
        self.config: Dict[str, Any] = config
        self.debug: bool = debug
        self.verbose: bool = verbose
        self.sources: List[Dict[str, Any]] = config.get("sources", [])
        self.sinks: List[Dict[str, Any]] = config.get("sinks", [])
        self.rules: List[Dict[str, Any]] = config.get("rules", [])
        self.analyzed_files: Set[str] = set()

    @abc.abstractmethod
    def analyze_file(self, file_path: str) -> List[Vulnerability]:
        """
        Analyze a file for taint vulnerabilities.

        Args:
            file_path: Path to the file to analyze

        Returns:
            List of vulnerability objects
        """
        pass

    def analyze_directory(self, directory_path: str) -> List[Vulnerability]:
        """
        Analyze all Python files in a directory for taint vulnerabilities.

        Args:
            directory_path: Path to the directory to analyze

        Returns:
            List of vulnerability objects
        """
        vulnerabilities: List[Vulnerability] = []

        # Use our optimized utility function to get all Python files
        python_files = get_python_files_in_directory(directory_path)

        for file_path in python_files:
            if self.debug or self.verbose:
                # Log using the instance's info method for verbose, or debug for debug
                self.info(f"Analyzing {file_path}")
            try:
                file_vulnerabilities = self.analyze_file(file_path)
                vulnerabilities.extend(file_vulnerabilities)
                self.analyzed_files.add(file_path)
            except Exception as e:
                self.logger.error(f"Error analyzing file {file_path}: {e}")
                if self.debug:
                    import traceback

                    traceback.print_exc()

        return vulnerabilities

    def analyze(self, target_path: str) -> AnalysisResults:
        """
        Analyze a file or directory for vulnerabilities.

        Args:
            target_path: Path to the file or directory to analyze

        Returns:
            Analysis results object

        Raises:
            FileNotFoundError: If target path does not exist
            PermissionError: If target path is not accessible
            ValueError: For other validation errors
        """
        # Better path validation
        if not os.path.exists(target_path):
            raise FileNotFoundError(f"Target path does not exist: {target_path}")

        if not os.access(target_path, os.R_OK):
            raise PermissionError(f"Target path is not readable: {target_path}")

        # Create results object
        results = AnalysisResults(target=target_path)
        self.analyzed_files.clear()  # Clear for a new analysis run

        # Track timing
        start_time = time.time()

        if os.path.isfile(target_path):
            if not target_path.endswith(".py"):
                self.info(
                    f"Target path {target_path} is not a Python file. Skipping analysis."
                )
                vulnerabilities = []
                results.stats["files_analyzed"] = 0
            else:
                vulnerabilities = self.analyze_file(target_path)
                results.vulnerabilities = vulnerabilities
                results.stats["files_analyzed"] = 1
                self.analyzed_files.add(
                    target_path
                )  # Ensure single file is in analyzed_files
        elif os.path.isdir(target_path):
            vulnerabilities = self.analyze_directory(target_path)
            results.vulnerabilities = vulnerabilities
            results.stats["files_analyzed"] = len(self.analyzed_files)
        else:
            # This case should ideally not be reached due to os.path.exists check,
            # but kept for robustness against symlinks or special files.
            raise ValueError(
                f"Target path {target_path} is not a valid file or directory."
            )

        # Update stats
        end_time = time.time()
        results.stats["analysis_time"] = round(end_time - start_time, 2)
        results.stats["vulnerability_count"] = len(vulnerabilities)

        # Generate summary
        results.generate_summary()  # Assuming this method exists on AnalysisResults

        return results

    def log(self, message: str) -> None:
        """
        Log a message using the debug logger if debug mode is enabled.

        Args:
            message: Message to log
        """
        if self.debug:
            debug(message)

    def info(self, message: str) -> None:
        """
        Log an info message if verbose mode or debug mode is enabled.
        Standard info messages are often useful in debug mode too.

        Args:
            message: Message to log
        """
        if self.verbose or self.debug:
            info(message)

    @classmethod
    def from_config_file(
        cls: Type[T], config_path: str, debug: bool = False, verbose: bool = False
    ) -> T:
        """
        Create an analyzer instance from a configuration file.

        Args:
            config_path: Path to configuration file
            debug: Whether to enable debug output
            verbose: Whether to enable verbose output

        Returns:
            Initialized analyzer instance
        """
        # Import locally to avoid circular dependencies if config module imports BaseAnalyzer
        from lanalyzer.config import load_config

        config_data = load_config(
            config_path, debug_mode=debug
        )  # Pass debug_mode to load_config
        return cls(config_data, debug, verbose)
