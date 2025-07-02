"""
Configuration loader module for LanaLyzer.

This module provides functionality for loading and validating configuration files.
"""

import json
import os
from typing import Any, Dict

from lanalyzer.logger import debug, error, info


class ConfigLoader:
    """
    Configuration loader for LanaLyzer.

    This class provides methods for loading and validating configuration files.
    """

    @staticmethod
    def load(config_path: str, debug_mode: bool = False) -> Dict[str, Any]:
        """
        Load configuration from a file.

        Args:
            config_path: Path to the configuration file
            debug_mode: Whether to print debug information

        Returns:
            Dictionary containing the configuration

        Raises:
            FileNotFoundError: If the configuration file does not exist
            json.JSONDecodeError: If the configuration file contains invalid JSON
            ValueError: If the configuration is invalid
        """
        if debug_mode:
            debug(f"Loading configuration from: {config_path}")

        if not os.path.exists(config_path):
            error_msg = f"Configuration file not found: {config_path}"
            error(error_msg)
            raise FileNotFoundError(error_msg)

        try:
            with open(config_path, "r") as f:
                config = json.load(f)

            # Validate the configuration
            ConfigLoader.validate(config, debug=debug_mode)

            if debug_mode:
                ConfigLoader.print_config_summary(config)

            return config

        except json.JSONDecodeError as e:
            error_msg = f"Invalid JSON in configuration file: {e}"
            error(error_msg)
            raise

    @staticmethod
    def validate(config: Dict[str, Any], debug: bool = False) -> bool:
        """
        Validate a configuration with enhanced error checking.

        Args:
            config: Configuration dictionary to validate
            debug: Whether to print debug information

        Returns:
            True if the configuration is valid, False otherwise

        Raises:
            ValueError: If the configuration is invalid
        """
        if not isinstance(config, dict):
            error_msg = "Configuration must be a dictionary"
            if debug:
                error(error_msg)
            raise ValueError(error_msg)

        # Check for required sections
        required_sections = ["sources", "sinks"]
        for section in required_sections:
            if section not in config:
                error_msg = f"Missing required configuration section: {section}"
                if debug:
                    error(error_msg)
                raise ValueError(error_msg)

        # Validate sources with enhanced checks
        sources = config.get("sources", [])
        if not isinstance(sources, list):
            error_msg = "Sources must be a list"
            if debug:
                error(error_msg)
            raise ValueError(error_msg)

        if not sources:
            error_msg = "Configuration must contain at least one source"
            if debug:
                error(error_msg)
            raise ValueError(error_msg)

        for i, source in enumerate(sources):
            if not isinstance(source, dict):
                error_msg = f"Source at index {i} must be a dictionary"
                if debug:
                    error(error_msg)
                raise ValueError(error_msg)

            if "name" not in source:
                error_msg = f"Source at index {i} missing required field: name"
                if debug:
                    error(error_msg)
                raise ValueError(error_msg)

            # Validate name
            name = source.get("name")
            if not isinstance(name, str) or not name.strip():
                error_msg = f"Source at index {i} name must be a non-empty string"
                if debug:
                    error(error_msg)
                raise ValueError(error_msg)

            if "patterns" not in source:
                error_msg = f"Source at index {i} missing required field: patterns"
                if debug:
                    error(error_msg)
                raise ValueError(error_msg)

            patterns = source.get("patterns", [])
            if not isinstance(patterns, list):
                error_msg = f"Source patterns for '{source['name']}' must be a list"
                if debug:
                    error(error_msg)
                raise ValueError(error_msg)

            if not patterns:
                error_msg = f"Source '{source['name']}' must have at least one pattern"
                if debug:
                    error(error_msg)
                raise ValueError(error_msg)

            # Validate each pattern
            for j, pattern in enumerate(patterns):
                if not isinstance(pattern, str) or not pattern.strip():
                    error_msg = f"Source '{source['name']}', pattern at index {j} must be a non-empty string"
                    if debug:
                        error(error_msg)
                    raise ValueError(error_msg)

        # Validate sinks
        sinks = config.get("sinks", [])
        if not isinstance(sinks, list):
            error_msg = "Sinks must be a list"
            if debug:
                error(error_msg)
            raise ValueError(error_msg)

        for i, sink in enumerate(sinks):
            if not isinstance(sink, dict):
                error_msg = f"Sink at index {i} must be a dictionary"
                if debug:
                    error(error_msg)
                raise ValueError(error_msg)

            if "name" not in sink:
                error_msg = f"Sink at index {i} missing required field: name"
                if debug:
                    error(error_msg)
                raise ValueError(error_msg)

            if "patterns" not in sink:
                error_msg = f"Sink at index {i} missing required field: patterns"
                if debug:
                    error(error_msg)
                raise ValueError(error_msg)

            if not isinstance(sink["patterns"], list):
                error_msg = f"Sink patterns for '{sink['name']}' must be a list"
                if debug:
                    error(error_msg)
                raise ValueError(error_msg)

        # Validate rules if present
        rules = config.get("rules", [])
        if rules and not isinstance(rules, list):
            error_msg = "Rules must be a list"
            if debug:
                error(error_msg)
            raise ValueError(error_msg)

        for i, rule in enumerate(rules):
            if not isinstance(rule, dict):
                error_msg = f"Rule at index {i} must be a dictionary"
                if debug:
                    error(error_msg)
                raise ValueError(error_msg)

            if "name" not in rule:
                error_msg = f"Rule at index {i} missing required field: name"
                if debug:
                    error(error_msg)
                raise ValueError(error_msg)

        return True

    @staticmethod
    def save_config(
        config: Dict[str, Any], output_path: str, pretty: bool = True
    ) -> bool:
        """
        Save a configuration to a file.

        Args:
            config: Configuration to save
            output_path: Path to save the configuration to
            pretty: Whether to format the JSON for readability

        Returns:
            True if saving was successful, False otherwise
        """
        try:
            with open(output_path, "w") as f:
                if pretty:
                    json.dump(config, f, indent=2)
                else:
                    json.dump(config, f)
            return True
        except Exception as e:
            error(f"Error saving configuration: {e}")
            return False

    @staticmethod
    def print_config_summary(config: Dict[str, Any]) -> None:
        """
        Print a summary of a configuration.

        Args:
            config: Configuration to print
        """
        info("\nConfiguration Summary:")
        info("-" * 40)

        info(f"Sources ({len(config.get('sources', []))}):")
        for source in config.get("sources", []):
            patterns = ", ".join(source.get("patterns", [])[:3])
            if len(source.get("patterns", [])) > 3:
                patterns += ", ..."
            info(f"  - {source.get('name')}: {patterns}")

        info(f"\nSinks ({len(config.get('sinks', []))}):")
        for sink in config.get("sinks", []):
            patterns = ", ".join(sink.get("patterns", [])[:3])
            if len(sink.get("patterns", [])) > 3:
                patterns += ", ..."
            info(f"  - {sink.get('name')}: {patterns}")

        if "sanitizers" in config:
            info(f"\nSanitizers ({len(config.get('sanitizers', []))}):")
            for sanitizer in config.get("sanitizers", []):
                patterns = ", ".join(sanitizer.get("patterns", [])[:3])
                if len(sanitizer.get("patterns", [])) > 3:
                    patterns += ", ..."
                info(f"  - {sanitizer.get('name')}: {patterns}")

        if "rules" in config:
            info(f"\nRules ({len(config.get('rules', []))}):")
            for rule in config.get("rules", []):
                info(
                    f"  - {rule.get('name')} (Severity: {rule.get('severity', 'unknown')})"
                )

        if "analysis" in config:
            info("\nAnalysis Settings:")
            for key, value in config.get("analysis", {}).items():
                if isinstance(value, list) and len(value) > 3:
                    info(f"  - {key}: {value[:3]} ... ({len(value)} items)")
                else:
                    info(f"  - {key}: {value}")

        info("-" * 40)


def load_config(config_path: str, debug_mode: bool = False) -> Dict[str, Any]:
    """
    Load configuration from a file.

    Args:
        config_path: Path to the configuration file
        debug_mode: Whether to print debug information

    Returns:
        Dictionary containing the configuration

    Raises:
        FileNotFoundError: If the configuration file does not exist
        json.JSONDecodeError: If the configuration file contains invalid JSON
    """
    return ConfigLoader.load(config_path, debug_mode=debug_mode)
