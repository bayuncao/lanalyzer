"""
Configuration Utilities Module - Provides configuration loading and result saving functionalities.
"""

import ast
import json
import os
from typing import Any, Dict, List, Optional, Tuple


def load_configuration(
    config_path: Optional[str], debug: bool = False
) -> Dict[str, Any]:
    """
    Load configuration from a file.

    Args:
        config_path: Path to the configuration file
        debug: Whether to enable debug output

    Returns:
        Configuration dictionary
    """
    if not config_path:
        if debug:
            print("No configuration file provided, using default")
        return {
            "sources": [],
            "sinks": [],
            "rules": [],
            "sanitizers": [],
        }

    if not os.path.exists(config_path):
        raise ValueError(f"Configuration file not found: {config_path}")

    try:
        with open(config_path, "r", encoding="utf-8") as file:
            config = json.load(file)

        if debug:
            print(f"Loaded configuration from {config_path}")

        if not isinstance(config, dict):
            raise ValueError("Configuration must be a JSON object")

        required_keys = ["sources", "sinks", "rules"]
        for key in required_keys:
            if key not in config:
                raise ValueError(f"Missing required key in configuration: {key}")

        return config
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in configuration file: {e}")
    except Exception as e:
        raise ValueError(f"Failed to load configuration: {e}")


def validate_configuration(config: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Validate configuration format and contents.

    Args:
        config: Configuration dictionary

    Returns:
        Tuple of (is_valid, issues)
    """
    issues = []

    if not isinstance(config, dict):
        issues.append("Configuration must be a JSON object")
        return False, issues

    required_keys = ["sources", "sinks", "rules"]
    for key in required_keys:
        if key not in config:
            issues.append(f"Missing required key: {key}")

    if "sources" in config:
        if not isinstance(config["sources"], list):
            issues.append("'sources' must be a list")
        else:
            source_names = set()
            for i, source in enumerate(config["sources"]):
                if not isinstance(source, dict):
                    issues.append(f"Source #{i+1} must be an object")
                    continue

                if "name" not in source:
                    issues.append(f"Source #{i+1} missing 'name' field")
                elif source["name"] in source_names:
                    issues.append(f"Duplicate source name: {source['name']}")
                else:
                    source_names.add(source["name"])

                if "patterns" not in source:
                    issues.append(
                        f"Source '{source.get('name', f'#{i+1}')}' missing 'patterns' field"
                    )
                elif not isinstance(source["patterns"], list):
                    issues.append(
                        f"Source '{source.get('name', f'#{i+1}')}' 'patterns' must be a list"
                    )

    if "sinks" in config:
        if not isinstance(config["sinks"], list):
            issues.append("'sinks' must be a list")
        else:
            sink_names = set()
            for i, sink in enumerate(config["sinks"]):
                if not isinstance(sink, dict):
                    issues.append(f"Sink #{i+1} must be an object")
                    continue

                if "name" not in sink:
                    issues.append(f"Sink #{i+1} missing 'name' field")
                elif sink["name"] in sink_names:
                    issues.append(f"Duplicate sink name: {sink['name']}")
                else:
                    sink_names.add(sink["name"])

                if "patterns" not in sink:
                    issues.append(
                        f"Sink '{sink.get('name', f'#{i+1}')}' missing 'patterns' field"
                    )
                elif not isinstance(sink["patterns"], list):
                    issues.append(
                        f"Sink '{sink.get('name', f'#{i+1}')}' 'patterns' must be a list"
                    )

    if "sanitizers" in config:
        if not isinstance(config["sanitizers"], list):
            issues.append("'sanitizers' must be a list")
        else:
            sanitizer_names = set()
            for i, sanitizer in enumerate(config["sanitizers"]):
                if not isinstance(sanitizer, dict):
                    issues.append(f"Sanitizer #{i+1} must be an object")
                    continue

                if "name" not in sanitizer:
                    issues.append(f"Sanitizer #{i+1} missing 'name' field")
                elif sanitizer["name"] in sanitizer_names:
                    issues.append(f"Duplicate sanitizer name: {sanitizer['name']}")
                else:
                    sanitizer_names.add(sanitizer["name"])

                if "patterns" not in sanitizer:
                    issues.append(
                        f"Sanitizer '{sanitizer.get('name', f'#{i+1}')}' missing 'patterns' field"
                    )
                elif not isinstance(sanitizer["patterns"], list):
                    issues.append(
                        f"Sanitizer '{sanitizer.get('name', f'#{i+1}')}' 'patterns' must be a list"
                    )

    if "rules" in config:
        if not isinstance(config["rules"], list):
            issues.append("'rules' must be a list")
        else:
            source_names = {source.get("name") for source in config.get("sources", [])}
            sink_names = {sink.get("name") for sink in config.get("sinks", [])}
            sanitizer_names = {
                sanitizer.get("name") for sanitizer in config.get("sanitizers", [])
            }

            for i, rule in enumerate(config["rules"]):
                if not isinstance(rule, dict):
                    issues.append(f"Rule #{i+1} must be an object")
                    continue

                if "name" not in rule:
                    issues.append(f"Rule #{i+1} missing 'name' field")

                if "sources" not in rule:
                    issues.append(
                        f"Rule '{rule.get('name', f'#{i+1}')}' missing 'sources' field"
                    )
                elif not isinstance(rule["sources"], list):
                    issues.append(
                        f"Rule '{rule.get('name', f'#{i+1}')}' 'sources' must be a list"
                    )
                else:
                    for source in rule["sources"]:
                        if source not in source_names:
                            issues.append(
                                f"Rule '{rule.get('name', f'#{i+1}')}' references undefined source: {source}"
                            )

                if "sinks" not in rule:
                    issues.append(
                        f"Rule '{rule.get('name', f'#{i+1}')}' missing 'sinks' field"
                    )
                elif not isinstance(rule["sinks"], list):
                    issues.append(
                        f"Rule '{rule.get('name', f'#{i+1}')}' 'sinks' must be a list"
                    )
                else:
                    for sink in rule["sinks"]:
                        if sink not in sink_names:
                            issues.append(
                                f"Rule '{rule.get('name', f'#{i+1}')}' references undefined sink: {sink}"
                            )

                if "message" not in rule:
                    issues.append(
                        f"Rule '{rule.get('name', f'#{i+1}')}' missing 'message' field"
                    )

                if "sanitizers" in rule:
                    if not isinstance(rule["sanitizers"], list):
                        issues.append(
                            f"Rule '{rule.get('name', f'#{i+1}')}' 'sanitizers' must be a list"
                        )
                    else:
                        for sanitizer in rule["sanitizers"]:
                            if sanitizer not in sanitizer_names:
                                issues.append(
                                    f"Rule '{rule.get('name', f'#{i+1}')}' references undefined sanitizer: {sanitizer}"
                                )

    return len(issues) == 0, issues


def save_output(vulnerabilities, output_path, pretty=False, debug=False):
    """
    Save output to a file.

    Args:
        vulnerabilities: List of vulnerabilities to save
        output_path: Path to the output file
        pretty: Whether to pretty-print the JSON
        debug: Whether to enable debug output
    """
    try:
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)

        with open(output_path, "w", encoding="utf-8") as f:
            if pretty:
                json.dump(vulnerabilities, f, indent=2)
            else:
                json.dump(vulnerabilities, f)

        if debug:
            print(f"Saved output to {output_path}")
    except Exception as e:
        print(f"Error saving output to {output_path}: {e}")


def prepare_for_json(obj):
    """
    Recursively process the object to make it JSON serializable.

    Handles:
    - AST nodes converted to string representation
    - Sets converted to lists
    - Other non-serializable objects converted to strings

    Args:
        obj: The object to process

    Returns:
        A serializable object
    """
    if isinstance(obj, ast.AST):
        return f"<{obj.__class__.__name__}>"
    elif isinstance(obj, dict):
        return {k: prepare_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [prepare_for_json(item) for item in obj]
    elif isinstance(obj, set):
        return [prepare_for_json(item) for item in obj]
    elif hasattr(obj, "__dict__"):
        return f"<{obj.__class__.__name__}>"
    else:
        try:
            json.dumps(obj)
            return obj
        except (TypeError, OverflowError):
            return str(obj)
