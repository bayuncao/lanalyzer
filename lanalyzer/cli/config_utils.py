"""
Configuration Utilities Module - Provides configuration loading and result saving functionalities.
"""

import json
import os
import ast


def load_configuration(config_path, debug=False):
    """Load the configuration file"""
    if debug:
        print(f"[Config] Loading configuration file: {config_path}")

    if not config_path:
        print("[Error] Configuration file path not provided")
        raise ValueError("Configuration file path must be provided")

    if not os.path.exists(config_path):
        print(f"[Error] Configuration file not found: {config_path}")
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    try:
        with open(config_path, "r") as f:
            config = json.load(f)
            if debug:
                print("[Config] Successfully loaded configuration, containing:")
                print(f"  - {len(config.get('sources', []))} sources")
                print(f"  - {len(config.get('sinks', []))} sinks")
                print(f"  - {len(config.get('rules', []))} rules")
            return config
    except json.JSONDecodeError as e:
        print(f"[Error] Configuration file {config_path} contains invalid JSON: {e}")
        raise
    except Exception as e:
        print(f"[Error] Failed to load configuration file: {e}")
        raise


def save_output(vulnerabilities, output_path, pretty=False, debug=False):
    """Save analysis results to a file"""
    if not output_path:
        return

    if debug:
        print(f"[Output] Saving results to: {output_path}")

    try:
        # Preprocess results to ensure they can be serialized correctly
        processed_vulns = prepare_for_json(vulnerabilities)

        with open(output_path, "w", encoding="utf-8") as f:
            if pretty:
                json.dump(processed_vulns, f, indent=2, ensure_ascii=False)
            else:
                json.dump(processed_vulns, f, ensure_ascii=False)

        if debug:
            print(
                f"[Output] Successfully saved {len(vulnerabilities)} vulnerability results to {output_path}"
            )
    except Exception as e:
        print(f"[Error] Failed to save output: {e}")
        if debug:
            import traceback

            print(traceback.format_exc())


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
        # Handle AST nodes
        return f"<{obj.__class__.__name__}>"
    elif isinstance(obj, dict):
        # Recursively process dictionaries
        return {k: prepare_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        # Recursively process lists and tuples
        return [prepare_for_json(item) for item in obj]
    elif isinstance(obj, set):
        # Handle sets
        return [prepare_for_json(item) for item in obj]
    elif hasattr(obj, "__dict__"):
        # Handle custom objects
        return f"<{obj.__class__.__name__}>"
    else:
        # Try to return directly, convert to string if not serializable
        try:
            json.dumps(obj)
            return obj
        except (TypeError, OverflowError):
            return str(obj)
