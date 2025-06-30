"""
File Processing Utilities Module - Provides file searching, listing, and collection functionalities.
"""

import os

from lanalyzer.logger import error, info, warning


def list_target_files(target_path):
    """List all Python files in the target path"""
    info(f"[File List] Target path: {target_path}")
    if not os.path.exists(target_path):
        error(f"[Error] Target path does not exist: {target_path}")
        return

    if os.path.isdir(target_path):
        for root, dirs, files in os.walk(target_path):
            for file in files:
                if file.endswith(".py"):
                    full_path = os.path.join(root, file)
                    info(f"[File List] Found Python file: {full_path}")
    else:
        info(f"[File List] Single file: {target_path}")


def search_for_file(base_dir, filename):
    """Search for a specific file"""
    info(f"[Search] Searching for {filename} in {base_dir}...")
    found_locations = []

    if os.path.isdir(base_dir):
        for root, dirs, files in os.walk(base_dir):
            if filename in files:
                found_locations.append(os.path.join(root, filename))

    if found_locations:
        info(f"[Search] Found {filename} at the following locations:")
        for loc in found_locations:
            info(f"  - {loc}")
    else:
        info(f"[Search] Could not find {filename}")


def gather_target_files(target_path):
    """Gather the list of target files to analyze"""
    if not os.path.exists(target_path):
        error(f"[Error] Target path does not exist: {target_path}")
        return []

    if os.path.isdir(target_path):
        target_files = []
        for root, dirs, files in os.walk(target_path):
            for file in files:
                if file.endswith(".py"):
                    target_files.append(os.path.join(root, file))
        return target_files
    else:
        # Single file
        if target_path.endswith(".py"):
            return [target_path]
        else:
            warning(f"[Warning] Target is not a Python file: {target_path}")
            return []
