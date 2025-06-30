"""
Standard library detection utilities for LanaLyzer.

This module provides comprehensive detection of Python standard library modules
using multiple methods to ensure accuracy across different Python versions.
"""

import importlib.util
import sys
from functools import lru_cache
from typing import Any, Dict, Optional, Set

from lanalyzer.logger import debug, get_logger

logger = get_logger("lanalyzer.utils.stdlib_detector")


class StandardLibraryDetector:
    """
    Detects Python standard library modules using multiple methods.

    This class provides a comprehensive approach to identifying standard library
    modules, combining modern Python features with fallback methods for compatibility.
    """

    def __init__(self, debug_mode: bool = False):
        """
        Initialize the standard library detector.

        Args:
            debug_mode: Whether to enable debug logging
        """
        self.debug = debug_mode
        self._stdlib_cache: Optional[Set[str]] = None
        self._builtin_cache: Optional[Set[str]] = None

    @property
    @lru_cache(maxsize=1)
    def stdlib_modules(self) -> Set[str]:
        """
        Get the complete set of standard library module names.

        Returns:
            Set of standard library module names
        """
        if self._stdlib_cache is not None:
            return self._stdlib_cache

        stdlib_set = set()

        # Method 1: Use sys.stdlib_module_names (Python 3.10+)
        if hasattr(sys, "stdlib_module_names"):
            stdlib_set.update(sys.stdlib_module_names)
            if self.debug:
                debug(
                    f"Found {len(sys.stdlib_module_names)} modules via sys.stdlib_module_names"
                )
        else:
            # Fallback for older Python versions
            stdlib_set.update(self._get_fallback_stdlib_modules())
            if self.debug:
                debug(
                    f"Using fallback stdlib detection, found {len(stdlib_set)} modules"
                )

        # Method 2: Add builtin modules
        if hasattr(sys, "builtin_module_names"):
            builtin_count = len(sys.builtin_module_names)
            stdlib_set.update(sys.builtin_module_names)
            if self.debug:
                debug(f"Added {builtin_count} builtin modules")

        self._stdlib_cache = stdlib_set

        if self.debug:
            debug(f"Total standard library modules detected: {len(stdlib_set)}")

        return stdlib_set

    @property
    @lru_cache(maxsize=1)
    def builtin_modules(self) -> Set[str]:
        """
        Get the set of builtin module names.

        Returns:
            Set of builtin module names
        """
        if self._builtin_cache is not None:
            return self._builtin_cache

        if hasattr(sys, "builtin_module_names"):
            self._builtin_cache = set(sys.builtin_module_names)
        else:
            self._builtin_cache = set()

        return self._builtin_cache

    def is_standard_library(self, module_name: str) -> bool:
        """
        Check if a module is part of the Python standard library.

        Args:
            module_name: Name of the module to check

        Returns:
            True if the module is part of the standard library, False otherwise
        """
        if not module_name:
            return False

        # Get the root module name (e.g., 'urllib' from 'urllib.parse')
        root_module = module_name.split(".")[0]

        # Check against our comprehensive stdlib set
        return root_module in self.stdlib_modules

    def is_builtin_module(self, module_name: str) -> bool:
        """
        Check if a module is a builtin module.

        Args:
            module_name: Name of the module to check

        Returns:
            True if the module is builtin, False otherwise
        """
        if not module_name:
            return False

        root_module = module_name.split(".")[0]
        return root_module in self.builtin_modules

    def get_module_info(self, module_name: str) -> Dict[str, Any]:
        """
        Get comprehensive information about a module.

        Args:
            module_name: Name of the module to analyze

        Returns:
            Dictionary containing module information
        """
        if not module_name:
            return {"error": "Empty module name"}

        root_module = module_name.split(".")[0]

        info = {
            "module_name": module_name,
            "root_module": root_module,
            "is_stdlib": self.is_standard_library(module_name),
            "is_builtin": self.is_builtin_module(module_name),
            "is_third_party": False,
        }

        # Determine if it's third-party
        info["is_third_party"] = not (info["is_stdlib"] or info["is_builtin"])

        # Try to get module spec for additional information
        try:
            spec = importlib.util.find_spec(root_module)
            if spec:
                info["spec_available"] = True
                info["has_location"] = spec.origin is not None
                if spec.origin:
                    info["origin"] = spec.origin
                    # Additional classification based on path
                    if "site-packages" in spec.origin:
                        info["likely_third_party"] = True
                    elif (
                        "lib/python" in spec.origin
                        and "site-packages" not in spec.origin
                    ):
                        info["likely_stdlib"] = True
            else:
                info["spec_available"] = False
        except (ImportError, AttributeError, ValueError) as e:
            info["spec_error"] = str(e)

        return info

    def _get_fallback_stdlib_modules(self) -> Set[str]:
        """
        Fallback method for older Python versions that don't have sys.stdlib_module_names.

        Returns:
            Set of known standard library module names
        """
        # Comprehensive list based on Python 3.11 standard library
        return {
            "__future__",
            "_abc",
            "_ast",
            "_asyncio",
            "_bisect",
            "_blake2",
            "_bootsubprocess",
            "_bz2",
            "_codecs",
            "_collections",
            "_collections_abc",
            "_compat_pickle",
            "_compression",
            "_contextvars",
            "_csv",
            "_ctypes",
            "_curses",
            "_curses_panel",
            "_datetime",
            "_decimal",
            "_elementtree",
            "_functools",
            "_gdbm",
            "_hashlib",
            "_heapq",
            "_imp",
            "_io",
            "_json",
            "_locale",
            "_lsprof",
            "_lzma",
            "_md5",
            "_multibytecodec",
            "_multiprocessing",
            "_opcode",
            "_operator",
            "_pickle",
            "_posixsubprocess",
            "_py_abc",
            "_pydecimal",
            "_pyio",
            "_queue",
            "_random",
            "_sha1",
            "_sha256",
            "_sha3",
            "_sha512",
            "_signal",
            "_socket",
            "_sqlite3",
            "_sre",
            "_ssl",
            "_stat",
            "_statistics",
            "_string",
            "_strptime",
            "_struct",
            "_symtable",
            "_thread",
            "_threading_local",
            "_tkinter",
            "_tokenize",
            "_tracemalloc",
            "_uuid",
            "_warnings",
            "_weakref",
            "_weakrefset",
            "_zoneinfo",
            "abc",
            "aifc",
            "argparse",
            "array",
            "ast",
            "asynchat",
            "asyncio",
            "asyncore",
            "atexit",
            "audioop",
            "base64",
            "bdb",
            "binascii",
            "binhex",
            "bisect",
            "builtins",
            "bz2",
            "calendar",
            "cgi",
            "cgitb",
            "chunk",
            "cmath",
            "cmd",
            "code",
            "codecs",
            "codeop",
            "collections",
            "colorsys",
            "compileall",
            "concurrent",
            "configparser",
            "contextlib",
            "contextvars",
            "copy",
            "copyreg",
            "cProfile",
            "crypt",
            "csv",
            "ctypes",
            "curses",
            "dataclasses",
            "datetime",
            "dbm",
            "decimal",
            "difflib",
            "dis",
            "distutils",
            "doctest",
            "email",
            "encodings",
            "ensurepip",
            "enum",
            "errno",
            "faulthandler",
            "fcntl",
            "filecmp",
            "fileinput",
            "fnmatch",
            "fractions",
            "ftplib",
            "functools",
            "gc",
            "getopt",
            "getpass",
            "gettext",
            "glob",
            "graphlib",
            "grp",
            "gzip",
            "hashlib",
            "heapq",
            "hmac",
            "html",
            "http",
            "imaplib",
            "imghdr",
            "imp",
            "importlib",
            "inspect",
            "io",
            "ipaddress",
            "itertools",
            "json",
            "keyword",
            "lib2to3",
            "linecache",
            "locale",
            "logging",
            "lzma",
            "mailbox",
            "mailcap",
            "marshal",
            "math",
            "mimetypes",
            "mmap",
            "modulefinder",
            "multiprocessing",
            "netrc",
            "nntplib",
            "numbers",
            "operator",
            "optparse",
            "os",
            "pathlib",
            "pdb",
            "pickle",
            "pickletools",
            "pipes",
            "pkgutil",
            "platform",
            "plistlib",
            "poplib",
            "posix",
            "pprint",
            "profile",
            "pstats",
            "pty",
            "pwd",
            "py_compile",
            "pyclbr",
            "pydoc",
            "queue",
            "quopri",
            "random",
            "re",
            "readline",
            "reprlib",
            "resource",
            "rlcompleter",
            "runpy",
            "sched",
            "secrets",
            "select",
            "selectors",
            "shelve",
            "shlex",
            "shutil",
            "signal",
            "site",
            "smtpd",
            "smtplib",
            "sndhdr",
            "socket",
            "socketserver",
            "sqlite3",
            "ssl",
            "stat",
            "statistics",
            "string",
            "stringprep",
            "struct",
            "subprocess",
            "sunau",
            "symtable",
            "sys",
            "sysconfig",
            "tabnanny",
            "tarfile",
            "telnetlib",
            "tempfile",
            "termios",
            "test",
            "textwrap",
            "threading",
            "time",
            "timeit",
            "tkinter",
            "token",
            "tokenize",
            "trace",
            "traceback",
            "tracemalloc",
            "tty",
            "turtle",
            "types",
            "typing",
            "unicodedata",
            "unittest",
            "urllib",
            "uu",
            "uuid",
            "venv",
            "warnings",
            "wave",
            "weakref",
            "webbrowser",
            "winreg",
            "winsound",
            "wsgiref",
            "xdrlib",
            "xml",
            "xmlrpc",
            "zipapp",
            "zipfile",
            "zipimport",
            "zlib",
            "zoneinfo",
        }

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about detected standard library modules.

        Returns:
            Dictionary containing detection statistics
        """
        stdlib_count = len(self.stdlib_modules)
        builtin_count = len(self.builtin_modules)

        return {
            "total_stdlib_modules": stdlib_count,
            "builtin_modules": builtin_count,
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "has_sys_stdlib_module_names": hasattr(sys, "stdlib_module_names"),
            "detection_method": "sys.stdlib_module_names"
            if hasattr(sys, "stdlib_module_names")
            else "fallback",
        }


# Global instance for easy access
_detector_instance: Optional[StandardLibraryDetector] = None


def get_stdlib_detector(debug: bool = False) -> StandardLibraryDetector:
    """
    Get a global instance of the standard library detector.

    Args:
        debug: Whether to enable debug mode

    Returns:
        StandardLibraryDetector instance
    """
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = StandardLibraryDetector(debug_mode=debug)
    return _detector_instance


def is_standard_library(module_name: str, debug: bool = False) -> bool:
    """
    Convenience function to check if a module is part of the standard library.

    Args:
        module_name: Name of the module to check
        debug: Whether to enable debug mode

    Returns:
        True if the module is part of the standard library, False otherwise
    """
    detector = get_stdlib_detector(debug)
    return detector.is_standard_library(module_name)
