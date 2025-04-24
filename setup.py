#!/usr/bin/env python3
"""
LanaLyzer setup script
"""

from setuptools import setup, find_packages

setup(
    name="lanalyzer",
    version="0.1.0",
    description="Python taint analysis tool",
    author="MXCrafts",
    packages=find_packages(),
    install_requires=[
        # Add dependencies here
    ],
    entry_points={
        "console_scripts": [
            "lanalyzer=lanalyzer.cli.enhanced:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)
