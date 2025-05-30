#!/usr/bin/env python3
"""
LanaLyzer setup script
"""

import os
from setuptools import setup, find_packages

# Read the contents of README.md
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="lanalyzer",
    version="0.1.0",
    description="Python Taint Analysis Tool for finding security vulnerabilities",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="LanaLyzer Team",
    author_email="lanalyzer@example.com",
    packages=find_packages(),
    install_requires=[
        "requests>=2.32.3,<3",
        "colorama>=0.4.6,<0.5",
        "rich>=13.7.0,<14",
        "jinja2>=3.1.3,<4",
        "pyyaml>=6.0.1,<7",
        "astroid>=3.0.2,<4",
        "click>=8.1.7,<9",
    ],
    extras_require={
        "mcp": [
            "fastapi>=0.103.0,<0.104.0",
            "uvicorn[standard]>=0.23.2,<0.24.0",
            "pydantic>=2.4.0,<3.0.0",
            "fastmcp>=2.0.0",
        ],
        "dev": [
            "pytest>=7.4.0,<8",
            "pytest-cov>=4.1.0,<5",
            "black>=23.7.0,<24",
            "isort>=5.12.0,<6",
            "mypy>=1.5.1,<2",
            "flake8>=6.1.0,<7",
            "pre-commit>=4.2.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "lanalyzer=lanalyzer.main:run_lanalyzer",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
    python_requires=">=3.10",
    keywords=[
        "security",
        "static-analysis",
        "taint-analysis",
        "vulnerability-detection",
        "mcp",
        "model-context-protocol",
    ],
    project_urls={
        "Homepage": "https://github.com/mxcrafts/lanalyzer",
        "Bug Tracker": "https://github.com/mxcrafts/lanalyzer/issues",
        "Documentation": "https://github.com/mxcrafts/lanalyzer#readme",
        "Source Code": "https://github.com/mxcrafts/lanalyzer",
    },
    include_package_data=True,
)
