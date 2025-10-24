#!/usr/bin/env python3
"""Setup script for PCAP Analysis System."""

from setuptools import setup, find_packages
import os
import sys

# Ensure Python 3.8+
if sys.version_info < (3, 8):
    print("Error: Python 3.8 or higher is required.")
    sys.exit(1)


# Read version from __init__.py
def get_version():
    """Get version from package __init__.py file."""
    version_file = os.path.join(os.path.dirname(__file__), "..", "__init__.py")
    with open(version_file, "r") as f:
        for line in f:
            if line.startswith("__version__"):
                return line.split("=")[1].strip().strip("\"'")
    return "1.0.0"


# Read requirements from requirements.txt
def get_requirements():
    """Get requirements from requirements.txt file."""
    requirements_file = os.path.join(os.path.dirname(__file__), "requirements.txt")
    with open(requirements_file, "r") as f:
        requirements = []
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                requirements.append(line)
        return requirements


# Read long description from README
def get_long_description():
    """Get long description from README file."""
    readme_file = os.path.join(os.path.dirname(__file__), "..", "docs", "README.md")
    if os.path.exists(readme_file):
        with open(readme_file, "r", encoding="utf-8") as f:
            return f.read()
    return "PCAP Analysis System for DPI bypass comparison and optimization"


setup(
    name="pcap-analysis-system",
    version=get_version(),
    description="PCAP Analysis System for DPI bypass comparison and optimization",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    author="PCAP Analysis Team",
    author_email="team@pcap-analysis.com",
    url="https://github.com/pcap-analysis/pcap-analysis-system",
    license="MIT",
    # Package configuration
    packages=find_packages(where=".."),
    package_dir={"": ".."},
    include_package_data=True,
    zip_safe=False,
    # Requirements
    python_requires=">=3.8",
    install_requires=get_requirements(),
    # Optional dependencies
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "pytest-asyncio>=0.20.0",
            "black>=22.0.0",
            "isort>=5.10.0",
            "flake8>=5.0.0",
            "mypy>=0.991",
        ],
        "docs": [
            "sphinx>=5.0.0",
            "sphinx-rtd-theme>=1.0.0",
            "myst-parser>=0.18.0",
        ],
        "monitoring": [
            "prometheus-client>=0.15.0",
            "grafana-api>=1.0.3",
        ],
        "database": [
            "sqlalchemy>=1.4.0",
            "psycopg2-binary>=2.9.0",
            "redis>=4.0.0",
        ],
        "visualization": [
            "matplotlib>=3.5.0",
            "plotly>=5.0.0",
            "seaborn>=0.11.0",
        ],
    },
    # Entry points
    entry_points={
        "console_scripts": [
            "pcap-analysis=core.pcap_analysis.cli:main",
            "pcap-compare=core.pcap_analysis.cli:compare_command",
            "pcap-analyze=core.pcap_analysis.cli:analyze_command",
            "pcap-validate=core.pcap_analysis.cli:validate_command",
        ],
    },
    # Package data
    package_data={
        "core.pcap_analysis": [
            "config/*.conf",
            "config/*.json",
            "docs/*.md",
            "deployment/*.yml",
            "deployment/*.yaml",
            "deployment/kubernetes/*.yaml",
        ],
    },
    # Classifiers
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "Topic :: System :: Networking :: Monitoring",
    ],
    # Keywords
    keywords="pcap analysis dpi bypass network security packet capture",
    # Project URLs
    project_urls={
        "Bug Reports": "https://github.com/pcap-analysis/pcap-analysis-system/issues",
        "Source": "https://github.com/pcap-analysis/pcap-analysis-system",
        "Documentation": "https://pcap-analysis.readthedocs.io/",
    },
)
