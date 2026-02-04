"""
Setup script for IntelliRefactor

Intelligent Project Analysis and Refactoring System
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

# Read requirements
requirements_path = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_path.exists():
    requirements = requirements_path.read_text().strip().split('\n')
    requirements = [req.strip() for req in requirements if req.strip() and not req.startswith('#')]

setup(
    name="intellirefactor",
    version="0.1.0",
    author="IntelliRefactor Team",
    author_email="contact@intellirefactor.dev",
    description="Intelligent Project Analysis and Refactoring System",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/intellirefactor/intellirefactor",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Code Generators",
        "Topic :: Software Development :: Quality Assurance",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "pytest-benchmark>=4.0.0",
            "hypothesis>=6.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=1.0.0",
        ],
        "docs": [
            "sphinx>=5.0.0",
            "sphinx-rtd-theme>=1.0.0",
            "myst-parser>=0.18.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "intellirefactor=intellirefactor.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "intellirefactor": [
            "knowledge/*.json",
            "knowledge/*.md",
            "templates/*.json",
            "templates/*.yaml",
        ],
    },
    keywords=[
        "refactoring",
        "code-analysis", 
        "automation",
        "code-quality",
        "static-analysis",
        "project-analysis",
        "intelligent-refactoring",
        "code-transformation",
    ],
    project_urls={
        "Bug Reports": "https://github.com/intellirefactor/intellirefactor/issues",
        "Source": "https://github.com/intellirefactor/intellirefactor",
        "Documentation": "https://intellirefactor.readthedocs.io/",
    },
)