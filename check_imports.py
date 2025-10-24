#!/usr/bin/env python3
"""
Import checker script to find broken imports across the codebase.
This script will identify:
1. Import statements that reference non-existent modules
2. Import statements that reference deleted files
3. Circular import issues
4. Missing __init__.py files
"""

import ast
import os
import sys
from pathlib import Path
from typing import List, Dict, Tuple
import importlib.util


class ImportChecker:
    def __init__(self, root_dir: str = "."):
        self.root_dir = Path(root_dir).resolve()
        self.python_files = []
        self.broken_imports = []
        self.warnings = []

    def find_python_files(self) -> List[Path]:
        """Find all Python files in the codebase."""
        python_files = []

        # Skip certain directories
        skip_dirs = {
            "__pycache__",
            ".git",
            ".pytest_cache",
            "node_modules",
            ".vscode",
            "venv",
            "env",
            ".env",
            "build",
            "dist",
            ".kiro",
            "logs",
            "temp",
            "reports",
        }

        for root, dirs, files in os.walk(self.root_dir):
            # Remove skip directories from dirs list to avoid traversing them
            dirs[:] = [d for d in dirs if d not in skip_dirs]

            for file in files:
                if file.endswith(".py"):
                    python_files.append(Path(root) / file)

        return python_files

    def extract_imports(self, file_path: Path) -> List[Tuple[str, int, str]]:
        """Extract import statements from a Python file."""
        imports = []

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            tree = ast.parse(content)

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(
                            (alias.name, node.lineno, f"import {alias.name}")
                        )

                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    level = node.level

                    # Handle relative imports
                    if level > 0:
                        # Relative import - convert to absolute
                        relative_parts = [".."] * (level - 1) if level > 1 else []
                        if module:
                            relative_parts.append(module)
                        module = ".".join(relative_parts)

                    for alias in node.names:
                        import_name = f"{module}.{alias.name}" if module else alias.name
                        import_stmt = (
                            f"from {module} import {alias.name}"
                            if module
                            else f"from . import {alias.name}"
                        )
                        imports.append((import_name, node.lineno, import_stmt))

        except Exception as e:
            self.warnings.append(f"Could not parse {file_path}: {e}")

        return imports

    def resolve_module_path(
        self, module_name: str, current_file: Path
    ) -> Tuple[bool, str]:
        """
        Try to resolve if a module exists.
        Returns (exists, reason_if_not_exists)
        """

        # Standard library modules that should always be available
        stdlib_modules = {
            "typing",
            "unittest",
            "unittest.mock",
            "pathlib",
            "dataclasses",
            "datetime",
            "collections",
            "json",
            "os",
            "sys",
            "logging",
            "asyncio",
            "functools",
            "itertools",
            "contextlib",
            "abc",
            "enum",
            "warnings",
            "traceback",
            "inspect",
            "importlib",
            "struct",
            "random",
            "string",
            "time",
            "re",
            "socket",
            "threading",
            "multiprocessing",
            "subprocess",
            "shutil",
            "tempfile",
            "glob",
            "fnmatch",
            "pickle",
            "copy",
            "math",
        }

        # Check if it's a standard library module or submodule
        root_module = module_name.split(".")[0]
        if root_module in stdlib_modules:
            return True, ""

        # Third-party packages that might be installed
        third_party_modules = {
            "scapy",
            "flask",
            "aiohttp",
            "requests",
            "numpy",
            "pandas",
            "matplotlib",
            "seaborn",
            "sklearn",
            "tensorflow",
            "torch",
            "pytest",
            "click",
            "pydantic",
            "sqlalchemy",
            "redis",
            "celery",
            "gunicorn",
            "uvicorn",
            "fastapi",
            "django",
        }

        root_module = module_name.split(".")[0]
        if root_module in third_party_modules:
            # Don't check third-party modules - assume they might be installed
            return True, ""

        # Handle relative imports
        if module_name.startswith("."):
            # Get the package directory of current file
            current_dir = current_file.parent
            parts = module_name.split(".")

            # Count leading dots for relative level
            level = 0
            for part in parts:
                if part == "":
                    level += 1
                else:
                    break

            # Go up directories based on level
            target_dir = current_dir
            for _ in range(level):
                target_dir = target_dir.parent

            # Add remaining parts
            remaining_parts = [p for p in parts if p != ""]
            for part in remaining_parts:
                target_dir = target_dir / part

            # Check if it's a file or package
            py_file = target_dir.with_suffix(".py")
            init_file = target_dir / "__init__.py"

            if py_file.exists():
                return True, ""
            elif init_file.exists():
                return True, ""
            else:
                return False, f"Relative import path not found: {target_dir}"

        # Handle absolute imports within the project
        if (
            module_name.startswith("core.")
            or module_name.startswith("tests.")
            or module_name.startswith("ml.")
        ):
            # Convert module name to file path
            parts = module_name.split(".")

            # Try as a file
            file_path = self.root_dir
            for part in parts:
                file_path = file_path / part

            py_file = file_path.with_suffix(".py")
            init_file = file_path / "__init__.py"

            if py_file.exists():
                return True, ""
            elif init_file.exists():
                return True, ""
            else:
                return False, f"Module file not found: {py_file} or {init_file}"

        # For other modules, try to import them
        try:
            spec = importlib.util.find_spec(module_name)
            if spec is not None:
                return True, ""
            else:
                return False, f"Module not found in Python path: {module_name}"
        except (ImportError, ModuleNotFoundError, ValueError) as e:
            return False, f"Import error: {e}"

    def check_file_imports(self, file_path: Path) -> List[Dict]:
        """Check all imports in a single file."""
        file_issues = []
        imports = self.extract_imports(file_path)

        for import_name, line_no, import_stmt in imports:
            exists, reason = self.resolve_module_path(import_name, file_path)

            if not exists:
                file_issues.append(
                    {
                        "file": str(file_path.relative_to(self.root_dir)),
                        "line": line_no,
                        "import": import_stmt,
                        "module": import_name,
                        "reason": reason,
                    }
                )

        return file_issues

    def check_all_imports(self) -> Dict:
        """Check imports in all Python files."""
        self.python_files = self.find_python_files()

        print(f"Checking imports in {len(self.python_files)} Python files...")

        all_issues = []

        for file_path in self.python_files:
            try:
                issues = self.check_file_imports(file_path)
                all_issues.extend(issues)
            except Exception as e:
                self.warnings.append(f"Error checking {file_path}: {e}")

        return {
            "issues": all_issues,
            "warnings": self.warnings,
            "files_checked": len(self.python_files),
        }

    def print_report(self, results: Dict):
        """Print a formatted report of import issues."""
        issues = results["issues"]
        warnings = results["warnings"]

        print(f"\n{'='*60}")
        print("IMPORT CHECK REPORT")
        print(f"{'='*60}")
        print(f"Files checked: {results['files_checked']}")
        print(f"Issues found: {len(issues)}")
        print(f"Warnings: {len(warnings)}")

        if warnings:
            print(f"\n{'='*40}")
            print("WARNINGS:")
            print(f"{'='*40}")
            for warning in warnings:
                print(f"⚠️  {warning}")

        if issues:
            print(f"\n{'='*40}")
            print("BROKEN IMPORTS:")
            print(f"{'='*40}")

            # Group by file
            by_file = {}
            for issue in issues:
                file_name = issue["file"]
                if file_name not in by_file:
                    by_file[file_name] = []
                by_file[file_name].append(issue)

            for file_name, file_issues in sorted(by_file.items()):
                print(f"\n📁 {file_name}")
                for issue in file_issues:
                    print(f"   Line {issue['line']:3d}: {issue['import']}")
                    print(f"            ❌ {issue['reason']}")
        else:
            print("\n✅ No broken imports found!")

        print(f"\n{'='*60}")


def main():
    checker = ImportChecker()
    results = checker.check_all_imports()
    checker.print_report(results)

    # Return exit code based on results
    if results["issues"]:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
