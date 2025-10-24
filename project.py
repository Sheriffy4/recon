#!/usr/bin/env python3
"""
Dependency analyzer for bypass_engine and hybrid_engine refactoring.
This script will analyze the codebase to understand dependencies and usage patterns.
"""

import os
import ast
import json
import sys
from pathlib import Path
from typing import Dict, List
from collections import defaultdict


class DependencyAnalyzer:
    """Analyzes Python project dependencies and usage patterns."""

    def __init__(self, project_root: str = "."):
        self.project_root = Path(project_root).resolve()
        self.imports_map = defaultdict(set)  # module -> imported items
        self.reverse_imports = defaultdict(set)  # module -> modules that import it
        self.class_methods = defaultdict(dict)  # module -> class -> methods
        self.function_calls = defaultdict(set)  # module -> called functions
        self.attribute_access = defaultdict(set)  # module -> accessed attributes
        self.inheritance_map = defaultdict(set)  # class -> parent classes

    def analyze_project(self, target_modules: List[str]) -> Dict:
        """Analyze the entire project focusing on target modules."""
        print(f"🔍 Analyzing project at: {self.project_root}")

        # Find all Python files
        python_files = list(self.project_root.rglob("*.py"))
        print(f"📁 Found {len(python_files)} Python files")

        # Analyze each file
        for py_file in python_files:
            if any(part.startswith(".") for part in py_file.parts):
                continue  # Skip hidden directories

            rel_path = py_file.relative_to(self.project_root)
            module_name = str(rel_path).replace(os.sep, ".").replace(".py", "")

            try:
                with open(py_file, "r", encoding="utf-8") as f:
                    content = f.read()
                    self._analyze_file(module_name, content, target_modules)
            except Exception as e:
                print(f"⚠️  Error analyzing {py_file}: {e}")

        return self._generate_report(target_modules)

    def _analyze_file(self, module_name: str, content: str, target_modules: List[str]):
        """Analyze a single Python file."""
        try:
            tree = ast.parse(content)

            # Check if this file imports our target modules
            imports_targets = False
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    if self._imports_target(node, target_modules):
                        imports_targets = True
                        self._extract_import(node, module_name, target_modules)

            # If this file imports target modules, analyze usage
            if imports_targets or any(
                target in module_name for target in target_modules
            ):
                self._analyze_usage(tree, module_name)

            # If this IS one of our target modules, extract structure
            if any(target in module_name for target in target_modules):
                self._extract_structure(tree, module_name)

        except SyntaxError:
            pass  # Skip files with syntax errors

    def _imports_target(self, node: ast.AST, target_modules: List[str]) -> bool:
        """Check if import node imports any target module."""
        if isinstance(node, ast.Import):
            for alias in node.names:
                if any(target in alias.name for target in target_modules):
                    return True
        elif isinstance(node, ast.ImportFrom):
            if node.module and any(target in node.module for target in target_modules):
                return True
        return False

    def _extract_import(self, node: ast.AST, importer: str, target_modules: List[str]):
        """Extract import information."""
        if isinstance(node, ast.Import):
            for alias in node.names:
                for target in target_modules:
                    if target in alias.name:
                        self.reverse_imports[target].add(importer)
                        self.imports_map[importer].add(f"import {alias.name}")

        elif isinstance(node, ast.ImportFrom):
            if node.module:
                for target in target_modules:
                    if target in node.module:
                        self.reverse_imports[target].add(importer)
                        items = [n.name for n in node.names] if node.names else ["*"]
                        for item in items:
                            self.imports_map[importer].add(
                                f"from {node.module} import {item}"
                            )

    def _analyze_usage(self, tree: ast.AST, module_name: str):
        """Analyze how the module uses imported items."""

        class UsageVisitor(ast.NodeVisitor):
            def __init__(self, analyzer, module):
                self.analyzer = analyzer
                self.module = module

            def visit_Call(self, node):
                # Track function/method calls
                if isinstance(node.func, ast.Name):
                    self.analyzer.function_calls[self.module].add(node.func.id)
                elif isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name):
                        call_str = f"{node.func.value.id}.{node.func.attr}"
                        self.analyzer.function_calls[self.module].add(call_str)
                self.generic_visit(node)

            def visit_Attribute(self, node):
                # Track attribute access
                if isinstance(node.value, ast.Name):
                    attr_str = f"{node.value.id}.{node.attr}"
                    self.analyzer.attribute_access[self.module].add(attr_str)
                self.generic_visit(node)

        visitor = UsageVisitor(self, module_name)
        visitor.visit(tree)

    def _extract_structure(self, tree: ast.AST, module_name: str):
        """Extract class and method structure from target modules."""

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                class_name = node.name
                methods = []
                attributes = []

                # Extract parent classes
                for base in node.bases:
                    if isinstance(base, ast.Name):
                        self.inheritance_map[f"{module_name}.{class_name}"].add(base.id)
                    elif isinstance(base, ast.Attribute):
                        self.inheritance_map[f"{module_name}.{class_name}"].add(
                            ast.unparse(base)
                        )

                # Extract methods and attributes
                for item in node.body:
                    if isinstance(item, ast.FunctionDef):
                        # Get method signature
                        args = []
                        if item.args.args:
                            args = [arg.arg for arg in item.args.args]
                        methods.append(
                            {
                                "name": item.name,
                                "args": args,
                                "is_async": isinstance(item, ast.AsyncFunctionDef),
                                "decorators": [
                                    ast.unparse(d) for d in item.decorator_list
                                ],
                            }
                        )
                    elif isinstance(item, ast.Assign):
                        for target in item.targets:
                            if isinstance(target, ast.Name):
                                attributes.append(target.id)

                self.class_methods[module_name][class_name] = {
                    "methods": methods,
                    "attributes": attributes,
                }

    def _generate_report(self, target_modules: List[str]) -> Dict:
        """Generate analysis report."""
        report = {
            "target_modules": target_modules,
            "modules_importing_targets": {},
            "target_module_structure": {},
            "usage_patterns": {},
            "critical_dependencies": [],
            "refactoring_risks": [],
        }

        # Collect modules that import targets
        for target in target_modules:
            importers = list(self.reverse_imports.get(target, set()))
            if importers:
                report["modules_importing_targets"][target] = {
                    "imported_by": importers,
                    "import_count": len(importers),
                }

        # Collect target module structure
        for module, classes in self.class_methods.items():
            if any(target in module for target in target_modules):
                report["target_module_structure"][module] = {
                    "classes": classes,
                    "inheritance": dict(self.inheritance_map),
                }

        # Analyze usage patterns
        for module, calls in self.function_calls.items():
            relevant_calls = [
                c
                for c in calls
                if any(
                    t in c for t in ["BypassEngine", "HybridEngine", "BypassTechniques"]
                )
            ]
            if relevant_calls:
                report["usage_patterns"][module] = {
                    "method_calls": list(relevant_calls),
                    "attribute_access": list(self.attribute_access.get(module, set())),
                }

        # Identify critical dependencies
        critical_classes = ["BypassEngine", "HybridEngine", "BypassTechniques"]
        for cls in critical_classes:
            users = []
            for module, calls in self.function_calls.items():
                if any(cls in call for call in calls):
                    users.append(module)
            if users:
                report["critical_dependencies"].append(
                    {
                        "class": cls,
                        "used_by": users,
                        "risk_level": "HIGH" if len(users) > 5 else "MEDIUM",
                    }
                )

        # Identify refactoring risks
        self._identify_risks(report)

        return report

    def _identify_risks(self, report: Dict):
        """Identify potential refactoring risks."""
        risks = []

        # Risk: Many modules depend on target
        for target, info in report["modules_importing_targets"].items():
            if info["import_count"] > 10:
                risks.append(
                    {
                        "type": "high_coupling",
                        "module": target,
                        "description": f"{info['import_count']} modules depend on {target}",
                        "severity": "HIGH",
                    }
                )

        # Risk: Complex inheritance
        for module, structure in report["target_module_structure"].items():
            for class_name, class_info in structure.get("classes", {}).items():
                if len(class_info.get("methods", [])) > 20:
                    risks.append(
                        {
                            "type": "large_class",
                            "module": module,
                            "class": class_name,
                            "description": f"Class has {len(class_info['methods'])} methods",
                            "severity": "MEDIUM",
                        }
                    )

        report["refactoring_risks"] = risks


def find_additional_modules(report: Dict) -> List[str]:
    """Identify additional modules that should be provided for refactoring."""
    modules_to_provide = set()

    # Add all modules that import the targets
    for target, info in report["modules_importing_targets"].items():
        for module in info["imported_by"]:
            # Filter out standard library and third-party modules
            if not module.startswith(("test", "tests", "__pycache__")):
                if "core" in module or "bypass" in module:
                    modules_to_provide.add(module)

    # Add modules with high usage
    for module, usage in report["usage_patterns"].items():
        if len(usage["method_calls"]) > 5:
            modules_to_provide.add(module)

    # Add critical dependencies
    for dep in report["critical_dependencies"]:
        if dep["risk_level"] == "HIGH":
            modules_to_provide.update(dep["used_by"])

    return sorted(list(modules_to_provide))


def main():
    """Main entry point."""
    print("=" * 60)
    print("🔧 BYPASS ENGINE DEPENDENCY ANALYZER")
    print("=" * 60)

    # Get project root
    project_root = input(
        "Enter project root path (or press Enter for current directory): "
    ).strip()
    if not project_root:
        project_root = "."

    # Check if path exists
    if not os.path.exists(project_root):
        print(f"❌ Path {project_root} does not exist!")
        return 1

    # Target modules to analyze
    target_modules = [
        "bypass_engine",
        "hybrid_engine",
        "BypassEngine",
        "HybridEngine",
        "BypassTechniques",
    ]

    # Run analysis
    analyzer = DependencyAnalyzer(project_root)
    report = analyzer.analyze_project(target_modules)

    # Save report
    report_file = "refactoring_analysis.json"
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

    print(f"\n✅ Analysis complete! Report saved to {report_file}")

    # Print summary
    print("\n" + "=" * 60)
    print("📊 ANALYSIS SUMMARY")
    print("=" * 60)

    # Modules importing targets
    print("\n🔗 Modules that import bypass_engine or hybrid_engine:")
    for target, info in report["modules_importing_targets"].items():
        print(f"\n  {target}:")
        for importer in info["imported_by"][:5]:  # Show first 5
            print(f"    - {importer}")
        if len(info["imported_by"]) > 5:
            print(f"    ... and {len(info['imported_by']) - 5} more")

    # Critical dependencies
    print("\n⚠️  Critical Dependencies:")
    for dep in report["critical_dependencies"]:
        print(
            f"  {dep['class']}: used by {len(dep['used_by'])} modules (Risk: {dep['risk_level']})"
        )

    # Refactoring risks
    if report["refactoring_risks"]:
        print("\n⛔ Refactoring Risks:")
        for risk in report["refactoring_risks"][:5]:
            print(f"  [{risk['severity']}] {risk['type']}: {risk['description']}")

    # Additional modules needed
    additional = find_additional_modules(report)
    if additional:
        print("\n📦 MODULES YOU SHOULD PROVIDE FOR COMPLETE REFACTORING:")
        print("-" * 60)
        for module in additional:
            module_path = module.replace(".", os.sep) + ".py"
            print(f"  - {module_path}")

        print("\n💡 To provide these modules, please share the following files:")
        for module in additional[:10]:  # Limit to first 10 most important
            module_path = module.replace(".", os.sep) + ".py"
            full_path = os.path.join(project_root, module_path)
            if os.path.exists(full_path):
                size = os.path.getsize(full_path)
                print(f"    {module_path} ({size} bytes)")

    print("\n" + "=" * 60)
    print("✨ Analysis complete!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
