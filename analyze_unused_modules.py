#!/usr/bin/env python3
"""
Static analysis tool to find unused modules and orphaned files.
Part of engine unification refactoring - Task 2.1
"""

import os
import ast
import glob
from pathlib import Path
from typing import Set, Dict, List, Tuple
import json

class UnusedModuleAnalyzer:
    def __init__(self, project_root: str = "."):
        self.project_root = Path(project_root)
        self.python_files = []
        self.imports = {}
        self.file_references = set()
        self.all_python_files = set()
        
    def scan_python_files(self) -> List[Path]:
        """Scan for all Python files in the project."""
        patterns = ["**/*.py"]
        files = []
        
        for pattern in patterns:
            files.extend(self.project_root.glob(pattern))
            
        # Filter out __pycache__ and .git directories
        filtered_files = []
        for file in files:
            if "__pycache__" not in str(file) and ".git" not in str(file):
                filtered_files.append(file)
                
        return filtered_files
    
    def extract_imports(self, file_path: Path) -> Set[str]:
        """Extract all imports from a Python file."""
        imports = set()
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            tree = ast.parse(content)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.add(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.add(node.module)
                        # Also add submodules
                        for alias in node.names:
                            if node.module:
                                full_import = f"{node.module}.{alias.name}"
                                imports.add(full_import)
                            
        except (SyntaxError, UnicodeDecodeError, Exception) as e:
            print(f"Warning: Could not parse {file_path}: {e}")
            
        return imports
    
    def find_local_modules(self) -> Dict[str, Path]:
        """Find all local Python modules that could be imported."""
        local_modules = {}
        
        for file_path in self.python_files:
            # Convert file path to module name
            relative_path = file_path.relative_to(self.project_root)
            
            # Remove .py extension and convert path separators to dots
            module_parts = list(relative_path.parts[:-1]) + [relative_path.stem]
            
            # Skip __init__ files for module name
            if module_parts[-1] == "__init__":
                module_parts = module_parts[:-1]
                
            if module_parts:
                module_name = ".".join(module_parts)
                local_modules[module_name] = file_path
                
                # Also add shorter versions (for relative imports)
                for i in range(1, len(module_parts)):
                    short_name = ".".join(module_parts[i:])
                    if short_name not in local_modules:
                        local_modules[short_name] = file_path
                        
        return local_modules
    
    def analyze_usage(self) -> Dict[str, any]:
        """Analyze which modules are used and which are orphaned."""
        print("Scanning Python files...")
        self.python_files = self.scan_python_files()
        
        print(f"Found {len(self.python_files)} Python files")
        
        # Extract imports from all files
        print("Extracting imports...")
        all_imports = set()
        file_imports = {}
        
        for file_path in self.python_files:
            imports = self.extract_imports(file_path)
            file_imports[str(file_path)] = imports
            all_imports.update(imports)
            
        # Find local modules
        print("Identifying local modules...")
        local_modules = self.find_local_modules()
        
        # Determine unused modules
        unused_modules = []
        used_modules = []
        
        for module_name, module_path in local_modules.items():
            is_used = False
            
            # Check if this module is imported anywhere
            for import_name in all_imports:
                if (module_name == import_name or 
                    import_name.startswith(module_name + ".") or
                    module_name.startswith(import_name + ".")):
                    is_used = True
                    break
                    
            if is_used:
                used_modules.append({
                    "module": module_name,
                    "path": str(module_path),
                    "imported_by": []
                })
            else:
                unused_modules.append({
                    "module": module_name,
                    "path": str(module_path),
                    "size_bytes": module_path.stat().st_size if module_path.exists() else 0
                })
        
        # Find which files import each used module
        for used_module in used_modules:
            module_name = used_module["module"]
            for file_path, imports in file_imports.items():
                for import_name in imports:
                    if (module_name == import_name or 
                        import_name.startswith(module_name + ".") or
                        module_name.startswith(import_name + ".")):
                        used_module["imported_by"].append(file_path)
                        break
        
        return {
            "total_files": len(self.python_files),
            "total_imports": len(all_imports),
            "local_modules": len(local_modules),
            "used_modules": used_modules,
            "unused_modules": unused_modules,
            "unused_count": len(unused_modules),
            "potential_savings_bytes": sum(m["size_bytes"] for m in unused_modules)
        }
    
    def find_engine_files(self) -> List[Dict[str, any]]:
        """Specifically find engine-related files for cleanup analysis."""
        engine_patterns = [
            "*engine*.py",
            "*bypass*.py", 
            "*hybrid*.py"
        ]
        
        engine_files = []
        
        for pattern in engine_patterns:
            for file_path in self.project_root.rglob(pattern):
                if "__pycache__" not in str(file_path) and file_path.suffix == ".py":
                    engine_files.append({
                        "path": str(file_path),
                        "name": file_path.name,
                        "size_bytes": file_path.stat().st_size,
                        "category": "engine"
                    })
                    
        return engine_files
    
    def find_duplicate_analyzers(self) -> List[Dict[str, any]]:
        """Find duplicate PCAP analyzers and similar files."""
        analyzer_patterns = [
            "*analyzer*.py",
            "*pcap*.py",
            "*compare*.py"
        ]
        
        analyzer_files = []
        
        for pattern in analyzer_patterns:
            for file_path in self.project_root.rglob(pattern):
                if "__pycache__" not in str(file_path) and file_path.suffix == ".py":
                    analyzer_files.append({
                        "path": str(file_path),
                        "name": file_path.name,
                        "size_bytes": file_path.stat().st_size,
                        "category": "analyzer"
                    })
                    
        return analyzer_files

def main():
    analyzer = UnusedModuleAnalyzer(".")
    
    print("=== Unused Module Analysis ===")
    print("Analyzing project for unused modules and orphaned files...")
    
    # General unused module analysis
    results = analyzer.analyze_usage()
    
    print(f"\n=== SUMMARY ===")
    print(f"Total Python files: {results['total_files']}")
    print(f"Total local modules: {results['local_modules']}")
    print(f"Used modules: {len(results['used_modules'])}")
    print(f"Unused modules: {results['unused_count']}")
    print(f"Potential space savings: {results['potential_savings_bytes']:,} bytes")
    
    # Engine files analysis
    print(f"\n=== ENGINE FILES ===")
    engine_files = analyzer.find_engine_files()
    print(f"Found {len(engine_files)} engine-related files:")
    for engine_file in sorted(engine_files, key=lambda x: x['name']):
        print(f"  - {engine_file['name']} ({engine_file['size_bytes']:,} bytes)")
        print(f"    Path: {engine_file['path']}")
    
    # Analyzer files
    print(f"\n=== ANALYZER FILES ===")
    analyzer_files = analyzer.find_duplicate_analyzers()
    print(f"Found {len(analyzer_files)} analyzer-related files:")
    
    # Group by similar names to identify duplicates
    name_groups = {}
    for analyzer_file in analyzer_files:
        base_name = analyzer_file['name'].lower()
        # Remove common suffixes to group similar files
        for suffix in ['_fixed', '_new', '_old', '_backup', '_v2', '_enhanced']:
            base_name = base_name.replace(suffix, '')
        
        if base_name not in name_groups:
            name_groups[base_name] = []
        name_groups[base_name].append(analyzer_file)
    
    for base_name, files in name_groups.items():
        if len(files) > 1:
            print(f"\n  Potential duplicates for '{base_name}':")
            for file in sorted(files, key=lambda x: x['name']):
                print(f"    - {file['name']} ({file['size_bytes']:,} bytes)")
                print(f"      Path: {file['path']}")
    
    # Save detailed results
    output_file = "unused_modules_analysis.json"
    detailed_results = {
        "summary": results,
        "engine_files": engine_files,
        "analyzer_files": analyzer_files,
        "analysis_timestamp": "2025-01-07"
    }
    
    with open(output_file, 'w') as f:
        json.dump(detailed_results, f, indent=2)
    
    print(f"\n=== UNUSED MODULES ===")
    if results['unused_modules']:
        print("The following modules appear to be unused:")
        for module in sorted(results['unused_modules'], key=lambda x: x['size_bytes'], reverse=True):
            print(f"  - {module['module']} ({module['size_bytes']:,} bytes)")
            print(f"    Path: {module['path']}")
    else:
        print("No obviously unused modules found.")
    
    print(f"\nDetailed analysis saved to: {output_file}")
    
    return detailed_results

if __name__ == "__main__":
    main()