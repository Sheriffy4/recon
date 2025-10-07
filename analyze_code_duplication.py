#!/usr/bin/env python3
"""
Code duplication analyzer for engine unification refactoring.
Identifies duplicate functionality and redundant implementations.
Part of Task 2.2
"""

import os
import ast
import hashlib
from pathlib import Path
from typing import Dict, List, Set, Tuple
import json
from collections import defaultdict
import difflib

class CodeDuplicationAnalyzer:
    def __init__(self, project_root: str = "."):
        self.project_root = Path(project_root)
        self.python_files = []
        self.function_signatures = defaultdict(list)
        self.class_signatures = defaultdict(list)
        self.file_hashes = {}
        self.similar_files = []
        
    def scan_python_files(self) -> List[Path]:
        """Scan for all Python files in the project."""
        files = []
        for file_path in self.project_root.rglob("*.py"):
            if "__pycache__" not in str(file_path) and ".git" not in str(file_path):
                files.append(file_path)
        return files
    
    def extract_function_signature(self, node: ast.FunctionDef) -> str:
        """Extract a normalized function signature."""
        args = []
        for arg in node.args.args:
            args.append(arg.arg)
        
        # Create signature without considering variable names
        signature = f"{node.name}({len(args)})"
        return signature
    
    def extract_class_signature(self, node: ast.ClassDef) -> str:
        """Extract a normalized class signature."""
        methods = []
        for item in node.body:
            if isinstance(item, ast.FunctionDef):
                methods.append(item.name)
        
        signature = f"{node.name}({sorted(methods)})"
        return signature
    
    def get_file_content_hash(self, file_path: Path) -> str:
        """Get a hash of the file content for similarity comparison."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Normalize content by removing comments and whitespace
            lines = []
            for line in content.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    lines.append(line)
            
            normalized_content = '\n'.join(lines)
            return hashlib.md5(normalized_content.encode()).hexdigest()
        except Exception:
            return ""
    
    def analyze_file(self, file_path: Path) -> Dict:
        """Analyze a single file for functions, classes, and content."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            tree = ast.parse(content)
            
            functions = []
            classes = []
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    sig = self.extract_function_signature(node)
                    functions.append({
                        'name': node.name,
                        'signature': sig,
                        'line': node.lineno,
                        'args_count': len(node.args.args)
                    })
                    self.function_signatures[sig].append({
                        'file': str(file_path),
                        'name': node.name,
                        'line': node.lineno
                    })
                
                elif isinstance(node, ast.ClassDef):
                    sig = self.extract_class_signature(node)
                    classes.append({
                        'name': node.name,
                        'signature': sig,
                        'line': node.lineno
                    })
                    self.class_signatures[sig].append({
                        'file': str(file_path),
                        'name': node.name,
                        'line': node.lineno
                    })
            
            # Get file hash for similarity comparison
            file_hash = self.get_file_content_hash(file_path)
            self.file_hashes[str(file_path)] = file_hash
            
            return {
                'file': str(file_path),
                'functions': functions,
                'classes': classes,
                'hash': file_hash,
                'size': file_path.stat().st_size
            }
            
        except Exception as e:
            print(f"Warning: Could not analyze {file_path}: {e}")
            return {
                'file': str(file_path),
                'functions': [],
                'classes': [],
                'hash': '',
                'size': 0
            }
    
    def find_similar_files(self, threshold: float = 0.8) -> List[Dict]:
        """Find files with similar content using text similarity."""
        similar_pairs = []
        files_list = list(self.file_hashes.keys())
        
        for i, file1 in enumerate(files_list):
            for file2 in files_list[i+1:]:
                try:
                    with open(file1, 'r', encoding='utf-8', errors='ignore') as f:
                        content1 = f.read()
                    with open(file2, 'r', encoding='utf-8', errors='ignore') as f:
                        content2 = f.read()
                    
                    # Calculate similarity using difflib
                    similarity = difflib.SequenceMatcher(None, content1, content2).ratio()
                    
                    if similarity > threshold:
                        similar_pairs.append({
                            'file1': file1,
                            'file2': file2,
                            'similarity': similarity,
                            'size1': Path(file1).stat().st_size,
                            'size2': Path(file2).stat().st_size
                        })
                        
                except Exception:
                    continue
        
        return sorted(similar_pairs, key=lambda x: x['similarity'], reverse=True)
    
    def find_engine_duplicates(self) -> Dict:
        """Specifically find engine-related duplicates."""
        engine_patterns = [
            "engine", "bypass", "hybrid", "smart", "improved"
        ]
        
        engine_files = []
        for file_path in self.python_files:
            file_name = file_path.name.lower()
            if any(pattern in file_name for pattern in engine_patterns):
                engine_files.append(str(file_path))
        
        # Analyze engine files for duplicates
        engine_analysis = {}
        for file_path in engine_files:
            analysis = self.analyze_file(Path(file_path))
            engine_analysis[file_path] = analysis
        
        # Find similar engine files
        similar_engines = []
        for i, file1 in enumerate(engine_files):
            for file2 in engine_files[i+1:]:
                if file1 in self.file_hashes and file2 in self.file_hashes:
                    hash1 = self.file_hashes[file1]
                    hash2 = self.file_hashes[file2]
                    
                    if hash1 == hash2 and hash1:  # Identical files
                        similar_engines.append({
                            'file1': file1,
                            'file2': file2,
                            'type': 'identical',
                            'similarity': 1.0
                        })
        
        return {
            'engine_files': engine_files,
            'engine_analysis': engine_analysis,
            'similar_engines': similar_engines
        }
    
    def find_analyzer_duplicates(self) -> Dict:
        """Find duplicate analyzer files."""
        analyzer_patterns = [
            "analyzer", "pcap", "compare", "analysis"
        ]
        
        analyzer_files = []
        for file_path in self.python_files:
            file_name = file_path.name.lower()
            if any(pattern in file_name for pattern in analyzer_patterns):
                analyzer_files.append(str(file_path))
        
        # Group by similar names
        name_groups = defaultdict(list)
        for file_path in analyzer_files:
            base_name = Path(file_path).stem.lower()
            # Remove common suffixes
            for suffix in ['_fixed', '_new', '_old', '_backup', '_v2', '_enhanced', '_simple']:
                base_name = base_name.replace(suffix, '')
            name_groups[base_name].append(file_path)
        
        # Find groups with multiple files (potential duplicates)
        duplicate_groups = {k: v for k, v in name_groups.items() if len(v) > 1}
        
        return {
            'analyzer_files': analyzer_files,
            'duplicate_groups': duplicate_groups,
            'total_groups': len(duplicate_groups)
        }
    
    def analyze_all(self) -> Dict:
        """Run complete duplication analysis."""
        print("Scanning Python files...")
        self.python_files = self.scan_python_files()
        print(f"Found {len(self.python_files)} Python files")
        
        print("Analyzing files...")
        file_analyses = []
        for file_path in self.python_files:
            analysis = self.analyze_file(file_path)
            file_analyses.append(analysis)
        
        print("Finding duplicate functions...")
        duplicate_functions = {k: v for k, v in self.function_signatures.items() if len(v) > 1}
        
        print("Finding duplicate classes...")
        duplicate_classes = {k: v for k, v in self.class_signatures.items() if len(v) > 1}
        
        print("Finding similar files...")
        similar_files = self.find_similar_files(threshold=0.7)
        
        print("Analyzing engine duplicates...")
        engine_duplicates = self.find_engine_duplicates()
        
        print("Analyzing analyzer duplicates...")
        analyzer_duplicates = self.find_analyzer_duplicates()
        
        return {
            'summary': {
                'total_files': len(self.python_files),
                'duplicate_functions': len(duplicate_functions),
                'duplicate_classes': len(duplicate_classes),
                'similar_files': len(similar_files),
                'engine_files': len(engine_duplicates['engine_files']),
                'analyzer_files': len(analyzer_duplicates['analyzer_files'])
            },
            'duplicate_functions': duplicate_functions,
            'duplicate_classes': duplicate_classes,
            'similar_files': similar_files,
            'engine_duplicates': engine_duplicates,
            'analyzer_duplicates': analyzer_duplicates,
            'file_analyses': file_analyses
        }

def main():
    analyzer = CodeDuplicationAnalyzer(".")
    
    print("=== Code Duplication Analysis ===")
    print("Analyzing project for duplicate functionality and redundant implementations...")
    
    results = analyzer.analyze_all()
    
    print(f"\n=== SUMMARY ===")
    print(f"Total Python files: {results['summary']['total_files']}")
    print(f"Duplicate function signatures: {results['summary']['duplicate_functions']}")
    print(f"Duplicate class signatures: {results['summary']['duplicate_classes']}")
    print(f"Similar files (>70% similarity): {results['summary']['similar_files']}")
    print(f"Engine-related files: {results['summary']['engine_files']}")
    print(f"Analyzer-related files: {results['summary']['analyzer_files']}")
    
    # Engine duplicates
    print(f"\n=== ENGINE DUPLICATES ===")
    engine_files = results['engine_duplicates']['engine_files']
    print(f"Found {len(engine_files)} engine-related files:")
    for engine_file in sorted(engine_files):
        file_path = Path(engine_file)
        print(f"  - {file_path.name} ({file_path.stat().st_size:,} bytes)")
        print(f"    Path: {engine_file}")
    
    similar_engines = results['engine_duplicates']['similar_engines']
    if similar_engines:
        print(f"\nIdentical engine files:")
        for pair in similar_engines:
            print(f"  - {Path(pair['file1']).name} == {Path(pair['file2']).name}")
            print(f"    File1: {pair['file1']}")
            print(f"    File2: {pair['file2']}")
    
    # Analyzer duplicates
    print(f"\n=== ANALYZER DUPLICATES ===")
    duplicate_groups = results['analyzer_duplicates']['duplicate_groups']
    print(f"Found {len(duplicate_groups)} groups of potentially duplicate analyzers:")
    
    for base_name, files in duplicate_groups.items():
        print(f"\n  Group '{base_name}' ({len(files)} files):")
        for file_path in sorted(files):
            file_size = Path(file_path).stat().st_size
            print(f"    - {Path(file_path).name} ({file_size:,} bytes)")
            print(f"      Path: {file_path}")
    
    # Similar files
    print(f"\n=== SIMILAR FILES ===")
    similar_files = results['similar_files'][:10]  # Top 10 most similar
    if similar_files:
        print("Top 10 most similar file pairs:")
        for pair in similar_files:
            print(f"  - Similarity: {pair['similarity']:.2%}")
            print(f"    File1: {Path(pair['file1']).name} ({pair['size1']:,} bytes)")
            print(f"    File2: {Path(pair['file2']).name} ({pair['size2']:,} bytes)")
            print(f"    Paths: {pair['file1']} | {pair['file2']}")
            print()
    
    # Duplicate functions
    print(f"\n=== DUPLICATE FUNCTIONS ===")
    duplicate_functions = results['duplicate_functions']
    if duplicate_functions:
        print("Functions with identical signatures:")
        for signature, occurrences in list(duplicate_functions.items())[:10]:  # Top 10
            if len(occurrences) > 1:
                print(f"  - Signature: {signature} ({len(occurrences)} occurrences)")
                for occurrence in occurrences:
                    print(f"    {Path(occurrence['file']).name}:{occurrence['line']} - {occurrence['name']}")
                print()
    
    # Save detailed results
    output_file = "code_duplication_analysis.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nDetailed analysis saved to: {output_file}")
    
    # Generate cleanup recommendations
    print(f"\n=== CLEANUP RECOMMENDATIONS ===")
    
    # Engine cleanup
    if len(engine_files) > 3:
        print("ENGINE CLEANUP:")
        print("  - Consider consolidating multiple engine files into a single unified engine")
        print("  - Recommended to keep: core/bypass/engine/base_engine.py")
        print("  - Consider removing:")
        for engine_file in engine_files:
            if "base_engine" not in engine_file and "hybrid" not in engine_file:
                print(f"    * {engine_file}")
    
    # Analyzer cleanup
    if len(duplicate_groups) > 5:
        print("\nANALYZER CLEANUP:")
        print("  - Multiple analyzer files detected, consider consolidating")
        print("  - Merge similar functionality into core analyzers")
        for base_name, files in list(duplicate_groups.items())[:5]:
            if len(files) > 2:
                print(f"  - Consolidate '{base_name}' group ({len(files)} files)")
    
    # Similar files cleanup
    if len(similar_files) > 0:
        print("\nSIMILAR FILES CLEANUP:")
        print("  - Review highly similar files for merge opportunities")
        for pair in similar_files[:3]:
            if pair['similarity'] > 0.9:
                print(f"  - Consider merging: {Path(pair['file1']).name} & {Path(pair['file2']).name}")
    
    return results

if __name__ == "__main__":
    main()