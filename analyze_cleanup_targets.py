#!/usr/bin/env python3
"""
Focused cleanup target analyzer for engine unification refactoring.
Identifies specific cleanup targets without expensive similarity analysis.
Part of Task 2.1 and 2.2
"""

import os
from pathlib import Path
from typing import Dict, List, Set
import json
import re

class CleanupTargetAnalyzer:
    def __init__(self, project_root: str = "."):
        self.project_root = Path(project_root)
        
    def find_engine_files(self) -> Dict:
        """Find all engine-related files for cleanup analysis."""
        engine_patterns = [
            "*engine*.py",
            "*bypass*.py", 
            "*hybrid*.py"
        ]
        
        engine_files = []
        
        for pattern in engine_patterns:
            for file_path in self.project_root.rglob(pattern):
                if "__pycache__" not in str(file_path) and file_path.suffix == ".py":
                    try:
                        size = file_path.stat().st_size
                        engine_files.append({
                            "path": str(file_path),
                            "name": file_path.name,
                            "size_bytes": size,
                            "category": "engine",
                            "relative_path": str(file_path.relative_to(self.project_root))
                        })
                    except:
                        continue
                    
        return {
            "engine_files": sorted(engine_files, key=lambda x: x['size_bytes'], reverse=True),
            "total_count": len(engine_files),
            "total_size": sum(f['size_bytes'] for f in engine_files)
        }
    
    def find_analyzer_files(self) -> Dict:
        """Find analyzer and PCAP-related files."""
        analyzer_patterns = [
            "*analyzer*.py",
            "*pcap*.py",
            "*compare*.py",
            "*analysis*.py"
        ]
        
        analyzer_files = []
        
        for pattern in analyzer_patterns:
            for file_path in self.project_root.rglob(pattern):
                if "__pycache__" not in str(file_path) and file_path.suffix == ".py":
                    try:
                        size = file_path.stat().st_size
                        analyzer_files.append({
                            "path": str(file_path),
                            "name": file_path.name,
                            "size_bytes": size,
                            "category": "analyzer",
                            "relative_path": str(file_path.relative_to(self.project_root))
                        })
                    except:
                        continue
        
        # Group by similar names to identify potential duplicates
        name_groups = {}
        for analyzer_file in analyzer_files:
            base_name = analyzer_file['name'].lower()
            # Remove common suffixes to group similar files
            for suffix in ['_fixed', '_new', '_old', '_backup', '_v2', '_enhanced', '_simple', '_demo']:
                base_name = base_name.replace(suffix, '')
            
            if base_name not in name_groups:
                name_groups[base_name] = []
            name_groups[base_name].append(analyzer_file)
        
        # Find groups with multiple files (potential duplicates)
        duplicate_groups = {k: v for k, v in name_groups.items() if len(v) > 1}
        
        return {
            "analyzer_files": sorted(analyzer_files, key=lambda x: x['size_bytes'], reverse=True),
            "duplicate_groups": duplicate_groups,
            "total_count": len(analyzer_files),
            "total_size": sum(f['size_bytes'] for f in analyzer_files),
            "duplicate_count": sum(len(v) for v in duplicate_groups.values())
        }
    
    def find_test_files(self) -> Dict:
        """Find test files that might be obsolete."""
        test_patterns = [
            "test_*.py",
            "*_test.py"
        ]
        
        test_files = []
        
        for pattern in test_patterns:
            for file_path in self.project_root.rglob(pattern):
                if "__pycache__" not in str(file_path) and file_path.suffix == ".py":
                    try:
                        size = file_path.stat().st_size
                        test_files.append({
                            "path": str(file_path),
                            "name": file_path.name,
                            "size_bytes": size,
                            "category": "test",
                            "relative_path": str(file_path.relative_to(self.project_root))
                        })
                    except:
                        continue
        
        # Identify potentially obsolete tests
        obsolete_patterns = [
            "old", "backup", "temp", "deprecated", "unused", "legacy"
        ]
        
        potentially_obsolete = []
        for test_file in test_files:
            name_lower = test_file['name'].lower()
            if any(pattern in name_lower for pattern in obsolete_patterns):
                potentially_obsolete.append(test_file)
        
        return {
            "test_files": sorted(test_files, key=lambda x: x['size_bytes'], reverse=True),
            "potentially_obsolete": potentially_obsolete,
            "total_count": len(test_files),
            "total_size": sum(f['size_bytes'] for f in test_files),
            "obsolete_count": len(potentially_obsolete)
        }
    
    def find_backup_files(self) -> Dict:
        """Find backup and temporary files."""
        backup_patterns = [
            "*.backup",
            "*_backup.py",
            "*_old.py",
            "*_temp.py",
            "*_fixed.py",
            "*.bak"
        ]
        
        backup_files = []
        
        for pattern in backup_patterns:
            for file_path in self.project_root.rglob(pattern):
                if "__pycache__" not in str(file_path):
                    try:
                        size = file_path.stat().st_size
                        backup_files.append({
                            "path": str(file_path),
                            "name": file_path.name,
                            "size_bytes": size,
                            "category": "backup",
                            "relative_path": str(file_path.relative_to(self.project_root))
                        })
                    except:
                        continue
        
        return {
            "backup_files": sorted(backup_files, key=lambda x: x['size_bytes'], reverse=True),
            "total_count": len(backup_files),
            "total_size": sum(f['size_bytes'] for f in backup_files)
        }
    
    def find_large_files(self, min_size: int = 50000) -> Dict:
        """Find large files that might need review."""
        large_files = []
        
        for file_path in self.project_root.rglob("*.py"):
            if "__pycache__" not in str(file_path):
                try:
                    size = file_path.stat().st_size
                    if size > min_size:
                        large_files.append({
                            "path": str(file_path),
                            "name": file_path.name,
                            "size_bytes": size,
                            "category": "large",
                            "relative_path": str(file_path.relative_to(self.project_root))
                        })
                except:
                    continue
        
        return {
            "large_files": sorted(large_files, key=lambda x: x['size_bytes'], reverse=True),
            "total_count": len(large_files),
            "total_size": sum(f['size_bytes'] for f in large_files)
        }
    
    def analyze_imports_in_file(self, file_path: Path) -> Set[str]:
        """Analyze imports in a specific file."""
        imports = set()
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Simple regex-based import extraction
            import_patterns = [
                r'from\s+(\S+)\s+import',
                r'import\s+(\S+)'
            ]
            
            for pattern in import_patterns:
                matches = re.findall(pattern, content)
                imports.update(matches)
                
        except Exception:
            pass
        
        return imports
    
    def generate_cleanup_recommendations(self) -> Dict:
        """Generate specific cleanup recommendations."""
        recommendations = {
            "high_priority": [],
            "medium_priority": [],
            "low_priority": []
        }
        
        # Analyze each category
        engines = self.find_engine_files()
        analyzers = self.find_analyzer_files()
        tests = self.find_test_files()
        backups = self.find_backup_files()
        large_files = self.find_large_files()
        
        # High priority: Engine consolidation
        if engines["total_count"] > 3:
            recommendations["high_priority"].append({
                "action": "Consolidate engine files",
                "description": f"Found {engines['total_count']} engine files, recommend keeping only base_engine.py",
                "files_to_review": [f["relative_path"] for f in engines["engine_files"]],
                "potential_savings": engines["total_size"] * 0.7  # Estimate 70% reduction
            })
        
        # High priority: Remove backup files
        if backups["total_count"] > 0:
            recommendations["high_priority"].append({
                "action": "Remove backup files",
                "description": f"Found {backups['total_count']} backup files taking {backups['total_size']:,} bytes",
                "files_to_remove": [f["relative_path"] for f in backups["backup_files"]],
                "potential_savings": backups["total_size"]
            })
        
        # Medium priority: Analyzer consolidation
        if analyzers["duplicate_count"] > 10:
            recommendations["medium_priority"].append({
                "action": "Consolidate analyzer files",
                "description": f"Found {analyzers['duplicate_count']} potentially duplicate analyzers",
                "duplicate_groups": analyzers["duplicate_groups"],
                "potential_savings": analyzers["total_size"] * 0.4  # Estimate 40% reduction
            })
        
        # Medium priority: Review large files
        if large_files["total_count"] > 0:
            recommendations["medium_priority"].append({
                "action": "Review large files",
                "description": f"Found {large_files['total_count']} files larger than 50KB",
                "files_to_review": [f["relative_path"] for f in large_files["large_files"][:10]],
                "potential_savings": 0  # Manual review needed
            })
        
        # Low priority: Obsolete tests
        if tests["obsolete_count"] > 0:
            recommendations["low_priority"].append({
                "action": "Review obsolete tests",
                "description": f"Found {tests['obsolete_count']} potentially obsolete test files",
                "files_to_review": [f["relative_path"] for f in tests["potentially_obsolete"]],
                "potential_savings": sum(f["size_bytes"] for f in tests["potentially_obsolete"])
            })
        
        return recommendations

def main():
    analyzer = CleanupTargetAnalyzer(".")
    
    print("=== Cleanup Target Analysis ===")
    print("Identifying specific cleanup targets for engine unification refactoring...")
    
    # Analyze each category
    print("\nAnalyzing engine files...")
    engines = analyzer.find_engine_files()
    
    print("Analyzing analyzer files...")
    analyzers = analyzer.find_analyzer_files()
    
    print("Analyzing test files...")
    tests = analyzer.find_test_files()
    
    print("Analyzing backup files...")
    backups = analyzer.find_backup_files()
    
    print("Analyzing large files...")
    large_files = analyzer.find_large_files()
    
    print("Generating recommendations...")
    recommendations = analyzer.generate_cleanup_recommendations()
    
    # Summary
    print(f"\n=== SUMMARY ===")
    print(f"Engine files: {engines['total_count']} ({engines['total_size']:,} bytes)")
    print(f"Analyzer files: {analyzers['total_count']} ({analyzers['total_size']:,} bytes)")
    print(f"Test files: {tests['total_count']} ({tests['total_size']:,} bytes)")
    print(f"Backup files: {backups['total_count']} ({backups['total_size']:,} bytes)")
    print(f"Large files (>50KB): {large_files['total_count']} ({large_files['total_size']:,} bytes)")
    
    # Engine files detail
    print(f"\n=== ENGINE FILES ===")
    print(f"Found {engines['total_count']} engine-related files:")
    for engine_file in engines["engine_files"][:10]:  # Top 10
        print(f"  - {engine_file['name']} ({engine_file['size_bytes']:,} bytes)")
        print(f"    Path: {engine_file['relative_path']}")
    
    # Analyzer duplicates
    print(f"\n=== ANALYZER DUPLICATES ===")
    duplicate_groups = analyzers["duplicate_groups"]
    print(f"Found {len(duplicate_groups)} groups of potentially duplicate analyzers:")
    
    for base_name, files in list(duplicate_groups.items())[:5]:  # Top 5 groups
        print(f"\n  Group '{base_name}' ({len(files)} files):")
        for file_info in files:
            print(f"    - {file_info['name']} ({file_info['size_bytes']:,} bytes)")
            print(f"      Path: {file_info['relative_path']}")
    
    # Backup files
    if backups['total_count'] > 0:
        print(f"\n=== BACKUP FILES ===")
        print(f"Found {backups['total_count']} backup files:")
        for backup_file in backups["backup_files"][:10]:  # Top 10
            print(f"  - {backup_file['name']} ({backup_file['size_bytes']:,} bytes)")
            print(f"    Path: {backup_file['relative_path']}")
    
    # Recommendations
    print(f"\n=== CLEANUP RECOMMENDATIONS ===")
    
    total_potential_savings = 0
    
    if recommendations["high_priority"]:
        print("\nHIGH PRIORITY:")
        for rec in recommendations["high_priority"]:
            print(f"  - {rec['action']}")
            print(f"    {rec['description']}")
            if 'potential_savings' in rec:
                total_potential_savings += rec['potential_savings']
                print(f"    Potential savings: {rec['potential_savings']:,.0f} bytes")
            print()
    
    if recommendations["medium_priority"]:
        print("MEDIUM PRIORITY:")
        for rec in recommendations["medium_priority"]:
            print(f"  - {rec['action']}")
            print(f"    {rec['description']}")
            if 'potential_savings' in rec:
                total_potential_savings += rec['potential_savings']
                print(f"    Potential savings: {rec['potential_savings']:,.0f} bytes")
            print()
    
    if recommendations["low_priority"]:
        print("LOW PRIORITY:")
        for rec in recommendations["low_priority"]:
            print(f"  - {rec['action']}")
            print(f"    {rec['description']}")
            if 'potential_savings' in rec:
                total_potential_savings += rec['potential_savings']
                print(f"    Potential savings: {rec['potential_savings']:,.0f} bytes")
            print()
    
    print(f"TOTAL ESTIMATED SAVINGS: {total_potential_savings:,.0f} bytes ({total_potential_savings/1024/1024:.1f} MB)")
    
    # Save results
    results = {
        "engines": engines,
        "analyzers": analyzers,
        "tests": tests,
        "backups": backups,
        "large_files": large_files,
        "recommendations": recommendations,
        "analysis_timestamp": "2025-01-07"
    }
    
    output_file = "cleanup_targets_analysis.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nDetailed analysis saved to: {output_file}")
    
    return results

if __name__ == "__main__":
    main()