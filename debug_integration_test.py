#!/usr/bin/env python3
"""
Debug script for integration test issues.
"""

import sys
from pathlib import Path

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent))

from intellirefactor.api import IntelliRefactor
from intellirefactor.config import IntelliRefactorConfig

def debug_project_analysis():
    """Debug project analysis issues."""
    
    # Test with sample project
    sample_project_path = Path("tests/intellirefactor/integration/sample_projects/simple_project")
    
    print(f"Sample project path: {sample_project_path}")
    print(f"Sample project exists: {sample_project_path.exists()}")
    
    if sample_project_path.exists():
        print("Files in sample project:")
        for file in sample_project_path.iterdir():
            print(f"  - {file.name}")
    
    # Test file discovery manually
    print(f"\nManual file discovery:")
    for py_file in sample_project_path.rglob("*.py"):
        print(f"Found Python file: {py_file}")
        file_str = str(py_file).lower()
        skip_patterns = ["__pycache__", ".git", "build", "dist"]
        
        # Only skip if it's actually a test file within the project being analyzed
        relative_path = py_file.relative_to(sample_project_path)
        is_test_file = (
            py_file.name.startswith("test_") or 
            py_file.name.endswith("_test.py") or
            "tests" in relative_path.parts[:-1]  # tests in relative path, not absolute
        )
        
        should_skip = any(skip in file_str for skip in skip_patterns) or is_test_file
        
        print(f"  - File: {py_file}")
        print(f"  - Parts: {py_file.parts}")
        print(f"  - Is test file: {is_test_file}")
        print(f"  - Should skip: {should_skip}")
        print()
    
    # Create IntelliRefactor instance
    config = IntelliRefactorConfig.default()
    intellirefactor = IntelliRefactor(config)
    
    print(f"\nIntelliRefactor initialized: {intellirefactor.is_initialized}")
    
    # Test project analyzer directly
    project_analyzer = intellirefactor._components['project_analyzer']
    
    print(f"\nTesting identify_source_files:")
    source_files = project_analyzer.identify_source_files(sample_project_path)
    print(f"Found {len(source_files)} source files:")
    for file in source_files:
        print(f"  - {file}")
    
    # Test full analysis
    print(f"\nTesting full project analysis:")
    analysis_result = intellirefactor.analyze_project(sample_project_path)
    
    print(f"Analysis success: {analysis_result.success}")
    print(f"Analysis errors: {analysis_result.errors}")
    print(f"Analysis data keys: {list(analysis_result.data.keys())}")
    
    if 'total_files' in analysis_result.data:
        print(f"Total files found: {analysis_result.data['total_files']}")
    
    return analysis_result

if __name__ == "__main__":
    debug_project_analysis()