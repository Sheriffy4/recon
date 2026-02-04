#!/usr/bin/env python3
"""
Debug script for file analyzer issues.
"""

import sys
from pathlib import Path

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent))

from intellirefactor.analysis.file_analyzer import FileAnalyzer
from intellirefactor.config import AnalysisConfig

def debug_file_analysis():
    """Debug file analysis issues."""
    
    # Test with sample file
    sample_file_path = Path("tests/intellirefactor/integration/sample_projects/simple_project/main.py")
    
    print(f"Sample file path: {sample_file_path}")
    print(f"Sample file exists: {sample_file_path.exists()}")
    
    # Create file analyzer
    config = AnalysisConfig()
    file_analyzer = FileAnalyzer(config)
    
    print(f"\nTesting file analysis:")
    try:
        analysis_result = file_analyzer.analyze_file(sample_file_path)
        
        print(f"Analysis success: {analysis_result.success}")
        print(f"Analysis errors: {analysis_result.issues}")
        print(f"Analysis data keys: {list(analysis_result.data.keys())}")
        
        if 'classes' in analysis_result.data:
            classes = analysis_result.data['classes']
            print(f"Classes found: {len(classes)}")
            for cls in classes:
                print(f"  - {cls}")
        
    except Exception as e:
        print(f"Exception during analysis: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    debug_file_analysis()