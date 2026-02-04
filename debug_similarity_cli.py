#!/usr/bin/env python3
"""Debug script for semantic similarity CLI."""

import sys
from pathlib import Path

# Add intellirefactor to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from intellirefactor.analysis.semantic_similarity_matcher import SemanticSimilarityMatcher, SimilarityType
    from intellirefactor.analysis.index_builder import IndexBuilder
    from intellirefactor.analysis.index_store import IndexStore
    
    print("✓ All imports successful")
    
    # Test basic functionality
    project_path = Path("test_similarity_project")
    print(f"✓ Project path: {project_path}")
    print(f"✓ Project exists: {project_path.exists()}")
    print(f"✓ Project is dir: {project_path.is_dir()}")
    
    # Test index creation
    index_db_path = project_path / '.intellirefactor' / 'index.db'
    print(f"✓ Index path: {index_db_path}")
    
    # Create .intellirefactor directory
    intellirefactor_dir = project_path / '.intellirefactor'
    intellirefactor_dir.mkdir(exist_ok=True)
    print(f"✓ Created intellirefactor dir: {intellirefactor_dir}")
    
    # Test index builder
    print("Building index...")
    index_builder = IndexBuilder(str(index_db_path))
    index_result = index_builder.build_index(
        project_path,
        incremental=False
    )
    print(f"✓ Index built: {index_result.symbols_found} symbols found")
    
    # Test index store
    index_store = IndexStore(str(index_db_path))
    methods = index_store.get_all_deep_method_infos()
    print(f"✓ Found {len(methods)} methods")
    
    for method in methods[:3]:  # Show first 3 methods
        print(f"  - {method.qualified_name}")
    
    # Test similarity matcher
    matcher = SemanticSimilarityMatcher()
    print("✓ Similarity matcher created")
    
    # Find similarities
    matches = matcher.find_similar_methods(methods)
    print(f"✓ Found {len(matches)} similarity matches")
    
    for match in matches[:2]:  # Show first 2 matches
        print(f"  Target: {match.target_method.name}")
        print(f"  Similar methods: {len(match.similar_methods)}")
    
    print("\n✓ All tests passed!")
    
except Exception as e:
    import traceback
    print(f"✗ Error: {e}")
    traceback.print_exc()