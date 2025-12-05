#!/usr/bin/env python3
"""
Script to update documentation references from deprecated analyze scripts to new components.

This script updates markdown files to reference UnifiedPCAPAnalyzer and StrategyValidator
instead of deprecated analyze_*.py scripts.

Task: .kiro/specs/auto-strategy-discovery/tasks.md - Task 14.2
Requirements: 9.3
"""

import re
from pathlib import Path
from typing import Dict, List, Tuple

# Mapping of old script references to new component references
REPLACEMENTS: List[Tuple[str, str, str]] = [
    # (old_pattern, new_replacement, description)
    (
        r'python analyze_pcap\.py',
        'python -m core.pcap.unified_analyzer',
        'Basic PCAP analysis'
    ),
    (
        r'python analyze_strategy_correctness\.py',
        'python -m core.strategy_validator',
        'Strategy validation'
    ),
    (
        r'python analyze_googlevideo_strategy\.py',
        'python -m core.strategy_validator',
        'GoogleVideo strategy validation'
    ),
    (
        r'python analyze_googlevideo_pcap\.py',
        'python -m core.pcap.unified_analyzer',
        'GoogleVideo PCAP analysis'
    ),
    (
        r'python analyze_youtube_pcap\.py',
        'python -m core.pcap.unified_analyzer',
        'YouTube PCAP analysis'
    ),
    (
        r'analyze_pcap\.py',
        'core.pcap.unified_analyzer.UnifiedPCAPAnalyzer',
        'PCAP analyzer reference'
    ),
    (
        r'analyze_strategy_correctness\.py',
        'core.strategy_validator.StrategyValidator',
        'Strategy validator reference'
    ),
    (
        r'analyze_googlevideo_strategy\.py',
        'core.strategy_validator.StrategyValidator',
        'GoogleVideo validator reference'
    ),
]


def update_file(file_path: Path) -> Tuple[bool, int]:
    """
    Update a single file with new references.
    
    Returns:
        (modified, replacement_count)
    """
    try:
        content = file_path.read_text(encoding='utf-8')
        original_content = content
        replacement_count = 0
        
        for old_pattern, new_replacement, description in REPLACEMENTS:
            matches = re.findall(old_pattern, content)
            if matches:
                content = re.sub(old_pattern, new_replacement, content)
                replacement_count += len(matches)
                print(f"    - Replaced {len(matches)}x: {description}")
        
        if content != original_content:
            file_path.write_text(content, encoding='utf-8')
            return True, replacement_count
        
        return False, 0
        
    except Exception as e:
        print(f"    ❌ Error: {e}")
        return False, 0


def main():
    """Main function to update all documentation files."""
    print("=" * 80)
    print("Updating Documentation References")
    print("=" * 80)
    print()
    
    # Find all markdown files
    root_dir = Path(".")
    md_files = list(root_dir.glob("*.md"))
    
    # Also check docs directory if it exists
    docs_dir = root_dir / "docs"
    if docs_dir.exists():
        md_files.extend(docs_dir.glob("*.md"))
    
    print(f"Found {len(md_files)} markdown files to check")
    print()
    
    modified_count = 0
    total_replacements = 0
    
    for md_file in sorted(md_files):
        # Skip DEPRECATED_ANALYZERS.md as it's our reference document
        if md_file.name == "DEPRECATED_ANALYZERS.md":
            continue
        
        print(f"Checking: {md_file.name}")
        modified, replacements = update_file(md_file)
        
        if modified:
            modified_count += 1
            total_replacements += replacements
            print(f"  ✅ Updated ({replacements} replacements)")
        else:
            print(f"  ⏭️  No changes needed")
        print()
    
    print("=" * 80)
    print("Summary")
    print("=" * 80)
    print(f"  Files checked:  {len(md_files)}")
    print(f"  Files modified: {modified_count}")
    print(f"  Total replacements: {total_replacements}")
    print()
    
    if modified_count > 0:
        print("✅ Documentation updated successfully!")
        print()
        print("Updated files now reference:")
        print("  - core.pcap.unified_analyzer.UnifiedPCAPAnalyzer")
        print("  - core.strategy_validator.StrategyValidator")
    else:
        print("ℹ️  No documentation updates needed")
    print()


if __name__ == "__main__":
    main()
