#!/usr/bin/env python3
"""
Find files that use @register_attack but don't import register_attack
"""

import os
import re
from pathlib import Path
from core.bypass.attacks.attack_registry import register_attack

def check_file_for_missing_import(file_path):
    """Check if file uses @register_attack but doesn't import it."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check if file uses @register_attack
        if '@register_attack' not in content:
            return False, "No @register_attack usage"
        
        # Check if file imports register_attack
        import_patterns = [
            r'from.*register_attack',
            r'import.*register_attack',
        ]
        
        has_import = any(re.search(pattern, content) for pattern in import_patterns)
        
        if not has_import:
            return True, "Uses @register_attack but missing import"
        
        return False, "Has proper import"
        
    except Exception as e:
        return False, f"Error reading file: {e}"

def scan_directory(directory):
    """Scan directory for Python files with missing imports."""
    issues = []
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                has_issue, reason = check_file_for_missing_import(file_path)
                
                if has_issue:
                    issues.append((file_path, reason))
                    print(f"❌ {file_path}: {reason}")
                else:
                    print(f"✅ {file_path}: {reason}")
    
    return issues

if __name__ == "__main__":
    print("🔍 Scanning for files with missing register_attack imports...")
    print("=" * 70)
    
    # Scan core/bypass/attacks directory
    attacks_dir = "core/bypass/attacks"
    if os.path.exists(attacks_dir):
        print(f"\n📁 Scanning {attacks_dir}...")
        issues = scan_directory(attacks_dir)
        
        if issues:
            print(f"\n❌ Found {len(issues)} files with missing imports:")
            for file_path, reason in issues:
                print(f"  - {file_path}: {reason}")
        else:
            print(f"\n✅ All files in {attacks_dir} have proper imports")
    else:
        print(f"❌ Directory {attacks_dir} not found")
    
    # Also scan current directory for test files
    print(f"\n📁 Scanning current directory for test files...")
    current_issues = []
    for file in os.listdir('.'):
        if file.endswith('.py') and '@register_attack' in open(file, 'r', encoding='utf-8', errors='ignore').read():
            has_issue, reason = check_file_for_missing_import(file)
            if has_issue:
                current_issues.append((file, reason))
                print(f"❌ {file}: {reason}")
            else:
                print(f"✅ {file}: {reason}")
    
    if current_issues:
        print(f"\n❌ Found {len(current_issues)} files in current directory with missing imports:")
        for file_path, reason in current_issues:
            print(f"  - {file_path}: {reason}")
    
    print("\n" + "=" * 70)
    print("🎯 Scan complete!")