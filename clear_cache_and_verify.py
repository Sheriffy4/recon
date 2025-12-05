#!/usr/bin/env python3
"""
Clear Python cache and verify the None type fixes are in place.
"""

import os
import shutil
from pathlib import Path


def clear_pycache():
    """Remove all __pycache__ directories."""
    print("🧹 Clearing Python cache...")
    
    count = 0
    for root, dirs, files in os.walk('.'):
        if '__pycache__' in dirs:
            cache_dir = os.path.join(root, '__pycache__')
            try:
                shutil.rmtree(cache_dir)
                print(f"   Removed: {cache_dir}")
                count += 1
            except Exception as e:
                print(f"   ⚠️  Failed to remove {cache_dir}: {e}")
    
    print(f"✅ Cleared {count} __pycache__ directories\n")


def verify_fixes():
    """Verify that the fixes are in place by checking key files."""
    print("🔍 Verifying fixes are in place...")
    
    checks = [
        {
            "file": "core/strategy/strategy_generator.py",
            "pattern": "filtered_attacks = [a for a in combo_strategy.attacks if a is not None]",
            "description": "Attack filtering in strategy generator"
        },
        {
            "file": "core/strategy/smart_attack_combinator.py",
            "pattern": "available_attacks = [a for a in available_attacks if a is not None and isinstance(a, str)]",
            "description": "Entry point filtering in combinator"
        },
        {
            "file": "core/adaptive_engine.py",
            "pattern": "attacks = [a for a in attacks if a is not None and isinstance(a, str)]",
            "description": "Attack filtering in adaptive engine"
        },
        {
            "file": "core/cli/adaptive_cli_wrapper.py",
            "pattern": "filtered_attacks = [a for a in result.strategy.attack_combination if a is not None]",
            "description": "Attack filtering in CLI wrapper"
        },
    ]
    
    all_good = True
    for check in checks:
        file_path = Path(check["file"])
        if not file_path.exists():
            print(f"   ❌ File not found: {check['file']}")
            all_good = False
            continue
        
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        if check["pattern"] in content:
            print(f"   ✅ {check['description']}")
        else:
            print(f"   ❌ {check['description']} - FIX NOT FOUND!")
            all_good = False
    
    print()
    return all_good


def main():
    """Main function."""
    print("="*70)
    print("Python Cache Cleaner & Fix Verifier")
    print("="*70)
    print()
    
    # Clear cache
    clear_pycache()
    
    # Verify fixes
    if verify_fixes():
        print("="*70)
        print("✅ ALL FIXES VERIFIED!")
        print("="*70)
        print("\nThe None type error fixes are in place.")
        print("You can now run your adaptive engine test.")
        print("\nRecommended command:")
        print("  python cli.py auto <domain> --mode deep --debug")
    else:
        print("="*70)
        print("⚠️  SOME FIXES NOT FOUND!")
        print("="*70)
        print("\nPlease ensure all fix files have been saved properly.")
        print("Check the COMPLETE_FIX_REPORT.md for details.")


if __name__ == "__main__":
    main()
