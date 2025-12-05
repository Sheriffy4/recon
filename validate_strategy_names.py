#!/usr/bin/env python3
"""
Validate and fix strategy names in JSON files

This script checks for and fixes the "existing_" prefix that sometimes
gets incorrectly added to attack names in strategy files.
"""

import json
from pathlib import Path
from typing import Dict, Any, List

def fix_strategy_name(name: str) -> str:
    """Remove ALL 'existing_' prefixes from strategy name"""
    if isinstance(name, str):
        # Keep removing 'existing_' prefix until there are no more
        while name.startswith('existing_'):
            name = name.replace('existing_', '', 1)
    return name

def fix_dict_recursive(data: Any) -> tuple[Any, bool]:
    """Recursively fix strategy names in a dictionary or list"""
    changed = False
    
    if isinstance(data, dict):
        fixed_data = {}
        for key, value in data.items():
            # Fix the value itself if it's a strategy name field
            if key in ['strategy', 'attack_name', 'type', 'attack_type', 'strategy_name']:
                if isinstance(value, str) and value.startswith('existing_'):
                    fixed_value = fix_strategy_name(value)
                    fixed_data[key] = fixed_value
                    changed = True
                    print(f"  ✅ Fixed '{key}': {value} -> {fixed_value}")
                else:
                    fixed_data[key] = value
            # Fix arrays of attacks
            elif key in ['attacks', 'attack_combination']:
                if isinstance(value, list):
                    fixed_list, list_changed = fix_dict_recursive(value)
                    fixed_data[key] = fixed_list
                    changed = changed or list_changed
                else:
                    fixed_data[key] = value
            # Recursively process nested structures
            else:
                fixed_value, value_changed = fix_dict_recursive(value)
                fixed_data[key] = fixed_value
                changed = changed or value_changed
        return fixed_data, changed
    
    elif isinstance(data, list):
        fixed_list = []
        for item in data:
            fixed_item, item_changed = fix_dict_recursive(item)
            fixed_list.append(fixed_item)
            changed = changed or item_changed
        return fixed_list, changed
    
    elif isinstance(data, str) and data.startswith('existing_'):
        # Fix standalone strings
        fixed = fix_strategy_name(data)
        print(f"  ✅ Fixed string: {data} -> {fixed}")
        return fixed, True
    
    else:
        return data, False

def validate_and_fix_file(file_path: Path) -> bool:
    """Validate and fix a JSON file"""
    if not file_path.exists():
        return False
    
    try:
        print(f"\n📄 Checking {file_path}...")
        
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        fixed_data, changed = fix_dict_recursive(data)
        
        if changed:
            # Save the fixed file
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(fixed_data, f, indent=2, ensure_ascii=False)
            print(f"✅ Fixed and saved {file_path}")
            return True
        else:
            print(f"✅ No issues found in {file_path}")
            return False
            
    except Exception as e:
        print(f"❌ Error processing {file_path}: {e}")
        return False

def main():
    """Main function to validate all strategy files"""
    print("🔍 Validating strategy files for 'existing_' prefix...\n")
    
    files_to_check = [
        "best_strategy.json",
        "domain_rules.json",
        "domain_strategies.json",
        "strategies_enhanced.json",
    ]
    
    files_fixed = 0
    
    for filename in files_to_check:
        file_path = Path(filename)
        if validate_and_fix_file(file_path):
            files_fixed += 1
    
    print(f"\n{'='*60}")
    if files_fixed > 0:
        print(f"✅ Fixed {files_fixed} file(s)")
    else:
        print("✅ All files are valid - no fixes needed")
    print(f"{'='*60}")

if __name__ == "__main__":
    main()
