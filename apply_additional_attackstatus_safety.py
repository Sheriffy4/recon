#!/usr/bin/env python3
"""
Apply additional AttackStatus safety measures to prevent future errors.
This script adds safe result creation to the most commonly used attacks.
"""

import logging
import sys
import os
from typing import List, Tuple

logging.basicConfig(level=logging.INFO, format='%(levelname)-8s %(message)s')
LOG = logging.getLogger("AttackStatusSafety")

def get_high_risk_attack_files() -> List[str]:
    """Get list of attack files that use direct AttackStatus and need safety measures."""
    return [
        "core/bypass/attacks/tls/extension_attacks.py",
        "core/bypass/attacks/tls/record_manipulation.py", 
        "core/bypass/attacks/tls/ech_attacks.py",
        "core/bypass/attacks/tunneling/protocol_tunneling.py",
        "core/bypass/attacks/tunneling/dns_tunneling.py",
    ]

def add_safe_imports_to_file(file_path: str) -> bool:
    """Add safe result utils import to a file if not already present."""
    try:
        if not os.path.exists(file_path):
            LOG.warning(f"File not found: {file_path}")
            return False
            
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check if safe imports already exist
        if "from ..safe_result_utils import" in content:
            LOG.info(f"✅ {file_path} already has safe imports")
            return True
            
        # Find the base import line
        base_import_patterns = [
            "from ..base import BaseAttack, AttackContext, AttackResult, AttackStatus",
            "from ..base import BaseAttack, AttackResult, AttackStatus, AttackContext",
        ]
        
        modified = False
        for pattern in base_import_patterns:
            if pattern in content:
                # Add safe imports after the base import
                new_import = f"{pattern}\nfrom ..safe_result_utils import create_success_result, create_error_result, create_failed_result"
                content = content.replace(pattern, new_import)
                modified = True
                break
        
        if modified:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            LOG.info(f"✅ Added safe imports to {file_path}")
            return True
        else:
            LOG.warning(f"⚠️  Could not find base import pattern in {file_path}")
            return False
            
    except Exception as e:
        LOG.error(f"❌ Error processing {file_path}: {e}")
        return False

def create_safety_wrapper_function() -> str:
    """Create a safety wrapper function for AttackResult creation."""
    return '''
# Safety wrapper for AttackResult creation
def _safe_create_result(status_name: str, **kwargs):
    """Safely create AttackResult to prevent AttackStatus errors."""
    try:
        from ..safe_result_utils import safe_create_attack_result
        return safe_create_attack_result(status_name, **kwargs)
    except Exception:
        # Ultimate fallback
        try:
            from ..base import AttackResult, AttackStatus
            status = getattr(AttackStatus, status_name)
            return AttackResult(status=status, **kwargs)
        except Exception:
            return None
'''

def add_safety_wrapper_to_file(file_path: str) -> bool:
    """Add safety wrapper function to a file."""
    try:
        if not os.path.exists(file_path):
            return False
            
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check if wrapper already exists
        if "_safe_create_result" in content:
            LOG.info(f"✅ {file_path} already has safety wrapper")
            return True
            
        # Find a good place to insert the wrapper (after imports, before first class)
        lines = content.split('\n')
        insert_index = -1
        
        for i, line in enumerate(lines):
            if line.startswith('class ') or line.startswith('@register_attack'):
                insert_index = i
                break
        
        if insert_index > 0:
            wrapper = create_safety_wrapper_function()
            lines.insert(insert_index, wrapper)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(lines))
            
            LOG.info(f"✅ Added safety wrapper to {file_path}")
            return True
        else:
            LOG.warning(f"⚠️  Could not find insertion point in {file_path}")
            return False
            
    except Exception as e:
        LOG.error(f"❌ Error adding wrapper to {file_path}: {e}")
        return False

def validate_attack_file_safety(file_path: str) -> Tuple[bool, List[str]]:
    """Validate that an attack file uses safe result creation."""
    issues = []
    
    try:
        if not os.path.exists(file_path):
            return False, ["File not found"]
            
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check for direct AttackStatus usage
        if "AttackStatus.SUCCESS" in content:
            issues.append("Direct AttackStatus.SUCCESS usage found")
        if "AttackStatus.ERROR" in content:
            issues.append("Direct AttackStatus.ERROR usage found")
        if "AttackStatus.FAILED" in content:
            issues.append("Direct AttackStatus.FAILED usage found")
            
        # Check for safe imports or wrapper
        has_safe_imports = "from ..safe_result_utils import" in content
        has_wrapper = "_safe_create_result" in content
        
        if not has_safe_imports and not has_wrapper:
            issues.append("No safe result creation mechanism found")
            
        return len(issues) == 0, issues
        
    except Exception as e:
        return False, [f"Error reading file: {e}"]

def main():
    """Apply additional AttackStatus safety measures."""
    LOG.info("🚀 Applying additional AttackStatus safety measures...")
    
    high_risk_files = get_high_risk_attack_files()
    
    results = []
    
    for file_path in high_risk_files:
        LOG.info(f"\n--- Processing {file_path} ---")
        
        # Validate current state
        is_safe, issues = validate_attack_file_safety(file_path)
        
        if is_safe:
            LOG.info(f"✅ {file_path} is already safe")
            results.append((file_path, True, "Already safe"))
            continue
        
        LOG.info(f"⚠️  Issues found in {file_path}: {issues}")
        
        # Try to add safe imports
        import_success = add_safe_imports_to_file(file_path)
        
        # Try to add safety wrapper as backup
        wrapper_success = add_safety_wrapper_to_file(file_path)
        
        # Re-validate
        is_safe_now, remaining_issues = validate_attack_file_safety(file_path)
        
        if is_safe_now:
            LOG.info(f"✅ {file_path} is now safe")
            results.append((file_path, True, "Fixed"))
        else:
            LOG.error(f"❌ {file_path} still has issues: {remaining_issues}")
            results.append((file_path, False, f"Issues remain: {remaining_issues}"))
    
    # Summary
    LOG.info(f"\n🎯 AttackStatus Safety Results:")
    successful = 0
    
    for file_path, success, status in results:
        if success:
            successful += 1
            LOG.info(f"   ✅ {os.path.basename(file_path)}: {status}")
        else:
            LOG.error(f"   ❌ {os.path.basename(file_path)}: {status}")
    
    LOG.info(f"\n📊 Summary: {successful}/{len(results)} files secured")
    
    if successful == len(results):
        LOG.info("🎉 All high-risk attack files are now safe!")
        LOG.info("AttackStatus errors should be prevented in production.")
    else:
        LOG.warning("⚠️  Some files still need manual attention.")
        LOG.warning("Consider reviewing the remaining issues.")
    
    return successful == len(results)

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)