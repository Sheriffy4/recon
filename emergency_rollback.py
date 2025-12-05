#!/usr/bin/env python3
"""
Emergency Rollback Script

This script rolls back ALL googlevideo.com and youtube.com strategies
to simple, working configurations.
"""

import json
import shutil
from pathlib import Path
from datetime import datetime

def backup_current():
    """Backup current domain_rules.json."""
    rules_path = Path("domain_rules.json")
    if not rules_path.exists():
        print("❌ domain_rules.json not found!")
        return False
    
    backup_path = Path(f"domain_rules.json.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    shutil.copy(rules_path, backup_path)
    print(f"✅ Backed up to: {backup_path}")
    return True


def rollback_to_simple_strategies():
    """Rollback to simple, working strategies."""
    print("\n" + "=" * 80)
    print("EMERGENCY ROLLBACK")
    print("=" * 80)
    
    rules_path = Path("domain_rules.json")
    if not rules_path.exists():
        print("❌ domain_rules.json not found!")
        return False
    
    with open(rules_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    domain_rules = data.get('domain_rules', {})
    
    # Rollback strategies
    changes = []
    
    # 1. www.googlevideo.com - use simple disorder
    if 'www.googlevideo.com' in domain_rules:
        domain_rules['www.googlevideo.com'] = {
            "type": "disorder",
            "attacks": ["disorder"],
            "params": {
                "split_pos": 2,
                "disorder_method": "reverse",
                "no_fallbacks": True,
                "forced": True
            },
            "metadata": {
                "source": "emergency_rollback",
                "discovered_at": datetime.now().isoformat(),
                "rationale": "Emergency rollback to simple disorder"
            }
        }
        changes.append("www.googlevideo.com → simple disorder")
    
    # 2. *.googlevideo.com - use simple disorder
    if '*.googlevideo.com' in domain_rules:
        domain_rules['*.googlevideo.com'] = {
            "type": "disorder",
            "attacks": ["disorder"],
            "params": {
                "split_pos": 2,
                "disorder_method": "reverse",
                "no_fallbacks": True,
                "forced": True
            },
            "metadata": {
                "source": "emergency_rollback",
                "discovered_at": datetime.now().isoformat(),
                "rationale": "Emergency rollback to simple disorder"
            }
        }
        changes.append("*.googlevideo.com → simple disorder")
    
    # 3. www.youtube.com - use simple disorder
    if 'www.youtube.com' in domain_rules:
        domain_rules['www.youtube.com'] = {
            "type": "disorder",
            "attacks": ["disorder"],
            "params": {
                "split_pos": 2,
                "disorder_method": "reverse",
                "no_fallbacks": True,
                "forced": True
            },
            "metadata": {
                "source": "emergency_rollback",
                "discovered_at": datetime.now().isoformat(),
                "rationale": "Emergency rollback to simple disorder"
            }
        }
        changes.append("www.youtube.com → simple disorder")
    
    # 4. youtube.com - keep as is (it's working)
    # No changes needed
    
    # Save changes
    data['domain_rules'] = domain_rules
    data['last_updated'] = datetime.now().isoformat()
    
    with open(rules_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    
    print("\n✅ Rollback completed!")
    print("\nChanges made:")
    for change in changes:
        print(f"  - {change}")
    
    print("\n" + "=" * 80)
    print("NEXT STEPS")
    print("=" * 80)
    print("\n1. Restart the service:")
    print("   python recon_service.py")
    print("\n2. Test YouTube:")
    print("   - Open www.youtube.com")
    print("   - Should load now")
    print("\n3. If still not working, try removing strategies:")
    print("   python cli.py test www.youtube.com --strategy none")
    print()
    
    return True


def main():
    print("🚨 EMERGENCY ROLLBACK SCRIPT")
    print("This will revert all YouTube/Googlevideo strategies to simple disorder\n")
    
    response = input("Continue? (yes/no): ")
    if response.lower() != 'yes':
        print("Cancelled.")
        return
    
    # Backup first
    if not backup_current():
        return
    
    # Rollback
    if rollback_to_simple_strategies():
        print("\n✅ Rollback successful!")
        print("Restart service to apply changes.")
    else:
        print("\n❌ Rollback failed!")


if __name__ == "__main__":
    main()
