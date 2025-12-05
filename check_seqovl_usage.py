#!/usr/bin/env python3
"""
Script to check if seqovl attack is actually used in domain_strategies.json
and understand the root cause of the issue.

Task: 10.1.4 Исправить seqovl атаки
"""

import json
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))


def check_domain_strategies():
    """Check domain_rules.json and domain_strategies.json for seqovl usage."""
    print("=" * 80)
    print("Checking domain configuration files for seqovl attack usage")
    print("=" * 80)
    
    # Try domain_rules.json first (current file)
    config_file = None
    if Path("domain_rules.json").exists():
        config_file = "domain_rules.json"
        print(f"✅ Found {config_file}")
    elif Path("domain_strategies.json").exists():
        config_file = "domain_strategies.json"
        print(f"✅ Found {config_file}")
    else:
        print("❌ Neither domain_rules.json nor domain_strategies.json found")
        return False
    
    try:
        with open(config_file, "r", encoding="utf-8") as f:
            strategies = json.load(f)
    except Exception as e:
        print(f"❌ Error reading {config_file}: {e}")
        return False
    
    seqovl_count = 0
    total_strategies = 0
    
    for domain, strategy_list in strategies.items():
        if not isinstance(strategy_list, list):
            continue
        
        for strategy in strategy_list:
            total_strategies += 1
            strategy_type = strategy.get("type", "")
            
            if strategy_type == "seqovl":
                seqovl_count += 1
                print(f"\n✅ Found seqovl strategy for domain: {domain}")
                print(f"   Strategy: {json.dumps(strategy, indent=2)}")
    
    print(f"\n" + "=" * 80)
    print(f"Summary for {config_file}:")
    print(f"  Total strategies: {total_strategies}")
    print(f"  Seqovl strategies: {seqovl_count}")
    print("=" * 80)
    
    if seqovl_count == 0:
        print("\n⚠️  ROOT CAUSE FOUND:")
        print(f"   No strategies with type='seqovl' found in {config_file}!")
        print("   This means seqovl attack is never used in service mode.")
        print("\n   The 'seqovl' attack type exists in the attack registry,")
        print("   but no domain is configured to use it.")
        print("\n   Solution:")
        print(f"   1. Add a test domain with seqovl strategy to {config_file}")
        print("   2. Test in both CLI and Service modes")
        print("   3. Compare PCAP files to verify parity")
        return False
    
    return True


def check_attack_registry():
    """Check if seqovl is registered in attack registry."""
    print("\n" + "=" * 80)
    print("Checking attack registry for seqovl registration")
    print("=" * 80)
    
    try:
        from core.bypass.attacks.attack_registry import get_attack_registry
        
        registry = get_attack_registry()
        
        # Check if seqovl is registered
        try:
            handler = registry.get_attack_handler("seqovl")
            if handler:
                print("✅ seqovl is registered in attack registry")
                print(f"   Handler: {handler}")
                return True
            else:
                print("❌ seqovl is NOT registered in attack registry")
                return False
        except (KeyError, AttributeError) as e:
            print(f"❌ Error getting seqovl handler: {e}")
            return False
            
    except Exception as e:
        print(f"❌ Error checking attack registry: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Main execution."""
    print("\n" + "=" * 80)
    print("SEQOVL ATTACK USAGE ANALYSIS")
    print("Task: 10.1.4 Исправить seqovl атаки")
    print("=" * 80)
    
    # Check 1: Attack registry
    registry_ok = check_attack_registry()
    
    # Check 2: Domain strategies
    strategies_ok = check_domain_strategies()
    
    # Summary
    print("\n" + "=" * 80)
    print("ANALYSIS SUMMARY")
    print("=" * 80)
    
    if registry_ok and not strategies_ok:
        print("\n🔍 ROOT CAUSE IDENTIFIED:")
        print("   - seqovl attack IS registered in attack registry ✅")
        print("   - seqovl attack is NOT used in any domain strategy ❌")
        print("\n   This explains why PCAP files don't contain seqovl attacks!")
        print("   The attack exists but is never applied.")
        print("\n📋 NEXT STEPS:")
        print("   1. Create a test strategy with type='seqovl' in domain_strategies.json")
        print("   2. Test the strategy in CLI mode: cli.py test <domain> --strategy 'seqovl; split_pos=10; overlap_size=5'")
        print("   3. Test the same domain in Service mode")
        print("   4. Capture PCAP files in both modes")
        print("   5. Compare the PCAP files to verify seqovl parity")
        return 1
    elif not registry_ok:
        print("\n❌ CRITICAL ISSUE:")
        print("   seqovl attack is not registered in attack registry!")
        print("   This needs to be fixed first.")
        return 2
    else:
        print("\n✅ seqovl attack is properly configured and used")
        return 0


if __name__ == "__main__":
    sys.exit(main())
