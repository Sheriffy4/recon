#!/usr/bin/env python3
"""
Strategy Conflict Checker CLI Command

Provides CLI command to show strategy conflicts between subdomains and parent domains.

Requirements: 10.2, 10.5
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, List

LOG = logging.getLogger(__name__)


def load_domain_rules(domain_rules_path: str = "domain_rules.json") -> Dict[str, Any]:
    """Load domain rules from JSON file."""
    try:
        if Path(domain_rules_path).exists():
            with open(domain_rules_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get('domain_rules', {})
        return {}
    except Exception as e:
        LOG.error(f"Error loading domain rules: {e}")
        return {}


def check_parent_domain_exists(domain: str, domain_rules: Dict[str, Any]) -> tuple:
    """
    Check if parent domain strategy exists.
    
    Args:
        domain: Subdomain to check
        domain_rules: Dictionary of domain rules
        
    Returns:
        Tuple of (exists, parent_domain, parent_strategy)
    """
    if not domain or '.' not in domain:
        return False, None, None
    
    parts = domain.split('.')
    if len(parts) <= 2:
        return False, None, None
    
    parent_domain = '.'.join(parts[1:])
    
    # Check exact parent domain
    if parent_domain in domain_rules:
        return True, parent_domain, domain_rules[parent_domain]
    
    # Check wildcard pattern
    wildcard_pattern = f"*.{parent_domain}"
    if wildcard_pattern in domain_rules:
        return True, wildcard_pattern, domain_rules[wildcard_pattern]
    
    return False, parent_domain, None


def find_strategy_conflicts(domain_rules: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Find conflicts between subdomain and parent domain strategies.
    
    Requirements: 10.2, 10.5
    """
    conflicts = []
    
    for domain, strategy in domain_rules.items():
        # Skip wildcard patterns
        if domain.startswith('*.'):
            continue
        
        # Check if this domain has a parent
        parent_exists, parent_key, parent_strategy = check_parent_domain_exists(domain, domain_rules)
        
        if parent_exists and parent_strategy:
            # Check if strategies are different
            subdomain_type = strategy.get('type', 'unknown')
            parent_type = parent_strategy.get('type', 'unknown')
            
            if subdomain_type != parent_type:
                conflicts.append({
                    'subdomain': domain,
                    'parent_domain': parent_key,
                    'subdomain_strategy_type': subdomain_type,
                    'parent_strategy_type': parent_type,
                    'subdomain_strategy': strategy,
                    'parent_strategy': parent_strategy,
                    'conflict_type': 'different_strategy_types'
                })
            else:
                # Same type, check if parameters differ significantly
                subdomain_params = strategy.get('params', {})
                parent_params = parent_strategy.get('params', {})
                
                # Check critical parameters
                critical_params = ['split_pos', 'split_count', 'ttl', 'fooling', 'disorder_method']
                param_diffs = []
                
                for param in critical_params:
                    if param in subdomain_params or param in parent_params:
                        subdomain_val = subdomain_params.get(param)
                        parent_val = parent_params.get(param)
                        
                        if subdomain_val != parent_val:
                            param_diffs.append({
                                'param': param,
                                'subdomain_value': subdomain_val,
                                'parent_value': parent_val
                            })
                
                if param_diffs:
                    conflicts.append({
                        'subdomain': domain,
                        'parent_domain': parent_key,
                        'subdomain_strategy_type': subdomain_type,
                        'parent_strategy_type': parent_type,
                        'subdomain_strategy': strategy,
                        'parent_strategy': parent_strategy,
                        'conflict_type': 'different_parameters',
                        'parameter_differences': param_diffs
                    })
    
    return conflicts


def print_strategy_conflicts(conflicts: List[Dict[str, Any]], verbose: bool = False):
    """
    Print strategy conflicts in a readable format.
    
    Args:
        conflicts: List of conflicts from find_strategy_conflicts()
        verbose: If True, print detailed strategy information
        
    Requirements: 10.2, 10.5
    """
    if not conflicts:
        print("✅ No strategy conflicts detected")
        print("\nAll subdomain strategies are consistent with their parent domains.")
        return
    
    print("=" * 80)
    print(f"STRATEGY CONFLICTS DETECTED: {len(conflicts)} conflicts")
    print("=" * 80)
    
    for i, conflict in enumerate(conflicts, 1):
        print(f"\nConflict #{i}:")
        print(f"  Subdomain: {conflict['subdomain']}")
        print(f"  Parent Domain: {conflict['parent_domain']}")
        print(f"  Conflict Type: {conflict['conflict_type']}")
        
        if conflict['conflict_type'] == 'different_strategy_types':
            print(f"  Subdomain Strategy: {conflict['subdomain_strategy_type']}")
            print(f"  Parent Strategy: {conflict['parent_strategy_type']}")
            print(f"  💡 Consider removing subdomain strategy to use parent domain strategy")
            
            if verbose:
                print(f"\n  Subdomain Strategy Details:")
                print(f"    Type: {conflict['subdomain_strategy'].get('type')}")
                print(f"    Params: {conflict['subdomain_strategy'].get('params', {})}")
                print(f"\n  Parent Strategy Details:")
                print(f"    Type: {conflict['parent_strategy'].get('type')}")
                print(f"    Params: {conflict['parent_strategy'].get('params', {})}")
        
        elif conflict['conflict_type'] == 'different_parameters':
            print(f"  Strategy Type: {conflict['subdomain_strategy_type']}")
            print(f"  Parameter Differences:")
            for diff in conflict['parameter_differences']:
                print(f"    - {diff['param']}: subdomain={diff['subdomain_value']}, parent={diff['parent_value']}")
            print(f"  💡 Consider testing if parent domain parameters work for subdomain")
            
            if verbose:
                print(f"\n  Subdomain Parameters:")
                for key, value in conflict['subdomain_strategy'].get('params', {}).items():
                    print(f"    {key}: {value}")
                print(f"\n  Parent Parameters:")
                for key, value in conflict['parent_strategy'].get('params', {}).items():
                    print(f"    {key}: {value}")
    
    print("")
    print("💡 To resolve conflicts:")
    print("   1. Test parent domain strategies with subdomains")
    print("   2. Remove subdomain entries if parent strategy works")
    print("   3. Use wildcard patterns (*.domain.com) for consistency")
    print("   4. Run 'cli.py auto <subdomain>' to find optimal strategy")
    print("=" * 80)


def check_parent_domain_during_testing(domain: str, domain_rules_path: str = "domain_rules.json") -> bool:
    """
    Check if parent domain strategy exists during testing and log recommendation.
    
    This function is called during strategy testing to inform the user if a parent
    domain strategy already exists.
    
    Args:
        domain: Domain being tested
        domain_rules_path: Path to domain_rules.json
        
    Returns:
        True if parent domain strategy exists, False otherwise
        
    Requirements: 10.3
    """
    domain_rules = load_domain_rules(domain_rules_path)
    
    parent_exists, parent_key, parent_strategy = check_parent_domain_exists(domain, domain_rules)
    
    if parent_exists and parent_strategy:
        print("")
        print("=" * 80)
        print("ℹ️  PARENT DOMAIN STRATEGY EXISTS")
        print("=" * 80)
        print(f"Domain being tested: {domain}")
        print(f"Parent domain: {parent_key}")
        print(f"Parent strategy type: {parent_strategy.get('type', 'unknown')}")
        print("")
        print("💡 RECOMMENDATION:")
        print(f"   A strategy already exists for the parent domain '{parent_key}'.")
        print(f"   Consider testing if the parent domain strategy works for '{domain}'")
        print(f"   before creating a subdomain-specific strategy.")
        print("")
        print("   Benefits of using parent domain strategy:")
        print("   • Simpler configuration (fewer rules)")
        print("   • Easier maintenance")
        print("   • Consistent behavior across subdomains")
        print("")
        print("   If the parent strategy works, you can skip creating a subdomain rule.")
        print("=" * 80)
        print("")
        
        return True
    
    return False


def main():
    """Main entry point for CLI command."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Check for strategy conflicts between subdomains and parent domains"
    )
    parser.add_argument(
        '--domain-rules',
        default='domain_rules.json',
        help='Path to domain_rules.json file (default: domain_rules.json)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show detailed strategy information'
    )
    parser.add_argument(
        '--check-domain',
        help='Check if a specific domain has a parent domain strategy'
    )
    
    args = parser.parse_args()
    
    # Load domain rules
    domain_rules = load_domain_rules(args.domain_rules)
    
    if not domain_rules:
        print(f"❌ Error: Could not load domain rules from {args.domain_rules}")
        return 1
    
    print(f"Loaded {len(domain_rules)} domain rules from {args.domain_rules}")
    print("")
    
    # Check specific domain if requested
    if args.check_domain:
        parent_exists, parent_key, parent_strategy = check_parent_domain_exists(
            args.check_domain, domain_rules
        )
        
        if parent_exists:
            print(f"✅ Parent domain strategy exists for '{args.check_domain}'")
            print(f"   Parent domain: {parent_key}")
            print(f"   Parent strategy type: {parent_strategy.get('type', 'unknown')}")
            
            if args.verbose:
                print(f"\n   Parent strategy details:")
                print(f"   Type: {parent_strategy.get('type')}")
                print(f"   Params: {parent_strategy.get('params', {})}")
        else:
            print(f"ℹ️  No parent domain strategy found for '{args.check_domain}'")
            if parent_key:
                print(f"   Parent domain would be: {parent_key}")
        
        print("")
    
    # Find and print conflicts
    conflicts = find_strategy_conflicts(domain_rules)
    print_strategy_conflicts(conflicts, verbose=args.verbose)
    
    return 0 if not conflicts else 1


if __name__ == '__main__':
    import sys
    sys.exit(main())
