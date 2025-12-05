#!/usr/bin/env python3
"""Check which attacks are registered"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.bypass.attacks.attack_registry import get_attack_registry

registry = get_attack_registry()
attacks = registry.list_attacks()

print(f"Total registered attacks: {len(attacks)}")
print()

# Check specific attacks
check_list = ['multisplit', 'seqovl', 'payload_encryption', 'fake', 'disorder', 'split', 'fakeddisorder']

for attack in check_list:
    registered = attack in attacks
    status = "✅" if registered else "❌"
    print(f"{status} {attack}: {registered}")
    
    if registered:
        metadata = registry.get_attack_metadata(attack)
        if metadata:
            print(f"   Aliases: {metadata.aliases}")
            print(f"   Required params: {metadata.required_params}")

print()
print("All registered attacks:")
for attack in sorted(attacks):
    print(f"  - {attack}")
