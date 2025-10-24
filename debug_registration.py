#!/usr/bin/env python3
"""
Debug script to check attack registration.
"""

import sys
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)
LOG = logging.getLogger(__name__)

print("=== Attack Registration Debug ===")

# Step 1: Import attack registry
print("\n1. Importing attack registry...")
try:
    from core.bypass.attacks.attack_registry import get_attack_registry
    registry = get_attack_registry()
    print(f"✅ Registry imported. Initial attacks: {len(registry.attacks)}")
    print(f"   Initial attack names: {list(registry.attacks.keys())[:5]}...")
except Exception as e:
    print(f"❌ Failed to import registry: {e}")
    sys.exit(1)

# Step 2: Import tcp_advanced
print("\n2. Importing tcp_advanced...")
try:
    import core.bypass.attacks.tcp_advanced as tcp_adv
    print("✅ tcp_advanced imported")
    
    # Check if attacks were registered
    registry_after = get_attack_registry()
    print(f"   Attacks after tcp_advanced: {len(registry_after.attacks)}")
    
    # Look for tcp attacks
    tcp_attacks = [name for name in registry_after.attacks.keys() if 'tcp' in name.lower()]
    print(f"   TCP attacks found: {tcp_attacks}")
    
except Exception as e:
    print(f"❌ Failed to import tcp_advanced: {e}")
    import traceback
    traceback.print_exc()

# Step 3: Import tls_advanced
print("\n3. Importing tls_advanced...")
try:
    import core.bypass.attacks.tls_advanced as tls_adv
    print("✅ tls_advanced imported")
    
    # Check if attacks were registered
    registry_after = get_attack_registry()
    print(f"   Attacks after tls_advanced: {len(registry_after.attacks)}")
    
    # Look for tls attacks
    tls_attacks = [name for name in registry_after.attacks.keys() if 'tls' in name.lower() or 'sni' in name.lower()]
    print(f"   TLS attacks found: {tls_attacks}")
    
except Exception as e:
    print(f"❌ Failed to import tls_advanced: {e}")
    import traceback
    traceback.print_exc()

# Step 4: Import ip_obfuscation
print("\n4. Importing ip_obfuscation...")
try:
    import core.bypass.attacks.ip_obfuscation as ip_obf
    print("✅ ip_obfuscation imported")
    
    # Check if attacks were registered
    registry_after = get_attack_registry()
    print(f"   Attacks after ip_obfuscation: {len(registry_after.attacks)}")
    
    # Look for ip attacks
    ip_attacks = [name for name in registry_after.attacks.keys() if 'ip' in name.lower() or 'ttl' in name.lower()]
    print(f"   IP attacks found: {ip_attacks}")
    
except Exception as e:
    print(f"❌ Failed to import ip_obfuscation: {e}")
    import traceback
    traceback.print_exc()

# Step 5: Final registry state
print("\n5. Final registry state...")
final_registry = get_attack_registry()
print(f"   Total attacks: {len(final_registry.attacks)}")
print(f"   All attack names: {list(final_registry.attacks.keys())}")

# Step 6: Check for specific new attacks
print("\n6. Checking for specific new attacks...")
expected_attacks = [
    "tcp_window_manipulation",
    "tcp_sequence_manipulation", 
    "sni_manipulation",
    "ip_ttl_manipulation"
]

for attack_name in expected_attacks:
    handler = final_registry.get_attack_handler(attack_name)
    if handler:
        print(f"✅ {attack_name}: Found")
    else:
        print(f"❌ {attack_name}: Not found")

print("\n=== Debug Complete ===")