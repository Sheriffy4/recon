"""Test to verify registry singleton behavior."""

import sys

print("=" * 60)
print("Testing Registry Singleton")
print("=" * 60)

# Test 1: Import registry module
print("\n1. Importing attack_registry module...")
from core.bypass.attacks import attack_registry
print(f"   Module ID: {id(attack_registry)}")
print(f"   _global_registry ID: {id(attack_registry._global_registry)}")
print(f"   _global_registry value: {attack_registry._global_registry}")

# Test 2: Get registry first time
print("\n2. Getting registry first time...")
from core.bypass.attacks.attack_registry import get_attack_registry
registry1 = get_attack_registry()
print(f"   Registry ID: {id(registry1)}")
print(f"   Attacks count: {len(registry1.attacks)}")
print(f"   _global_registry after get: {id(attack_registry._global_registry)}")

# Test 3: Get registry second time
print("\n3. Getting registry second time...")
registry2 = get_attack_registry()
print(f"   Registry ID: {id(registry2)}")
print(f"   Same instance? {registry1 is registry2}")

# Test 4: Import tcp_advanced and check
print("\n4. Importing tcp_advanced...")
import core.bypass.attacks.tcp_advanced
print(f"   Registry after import: {id(attack_registry._global_registry)}")
registry3 = get_attack_registry()
print(f"   Registry ID after tcp import: {id(registry3)}")
print(f"   Same as registry1? {registry1 is registry3}")
print(f"   Attacks count: {len(registry3.attacks)}")

# Test 5: Check if tcp attacks are in registry
print("\n5. Checking for tcp_window_manipulation...")
handler = registry3.get_attack_handler("tcp_window_manipulation")
print(f"   Handler found: {handler is not None}")

# Test 6: List all attacks
print("\n6. All registered attacks:")
for name in sorted(registry3.attacks.keys()):
    print(f"   - {name}")

print("\n" + "=" * 60)
