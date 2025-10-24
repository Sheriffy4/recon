#!/usr/bin/env python3
"""
Test fresh import of tcp_advanced to see decorator execution.
"""

import sys
import logging

# Set up detailed logging
logging.basicConfig(level=logging.DEBUG)

print("=== Fresh Import Test ===")

# Step 1: Make sure the module is not already imported
print("\n1. Checking if module is already imported...")
if 'core.bypass.attacks.tcp_advanced' in sys.modules:
    print("⚠️ Module already imported, removing from sys.modules")
    del sys.modules['core.bypass.attacks.tcp_advanced']
else:
    print("✅ Module not yet imported")

# Step 2: Get registry before import
print("\n2. Getting registry before import...")
from core.bypass.attacks.attack_registry import get_attack_registry
registry = get_attack_registry()
print(f"Registry attacks before import: {len(registry.attacks)}")

# Step 3: Import with detailed error handling
print("\n3. Importing tcp_advanced with error handling...")
try:
    print("Starting import...")
    import core.bypass.attacks.tcp_advanced as tcp_mod
    print("✅ Import completed successfully")
except Exception as e:
    print(f"❌ Import failed: {e}")
    import traceback
    traceback.print_exc()
    exit(1)

# Step 4: Check registry after import
print("\n4. Checking registry after import...")
registry_after = get_attack_registry()
print(f"Registry attacks after import: {len(registry_after.attacks)}")
print(f"Same registry instance: {registry is registry_after}")

# Step 5: Check for decorator execution
print("\n5. Checking decorator execution...")
import inspect
classes = [name for name, obj in inspect.getmembers(tcp_mod, inspect.isclass) 
           if name.endswith('Attack') and not name.startswith('Base')]
print(f"Attack classes: {classes}")

for class_name in classes:
    cls = getattr(tcp_mod, class_name)
    has_metadata = hasattr(cls, '__attack_metadata__')
    print(f"{class_name}: metadata={has_metadata}")
    if has_metadata:
        metadata = cls.__attack_metadata__
        print(f"  - Name: {metadata.name}")
        print(f"  - Registered: {metadata.name in registry_after.attacks}")

# Step 6: Check module-level registration function
print("\n6. Checking module registration function...")
if hasattr(tcp_mod, 'register_tcp_advanced_attacks'):
    print("Found register_tcp_advanced_attacks function")
    try:
        tcp_mod.register_tcp_advanced_attacks()
        print("✅ Manual registration function executed")
        print(f"Registry attacks after manual call: {len(get_attack_registry().attacks)}")
    except Exception as e:
        print(f"❌ Manual registration failed: {e}")
        import traceback
        traceback.print_exc()
else:
    print("No register_tcp_advanced_attacks function found")

print(f"\nFinal registry state: {len(get_attack_registry().attacks)} attacks")