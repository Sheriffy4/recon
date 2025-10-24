#!/usr/bin/env python3
"""
Test decorator execution directly.
"""

print("=== Decorator Execution Test ===")

# Step 1: Get initial registry state
print("\n1. Initial registry state...")
from core.bypass.attacks.attack_registry import get_attack_registry
registry = get_attack_registry()
initial_count = len(registry.attacks)
print(f"Initial attacks: {initial_count}")
print(f"Initial attack names: {list(registry.attacks.keys())[:5]}...")

# Step 2: Import tcp_advanced module and check what happens
print("\n2. Importing tcp_advanced module...")
print("Before import - registry attacks:", len(registry.attacks))

# Let's import the module step by step
import sys
print(f"tcp_advanced in sys.modules: {'core.bypass.attacks.tcp_advanced' in sys.modules}")

# Import the module
import core.bypass.attacks.tcp_advanced as tcp_mod
print(f"After import - registry attacks: {len(registry.attacks)}")

# Step 3: Check if the classes exist in the module
print("\n3. Checking classes in tcp_advanced module...")
import inspect
classes = [name for name, obj in inspect.getmembers(tcp_mod, inspect.isclass) 
           if name.endswith('Attack')]
print(f"Attack classes found: {classes}")

# Step 4: Check if the decorators were applied
print("\n4. Checking decorator application...")
for class_name in classes:
    cls = getattr(tcp_mod, class_name)
    print(f"{class_name}:")
    print(f"  - Has __attack_metadata__: {hasattr(cls, '__attack_metadata__')}")
    if hasattr(cls, '__attack_metadata__'):
        metadata = cls.__attack_metadata__
        print(f"  - Metadata name: {metadata.name}")
        print(f"  - Metadata category: {metadata.category}")

# Step 5: Check if attacks are in registry
print("\n5. Checking registry for tcp attacks...")
tcp_attack_names = ['tcp_window_manipulation', 'tcp_sequence_manipulation', 
                   'tcp_window_scaling', 'urgent_pointer_manipulation']
for attack_name in tcp_attack_names:
    found = attack_name in registry.attacks
    print(f"{attack_name}: {'✅' if found else '❌'}")

# Step 6: Try to manually trigger registration
print("\n6. Manual registration test...")
print("Let's see if we can manually register one of the classes...")

# Get the TCPWindowManipulationAttack class
if hasattr(tcp_mod, 'TCPWindowManipulationAttack'):
    cls = tcp_mod.TCPWindowManipulationAttack
    print(f"Class found: {cls}")
    print(f"Class has metadata: {hasattr(cls, '__attack_metadata__')}")
    
    # Check if the decorator was applied but registration failed
    if hasattr(cls, '__attack_metadata__'):
        metadata = cls.__attack_metadata__
        print(f"Metadata: {metadata}")
        
        # Try to register manually
        from core.bypass.attacks.attack_registry import register_attack
        print("Attempting manual registration...")
        try:
            result = registry.register_attack(
                attack_type=metadata.name,
                handler=cls,
                metadata=metadata,
                priority=metadata.priority
            )
            print(f"Manual registration result: {result}")
            print(f"Registry attacks after manual: {len(registry.attacks)}")
        except Exception as e:
            print(f"Manual registration failed: {e}")
            import traceback
            traceback.print_exc()

print(f"\nFinal registry state: {len(registry.attacks)} attacks")