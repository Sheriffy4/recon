#!/usr/bin/env python3
"""
Test if the register_attack decorator can be imported and used.
"""

print("=== Decorator Import Test ===")

# Step 1: Test importing the decorator
print("\n1. Testing decorator import...")
try:
    from core.bypass.attacks.attack_registry import register_attack, RegistrationPriority
    print("✅ register_attack imported successfully")
    print(f"register_attack function: {register_attack}")
except Exception as e:
    print(f"❌ Failed to import register_attack: {e}")
    import traceback
    traceback.print_exc()
    exit(1)

# Step 2: Test importing metadata
print("\n2. Testing metadata import...")
try:
    from core.bypass.attacks.metadata import AttackCategories
    print("✅ AttackCategories imported successfully")
    print(f"AttackCategories.TCP: {AttackCategories.TCP}")
except Exception as e:
    print(f"❌ Failed to import AttackCategories: {e}")
    import traceback
    traceback.print_exc()
    exit(1)

# Step 3: Test importing base classes
print("\n3. Testing base class import...")
try:
    from core.bypass.attacks.base import BaseAttack, AttackContext, AttackResult, AttackStatus
    print("✅ Base classes imported successfully")
except Exception as e:
    print(f"❌ Failed to import base classes: {e}")
    import traceback
    traceback.print_exc()
    exit(1)

# Step 4: Test creating a simple decorated class
print("\n4. Testing decorator execution...")
try:
    @register_attack(
        name="test_decorator_execution",
        category=AttackCategories.TCP,
        priority=RegistrationPriority.NORMAL,
        required_params=[],
        optional_params={},
        aliases=["test_decorator"],
        description="Test decorator execution"
    )
    class TestDecoratorAttack(BaseAttack):
        @property
        def name(self) -> str:
            return "test_decorator_execution"
        
        @property
        def category(self) -> str:
            return AttackCategories.TCP
        
        @property
        def required_params(self) -> list:
            return []
        
        @property
        def optional_params(self) -> dict:
            return {}
        
        def execute(self, context: AttackContext) -> AttackResult:
            return AttackResult(status=AttackStatus.SUCCESS, technique_used=self.name)
    
    print("✅ Decorator executed successfully")
    print(f"Class has metadata: {hasattr(TestDecoratorAttack, '__attack_metadata__')}")
    
    if hasattr(TestDecoratorAttack, '__attack_metadata__'):
        metadata = TestDecoratorAttack.__attack_metadata__
        print(f"Metadata name: {metadata.name}")
        print(f"Metadata category: {metadata.category}")
    
    # Check if it was registered
    from core.bypass.attacks.attack_registry import get_attack_registry
    registry = get_attack_registry()
    print(f"Attack registered in registry: {'test_decorator_execution' in registry.attacks}")
    
except Exception as e:
    print(f"❌ Decorator execution failed: {e}")
    import traceback
    traceback.print_exc()

# Step 5: Test the exact imports used in tcp_advanced.py
print("\n5. Testing exact imports from tcp_advanced.py...")
try:
    from core.bypass.attacks.attack_registry import register_attack, RegistrationPriority
    from core.bypass.attacks.metadata import AttackCategories
    from core.bypass.attacks.base import AttackContext, AttackResult, AttackStatus, SegmentTuple, BaseAttack
    print("✅ All imports from tcp_advanced.py work")
except Exception as e:
    print(f"❌ Import error matching tcp_advanced.py: {e}")
    import traceback
    traceback.print_exc()

print("\n=== Test Complete ===")