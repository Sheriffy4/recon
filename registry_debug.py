#!/usr/bin/env python3
"""
Debug registry singleton behavior.
"""

print("=== Registry Singleton Debug ===")

# Step 1: Check initial state
print("\n1. Initial state...")
from core.bypass.attacks import attack_registry
print(f"Module _global_registry: {id(attack_registry._global_registry)}")

# Step 2: Get registry first time
print("\n2. Getting registry first time...")
from core.bypass.attacks.attack_registry import get_attack_registry
registry1 = get_attack_registry()
print(f"Registry1 ID: {id(registry1)}")
print(f"Registry1 attacks: {len(registry1.attacks)}")
print(f"Module _global_registry after get: {id(attack_registry._global_registry)}")
print(f"Same instance? {registry1 is attack_registry._global_registry}")

# Step 3: Import tcp_advanced and check registry
print("\n3. Importing tcp_advanced...")
import core.bypass.attacks.tcp_advanced
print(f"Module _global_registry after import: {id(attack_registry._global_registry)}")

# Step 4: Get registry again
print("\n4. Getting registry again...")
registry2 = get_attack_registry()
print(f"Registry2 ID: {id(registry2)}")
print(f"Registry2 attacks: {len(registry2.attacks)}")
print(f"Same as registry1? {registry1 is registry2}")
print(f"Same as module global? {registry2 is attack_registry._global_registry}")

# Step 5: Check if decorators are using the same registry
print("\n5. Checking decorator registration...")
print("Let's manually register a test attack to see what happens...")

from core.bypass.attacks.attack_registry import register_attack, RegistrationPriority
from core.bypass.attacks.metadata import AttackCategories
from core.bypass.attacks.base import BaseAttack, AttackContext, AttackResult, AttackStatus

@register_attack(
    name="debug_test_attack",
    category=AttackCategories.TCP,
    priority=RegistrationPriority.NORMAL,
    required_params=[],
    optional_params={},
    aliases=["debug_test"],
    description="Debug test attack"
)
class DebugTestAttack(BaseAttack):
    @property
    def name(self) -> str:
        return "debug_test_attack"
    
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

print("\n6. After manual registration...")
registry3 = get_attack_registry()
print(f"Registry3 ID: {id(registry3)}")
print(f"Registry3 attacks: {len(registry3.attacks)}")
print(f"Debug attack found: {'debug_test_attack' in registry3.attacks}")
print(f"Same as previous? {registry2 is registry3}")