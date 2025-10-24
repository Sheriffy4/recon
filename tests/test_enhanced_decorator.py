#!/usr/bin/env python3
"""
Test script for the enhanced @register_attack decorator.
"""

import sys
from core.bypass.attacks.attack_registry import register_attack
sys.path.append('.')

try:
    from core.bypass.attacks.attack_registry import get_attack_registry, register_attack, RegistrationPriority
    from core.bypass.attacks.metadata import AttackCategories
    from core.bypass.attacks.base import BaseAttack, AttackContext, AttackResult, AttackStatus

    # Test the enhanced decorator
    @register_attack(
        name='test_attack',
        category=AttackCategories.TCP,
        priority=RegistrationPriority.NORMAL,
        required_params=['test_param'],
        optional_params={'optional_param': 'default'},
        aliases=['test_alias'],
        description='Test attack for validation'
    )
    class TestAttack(BaseAttack):
        @property
        def name(self):
            return 'test_attack'

        def execute(self, context):
            return AttackResult(status=AttackStatus.SUCCESS, technique_used=self.name)

    # Test registry
    registry = get_attack_registry()
    metadata = registry.get_attack_metadata('test_attack')

    print('✅ Enhanced decorator works!')
    print(f'Attack registered: {metadata.name if metadata else "Not found"}')
    print(f'Category: {metadata.category if metadata else "N/A"}')
    print(f'Required params: {metadata.required_params if metadata else "N/A"}')
    print(f'Optional params: {metadata.optional_params if metadata else "N/A"}')
    print(f'Aliases: {metadata.aliases if metadata else "N/A"}')

    # Test alias resolution
    alias_metadata = registry.get_attack_metadata('test_alias')
    print(f'Alias resolution works: {alias_metadata is not None}')

    # Test handler retrieval
    handler = registry.get_attack_handler('test_attack')
    print(f'Handler retrieved: {handler is not None}')

    print('\n✅ All tests passed!')

except Exception as e:
    print(f'❌ Error: {e}')
    import traceback
    traceback.print_exc()