"""Test AttackRegistry registration messages."""

import pytest
from core.bypass.attacks.attack_registry import AttackRegistry
from core.bypass.attacks.registry.models import AttackMetadata, RegistrationPriority


def test_register_attack_message_format():
    """Test that registration message is properly formatted."""
    registry = AttackRegistry(lazy_loading=False)

    def dummy_handler(techniques, payload, **params):
        return []

    metadata = AttackMetadata(
        name="Test Attack",
        description="Test attack description",
        required_params=[],
        optional_params={},
        aliases=[],
        category="custom",
    )

    result = registry.register_attack(
        attack_type="test_attack",
        handler=dummy_handler,
        metadata=metadata,
        priority=RegistrationPriority.NORMAL,
    )

    assert result.success is True
    assert "test_attack" in result.message
    assert "NORMAL" in result.message
    # Check that f-string was properly formatted (no raw braces)
    assert "{" not in result.message
    assert "}" not in result.message
    # Check no newlines in middle of message
    assert "\n" not in result.message.strip()
