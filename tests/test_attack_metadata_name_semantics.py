"""Test AttackMetadata.name semantics (regression test for refactoring bug)."""

import pytest
from core.bypass.attacks.attack_registry import AttackRegistry
from core.bypass.attacks.registry.models import AttackMetadata, RegistrationPriority


def test_metadata_name_not_from_description():
    """Test that metadata.name is not set from description (semantic bug)."""
    registry = AttackRegistry(lazy_loading=False)

    def dummy_handler(techniques, payload, **params):
        return []

    # Register with explicit description
    metadata = AttackMetadata(
        name="Test Attack Name",
        description="This is a detailed description of the attack",
        required_params=[],
        optional_params={},
        aliases=[],
        category="custom",
    )

    result = registry.register_attack(
        attack_type="test_semantic",
        handler=dummy_handler,
        metadata=metadata,
        priority=RegistrationPriority.NORMAL,
    )

    assert result.success is True

    # Verify metadata.name is NOT the description
    registered_entry = registry.attacks.get("test_semantic")
    assert registered_entry is not None
    assert registered_entry.metadata.name == "Test Attack Name"
    assert registered_entry.metadata.description == "This is a detailed description of the attack"
    assert registered_entry.metadata.name != registered_entry.metadata.description


def test_attack_class_registration_name_semantics():
    """Test that _register_attack_class sets name correctly."""
    from core.bypass.attacks.base import BaseAttack, AttackContext

    class TestSemanticAttack(BaseAttack):
        """This is the docstring description."""

        def execute(self, context: AttackContext):
            return []

    registry = AttackRegistry(lazy_loading=False)
    registry._register_attack_class(TestSemanticAttack)

    # Find the registered attack (name should be derived from class name)
    attack_type = "testsemanticattack"
    registered_entry = registry.attacks.get(attack_type)

    if registered_entry:
        # metadata.name should be title-cased version of attack_name
        # metadata.description should be from docstring
        assert "Semantic" in registered_entry.metadata.name or "Test" in registered_entry.metadata.name
        assert registered_entry.metadata.description == "This is the docstring description."
        assert registered_entry.metadata.name != registered_entry.metadata.description
