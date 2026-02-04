"""
Unit tests for registry public exports.

Tests that all public exports from the refactored registry are accessible
and work correctly.
"""

import pytest


def test_registry_public_exports():
    """Test that all public exports are accessible from registry package."""
    from core.bypass.attacks.registry import (
        PriorityManager,
        register_attack,
        process_pending_registrations,
        get_pending_registrations,
        clear_pending_registrations,
        AttackParameterValidator,
        RegistryConfig,
        AttackAliasManager,
        LazyLoadingManager,
        AttackHandlerFactory,
    )

    # Verify all imports succeeded
    assert PriorityManager is not None
    assert register_attack is not None
    assert process_pending_registrations is not None
    assert get_pending_registrations is not None
    assert clear_pending_registrations is not None
    assert AttackParameterValidator is not None
    assert RegistryConfig is not None
    assert AttackAliasManager is not None
    assert LazyLoadingManager is not None
    assert AttackHandlerFactory is not None

    print("✓ All public exports are accessible")


def test_parameter_validator_basic_sni_validation_smoke():
    """Test that AttackParameterValidator basic SNI validation works."""
    from core.bypass.attacks.registry import RegistryConfig, AttackParameterValidator

    # Create validator instance
    config = RegistryConfig()
    validator = AttackParameterValidator(config)

    # Test basic SNI validation (should not crash)
    result = validator._basic_sni_validation("example.com")
    assert isinstance(result, bool), "SNI validation should return bool"

    # Test valid domain names
    assert validator._basic_sni_validation("example.com") is True
    assert validator._basic_sni_validation("sub.example.com") is True
    assert validator._basic_sni_validation("deep.sub.example.com") is True

    # Test invalid domain names
    assert validator._basic_sni_validation("") is False
    assert validator._basic_sni_validation(".example.com") is False
    assert validator._basic_sni_validation("example.com.") is False
    assert validator._basic_sni_validation("-example.com") is False
    assert validator._basic_sni_validation("example-.com") is False
    assert validator._basic_sni_validation("example") is False  # Single label
    assert validator._basic_sni_validation(None) is False

    print("✓ AttackParameterValidator basic SNI validation works correctly")


def test_decorator_functions_callable():
    """Test that decorator functions are callable."""
    from core.bypass.attacks.registry import (
        register_attack,
        process_pending_registrations,
        get_pending_registrations,
        clear_pending_registrations,
    )

    # Verify functions are callable
    assert callable(register_attack)
    assert callable(process_pending_registrations)
    assert callable(get_pending_registrations)
    assert callable(clear_pending_registrations)

    # Test get_pending_registrations returns a list
    pending = get_pending_registrations()
    assert isinstance(pending, list), "get_pending_registrations should return a list"

    print("✓ Decorator functions are callable and work correctly")


def test_priority_manager_instantiation():
    """Test that PriorityManager can be instantiated."""
    from core.bypass.attacks.registry import PriorityManager, RegistryConfig

    config = RegistryConfig()
    priority_manager = PriorityManager(config)

    assert priority_manager is not None
    assert hasattr(priority_manager, "can_replace")
    assert hasattr(priority_manager, "handle_registration_conflict")

    print("✓ PriorityManager can be instantiated")


if __name__ == "__main__":
    test_registry_public_exports()
    test_parameter_validator_basic_sni_validation_smoke()
    test_decorator_functions_callable()
    test_priority_manager_instantiation()
    print("\n✓ All tests passed!")
