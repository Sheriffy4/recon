"""Test lazy loading state synchronization between AttackRegistry and RegistrationManager."""

import pytest
from core.bypass.attacks.attack_registry import AttackRegistry


def test_lazy_loading_state_sync():
    """Test that lazy loading state is synchronized between registry and manager."""
    registry = AttackRegistry(lazy_loading=True)

    # Manually add entries to registry's lazy loading state
    registry._unloaded_modules["test_module_x"] = "core.bypass.attacks.test_module_x"
    registry._loaded_modules.add("core.bypass.attacks.test_module_y")

    # Get stats through RegistrationManager
    stats = registry.get_lazy_loading_stats()

    # Verify that RegistrationManager sees the same state
    assert stats["lazy_loading_enabled"] is True
    assert "test_module_x" in stats["unloaded_module_list"]
    assert "core.bypass.attacks.test_module_y" in stats["loaded_module_list"]


def test_lazy_loading_state_shared_containers():
    """Test that registry and manager share the same state containers."""
    registry = AttackRegistry(lazy_loading=True)

    # Verify that registration_manager has access to the same containers
    if hasattr(registry.registration_manager, "_unloaded_modules"):
        # Add through registry
        registry._unloaded_modules["shared_test"] = "core.bypass.attacks.shared_test"

        # Verify manager sees it
        assert "shared_test" in registry.registration_manager._unloaded_modules
        assert registry.registration_manager._unloaded_modules["shared_test"] == "core.bypass.attacks.shared_test"


def test_lazy_loading_disabled_state():
    """Test lazy loading stats when disabled."""
    registry = AttackRegistry(lazy_loading=False)

    stats = registry.get_lazy_loading_stats()

    # When lazy loading is disabled, unloaded_modules should be empty
    assert stats["lazy_loading_enabled"] is False or len(stats["unloaded_module_list"]) == 0
