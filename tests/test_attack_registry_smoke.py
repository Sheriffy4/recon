"""
Smoke tests for AttackRegistry refactoring.
Tests basic functionality after handler factory extraction.
"""

import pytest
from core.bypass.attacks.attack_registry import get_attack_registry, AttackRegistry


def test_registry_initialization():
    """Test that registry initializes successfully."""
    registry = get_attack_registry()
    assert registry is not None
    assert hasattr(registry, 'handler_factory')
    assert hasattr(registry, 'attacks')


def test_builtin_attacks_registered():
    """Test that built-in attacks are registered."""
    registry = get_attack_registry()
    attacks = registry.list_attacks()
    
    # Check for core attacks
    core_attacks = ['fakeddisorder', 'seqovl', 'multidisorder', 'disorder', 
                   'multisplit', 'split', 'fake']
    
    for attack in core_attacks:
        assert attack in attacks, f"Core attack '{attack}' not registered"


def test_get_attack_handler():
    """Test getting attack handlers."""
    registry = get_attack_registry()
    
    # Test getting a handler
    handler = registry.get_attack_handler('fakeddisorder')
    assert handler is not None
    assert callable(handler)


def test_handler_factory_integration():
    """Test that handler factory is properly integrated."""
    registry = get_attack_registry()
    
    # Check that factory can create handlers
    assert hasattr(registry.handler_factory, 'create_handler')
    assert hasattr(registry.handler_factory, 'has_handler')
    
    # Test factory methods
    assert registry.handler_factory.has_handler('fakeddisorder')
    assert registry.handler_factory.has_handler('multisplit')


def test_attack_metadata():
    """Test getting attack metadata."""
    registry = get_attack_registry()
    
    metadata = registry.get_attack_metadata('fakeddisorder')
    assert metadata is not None
    assert hasattr(metadata, 'name')
    assert hasattr(metadata, 'description')
    assert hasattr(metadata, 'required_params')
    assert hasattr(metadata, 'optional_params')


def test_registry_singleton():
    """Test that get_attack_registry returns singleton."""
    registry1 = get_attack_registry()
    registry2 = get_attack_registry()
    
    assert registry1 is registry2


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
