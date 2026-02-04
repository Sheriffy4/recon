"""
Unit tests for attack registry metadata semantics and validator adapter.

Tests that metadata.name is correctly set and validator adapter works with both
AttackValidator and AttackParameterValidator.
"""

from core.bypass.attacks.attack_registry import (
    clear_registry,
    configure_lazy_loading,
    get_attack_registry,
    register_attack,
)


def setup_function():
    clear_registry(clear_config=True)


def teardown_function():
    clear_registry(clear_config=True)


def test_register_attack_class_metadata_name_not_overwritten_by_description():
    """Test that metadata.name is derived from attack_name, not description."""
    configure_lazy_loading(True)

    @register_attack(name="meta_test", description="My Description")
    class MetaTest:
        def execute(self, context):
            return []

    reg = get_attack_registry()
    md = reg.get_attack_metadata("meta_test")
    assert md is not None
    assert md.name == "Meta Test", f"Expected 'Meta Test', got '{md.name}'"
    assert md.description == "My Description", f"Expected 'My Description', got '{md.description}'"


def test_register_attack_function_metadata_name_not_overwritten_by_description():
    """Test that function metadata.name is derived from attack_name, not description."""
    configure_lazy_loading(True)

    @register_attack(name="fn_meta_test", description="Fn Description")
    def fn_meta(payload: bytes, **params):
        return []

    reg = get_attack_registry()
    md = reg.get_attack_metadata("fn_meta_test")
    assert md is not None
    assert md.name == "Fn Meta Test", f"Expected 'Fn Meta Test', got '{md.name}'"
    assert md.description == "Fn Description", f"Expected 'Fn Description', got '{md.description}'"


def test_validate_parameters_adapter_supports_attack_parameter_validator():
    """Test that validate_parameters adapter works with AttackParameterValidator."""
    configure_lazy_loading(True)

    reg = get_attack_registry()
    from core.bypass.attacks.registry import RegistryConfig, AttackParameterValidator

    # Replace validator with AttackParameterValidator
    reg.validator = AttackParameterValidator(RegistryConfig())

    # split exists as builtin; should validate ok with split_pos provided
    result = reg.validate_parameters("split", {"split_pos": 3})
    assert result.is_valid is True, f"Expected valid result, got: {result.error_message}"


def test_validate_registry_integrity_fallback():
    """Test that validate_registry_integrity works with fallback when validator doesn't support it."""
    configure_lazy_loading(True)

    reg = get_attack_registry()
    from core.bypass.attacks.registry import RegistryConfig, AttackParameterValidator

    # Replace validator with AttackParameterValidator (doesn't have validate_registry_integrity)
    reg.validator = AttackParameterValidator(RegistryConfig())

    # Should use fallback implementation
    result = reg.validate_registry_integrity()
    
    assert isinstance(result, dict), "Result should be a dict"
    assert "is_valid" in result, "Result should have 'is_valid' key"
    assert "issues" in result, "Result should have 'issues' key"
    assert "warnings" in result, "Result should have 'warnings' key"
    assert "stats" in result, "Result should have 'stats' key"
    assert "timestamp" in result, "Result should have 'timestamp' key"


if __name__ == "__main__":
    test_register_attack_class_metadata_name_not_overwritten_by_description()
    test_register_attack_function_metadata_name_not_overwritten_by_description()
    test_validate_parameters_adapter_supports_attack_parameter_validator()
    test_validate_registry_integrity_fallback()
    print("\n✓ All metadata semantics tests passed!")
