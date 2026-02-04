"""
Test that zapret combo modules can be imported without circular import errors.
"""
import importlib


def test_import_zapret_strategy_no_circular():
    """Test that zapret_strategy can be imported without circular import."""
    importlib.import_module("core.bypass.attacks.combo.zapret_strategy")


def test_import_zapret_attack_adapter_no_circular():
    """Test that zapret_attack_adapter can be imported without circular import."""
    importlib.import_module("core.bypass.attacks.combo.zapret_attack_adapter")


def test_import_zapret_integration_no_circular():
    """Test that zapret_integration can be imported without circular import."""
    importlib.import_module("core.bypass.attacks.combo.zapret_integration")
