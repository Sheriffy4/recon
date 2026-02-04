"""
Test that attack registration does not call __init__ for metadata extraction.

This test ensures that the fix for circular imports is working correctly.
"""

from core.bypass.attacks.attack_registry import clear_registry, get_attack_registry, register_attack


def setup_function():
    clear_registry(clear_config=True)


def teardown_function():
    clear_registry(clear_config=True)


def test_register_attack_does_not_call_init_for_metadata_extraction():
    """Test that register_attack does not call __init__ during metadata extraction."""
    init_called = {"value": False}

    @register_attack  # no args → will auto-name based on class
    class InitBombAttack:
        def __init__(self):
            init_called["value"] = True
            raise RuntimeError("init should not be called during registration")

        def execute(self, context):
            class R:
                segments = [(b"x", 0, {})]

            return R()

    assert init_called["value"] is False, "Attack __init__ was called during registration"

    reg = get_attack_registry()
    # class name InitBombAttack -> init_bomb
    md = reg.get_attack_metadata("init_bomb")
    assert md is not None, "Attack metadata not found"
    assert md.name == "Init Bomb", f"Expected 'Init Bomb', got '{md.name}'"


if __name__ == "__main__":
    test_register_attack_does_not_call_init_for_metadata_extraction()
    print("✅ Test passed: register_attack does not call __init__ for metadata extraction")
