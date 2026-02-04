"""
Test lazy loading integration with decorator queue.

This test verifies that:
1. Lazy loading processes pending registrations from @register_attack decorator
2. Handler supports both new-style handler(context) and legacy calls
3. Async execute() methods are properly handled
"""

import sys
import types
from types import SimpleNamespace


def test_load_module_on_demand_processes_pending_registrations_and_handler_supports_context_call():
    """
    Test that load_module_on_demand processes pending registrations from decorator
    and that the handler supports new-style handler(context) calls.
    """
    from core.bypass.attacks.attack_registry import AttackRegistry
    from core.bypass.attacks.registry.decorator import clear_pending_registrations

    # Clear any pending registrations from previous tests
    clear_pending_registrations()

    # Create registry with lazy loading disabled for this test
    reg = AttackRegistry(lazy_loading=False)

    # Create a virtual module with @register_attack decorator
    mod_name = "core.bypass.attacks._test_lazy_queued_mod"
    mod = types.ModuleType(mod_name)

    # Define attack class using decorator in the module
    code = """
from core.bypass.attacks.registry.decorator import register_attack

@register_attack(name="lazy_queued_attack", description="Test lazy queued attack")
class LazyQueuedAttack:
    def execute(self, context):
        class R:
            segments = [(b"ok", 0, {})]
        return R()
"""
    exec(code, mod.__dict__)
    sys.modules[mod_name] = mod

    try:
        # Load via manager path (should also process pending registrations)
        assert reg.registration_manager.load_module_on_demand(mod_name, reg) is True

        # Verify attack was registered
        h = reg.get_attack_handler("lazy_queued_attack")
        assert h is not None, "Handler should be registered"

        # New-style call: handler(context)
        ctx = SimpleNamespace(payload=b"x", params={}, techniques=None)
        out = h(ctx)
        assert isinstance(out, list), f"Expected list, got {type(out)}"
        assert len(out) > 0, "Expected non-empty segments"
        assert out[0][0] == b"ok", f"Expected b'ok', got {out[0][0]}"

        print("✅ Test passed: lazy loading + decorator queue + handler(context) works")

    finally:
        # Cleanup
        if mod_name in sys.modules:
            del sys.modules[mod_name]


def test_handler_supports_legacy_call():
    """Test that handler also supports legacy calling convention."""
    from core.bypass.attacks.attack_registry import AttackRegistry
    from core.bypass.attacks.registry.decorator import clear_pending_registrations

    clear_pending_registrations()
    reg = AttackRegistry(lazy_loading=False)

    mod_name = "core.bypass.attacks._test_legacy_call_mod"
    mod = types.ModuleType(mod_name)

    code = """
from core.bypass.attacks.registry.decorator import register_attack

@register_attack(name="legacy_call_attack", description="Test legacy call attack")
class LegacyCallAttack:
    def execute(self, context):
        class R:
            segments = [(b"legacy_ok", 0, {})]
        return R()
"""
    exec(code, mod.__dict__)
    sys.modules[mod_name] = mod

    try:
        reg.registration_manager.load_module_on_demand(mod_name, reg)
        h = reg.get_attack_handler("legacy_call_attack")
        assert h is not None

        # Legacy-style call: handler(techniques, payload, **params)
        out = h(None, b"test_payload", param1="value1")
        assert isinstance(out, list)
        assert len(out) > 0
        assert out[0][0] == b"legacy_ok"

        print("✅ Test passed: handler supports legacy calling convention")

    finally:
        if mod_name in sys.modules:
            del sys.modules[mod_name]


def test_async_execute_support():
    """Test that async execute() methods are properly handled."""
    from core.bypass.attacks.attack_registry import AttackRegistry
    from core.bypass.attacks.registry.decorator import clear_pending_registrations

    clear_pending_registrations()
    reg = AttackRegistry(lazy_loading=False)

    mod_name = "core.bypass.attacks._test_async_mod"
    mod = types.ModuleType(mod_name)

    code = """
from core.bypass.attacks.registry.decorator import register_attack
import asyncio

@register_attack(name="async_attack", description="Test async attack")
class AsyncAttack:
    async def execute(self, context):
        await asyncio.sleep(0.001)  # Simulate async work
        class R:
            segments = [(b"async_ok", 0, {})]
        return R()
"""
    exec(code, mod.__dict__)
    sys.modules[mod_name] = mod

    try:
        reg.registration_manager.load_module_on_demand(mod_name, reg)
        h = reg.get_attack_handler("async_attack")
        assert h is not None

        # Call handler - should handle async execute() internally
        ctx = SimpleNamespace(payload=b"x", params={}, techniques=None)
        out = h(ctx)
        assert isinstance(out, list)
        assert len(out) > 0
        assert out[0][0] == b"async_ok"

        print("✅ Test passed: async execute() is properly handled")

    finally:
        if mod_name in sys.modules:
            del sys.modules[mod_name]


if __name__ == "__main__":
    test_load_module_on_demand_processes_pending_registrations_and_handler_supports_context_call()
    test_handler_supports_legacy_call()
    test_async_execute_support()
    print("\n✅ All tests passed!")
