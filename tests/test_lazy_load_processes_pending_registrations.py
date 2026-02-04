"""
Test that lazy loading processes pending registrations from decorator queue.

This test ensures that attacks registered via @register_attack decorator
are properly loaded when using lazy loading.
"""

import sys
import types
from types import SimpleNamespace


def test_load_module_on_demand_processes_pending_registrations_and_handler_supports_context_call():
    """Test that load_module_on_demand processes pending registrations and handler supports context call."""
    from core.bypass.attacks.attack_registry import AttackRegistry
    from core.bypass.attacks.registry.decorator import clear_pending_registrations

    clear_pending_registrations()
    reg = AttackRegistry(lazy_loading=False)

    mod_name = "core.bypass.attacks._test_lazy_queued_mod"
    mod = types.ModuleType(mod_name)
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

    assert (
        reg.registration_manager.load_module_on_demand(mod_name, reg) is True
    ), "Module loading failed"
    h = reg.get_attack_handler("lazy_queued_attack")
    assert h is not None, "Attack handler not found after lazy loading"

    # Test handler with context call (new style)
    out = h(SimpleNamespace(payload=b"x", params={}, techniques=None))
    assert isinstance(out, list), f"Expected list, got {type(out)}"
    assert out and out[0][0] == b"ok", f"Expected [(b'ok', 0, {{}})], got {out}"

    # Cleanup
    del sys.modules[mod_name]


if __name__ == "__main__":
    test_load_module_on_demand_processes_pending_registrations_and_handler_supports_context_call()
    print(
        "✅ Test passed: load_module_on_demand processes pending registrations and handler supports context call"
    )
