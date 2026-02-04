"""
Unified attack dispatcher engine.

Public API for attack execution and packet manipulation.
"""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

__all__ = [
    "UnifiedAttackDispatcher",
    "AttackConstants",
    "PacketSegment",
    "get_fake_params",
    "generate_fake_payload",
    "MetricsCircuitBreaker",
]

_LAZY_EXPORTS = {
    "UnifiedAttackDispatcher": (".unified_attack_dispatcher", "UnifiedAttackDispatcher"),
    "AttackConstants": (".attack_constants", "AttackConstants"),
    "PacketSegment": (".packet_segment", "PacketSegment"),
    "get_fake_params": (".attack_helpers", "get_fake_params"),
    "generate_fake_payload": (".attack_helpers", "generate_fake_payload"),
    "MetricsCircuitBreaker": (".metrics_circuit_breaker", "MetricsCircuitBreaker"),
}


def __getattr__(name: str) -> Any:
    """
    Lazy attribute resolver to avoid heavy imports and circular dependencies.
    Keeps backward-compatible public API:
      from core.bypass.engine import UnifiedAttackDispatcher
    """
    target = _LAZY_EXPORTS.get(name)
    if not target:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_path, attr_name = target
    module = import_module(module_path, __name__)
    value = getattr(module, attr_name)
    globals()[name] = value  # cache for next time
    return value


def __dir__() -> list[str]:
    return sorted(set(globals().keys()) | set(_LAZY_EXPORTS.keys()))


if TYPE_CHECKING:
    # For type checkers / IDEs only; does not execute at runtime.
    from .unified_attack_dispatcher import UnifiedAttackDispatcher
    from .attack_constants import AttackConstants
    from .packet_segment import PacketSegment
    from .attack_helpers import get_fake_params, generate_fake_payload
    from .metrics_circuit_breaker import MetricsCircuitBreaker
