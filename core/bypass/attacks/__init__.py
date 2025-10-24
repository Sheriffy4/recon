"""
Bypass Attacks Package - Unified Attack System

This package provides a centralized attack registry system with canonical implementations.

Architecture:
- Canonical implementations are in core/bypass/techniques/primitives.py
- All attacks are registered through the unified AttackRegistry
- External attacks are automatically discovered and registered
- Duplicate registrations are prevented through priority system

Canonical Attacks (from primitives.py):
- fakeddisorder: Fake packet + real parts in reverse order
- seqovl: Sequence overlap with fake packet
- multidisorder: Multiple split positions with disorder
- disorder/disorder2: Simple reordering without fake packet
- multisplit/split: Packet splitting at multiple/single positions
- fake: Race condition with fake packet

Usage:
    from core.bypass.attacks import get_attack_registry

    registry = get_attack_registry()
    handler = registry.get_attack_handler("fakeddisorder")
"""

import logging

LOG = logging.getLogger(__name__)

# Import core registry components
# The AttackRegistry automatically registers canonical implementations from primitives.py
# with CORE priority, ensuring they take precedence over any external implementations
from .attack_registry import (
    get_attack_registry,
    register_attack,
    AttackMetadata,
    ValidationResult,
    RegistrationPriority,
    AttackEntry,
    RegistrationResult,
)

# Automatic Attack Module Loading
#
# The AttackRegistry automatically handles attack registration in this order:
# 1. CORE attacks from primitives.py (highest priority, cannot be overridden)
# 2. External attacks from attack modules (normal priority, can be deduplicated)
#
# Canonical implementations (from primitives.py) are automatically registered
# when get_attack_registry() is first called. External modules are loaded below
# to provide additional attacks that don't conflict with canonical ones.
#
# Import external attack modules for automatic registration
try:
    from . import stateful_fragmentation

    LOG.info("Loaded stateful_fragmentation attacks")
except Exception as e:
    LOG.warning(f"Failed to load stateful_fragmentation: {e}")

try:
    from . import tls_record_manipulation

    LOG.info("Loaded tls_record_manipulation attacks")
except Exception as e:
    LOG.warning(f"Failed to load tls_record_manipulation: {e}")

try:
    from . import http_manipulation

    LOG.info("Loaded http_manipulation attacks")
except Exception as e:
    LOG.warning(f"Failed to load http_manipulation: {e}")

try:
    from . import pacing_attack

    LOG.info("Loaded pacing_attack")
except Exception as e:
    LOG.warning(f"Failed to load pacing_attack: {e}")

# Import advanced attacks BEFORE tcp_fragmentation
# to prevent them from being overwritten
try:
    from . import tcp_advanced

    LOG.info("Loaded tcp_advanced attacks")
except Exception as e:
    LOG.warning(f"Failed to load tcp_advanced: {e}")

try:
    from . import tls_advanced

    LOG.info("Loaded tls_advanced attacks")
except Exception as e:
    LOG.warning(f"Failed to load tls_advanced: {e}")

try:
    from . import ip_obfuscation

    LOG.info("Loaded ip_obfuscation attacks")
except Exception as e:
    LOG.warning(f"Failed to load ip_obfuscation: {e}")

# tcp_fragmentation.py has been removed - functionality migrated to primitives.py
# Unique features (window manipulation, TCP options modification) are now available
# as primitives.apply_window_manipulation() and primitives.apply_tcp_options_modification()

# Export main components for public API
__all__ = [
    "get_attack_registry",
    "register_attack",
    "AttackMetadata",
    "ValidationResult",
    "RegistrationPriority",
    "AttackEntry",
    "RegistrationResult",
]

# Initialization Summary:
# - Canonical attacks from primitives.py are registered with CORE priority
# - External attack modules are loaded and registered with NORMAL priority
# - Duplicate registrations are automatically handled by priority system
# - All attacks are available through get_attack_registry()

LOG.info("Bypass attacks package initialized successfully")
LOG.info("Canonical implementations from primitives.py have CORE priority")
LOG.info("Use get_attack_registry() to access all registered attacks")


# Force registration of new attacks as fallback
def _ensure_new_attacks_registered():
    """Ensure new attacks are registered as fallback."""
    try:
        from . import tcp_advanced, tls_advanced, ip_obfuscation
        
        # Force call registration functions
        if hasattr(tcp_advanced, 'register_tcp_advanced_attacks'):
            tcp_advanced.register_tcp_advanced_attacks()
        if hasattr(tls_advanced, 'register_tls_advanced_attacks'):
            tls_advanced.register_tls_advanced_attacks()
        if hasattr(ip_obfuscation, 'register_ip_obfuscation_attacks'):
            ip_obfuscation.register_ip_obfuscation_attacks()
            
        LOG.info("Force registration of new attacks completed")
    except Exception as e:
        LOG.warning(f"Force registration failed: {e}")

# Call force registration
_ensure_new_attacks_registered()
