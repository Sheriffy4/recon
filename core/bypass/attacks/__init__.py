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

# Import all subdirectory attack modules
# HTTP attacks
try:
    from .http import http2_attacks
    LOG.info("✓ Loaded http2_attacks module")
except ImportError as e:
    LOG.error(f"✗ Failed to import http2_attacks: {e}")
    import traceback
    LOG.error(f"  Traceback: {traceback.format_exc()}")
except Exception as e:
    LOG.error(f"✗ Error loading http2_attacks: {e}")
    import traceback
    LOG.error(traceback.format_exc())

try:
    from .http import header_attacks, method_attacks, quic_attacks
    LOG.info("Loaded other HTTP attack modules")
except Exception as e:
    LOG.warning(f"Failed to load other HTTP attacks: {e}")

# TLS attacks
# Import ECH attacks with detailed error handling
try:
    from .tls import ech_attacks
    LOG.info("✓ Loaded ech_attacks module")
except ImportError as e:
    LOG.error(f"✗ Failed to import ech_attacks: {e}")
    import traceback
    LOG.error(f"  Traceback: {traceback.format_exc()}")
except Exception as e:
    LOG.error(f"✗ Error loading ech_attacks: {e}")
    import traceback
    LOG.error(traceback.format_exc())

# Import other TLS attacks
try:
    from .tls import (
        extension_attacks, confusion, early_data_smuggling,
        early_data_tunnel, ja3_mimicry, record_manipulation, tls_evasion
    )
    LOG.info("Loaded other TLS attack modules")
except Exception as e:
    LOG.warning(f"Failed to load other TLS attacks: {e}")

# TCP attacks
try:
    from .tcp import (
        fakeddisorder_attack, fooling, manipulation, race_attacks,
        stateful_attacks, timing
    )
    LOG.info("Loaded TCP attack modules")
except Exception as e:
    LOG.warning(f"Failed to load TCP attacks: {e}")

# UDP attacks
try:
    from .udp import quic_bypass, stun_bypass, udp_fragmentation
    LOG.info("Loaded UDP attack modules")
except Exception as e:
    LOG.warning(f"Failed to load UDP attacks: {e}")

# Payload attacks
try:
    from .payload import encryption, noise, obfuscation
    LOG.info("Loaded payload attack modules")
except Exception as e:
    LOG.warning(f"Failed to load payload attacks: {e}")

# Tunneling attacks
try:
    from .tunneling import (
        icmp_tunneling, protocol_tunneling, quic_fragmentation, dns_tunneling_legacy
    )
    LOG.info("Loaded tunneling attack modules")
except Exception as e:
    LOG.warning(f"Failed to load tunneling attacks: {e}")

# IP attacks
try:
    from .ip import fragmentation, header_manipulation
    LOG.info("Loaded IP attack modules")
except Exception as e:
    LOG.warning(f"Failed to load IP attacks: {e}")

# DNS attacks
try:
    from .dns import dns_tunneling
    LOG.info("Loaded DNS attack modules")
except Exception as e:
    LOG.warning(f"Failed to load DNS attacks: {e}")

# Timing attacks
try:
    from .timing import burst_traffic, delay_evasion, jitter_injection, timing_base
    LOG.info("Loaded timing attack modules")
except Exception as e:
    LOG.warning(f"Failed to load timing attacks: {e}")

# Obfuscation attacks
try:
    from .obfuscation import (
        icmp_obfuscation, payload_encryption, protocol_mimicry,
        protocol_tunneling, quic_obfuscation, traffic_obfuscation
    )
    LOG.info("Loaded obfuscation attack modules")
except Exception as e:
    LOG.warning(f"Failed to load obfuscation attacks: {e}")

# Combo attacks
try:
    from .combo import (
        adaptive_combo, advanced_traffic_profiler, baseline, dynamic_combo,
        full_session_simulation, multi_flow_correlation, multi_layer,
        native_combo_engine, steganographic_engine, steganography,
        traffic_mimicry, traffic_profiles, zapret_attack_adapter,
        zapret_integration, zapret_strategy
    )
    LOG.info("Loaded combo attack modules")
except Exception as e:
    LOG.warning(f"Failed to load combo attacks: {e}")

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
        # Import all modules to ensure registration
        modules_to_check = [
            'tcp_advanced', 'tls_advanced', 'ip_obfuscation'
        ]
        
        for module_name in modules_to_check:
            try:
                module = globals().get(module_name)
                if module and hasattr(module, f'register_{module_name}_attacks'):
                    getattr(module, f'register_{module_name}_attacks')()
                    LOG.info(f"Force registered {module_name} attacks")
            except Exception as e:
                LOG.warning(f"Failed to force register {module_name}: {e}")
            
        LOG.info("Force registration of new attacks completed")
    except Exception as e:
        LOG.warning(f"Force registration failed: {e}")

# Call force registration
_ensure_new_attacks_registered()

# Verify all attacks are loaded
def _verify_attack_loading():
    """Verify that all expected attacks are loaded."""
    try:
        registry = get_attack_registry()
        attacks = registry.list_attacks()
        
        expected_categories = [
            'http', 'tls', 'tcp', 'udp', 'payload', 'tunneling', 
            'ip', 'dns', 'timing', 'obfuscation', 'combo'
        ]
        
        LOG.info(f"Total attacks loaded: {len(attacks)}")
        
        # Check for HTTP/2 attacks specifically
        expected_http2_attacks = [
            'h2_frame_splitting',
            'h2_hpack_manipulation',
            'h2_priority_manipulation',
            'h2c_upgrade',
            'h2_hpack_bomb'
        ]
        
        http2_attacks = [a for a in attacks if 'h2_' in a or 'http2' in a.lower()]
        
        if http2_attacks:
            LOG.info(f"✓ HTTP/2 attacks loaded: {', '.join(http2_attacks)}")
        else:
            LOG.warning("✗ No HTTP/2 attacks found")
            LOG.warning(f"  Expected: {', '.join(expected_http2_attacks)}")
            
        # Check for ECH attacks
        expected_ech_attacks = [
            'ech_fragmentation',
            'ech_grease',
            'ech_decoy',
            'ech_advanced_grease',
            'ech_outer_sni_manipulation',
            'ech_advanced_fragmentation'
        ]
        
        ech_attacks = [a for a in attacks if 'ech_' in a]
        
        if ech_attacks:
            LOG.info(f"✓ ECH attacks loaded: {', '.join(ech_attacks)}")
        else:
            LOG.warning("✗ No ECH attacks found")
            LOG.warning(f"  Expected: {', '.join(expected_ech_attacks)}")
            
    except Exception as e:
        LOG.error(f"Failed to verify attack loading: {e}")

# Verify loading
_verify_attack_loading()
