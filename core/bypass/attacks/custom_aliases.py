"""
Custom attack aliases for backward compatibility
"""

from __future__ import annotations

import logging
import os

from core.bypass.attacks.attack_registry import get_attack_registry

LOG = logging.getLogger(__name__)


def register_custom_aliases():
    """Register custom attack aliases."""
    registry = get_attack_registry()

    # Register disorder_short_ttl_decoy as alias for disorder
    result1 = registry.register_alias("disorder_short_ttl_decoy", "disorder")

    # Register disorder_short_ttl_decoy_optimized as alias for disorder
    result2 = registry.register_alias("disorder_short_ttl_decoy_optimized", "disorder")

    if result1 and result2:
        msg1 = "disorder_short_ttl_decoy -> disorder"
        msg2 = "disorder_short_ttl_decoy_optimized -> disorder"
        LOG.info("Registered custom attack aliases: %s; %s", msg1, msg2)
        if os.getenv("RECON_ATTACKS_CUSTOM_ALIASES_PRINT", "1") != "0":
            print("[OK] Registered custom attack aliases:")
            print(f"   - {msg1}")
            print(f"   - {msg2}")
    else:
        LOG.warning("Failed to register some custom attack aliases")
        if os.getenv("RECON_ATTACKS_CUSTOM_ALIASES_PRINT", "1") != "0":
            print("[ERROR] Failed to register some aliases")


# Auto-register on import
if os.getenv("RECON_ATTACKS_AUTO_REGISTER_CUSTOM_ALIASES", "1") != "0":
    register_custom_aliases()

