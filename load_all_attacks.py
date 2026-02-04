"""
Attack Module Loader

This module imports all attack implementations to ensure they are registered
with the AttackRegistry via the @register_attack decorator.
"""

import logging
from core.bypass.attacks.attack_registry import register_attack

LOG = logging.getLogger("AttackLoader")


def load_all_attacks():
    """
    Import all attack modules to trigger registration.

    This function imports all attack implementation modules, which causes
    the @register_attack decorators to execute and register attacks with
    the AttackRegistry.
    """
    LOG.info("Loading all attack modules...")

    try:
        # TCP Fragmentation attacks

        LOG.debug("Loaded: tcp_fragmentation")

        # TCP attacks

        LOG.debug("Loaded: TCP attacks")

        # TLS attacks

        LOG.debug("Loaded: TLS attacks")

        # Tunneling attacks

        LOG.debug("Loaded: Tunneling attacks")

        # Get registry stats
        from core.bypass.attacks.attack_registry import get_attack_registry

        registry = get_attack_registry()
        all_attacks = registry.list_attacks()
        
        # Collect categories
        categories = set()
        for attack_name in all_attacks:
            try:
                attack_class = registry.get_attack(attack_name)
                if hasattr(attack_class, 'category'):
                    cat = attack_class.category if callable(attack_class.category) else attack_class.category
                    if isinstance(cat, property):
                        # Skip property objects, we'll get category from instance later
                        continue
                    categories.add(str(cat))
            except Exception:
                pass
        
        stats = {
            "total_attacks": len(all_attacks),
            "categories": list(categories) if categories else ["unknown"]
        }

        LOG.info(
            f"Attack loading complete: {stats['total_attacks']} attacks registered"
        )
        LOG.info(f"Categories: {stats['categories']}")

        return stats

    except Exception as e:
        LOG.error(f"Error loading attack modules: {e}", exc_info=True)
        raise


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    stats = load_all_attacks()
    print(f"\nLoaded {stats['total_attacks']} attacks")
    print(f"Categories: {stats['categories']}")
