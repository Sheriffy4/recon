"""
Attack Module Loader

This module imports all attack implementations to ensure they are registered
with the AttackRegistry via the @register_attack decorator.
"""

import logging

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
        from core.bypass.attacks import tcp_fragmentation
        LOG.debug("Loaded: tcp_fragmentation")
        
        # TCP attacks
        from core.bypass.attacks.tcp import manipulation
        from core.bypass.attacks.tcp import fooling
        from core.bypass.attacks.tcp import timing
        from core.bypass.attacks.tcp import stateful_attacks
        from core.bypass.attacks.tcp import race_attacks
        LOG.debug("Loaded: TCP attacks")
        
        # TLS attacks
        from core.bypass.attacks.tls import record_manipulation
        from core.bypass.attacks.tls import tls_evasion
        from core.bypass.attacks.tls import ja3_mimicry
        from core.bypass.attacks.tls import extension_attacks
        from core.bypass.attacks.tls import ech_attacks
        from core.bypass.attacks.tls import early_data_tunnel
        from core.bypass.attacks.tls import early_data_smuggling
        from core.bypass.attacks.tls import confusion
        LOG.debug("Loaded: TLS attacks")
        
        # Tunneling attacks
        from core.bypass.attacks.tunneling import protocol_tunneling
        from core.bypass.attacks.tunneling import icmp_tunneling
        from core.bypass.attacks.tunneling import dns_tunneling_legacy
        from core.bypass.attacks.tunneling import quic_fragmentation
        LOG.debug("Loaded: Tunneling attacks")
        
        # Get registry stats
        from core.bypass.attacks.registry import AttackRegistry
        stats = AttackRegistry.get_stats()
        
        LOG.info(f"Attack loading complete: {stats['total_attacks']} attacks registered")
        LOG.info(f"Categories: {stats['categories']}")
        
        return stats
        
    except Exception as e:
        LOG.error(f"Error loading attack modules: {e}", exc_info=True)
        raise


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    stats = load_all_attacks()
    print(f"\nLoaded {stats['total_attacks']} attacks")
    print(f"Categories: {stats['categories']}")
