"""
Custom attack aliases for backward compatibility
"""

from core.bypass.attacks.attack_registry import get_attack_registry

def register_custom_aliases():
    """Register custom attack aliases."""
    registry = get_attack_registry()
    
    # Register disorder_short_ttl_decoy as alias for disorder
    result1 = registry.register_alias("disorder_short_ttl_decoy", "disorder")
    print(f"Register disorder_short_ttl_decoy: {result1.success} - {result1.message}")
    
    # Register disorder_short_ttl_decoy_optimized as alias for disorder
    result2 = registry.register_alias("disorder_short_ttl_decoy_optimized", "disorder")
    print(f"Register disorder_short_ttl_decoy_optimized: {result2.success} - {result2.message}")
    
    if result1.success and result2.success:
        print("[OK] Registered custom attack aliases:")
        print("   - disorder_short_ttl_decoy -> disorder")
        print("   - disorder_short_ttl_decoy_optimized -> disorder")
    else:
        print("[ERROR] Failed to register some aliases")

# Auto-register on import
register_custom_aliases()
