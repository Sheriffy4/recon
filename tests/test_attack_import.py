"""Quick test to verify new attacks can be imported and registered."""

import logging
logging.basicConfig(level=logging.INFO)

print("=" * 60)
print("Testing Attack Module Imports")
print("=" * 60)

# Test 1: Import tcp_advanced
print("\n1. Importing tcp_advanced.py...")
try:
    import core.bypass.attacks.tcp_advanced as tcp_adv
    print("✅ tcp_advanced imported successfully")
except Exception as e:
    print(f"❌ Failed to import tcp_advanced: {e}")
    import traceback
    traceback.print_exc()

# Test 2: Import tls_advanced
print("\n2. Importing tls_advanced.py...")
try:
    import core.bypass.attacks.tls_advanced as tls_adv
    print("✅ tls_advanced imported successfully")
except Exception as e:
    print(f"❌ Failed to import tls_advanced: {e}")
    import traceback
    traceback.print_exc()

# Test 3: Import ip_obfuscation
print("\n3. Importing ip_obfuscation.py...")
try:
    import core.bypass.attacks.ip_obfuscation as ip_obf
    print("✅ ip_obfuscation imported successfully")
except Exception as e:
    print(f"❌ Failed to import ip_obfuscation: {e}")
    import traceback
    traceback.print_exc()

# Test 4: Check registry
print("\n4. Checking AttackRegistry...")
try:
    from core.bypass.attacks.attack_registry import get_attack_registry
    registry = get_attack_registry()
    
    print(f"\nTotal attacks registered: {len(registry.attacks)}")
    print(f"Total aliases: {len(registry._aliases)}")
    
    # Check for our new attacks
    new_attacks = [
        "tcp_window_manipulation",
        "tcp_sequence_manipulation",
        "tcp_window_scaling",
        "urgent_pointer_manipulation",
        "tcp_options_padding",
        "tcp_timestamp_manipulation",
        "tcp_wssize_limit",
        "sni_manipulation",
        "alpn_manipulation",
        "grease_injection",
        "ip_ttl_manipulation",
        "ip_id_manipulation",
        "payload_padding",
        "noise_injection",
        "timing_obfuscation",
    ]
    
    print("\nChecking new attacks:")
    registered_count = 0
    for attack in new_attacks:
        handler = registry.get_attack_handler(attack)
        if handler:
            print(f"  ✅ {attack}")
            registered_count += 1
        else:
            print(f"  ❌ {attack} - NOT FOUND")
    
    print(f"\nRegistered: {registered_count}/{len(new_attacks)}")
    
    # List all registered attacks
    print("\nAll registered attacks:")
    for attack_name in sorted(registry.attacks.keys()):
        print(f"  - {attack_name}")
    
except Exception as e:
    print(f"❌ Failed to check registry: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 60)
print("Test Complete")
print("=" * 60)
