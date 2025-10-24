#!/usr/bin/env python3
"""
Simple test to check new attack registration.
"""

print("=== Simple New Attack Test ===")

# Step 1: Import registry first
print("\n1. Getting clean registry...")
from core.bypass.attacks.attack_registry import get_attack_registry
registry = get_attack_registry()
print(f"Initial attacks: {len(registry.attacks)}")

# Step 2: Import new attack modules one by one
print("\n2. Importing tcp_advanced...")
import core.bypass.attacks.tcp_advanced
print(f"After tcp_advanced: {len(registry.attacks)} attacks")

# Check if tcp attacks were added
tcp_attacks = [name for name in registry.attacks.keys() if 'tcp_window_manipulation' in name or 'tcp_sequence' in name]
print(f"TCP attacks found: {tcp_attacks}")

print("\n3. Importing tls_advanced...")
import core.bypass.attacks.tls_advanced
print(f"After tls_advanced: {len(registry.attacks)} attacks")

# Check if tls attacks were added
tls_attacks = [name for name in registry.attacks.keys() if 'sni_manipulation' in name or 'alpn' in name]
print(f"TLS attacks found: {tls_attacks}")

print("\n4. Importing ip_obfuscation...")
import core.bypass.attacks.ip_obfuscation
print(f"After ip_obfuscation: {len(registry.attacks)} attacks")

# Check if ip attacks were added
ip_attacks = [name for name in registry.attacks.keys() if 'ip_ttl_manipulation' in name or 'payload_padding' in name]
print(f"IP attacks found: {ip_attacks}")

print("\n5. Final check...")
print(f"Total attacks: {len(registry.attacks)}")
print("All attacks:", list(registry.attacks.keys()))

# Test specific attacks
test_attacks = ['tcp_window_manipulation', 'tcp_sequence_manipulation', 'sni_manipulation', 'ip_ttl_manipulation']
for attack in test_attacks:
    handler = registry.get_attack_handler(attack)
    print(f"{attack}: {'✅ Found' if handler else '❌ Not found'}")