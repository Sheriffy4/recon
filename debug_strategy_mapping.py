#!/usr/bin/env python3
"""
Debug script to test why domain-specific strategies aren't being applied.
"""

import json
import sys
from pathlib import Path
from unittest.mock import Mock

# Add project path
sys.path.insert(0, str(Path(__file__).parent))

def test_sni_extraction():
    """Test SNI extraction with a real TLS ClientHello packet."""
    from core.bypass_engine import BypassEngine
    
    engine = BypassEngine(debug=True)
    
    # Create a properly formatted TLS ClientHello with SNI for x.com
    sni_name = b'x.com'
    sni_ext = (
        b'\x00\x00'  # extension type (SNI)
        + (len(sni_name) + 5).to_bytes(2, 'big')  # extension length
        + (len(sni_name) + 3).to_bytes(2, 'big')  # server name list length
        + b'\x00'  # name type (hostname)
        + len(sni_name).to_bytes(2, 'big')  # name length
        + sni_name  # the actual SNI
    )
    
    tls_payload = (
        b'\x16\x03\x01\x02\x00'  # TLS record header
        + b'\x01\x00\x01\xfc'  # handshake header (ClientHello)
        + b'\x03\x03'  # TLS version
        + b'\x00' * 32  # random
        + b'\x00'  # session ID length
        + b'\x00\x02\x13\x01'  # cipher suites (minimal)
        + b'\x01\x00'  # compression methods
        + len(sni_ext).to_bytes(2, 'big')  # extensions length
        + sni_ext  # SNI extension
    )
    
    print("Testing SNI extraction:")
    sni = engine._extract_sni(tls_payload)
    print(f"Extracted SNI: {sni}")
    
    return sni

def test_strategy_mapping():
    """Test strategy mapping with domain-specific strategies."""
    print("\nTesting strategy mapping:")
    
    # Load strategies from file
    strategies_file = Path("strategies.json")
    if not strategies_file.exists():
        print("❌ strategies.json not found!")
        return
    
    with open(strategies_file, "r", encoding="utf-8") as f:
        strategies = json.load(f)
    
    print(f"Loaded {len(strategies)} strategies:")
    for domain, strategy in strategies.items():
        print(f"  {domain}: {strategy[:60]}...")
    
    # Test domain matching logic
    test_domains = ["x.com", "abs-0.twimg.com", "pbs.twimg.com", "unknown.twimg.com"]
    
    print(f"\nTesting domain matching:")
    for test_domain in test_domains:
        found_strategy = None
        
        # 1. Exact match
        if test_domain in strategies:
            found_strategy = strategies[test_domain]
            print(f"  {test_domain}: Found exact match")
        else:
            # 2. Wildcard match
            for pattern in strategies:
                if pattern.startswith("*.") and test_domain.endswith(pattern[1:]):
                    found_strategy = strategies[pattern]
                    print(f"  {test_domain}: Found wildcard match ({pattern})")
                    break
            
            if not found_strategy:
                # 3. Default
                found_strategy = strategies.get("default")
                print(f"  {test_domain}: Using default strategy")
        
        if found_strategy:
            print(f"    Strategy: {found_strategy[:60]}...")
        else:
            print(f"    No strategy found!")

def test_bypass_engine_integration():
    """Test the full BypassEngine integration."""
    print("\nTesting BypassEngine integration:")
    
    from core.bypass_engine import BypassEngine
    
    # Load strategies
    with open("strategies.json", "r", encoding="utf-8") as f:
        raw_strategies = json.load(f)
    
    # Convert to strategy_map format
    from recon_service import DPIBypassService
    
    service = DPIBypassService()
    service.domain_strategies = raw_strategies
    
    strategy_map = {}
    for domain, strategy_str in raw_strategies.items():
        if domain != "default":
            strategy_config = service.parse_strategy_config(strategy_str)
            strategy_task = service._config_to_strategy_task(strategy_config)
            strategy_map[domain] = strategy_task
    
    # Add default
    if "default" in raw_strategies:
        default_config = service.parse_strategy_config(raw_strategies["default"])
        default_task = service._config_to_strategy_task(default_config)
        strategy_map["default"] = default_task
    
    print(f"Strategy map contains {len(strategy_map)} entries:")
    for domain, task in strategy_map.items():
        print(f"  {domain}: {task['type']}")
    
    # Test strategy selection
    engine = BypassEngine(debug=True)
    
    # Mock packet for x.com
    mock_packet = Mock()
    mock_packet.dst_addr = "104.244.43.131"
    
    # Create TLS ClientHello with x.com SNI
    sni_name = b'x.com'
    sni_ext = (
        b'\x00\x00'  # extension type (SNI)
        + (len(sni_name) + 5).to_bytes(2, 'big')  # extension length
        + (len(sni_name) + 3).to_bytes(2, 'big')  # server name list length
        + b'\x00'  # name type (hostname)
        + len(sni_name).to_bytes(2, 'big')  # name length
        + sni_name  # the actual SNI
    )
    
    mock_packet.payload = (
        b'\x16\x03\x01\x02\x00'  # TLS record header
        + b'\x01\x00\x01\xfc'  # handshake header (ClientHello)
        + b'\x03\x03'  # TLS version
        + b'\x00' * 32  # random
        + b'\x00'  # session ID length
        + b'\x00\x02\x13\x01'  # cipher suites (minimal)
        + b'\x01\x00'  # compression methods
        + len(sni_ext).to_bytes(2, 'big')  # extensions length
        + sni_ext  # SNI extension
    )
    
    print(f"\nTesting strategy selection:")
    print(f"Packet destination: {mock_packet.dst_addr}")
    
    # Extract SNI
    sni = engine._extract_sni(mock_packet.payload)
    print(f"Extracted SNI: {sni}")
    
    # Choose strategy
    chosen_strategy = engine._choose_strategy(mock_packet, strategy_map)
    print(f"Chosen strategy: {chosen_strategy}")
    
    if chosen_strategy and sni == "x.com":
        print("✅ Strategy selection working correctly!")
    else:
        print("❌ Strategy selection not working!")

if __name__ == "__main__":
    print("🔧 === Debug Strategy Mapping ===\n")
    
    # Test 1: SNI extraction
    extracted_sni = test_sni_extraction()
    
    # Test 2: Strategy mapping
    test_strategy_mapping()
    
    # Test 3: Full integration
    test_bypass_engine_integration()
    
    print("\n🎉 === Debug Complete ===")