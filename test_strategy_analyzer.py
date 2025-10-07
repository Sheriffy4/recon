#!/usr/bin/env python3
"""
Test script for StrategyAnalyzer implementation.
"""

import sys
import os
from pathlib import Path

# Add recon to path
sys.path.insert(0, str(Path(__file__).parent))

from core.pcap_analysis.strategy_analyzer import StrategyAnalyzer
from core.pcap_analysis.strategy_config import StrategyConfig, StrategyType, FoolingMethod
from core.pcap_analysis.packet_info import PacketInfo


def test_strategy_config():
    """Test StrategyConfig data model."""
    print("Testing StrategyConfig...")
    
    # Test zapret parameter parsing
    zapret_params = {
        'dpi-desync': 'fake,fakeddisorder',
        'dpi-desync-split-pos': '3',
        'dpi-desync-split-seqovl': '1',
        'dpi-desync-ttl': '3',
        'dpi-desync-fooling': 'badsum,badseq'
    }
    
    config = StrategyConfig.from_zapret_params(zapret_params)
    
    assert config.dpi_desync == 'fake,fakeddisorder'
    assert config.split_pos == 3
    assert config.split_seqovl == 1
    assert config.ttl == 3
    assert config.fooling == ['badsum', 'badseq']
    assert config.source == 'zapret'
    
    print("✓ StrategyConfig zapret parsing works")
    
    # Test strategy type detection
    assert config.has_strategy('fake')
    assert config.has_strategy('fakeddisorder')
    assert config.is_fake_disorder_strategy()
    assert config.has_fooling_method('badsum')
    assert config.has_fooling_method('badseq')
    
    print("✓ StrategyConfig strategy detection works")
    
    # Test recon config parsing
    recon_config_dict = {
        'name': 'test_strategy',
        'strategy': 'fake,fakeddisorder',
        'split_pos': 3,
        'ttl': 3,
        'fooling': ['badsum', 'badseq']
    }
    
    recon_config = StrategyConfig.from_recon_config(recon_config_dict)
    assert recon_config.name == 'test_strategy'
    assert recon_config.dpi_desync == 'fake,fakeddisorder'
    assert recon_config.source == 'recon'
    
    print("✓ StrategyConfig recon parsing works")
    
    # Test equality
    assert config != recon_config  # Different sources
    
    # Make them equivalent
    recon_config.source = 'zapret'
    recon_config.split_seqovl = 1
    assert config == recon_config
    
    print("✓ StrategyConfig equality works")


def test_strategy_analyzer():
    """Test StrategyAnalyzer functionality."""
    print("\nTesting StrategyAnalyzer...")
    
    analyzer = StrategyAnalyzer()
    
    # Create mock packets for fake+disorder pattern
    fake_packet = PacketInfo(
        timestamp=1000.0,
        src_ip="192.168.1.100",
        dst_ip="1.1.1.1",
        src_port=12345,
        dst_port=443,
        sequence_num=1000,
        ack_num=0,
        ttl=3,  # Low TTL indicates fake packet
        flags=['PSH', 'ACK'],
        payload_length=0,
        checksum=0x1234,
        checksum_valid=False  # Bad checksum indicates fake
    )
    
    real_segment1 = PacketInfo(
        timestamp=1000.001,
        src_ip="192.168.1.100",
        dst_ip="1.1.1.1",
        src_port=12345,
        dst_port=443,
        sequence_num=1000,
        ack_num=0,
        ttl=64,  # Normal TTL
        flags=['PSH', 'ACK'],
        payload_length=3,  # Split at position 3
        payload=b'\x16\x03\x01',  # TLS handshake start
        checksum_valid=True,
        is_client_hello=True
    )
    
    real_segment2 = PacketInfo(
        timestamp=1000.002,
        src_ip="192.168.1.100",
        dst_ip="1.1.1.1",
        src_port=12345,
        dst_port=443,
        sequence_num=1002,  # Overlap of 1 byte (1000 + 3 - 1)
        ack_num=0,
        ttl=64,
        flags=['PSH', 'ACK'],
        payload_length=200,
        payload=b'\x01' + b'\x00' * 199,  # Rest of ClientHello
        checksum_valid=True
    )
    
    packets = [fake_packet, real_segment1, real_segment2]
    
    # Test strategy parsing from PCAP
    config = analyzer.parse_strategy_from_pcap(packets, "x.com")
    
    assert config.dpi_desync == "fake,fakeddisorder"
    assert config.split_pos == 3
    assert config.split_seqovl == 1
    assert config.ttl == 3
    assert 'badsum' in config.fooling
    assert config.source == "pcap_analysis"
    
    print("✓ Strategy parsing from PCAP works")
    
    # Test strategy comparison
    zapret_config = StrategyConfig(
        dpi_desync="fake,fakeddisorder",
        split_pos=3,
        split_seqovl=1,
        ttl=3,
        fooling=['badsum', 'badseq'],
        source="zapret"
    )
    
    recon_config = StrategyConfig(
        dpi_desync="fake,fakeddisorder",
        split_pos=5,  # Different split position
        split_seqovl=1,
        ttl=64,  # Different TTL
        fooling=['badsum'],  # Missing badseq
        source="recon"
    )
    
    comparison = analyzer.compare_strategies(recon_config, zapret_config)
    
    assert len(comparison.differences) > 0
    assert not comparison.is_compatible
    assert comparison.similarity_score < 1.0
    
    # Check for critical differences
    critical_diffs = comparison.get_critical_differences()
    assert len(critical_diffs) > 0
    
    # Should have TTL difference as critical
    ttl_diff = next((d for d in critical_diffs if d.parameter == "ttl"), None)
    assert ttl_diff is not None
    assert ttl_diff.recon_value == 64
    assert ttl_diff.zapret_value == 3
    
    print("✓ Strategy comparison works")
    
    # Test parameter validation
    invalid_config = StrategyConfig(
        dpi_desync="fakeddisorder",
        ttl=300,  # Invalid TTL
        split_pos=-1  # Invalid split position
    )
    
    validation = analyzer.validate_strategy_parameters(invalid_config)
    assert not validation['valid']
    assert len(validation['errors']) > 0
    
    print("✓ Parameter validation works")
    
    # Test effective parameter extraction
    params = analyzer.extract_effective_parameters(packets)
    
    assert 'ttl_range' in params
    assert 'unique_ttls' in params
    assert 'timing_gaps' in params
    assert 'fake_packet_count' in params
    assert params['fake_packet_count'] == 1
    
    print("✓ Effective parameter extraction works")


def test_integration():
    """Test integration between components."""
    print("\nTesting integration...")
    
    analyzer = StrategyAnalyzer()
    
    # Test complete workflow
    # 1. Parse strategy from PCAP
    # 2. Compare with expected zapret config
    # 3. Generate differences and fixes
    
    # Mock zapret-style packets
    zapret_packets = [
        PacketInfo(
            timestamp=1000.0,
            src_ip="192.168.1.100",
            dst_ip="104.244.42.1",  # x.com IP
            src_port=12345,
            dst_port=443,
            sequence_num=1000,
            ack_num=0,
            ttl=3,
            flags=['PSH', 'ACK'],
            payload_length=0,
            checksum_valid=False
        ),
        PacketInfo(
            timestamp=1000.001,
            src_ip="192.168.1.100",
            dst_ip="104.244.42.1",
            src_port=12345,
            dst_port=443,
            sequence_num=1000,
            ack_num=0,
            ttl=64,
            flags=['PSH', 'ACK'],
            payload_length=3,
            payload=b'\x16\x03\x01',
            checksum_valid=True,
            is_client_hello=True
        ),
        PacketInfo(
            timestamp=1000.002,
            src_ip="192.168.1.100",
            dst_ip="104.244.42.1",
            src_port=12345,
            dst_port=443,
            sequence_num=1003,
            ack_num=0,
            ttl=64,
            flags=['PSH', 'ACK'],
            payload_length=200,
            checksum_valid=True
        )
    ]
    
    # Parse zapret strategy
    zapret_strategy = analyzer.parse_strategy_from_pcap(zapret_packets, "x.com")
    
    # Mock recon-style packets (with issues)
    recon_packets = [
        PacketInfo(
            timestamp=2000.0,
            src_ip="192.168.1.100",
            dst_ip="104.244.42.1",
            src_port=12346,
            dst_port=443,
            sequence_num=2000,
            ack_num=0,
            ttl=64,  # Wrong TTL - should be 3
            flags=['PSH', 'ACK'],
            payload_length=0,
            checksum_valid=True  # Wrong checksum - should be bad
        ),
        PacketInfo(
            timestamp=2000.001,
            src_ip="192.168.1.100",
            dst_ip="104.244.42.1",
            src_port=12346,
            dst_port=443,
            sequence_num=2000,
            ack_num=0,
            ttl=64,
            flags=['PSH', 'ACK'],
            payload_length=5,  # Wrong split position - should be 3
            payload=b'\x16\x03\x01\x00\x01',
            checksum_valid=True,
            is_client_hello=True
        ),
        PacketInfo(
            timestamp=2000.002,
            src_ip="192.168.1.100",
            dst_ip="104.244.42.1",
            src_port=12346,
            dst_port=443,
            sequence_num=2005,  # No overlap - should have overlap
            ack_num=0,
            ttl=64,
            flags=['PSH', 'ACK'],
            payload_length=200,
            checksum_valid=True
        )
    ]
    
    # Parse recon strategy
    recon_strategy = analyzer.parse_strategy_from_pcap(recon_packets, "x.com")
    
    # Compare strategies
    comparison = analyzer.compare_strategies(recon_strategy, zapret_strategy)
    
    print(f"Found {len(comparison.differences)} differences")
    print(f"Similarity score: {comparison.similarity_score:.2f}")
    print(f"Compatible: {comparison.is_compatible}")
    
    for diff in comparison.differences:
        print(f"- {diff.parameter}: {diff.recon_value} -> {diff.zapret_value} ({diff.impact_level})")
    
    assert len(comparison.differences) > 0
    print("✓ Integration test passed")


def main():
    """Run all tests."""
    print("Running StrategyAnalyzer tests...\n")
    
    try:
        test_strategy_config()
        test_strategy_analyzer()
        test_integration()
        
        print("\n✅ All tests passed!")
        return 0
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())