#!/usr/bin/env python3
"""
Demonstration of StrategyAnalyzer functionality for task 2.
"""

import sys
from pathlib import Path

# Add recon to path
sys.path.insert(0, str(Path(__file__).parent))

from core.pcap_analysis import (
    StrategyAnalyzer, StrategyConfig, PacketInfo
)


def demo_zapret_parameter_parsing():
    """Demonstrate parsing zapret command line parameters."""
    print("=== Demo: Zapret Parameter Parsing ===")
    
    # Example zapret command: 
    # zapret --dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-split-seqovl=1 --dpi-desync-ttl=3 --dpi-desync-fooling=badsum,badseq
    
    zapret_params = {
        'dpi-desync': 'fake,fakeddisorder',
        'dpi-desync-split-pos': '3',
        'dpi-desync-split-seqovl': '1', 
        'dpi-desync-ttl': '3',
        'dpi-desync-fooling': 'badsum,badseq'
    }
    
    config = StrategyConfig.from_zapret_params(zapret_params)
    
    print(f"Parsed strategy: {config.dpi_desync}")
    print(f"Split position: {config.split_pos}")
    print(f"Split overlap: {config.split_seqovl}")
    print(f"TTL: {config.ttl}")
    print(f"Fooling methods: {config.fooling}")
    print(f"Is fake+disorder: {config.is_fake_disorder_strategy()}")
    print()


def demo_strategy_detection_from_pcap():
    """Demonstrate strategy detection from PCAP packet sequence."""
    print("=== Demo: Strategy Detection from PCAP ===")
    
    analyzer = StrategyAnalyzer()
    
    # Create mock packet sequence representing fake+disorder strategy
    packets = [
        # Fake packet with low TTL and bad checksum
        PacketInfo(
            timestamp=1000.0,
            src_ip="192.168.1.100",
            dst_ip="104.244.42.1",  # x.com
            src_port=12345,
            dst_port=443,
            sequence_num=1000,
            ack_num=0,
            ttl=3,  # Low TTL indicates fake
            flags=['PSH', 'ACK'],
            payload_length=0,
            checksum_valid=False  # Bad checksum
        ),
        
        # First real segment (split at position 3)
        PacketInfo(
            timestamp=1000.001,
            src_ip="192.168.1.100", 
            dst_ip="104.244.42.1",
            src_port=12345,
            dst_port=443,
            sequence_num=1000,
            ack_num=0,
            ttl=64,  # Normal TTL
            flags=['PSH', 'ACK'],
            payload_length=3,
            payload=b'\x16\x03\x01',  # TLS handshake start
            checksum_valid=True,
            is_client_hello=True
        ),
        
        # Second real segment (with overlap)
        PacketInfo(
            timestamp=1000.002,
            src_ip="192.168.1.100",
            dst_ip="104.244.42.1", 
            src_port=12345,
            dst_port=443,
            sequence_num=1002,  # 1000 + 3 - 1 (overlap of 1)
            ack_num=0,
            ttl=64,
            flags=['PSH', 'ACK'],
            payload_length=200,
            payload=b'\x01' + b'\x00' * 199,
            checksum_valid=True
        )
    ]
    
    # Parse strategy from packets
    detected_config = analyzer.parse_strategy_from_pcap(packets, "x.com")
    
    print(f"Detected strategy: {detected_config.dpi_desync}")
    print(f"Split position: {detected_config.split_pos}")
    print(f"Split overlap: {detected_config.split_seqovl}")
    print(f"TTL: {detected_config.ttl}")
    print(f"Fooling methods: {detected_config.fooling}")
    print(f"Confidence: {detected_config.confidence:.2f}")
    print()


def demo_strategy_comparison():
    """Demonstrate strategy comparison between recon and zapret."""
    print("=== Demo: Strategy Comparison ===")
    
    analyzer = StrategyAnalyzer()
    
    # Zapret strategy (working)
    zapret_config = StrategyConfig(
        dpi_desync="fake,fakeddisorder",
        split_pos=3,
        split_seqovl=1,
        ttl=3,
        fooling=['badsum', 'badseq'],
        source="zapret"
    )
    
    # Recon strategy (with issues)
    recon_config = StrategyConfig(
        dpi_desync="fake,fakeddisorder",
        split_pos=5,  # Wrong split position
        split_seqovl=0,  # Wrong overlap
        ttl=64,  # Wrong TTL
        fooling=['badsum'],  # Missing badseq
        source="recon"
    )
    
    # Compare strategies
    comparison = analyzer.compare_strategies(recon_config, zapret_config)
    
    print(f"Similarity score: {comparison.similarity_score:.2f}")
    print(f"Compatible: {comparison.is_compatible}")
    print(f"Total differences: {len(comparison.differences)}")
    print(f"Critical differences: {len(comparison.get_critical_differences())}")
    
    print("\nDifferences found:")
    for diff in comparison.differences:
        print(f"- {diff.parameter}: {diff.recon_value} -> {diff.zapret_value} ({diff.impact_level})")
        print(f"  Description: {diff.description}")
        print(f"  Fix: {diff.fix_suggestion}")
        print()


def demo_parameter_validation():
    """Demonstrate strategy parameter validation."""
    print("=== Demo: Parameter Validation ===")
    
    analyzer = StrategyAnalyzer()
    
    # Valid configuration
    valid_config = StrategyConfig(
        dpi_desync="fake,fakeddisorder",
        split_pos=3,
        ttl=3,
        fooling=['badsum', 'badseq']
    )
    
    validation = analyzer.validate_strategy_parameters(valid_config)
    print(f"Valid config validation: {validation['valid']}")
    print(f"Warnings: {len(validation['warnings'])}")
    print(f"Errors: {len(validation['errors'])}")
    
    # Invalid configuration
    invalid_config = StrategyConfig(
        dpi_desync="fakeddisorder",  # Missing split_pos
        ttl=300,  # Invalid TTL
        split_pos=-1  # Invalid split position
    )
    
    validation = analyzer.validate_strategy_parameters(invalid_config)
    print(f"\nInvalid config validation: {validation['valid']}")
    print(f"Warnings: {validation['warnings']}")
    print(f"Errors: {validation['errors']}")
    print()


def demo_fix_generation():
    """Demonstrate generating fixes from strategy differences."""
    print("=== Demo: Fix Generation ===")
    
    analyzer = StrategyAnalyzer()
    
    # Create comparison with differences
    zapret_config = StrategyConfig(
        dpi_desync="fake,fakeddisorder",
        split_pos=3,
        ttl=3,
        fooling=['badsum', 'badseq']
    )
    
    recon_config = StrategyConfig(
        dpi_desync="fake,fakeddisorder", 
        split_pos=5,
        ttl=64,
        fooling=['badsum']
    )
    
    comparison = analyzer.compare_strategies(recon_config, zapret_config)
    
    print("Generated fixes:")
    for diff in comparison.get_high_priority_differences():
        print(f"Fix {diff.parameter}:")
        print(f"  Current: {diff.recon_value}")
        print(f"  Should be: {diff.zapret_value}")
        print(f"  Impact: {diff.impact_level}")
        print(f"  Code fix: {diff.parameter} = {diff.zapret_value}")
        print()


def main():
    """Run all demonstrations."""
    print("StrategyAnalyzer Task 2 Implementation Demo")
    print("=" * 50)
    print()
    
    demo_zapret_parameter_parsing()
    demo_strategy_detection_from_pcap()
    demo_strategy_comparison()
    demo_parameter_validation()
    demo_fix_generation()
    
    print("=" * 50)
    print("Task 2 Implementation Complete!")
    print()
    print("Key features implemented:")
    print("✓ StrategyConfig data model for structured strategy representation")
    print("✓ StrategyAnalyzer class to parse strategy parameters from PCAP patterns")
    print("✓ Detection of fakeddisorder strategy parameters (split_pos, split_seqovl, TTL, fooling methods)")
    print("✓ Strategy comparison logic to identify parameter differences between recon and zapret")
    print("✓ Parameter validation and fix generation")
    print("✓ Integration with existing PCAP analysis infrastructure")


if __name__ == "__main__":
    main()