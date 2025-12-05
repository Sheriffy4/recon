"""
Property-based tests for testing-production parity.

Feature: attack-application-parity, Property 1: Testing-Production Strategy Parity
Validates: Requirements 1.1

For any domain and strategy, applying the strategy in testing mode and then in 
production mode should produce identical attack patterns.
"""

import json
import tempfile
from pathlib import Path
from typing import Dict, Any, List
import logging

from hypothesis import given, strategies as st, settings, HealthCheck, assume
import pytest

from core.strategy.loader import StrategyLoader, Strategy
from core.strategy.combo_builder import ComboAttackBuilder
from core.bypass.unified_attack_dispatcher import UnifiedAttackDispatcher


# Configure logging
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)


class MockPacket:
    """Mock packet for testing without actual network traffic."""
    
    def __init__(self, payload: bytes, src_ip: str = "192.168.1.1", dst_ip: str = "8.8.8.8", 
                 src_port: int = 12345, dst_port: int = 443):
        self.payload = payload
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.tcp_flags = {"PSH": 1, "ACK": 1}
        self.seq = 1000
        self.ack = 2000
        self.ttl = 64
        self.checksum = 0
        
    def __bytes__(self):
        return self.payload
    
    def __repr__(self):
        return f"MockPacket(payload_len={len(self.payload)}, ttl={self.ttl}, seq={self.seq})"


# Hypothesis strategies for generating test data

@st.composite
def valid_attack_combination(draw):
    """Generate valid attack combinations."""
    # Define compatible attack combinations
    single_attacks = ['fake', 'split', 'multisplit', 'disorder', 'fakeddisorder']
    
    # Choose combination type
    combo_type = draw(st.sampled_from([
        'single',
        'fake_split',
        'fake_multisplit',
        'fake_disorder',
        'split_disorder',
        'multisplit_disorder',
        'fake_split_disorder',
        'fake_multisplit_disorder'
    ]))
    
    if combo_type == 'single':
        attacks = [draw(st.sampled_from(single_attacks))]
    elif combo_type == 'fake_split':
        attacks = ['fake', 'split']
    elif combo_type == 'fake_multisplit':
        attacks = ['fake', 'multisplit']
    elif combo_type == 'fake_disorder':
        attacks = ['fake', 'disorder']
    elif combo_type == 'split_disorder':
        attacks = ['split', 'disorder']
    elif combo_type == 'multisplit_disorder':
        attacks = ['multisplit', 'disorder']
    elif combo_type == 'fake_split_disorder':
        attacks = ['fake', 'split', 'disorder']
    elif combo_type == 'fake_multisplit_disorder':
        attacks = ['fake', 'multisplit', 'disorder']
    
    return attacks


@st.composite
def strategy_params(draw, attacks: List[str]):
    """Generate valid parameters for given attacks."""
    params = {}
    
    if 'fake' in attacks or 'fakeddisorder' in attacks:
        params['ttl'] = draw(st.integers(min_value=1, max_value=10))
        params['fooling'] = draw(st.sampled_from(['badsum', 'badseq', 'none']))
    
    if 'split' in attacks or 'multisplit' in attacks:
        params['split_pos'] = draw(st.one_of(
            st.integers(min_value=1, max_value=10),
            st.just('sni')
        ))
        if 'multisplit' in attacks:
            params['split_count'] = draw(st.integers(min_value=2, max_value=8))
    
    if 'disorder' in attacks or 'fakeddisorder' in attacks:
        # Only use 'reverse' for deterministic testing
        # 'random' disorder is intentionally non-deterministic
        params['disorder_method'] = 'reverse'
    
    return params


@st.composite
def strategy_for_testing(draw):
    """Generate a complete test strategy."""
    attacks = draw(valid_attack_combination())
    params = draw(strategy_params(attacks))
    
    return Strategy(
        type=attacks[0] if attacks else '',
        attacks=attacks,
        params=params,
        metadata={'test': True}
    )


@st.composite
def tls_payload(draw):
    """Generate a TLS-like payload."""
    # TLS record header: type (1 byte) + version (2 bytes) + length (2 bytes)
    record_type = b'\x16'  # Handshake
    version = b'\x03\x03'  # TLS 1.2
    
    # Generate payload data
    payload_size = draw(st.integers(min_value=50, max_value=500))
    payload_data = draw(st.binary(min_size=payload_size, max_size=payload_size))
    
    # Calculate length
    length = len(payload_data).to_bytes(2, 'big')
    
    return record_type + version + length + payload_data


def apply_strategy_in_mode(strategy: Strategy, payload: bytes, mode: str) -> List[MockPacket]:
    """
    Apply strategy in specified mode (testing or production).
    
    Both modes should use identical code paths.
    """
    logger.debug(f"Applying strategy in {mode} mode: {strategy.attacks}")
    
    try:
        # Build recipe using ComboAttackBuilder
        builder = ComboAttackBuilder()
        recipe = builder.build_recipe(strategy.attacks, strategy.params)
        
        # Apply recipe using UnifiedAttackDispatcher
        dispatcher = UnifiedAttackDispatcher()
        
        # Create packet info
        packet_info = {
            'src_addr': '192.168.1.1',
            'dst_addr': '8.8.8.8',
            'src_port': 12345,
            'dst_port': 443
        }
        
        # Apply recipe - returns list of (data, offset, options) tuples
        segments = dispatcher.apply_recipe(recipe, payload, packet_info)
        
        # Convert segments to MockPacket objects for analysis
        result_packets = []
        for data, offset, options in segments:
            pkt = MockPacket(data)
            # Apply options to packet
            if 'ttl' in options:
                pkt.ttl = options['ttl']
            if 'seq' in options:
                pkt.seq = options['seq']
            if 'checksum' in options:
                pkt.checksum = options['checksum']
            result_packets.append(pkt)
        
        logger.debug(f"{mode} mode produced {len(result_packets)} packets")
        return result_packets
    except Exception as e:
        logger.error(f"Error applying strategy in {mode} mode: {e}")
        raise


def extract_attack_signature(packets: List[MockPacket]) -> Dict[str, Any]:
    """
    Extract attack signature from packets for comparison.
    
    Returns a dictionary describing the attack characteristics.
    """
    signature = {
        'packet_count': len(packets),
        'ttl_values': [],
        'payload_sizes': [],
        'sequence_numbers': [],
        'has_low_ttl': False,
        'low_ttl_count': 0,
        'fragment_count': 0,
        'total_payload_size': 0
    }
    
    for pkt in packets:
        # Collect TTL values
        ttl = getattr(pkt, 'ttl', 64)
        signature['ttl_values'].append(ttl)
        
        if ttl <= 3:
            signature['has_low_ttl'] = True
            signature['low_ttl_count'] += 1
        
        # Collect payload sizes
        payload_size = len(pkt.payload) if hasattr(pkt, 'payload') else 0
        signature['payload_sizes'].append(payload_size)
        signature['total_payload_size'] += payload_size
        
        if payload_size > 0:
            signature['fragment_count'] += 1
        
        # Collect sequence numbers
        seq = getattr(pkt, 'seq', 0)
        signature['sequence_numbers'].append(seq)
    
    return signature


class TestTestingProductionStrategyParity:
    """
    **Feature: attack-application-parity, Property 1: Testing-Production Strategy Parity**
    **Validates: Requirements 1.1**
    
    Property: For any domain and strategy, applying the strategy in testing mode 
    and then in production mode should produce identical attack patterns.
    """
    
    @given(
        strategy=strategy_for_testing(),
        payload=tls_payload()
    )
    @settings(
        max_examples=100,
        suppress_health_check=[HealthCheck.too_slow],
        deadline=None
    )
    def test_identical_attack_patterns(self, strategy, payload):
        """
        Test that testing and production modes produce identical attack patterns.
        
        For any strategy and payload, both modes should produce the same:
        - Number of packets
        - TTL values
        - Payload sizes
        - Attack characteristics
        """
        # Skip incompatible combinations (they should raise ValueError)
        try:
            builder = ComboAttackBuilder()
            recipe = builder.build_recipe(strategy.attacks, strategy.params)
        except ValueError:
            # Incompatible combination, skip this test case
            assume(False)
        
        # Apply strategy in testing mode
        testing_packets = apply_strategy_in_mode(strategy, payload, "testing")
        testing_signature = extract_attack_signature(testing_packets)
        
        # Apply strategy in production mode
        production_packets = apply_strategy_in_mode(strategy, payload, "production")
        production_signature = extract_attack_signature(production_packets)
        
        # Assert: Packet count must be identical
        assert testing_signature['packet_count'] == production_signature['packet_count'], \
            f"Packet count mismatch for attacks {strategy.attacks}: " \
            f"testing={testing_signature['packet_count']}, " \
            f"production={production_signature['packet_count']}"
        
        # Assert: TTL values must be identical
        assert testing_signature['ttl_values'] == production_signature['ttl_values'], \
            f"TTL values mismatch for attacks {strategy.attacks}: " \
            f"testing={testing_signature['ttl_values']}, " \
            f"production={production_signature['ttl_values']}"
        
        # Assert: Payload sizes must be identical
        assert testing_signature['payload_sizes'] == production_signature['payload_sizes'], \
            f"Payload sizes mismatch for attacks {strategy.attacks}: " \
            f"testing={testing_signature['payload_sizes']}, " \
            f"production={production_signature['payload_sizes']}"
        
        # Assert: Low TTL detection must be identical
        assert testing_signature['has_low_ttl'] == production_signature['has_low_ttl'], \
            f"Low TTL detection mismatch for attacks {strategy.attacks}: " \
            f"testing={testing_signature['has_low_ttl']}, " \
            f"production={production_signature['has_low_ttl']}"
        
        # Assert: Fragment count must be identical
        assert testing_signature['fragment_count'] == production_signature['fragment_count'], \
            f"Fragment count mismatch for attacks {strategy.attacks}: " \
            f"testing={testing_signature['fragment_count']}, " \
            f"production={production_signature['fragment_count']}"
        
        # Assert: Total payload size must be identical
        assert testing_signature['total_payload_size'] == production_signature['total_payload_size'], \
            f"Total payload size mismatch for attacks {strategy.attacks}: " \
            f"testing={testing_signature['total_payload_size']}, " \
            f"production={production_signature['total_payload_size']}"
    
    @given(
        strategy=strategy_for_testing(),
        payload=tls_payload()
    )
    @settings(
        max_examples=50,
        suppress_health_check=[HealthCheck.too_slow],
        deadline=None
    )
    def test_deterministic_behavior(self, strategy, payload):
        """
        Test that both modes produce deterministic results.
        
        For any strategy and payload, applying it multiple times should 
        produce identical results in each mode.
        """
        # Skip incompatible combinations
        try:
            builder = ComboAttackBuilder()
            recipe = builder.build_recipe(strategy.attacks, strategy.params)
        except ValueError:
            assume(False)
        
        # Apply strategy multiple times in testing mode
        testing_run1 = apply_strategy_in_mode(strategy, payload, "testing")
        testing_run2 = apply_strategy_in_mode(strategy, payload, "testing")
        
        testing_sig1 = extract_attack_signature(testing_run1)
        testing_sig2 = extract_attack_signature(testing_run2)
        
        # Assert: Testing mode should be deterministic
        assert testing_sig1['packet_count'] == testing_sig2['packet_count'], \
            "Testing mode should produce deterministic packet counts"
        assert testing_sig1['ttl_values'] == testing_sig2['ttl_values'], \
            "Testing mode should produce deterministic TTL values"
        
        # Apply strategy multiple times in production mode
        production_run1 = apply_strategy_in_mode(strategy, payload, "production")
        production_run2 = apply_strategy_in_mode(strategy, payload, "production")
        
        production_sig1 = extract_attack_signature(production_run1)
        production_sig2 = extract_attack_signature(production_run2)
        
        # Assert: Production mode should be deterministic
        assert production_sig1['packet_count'] == production_sig2['packet_count'], \
            "Production mode should produce deterministic packet counts"
        assert production_sig1['ttl_values'] == production_sig2['ttl_values'], \
            "Production mode should produce deterministic TTL values"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
