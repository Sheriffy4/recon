"""
Property-based tests for TTL preservation in strategy application.

This module tests Requirements 1.1, 1.2, 1.3, 1.4 from the strategy-application-bugs spec:
- TTL values are correctly applied to fake packets
- TTL values are preserved through the entire chain
- TTL values are identical in TEST and BYPASS modes

Uses Hypothesis for property-based testing with minimum 100 iterations.
"""

import pytest
from hypothesis import given, settings, strategies as st
from typing import Dict, Any
from core.bypass.unified_attack_dispatcher import UnifiedAttackDispatcher
from core.bypass.attacks.base import AttackContext


# Test data generators
@st.composite
def ttl_value(draw):
    """Generate valid TTL values (1-255)."""
    return draw(st.integers(min_value=1, max_value=255))


@st.composite
def fake_params(draw):
    """Generate parameters for fake attack with TTL."""
    ttl = draw(ttl_value())
    fooling = draw(st.sampled_from(['badsum', 'badseq', 'md5sig']))
    return {
        'ttl': ttl,
        'fooling': fooling,
        'fake_sni': True
    }


@st.composite
def tls_payload(draw):
    """Generate test TLS ClientHello payload."""
    # Minimal TLS ClientHello structure
    return draw(st.binary(min_size=50, max_size=500))


class TestTTLPreservation:
    """Test suite for TTL preservation properties."""
    
    @given(ttl=ttl_value(), payload=tls_payload())
    @settings(max_examples=100, deadline=None)
    def test_property_1_ttl_configuration_preservation(self, ttl, payload):
        """
        **Feature: strategy-application-bugs, Property 1: TTL Configuration Preservation**
        
        For any strategy configuration with a specified TTL value, when fake packets 
        are generated, the IP TTL field in all fake packets should equal the 
        configured TTL value.
        
        **Validates: Requirements 1.1, 1.2, 1.3**
        """
        # Arrange
        dispatcher = UnifiedAttackDispatcher()
        params = {
            'ttl': ttl,
            'fooling': 'badsum',
            'fake_sni': True
        }
        packet_info = {
            'src_addr': '192.168.1.1',
            'dst_addr': '8.8.8.8',
            'src_port': 12345,
            'dst_port': 443,
            'domain': 'test.com'
        }
        
        # Act
        segments = dispatcher.apply_fake(payload, params, packet_info)
        
        # Assert
        assert len(segments) > 0, "Should generate at least one segment"
        
        for segment_data, offset, options in segments:
            if options.get('is_fake', False):
                # Verify TTL in segment options matches configured value
                assert options['ttl'] == ttl, (
                    f"TTL in segment options should be {ttl}, got {options['ttl']}"
                )
    
    @given(ttl=ttl_value(), payload=tls_payload())
    @settings(max_examples=100, deadline=None)
    def test_property_1_ttl_with_fake_ttl_alias(self, ttl, payload):
        """
        Test TTL preservation when using fake_ttl alias.
        
        **Validates: Requirements 1.1, 1.2**
        """
        # Arrange
        dispatcher = UnifiedAttackDispatcher()
        params = {
            'fake_ttl': ttl,  # Use alias instead of ttl
            'fooling': 'badsum',
            'fake_sni': True
        }
        packet_info = {
            'src_addr': '192.168.1.1',
            'dst_addr': '8.8.8.8',
            'src_port': 12345,
            'dst_port': 443,
            'domain': 'test.com'
        }
        
        # Act
        segments = dispatcher.apply_fake(payload, params, packet_info)
        
        # Assert
        assert len(segments) > 0, "Should generate at least one segment"
        
        for segment_data, offset, options in segments:
            if options.get('is_fake', False):
                # Verify TTL in segment options matches configured value
                assert options['ttl'] == ttl, (
                    f"TTL from fake_ttl alias should be {ttl}, got {options['ttl']}"
                )
    
    @given(payload=tls_payload())
    @settings(max_examples=100, deadline=None)
    def test_property_1_ttl_required_for_fake(self, payload):
        """
        Test that TTL is required for fake packets (no default fallback).
        
        **Validates: Requirements 1.1, 1.2**
        """
        # Arrange
        dispatcher = UnifiedAttackDispatcher()
        params = {
            # No TTL specified
            'fooling': 'badsum',
            'fake_sni': True
        }
        packet_info = {
            'src_addr': '192.168.1.1',
            'dst_addr': '8.8.8.8',
            'src_port': 12345,
            'dst_port': 443,
            'domain': 'test.com'
        }
        
        # Act & Assert
        with pytest.raises(ValueError, match="TTL is required for fake packets"):
            dispatcher.apply_fake(payload, params, packet_info)
    
    @given(ttl=ttl_value(), payload=tls_payload(), split_count=st.integers(min_value=2, max_value=6))
    @settings(max_examples=100, deadline=None)
    def test_property_1_ttl_per_fragment_preservation(self, ttl, payload, split_count):
        """
        Test TTL preservation in per-fragment fake mode.
        
        For any strategy with fake_mode="per_fragment", all fake packets should 
        have the same configured TTL value.
        
        **Validates: Requirements 1.1, 1.3, 5.4**
        """
        # Arrange
        dispatcher = UnifiedAttackDispatcher()
        
        # First split the payload
        split_params = {'split_count': split_count}
        fragments = dispatcher.apply_split(payload, split_params, {})
        
        # Then apply fake per fragment
        fake_params = {
            'ttl': ttl,
            'fooling': 'badsum',
            'fake_mode': 'per_fragment'
        }
        packet_info = {
            'src_addr': '192.168.1.1',
            'dst_addr': '8.8.8.8',
            'src_port': 12345,
            'dst_port': 443,
            'domain': 'test.com'
        }
        
        # Act
        segments = dispatcher.apply_fake_to_fragments(fragments, fake_params, packet_info)
        
        # Assert
        fake_segments = [s for s in segments if s[2].get('is_fake', False)]
        assert len(fake_segments) > 0, "Should generate fake segments"
        
        for segment_data, offset, options in fake_segments:
            assert options['ttl'] == ttl, (
                f"All fake packets should have TTL={ttl}, got {options['ttl']}"
            )


class TestTTLModeParity:
    """Test suite for TTL mode parity (TEST vs BYPASS)."""
    
    @given(ttl=ttl_value(), payload=tls_payload())
    @settings(max_examples=100, deadline=None)
    def test_property_2_ttl_mode_parity(self, ttl, payload):
        """
        **Feature: strategy-application-bugs, Property 2: TTL Mode Parity**
        
        For any strategy configuration, when fake packets are generated in TEST mode 
        and BYPASS mode, the TTL values in both modes should be identical.
        
        **Validates: Requirements 1.4**
        """
        # Arrange
        dispatcher = UnifiedAttackDispatcher()
        params = {
            'ttl': ttl,
            'fooling': 'badsum',
            'fake_sni': True
        }
        
        # Test mode packet info
        test_packet_info = {
            'src_addr': '192.168.1.1',
            'dst_addr': '8.8.8.8',
            'src_port': 12345,
            'dst_port': 443,
            'domain': 'test.com',
            'mode': 'TEST'
        }
        
        # Bypass mode packet info
        bypass_packet_info = {
            'src_addr': '192.168.1.1',
            'dst_addr': '8.8.8.8',
            'src_port': 12345,
            'dst_port': 443,
            'domain': 'test.com',
            'mode': 'BYPASS'
        }
        
        # Act
        test_segments = dispatcher.apply_fake(payload, params, test_packet_info)
        bypass_segments = dispatcher.apply_fake(payload, params, bypass_packet_info)
        
        # Assert
        assert len(test_segments) > 0, "TEST mode should generate segments"
        assert len(bypass_segments) > 0, "BYPASS mode should generate segments"
        
        # Extract TTL from fake segments
        test_ttls = [s[2]['ttl'] for s in test_segments if s[2].get('is_fake', False)]
        bypass_ttls = [s[2]['ttl'] for s in bypass_segments if s[2].get('is_fake', False)]
        
        assert len(test_ttls) > 0, "TEST mode should have fake segments"
        assert len(bypass_ttls) > 0, "BYPASS mode should have fake segments"
        
        # Verify TTL is identical in both modes
        assert test_ttls[0] == bypass_ttls[0] == ttl, (
            f"TTL should be {ttl} in both modes, "
            f"got TEST={test_ttls[0]}, BYPASS={bypass_ttls[0]}"
        )
    
    @given(ttl=ttl_value(), payload=tls_payload(), split_count=st.integers(min_value=2, max_value=6))
    @settings(max_examples=100, deadline=None)
    def test_property_2_ttl_mode_parity_multisplit(self, ttl, payload, split_count):
        """
        Test TTL mode parity with multisplit + fake combination.
        
        **Validates: Requirements 1.4**
        """
        # Arrange
        dispatcher = UnifiedAttackDispatcher()
        
        # Split params
        split_params = {'split_count': split_count}
        
        # Fake params
        fake_params = {
            'ttl': ttl,
            'fooling': 'badsum',
            'fake_mode': 'per_fragment'
        }
        
        # Test mode
        test_packet_info = {'mode': 'TEST', 'domain': 'test.com'}
        test_fragments = dispatcher.apply_split(payload, split_params, test_packet_info)
        test_segments = dispatcher.apply_fake_to_fragments(
            test_fragments, fake_params, test_packet_info
        )
        
        # Bypass mode
        bypass_packet_info = {'mode': 'BYPASS', 'domain': 'test.com'}
        bypass_fragments = dispatcher.apply_split(payload, split_params, bypass_packet_info)
        bypass_segments = dispatcher.apply_fake_to_fragments(
            bypass_fragments, fake_params, bypass_packet_info
        )
        
        # Assert
        test_fake_ttls = [s[2]['ttl'] for s in test_segments if s[2].get('is_fake', False)]
        bypass_fake_ttls = [s[2]['ttl'] for s in bypass_segments if s[2].get('is_fake', False)]
        
        assert len(test_fake_ttls) > 0, "TEST mode should have fake segments"
        assert len(bypass_fake_ttls) > 0, "BYPASS mode should have fake segments"
        
        # All TTLs should be identical
        assert all(t == ttl for t in test_fake_ttls), (
            f"All TEST fake TTLs should be {ttl}, got {test_fake_ttls}"
        )
        assert all(t == ttl for t in bypass_fake_ttls), (
            f"All BYPASS fake TTLs should be {ttl}, got {bypass_fake_ttls}"
        )
        assert test_fake_ttls == bypass_fake_ttls, (
            f"TEST and BYPASS TTLs should be identical: "
            f"TEST={test_fake_ttls}, BYPASS={bypass_fake_ttls}"
        )


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
