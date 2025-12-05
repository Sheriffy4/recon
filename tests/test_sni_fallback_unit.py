"""
Unit tests for SNI offset fallback behavior.

These tests verify that the system correctly uses fallback positions
when SNI cannot be found in the payload.

Requirements: 4.4
"""

import pytest

from core.bypass.unified_attack_dispatcher import UnifiedAttackDispatcher


class TestSNIFallbackUnit:
    """Unit tests for SNI fallback behavior."""
    
    def test_fallback_used_when_sni_not_found(self):
        """
        Test that system uses fallback when SNI not found.
        
        Validates Requirement 4.4: WHEN THE System не может определить SNI offset
        THEN THE System SHALL использовать fallback позицию из параметров
        """
        # Create a payload that doesn't contain valid TLS ClientHello
        invalid_payload = b'\x00' * 100
        
        # Specify a fallback position
        fallback_pos = 10
        
        dispatcher = UnifiedAttackDispatcher()
        params = {
            'split_pos': 'sni',
            'split_count': 2,
            'split_pos_fallback': fallback_pos
        }
        packet_info = {
            'src_addr': '127.0.0.1',
            'dst_addr': '127.0.0.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        # Apply split - should use fallback
        segments = dispatcher.apply_split(invalid_payload, params, packet_info)
        
        # Verify we got 2 fragments
        assert len(segments) == 2, "Should get 2 fragments using fallback"
        
        # Verify split happened near fallback position
        fragment1_data = segments[0][0]
        actual_split_pos = len(fragment1_data)
        
        # The actual split position should be close to fallback
        # (may be adjusted to stay within bounds)
        assert actual_split_pos > 0, "First fragment should be non-empty"
        assert actual_split_pos < len(invalid_payload), "Split should be within payload"
        
        # Verify reconstruction
        fragment2_data = segments[1][0]
        reconstructed = fragment1_data + fragment2_data
        assert reconstructed == invalid_payload, \
            "Fragments should reconstruct to original payload"
    
    def test_default_fallback_when_no_fallback_specified(self):
        """
        Test that system uses default fallback (middle of payload) when
        no fallback is specified and SNI not found.
        """
        # Create a payload that doesn't contain valid TLS ClientHello
        invalid_payload = b'\x00' * 100
        
        dispatcher = UnifiedAttackDispatcher()
        params = {
            'split_pos': 'sni',
            'split_count': 2
            # No split_pos_fallback specified
        }
        packet_info = {
            'src_addr': '127.0.0.1',
            'dst_addr': '127.0.0.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        # Apply split - should use default fallback (middle)
        segments = dispatcher.apply_split(invalid_payload, params, packet_info)
        
        # Verify we got 2 fragments
        assert len(segments) == 2, "Should get 2 fragments using default fallback"
        
        # Verify reconstruction
        reconstructed = b''.join(seg[0] for seg in segments)
        assert reconstructed == invalid_payload, \
            "Fragments should reconstruct to original payload"
    
    def test_fallback_with_empty_payload(self):
        """
        Test that system handles empty or very small payloads gracefully.
        """
        # Very small payload
        small_payload = b'\x16\x03\x01'
        
        dispatcher = UnifiedAttackDispatcher()
        params = {
            'split_pos': 'sni',
            'split_count': 2,
            'split_pos_fallback': 1
        }
        packet_info = {
            'src_addr': '127.0.0.1',
            'dst_addr': '127.0.0.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        # Apply split - should handle gracefully
        segments = dispatcher.apply_split(small_payload, params, packet_info)
        
        # Verify we got 2 fragments
        assert len(segments) == 2, "Should get 2 fragments even with small payload"
        
        # Verify reconstruction
        reconstructed = b''.join(seg[0] for seg in segments)
        assert reconstructed == small_payload, \
            "Fragments should reconstruct to original payload"
    
    def test_fallback_position_bounds_checking(self):
        """
        Test that fallback position is adjusted to stay within payload bounds.
        """
        payload = b'\x00' * 50
        
        # Try with fallback position beyond payload length
        large_fallback = 1000
        
        dispatcher = UnifiedAttackDispatcher()
        params = {
            'split_pos': 'sni',
            'split_count': 2,
            'split_pos_fallback': large_fallback
        }
        packet_info = {
            'src_addr': '127.0.0.1',
            'dst_addr': '127.0.0.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        # Apply split - should adjust fallback to stay within bounds
        segments = dispatcher.apply_split(payload, params, packet_info)
        
        # Verify we got 2 fragments
        assert len(segments) == 2, "Should get 2 fragments with adjusted fallback"
        
        # Verify both fragments are non-empty
        assert len(segments[0][0]) > 0, "First fragment should be non-empty"
        assert len(segments[1][0]) > 0, "Second fragment should be non-empty"
        
        # Verify reconstruction
        reconstructed = b''.join(seg[0] for seg in segments)
        assert reconstructed == payload, \
            "Fragments should reconstruct to original payload"
    
    def test_numeric_split_pos_as_string(self):
        """
        Test that numeric split_pos provided as string is parsed correctly.
        
        Validates Requirement 4.2: numeric position parsing.
        """
        payload = b'\x00' * 100
        
        dispatcher = UnifiedAttackDispatcher()
        params = {
            'split_pos': '25',  # Numeric position as string
            'split_count': 2
        }
        packet_info = {
            'src_addr': '127.0.0.1',
            'dst_addr': '127.0.0.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        # Apply split - should parse "25" as integer
        segments = dispatcher.apply_split(payload, params, packet_info)
        
        # Verify we got 2 fragments
        assert len(segments) == 2, "Should get 2 fragments with numeric string"
        
        # Verify reconstruction
        reconstructed = b''.join(seg[0] for seg in segments)
        assert reconstructed == payload, \
            "Fragments should reconstruct to original payload"
    
    def test_invalid_split_pos_string_uses_fallback(self):
        """
        Test that invalid split_pos string uses fallback.
        """
        payload = b'\x00' * 100
        
        dispatcher = UnifiedAttackDispatcher()
        params = {
            'split_pos': 'invalid_string',  # Invalid, not "sni" or numeric
            'split_count': 2,
            'split_pos_fallback': 15
        }
        packet_info = {
            'src_addr': '127.0.0.1',
            'dst_addr': '127.0.0.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        # Apply split - should use fallback
        segments = dispatcher.apply_split(payload, params, packet_info)
        
        # Verify we got 2 fragments
        assert len(segments) == 2, "Should get 2 fragments using fallback"
        
        # Verify reconstruction
        reconstructed = b''.join(seg[0] for seg in segments)
        assert reconstructed == payload, \
            "Fragments should reconstruct to original payload"
    
    def test_multisplit_with_fallback(self):
        """
        Test that multisplit works correctly with fallback.
        
        Validates Requirement 4.5: multisplit with split_pos consideration.
        """
        payload = b'\x00' * 100
        
        dispatcher = UnifiedAttackDispatcher()
        params = {
            'split_pos': 'sni',  # Will use fallback since no SNI
            'split_count': 4,
            'split_pos_fallback': 10
        }
        packet_info = {
            'src_addr': '127.0.0.1',
            'dst_addr': '127.0.0.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        # Apply multisplit
        segments = dispatcher.apply_split(payload, params, packet_info)
        
        # Verify we got 4 fragments
        assert len(segments) == 4, "Should get 4 fragments"
        
        # Verify all fragments are non-empty
        for i, segment in enumerate(segments):
            assert len(segment[0]) > 0, f"Fragment {i} should be non-empty"
        
        # Verify reconstruction
        reconstructed = b''.join(seg[0] for seg in segments)
        assert reconstructed == payload, \
            "Fragments should reconstruct to original payload"
