"""
Property-based tests for split_count parameter.

These tests verify correctness properties for multisplit functionality.

Requirements: 3.1, 3.2, 3.3, 3.4, 3.5
"""

import pytest
from hypothesis import given, strategies as st, settings, assume

from core.bypass.unified_attack_dispatcher import UnifiedAttackDispatcher


class TestSplitCountProperties:
    """Property-based tests for split_count parameter."""
    
    @given(
        payload=st.binary(min_size=10, max_size=1000),
        split_count=st.integers(min_value=2, max_value=20)
    )
    @settings(max_examples=100, deadline=None)
    def test_property_7_split_count_fragment_generation(self, payload, split_count):
        """
        **Feature: strategy-application-bugs, Property 7: Split Count Fragment Generation**
        **Validates: Requirements 3.1**
        
        Property: For any payload and split_count value N, when the payload is split
        with split_count=N, the number of generated fragments should equal N.
        
        This test verifies that:
        1. split_count parameter is respected
        2. Exactly N fragments are created
        3. All fragments are non-empty
        """
        # Ensure split_count doesn't exceed payload length
        assume(split_count <= len(payload))
        
        dispatcher = UnifiedAttackDispatcher()
        params = {
            'split_count': split_count
        }
        packet_info = {
            'src_addr': '127.0.0.1',
            'dst_addr': '127.0.0.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments = dispatcher.apply_split(payload, params, packet_info)
        
        # Verify we got exactly split_count fragments (Requirement 3.1)
        assert len(segments) == split_count, \
            f"Should get {split_count} fragments, got {len(segments)}"
        
        # Verify all fragments are non-empty
        for i, segment in enumerate(segments):
            assert len(segment[0]) > 0, \
                f"Fragment {i} should be non-empty"
    
    @given(
        payload=st.binary(min_size=10, max_size=1000),
        split_count=st.integers(min_value=2, max_value=20)
    )
    @settings(max_examples=100, deadline=None)
    def test_property_8_split_count_byte_coverage(self, payload, split_count):
        """
        **Feature: strategy-application-bugs, Property 8: Split Count Byte Coverage**
        **Validates: Requirements 3.4**
        
        Property: For any payload of length L and split_count value N, when the payload
        is split, the sum of all fragment lengths should equal L (no bytes lost or duplicated).
        
        This test verifies that:
        1. All bytes from original payload are present in fragments
        2. No bytes are duplicated
        3. Fragments can be reassembled to original payload
        """
        # Ensure split_count doesn't exceed payload length
        assume(split_count <= len(payload))
        
        dispatcher = UnifiedAttackDispatcher()
        params = {
            'split_count': split_count
        }
        packet_info = {
            'src_addr': '127.0.0.1',
            'dst_addr': '127.0.0.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments = dispatcher.apply_split(payload, params, packet_info)
        
        # Calculate total length of all fragments
        total_length = sum(len(seg[0]) for seg in segments)
        
        # Verify total length equals original payload length (Requirement 3.4)
        assert total_length == len(payload), \
            f"Total fragment length {total_length} should equal payload length {len(payload)}"
        
        # Verify fragments can be reassembled to original payload
        reconstructed = b''.join(seg[0] for seg in segments)
        assert reconstructed == payload, \
            "Fragments should reconstruct to original payload"
    
    @given(
        split_count=st.integers(min_value=2, max_value=20),
        base_size=st.integers(min_value=10, max_value=50)
    )
    @settings(max_examples=100, deadline=None)
    def test_property_9_equal_fragment_sizing(self, split_count, base_size):
        """
        **Feature: strategy-application-bugs, Property 9: Equal Fragment Sizing**
        **Validates: Requirements 3.3**
        
        Property: For any payload evenly divisible by split_count N, when the payload
        is split, all fragments should have equal or nearly equal sizes (difference ≤ 1 byte).
        
        This test verifies that:
        1. When payload is evenly divisible, all fragments have equal size
        2. When payload has remainder, fragments differ by at most 1 byte
        3. Fragment sizes are distributed fairly
        """
        # Create payload evenly divisible by split_count
        payload_size = base_size * split_count
        payload = b'X' * payload_size
        
        dispatcher = UnifiedAttackDispatcher()
        params = {
            'split_count': split_count
        }
        packet_info = {
            'src_addr': '127.0.0.1',
            'dst_addr': '127.0.0.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments = dispatcher.apply_split(payload, params, packet_info)
        
        # Get fragment sizes
        fragment_sizes = [len(seg[0]) for seg in segments]
        
        # For evenly divisible payload, all fragments should have equal size (Requirement 3.3)
        min_size = min(fragment_sizes)
        max_size = max(fragment_sizes)
        
        assert max_size - min_size == 0, \
            f"For evenly divisible payload, all fragments should have equal size. " \
            f"Got sizes: {fragment_sizes}, min={min_size}, max={max_size}"
        
        # Verify all fragments have the expected size
        expected_size = base_size
        for i, size in enumerate(fragment_sizes):
            assert size == expected_size, \
                f"Fragment {i} should have size {expected_size}, got {size}"
    
    @given(
        split_count=st.integers(min_value=2, max_value=20),
        base_size=st.integers(min_value=10, max_value=50),
        remainder=st.integers(min_value=1, max_value=19)
    )
    @settings(max_examples=100, deadline=None)
    def test_property_9_nearly_equal_sizing_with_remainder(self, split_count, base_size, remainder):
        """
        Test equal fragment sizing with remainder bytes.
        
        This extends Property 9 to test the case where payload is not evenly divisible.
        """
        # Ensure remainder is less than split_count
        assume(remainder < split_count)
        
        # Create payload with remainder
        payload_size = base_size * split_count + remainder
        payload = b'X' * payload_size
        
        dispatcher = UnifiedAttackDispatcher()
        params = {
            'split_count': split_count
        }
        packet_info = {
            'src_addr': '127.0.0.1',
            'dst_addr': '127.0.0.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments = dispatcher.apply_split(payload, params, packet_info)
        
        # Get fragment sizes
        fragment_sizes = [len(seg[0]) for seg in segments]
        
        # With remainder, fragments should differ by at most 1 byte (Requirement 3.3)
        min_size = min(fragment_sizes)
        max_size = max(fragment_sizes)
        
        assert max_size - min_size <= 1, \
            f"Fragments should differ by at most 1 byte. " \
            f"Got sizes: {fragment_sizes}, min={min_size}, max={max_size}"
        
        # Verify the first 'remainder' fragments get the extra byte
        # (this is the implementation strategy)
        for i in range(remainder):
            assert fragment_sizes[i] == base_size + 1, \
                f"Fragment {i} should have size {base_size + 1} (gets extra byte), got {fragment_sizes[i]}"
        
        for i in range(remainder, split_count):
            assert fragment_sizes[i] == base_size, \
                f"Fragment {i} should have size {base_size}, got {fragment_sizes[i]}"
    
    @given(
        payload=st.binary(min_size=10, max_size=1000),
        split_pos=st.integers(min_value=2, max_value=50),
        split_count=st.integers(min_value=2, max_value=20)
    )
    @settings(max_examples=100, deadline=None)
    def test_split_count_overrides_split_pos(self, payload, split_pos, split_count):
        """
        Test that split_count takes priority over split_pos when both are specified.
        
        This verifies Requirement 3.2: prioritize split_count over split_pos.
        """
        # Ensure parameters are within bounds
        assume(split_pos < len(payload) - 1)
        assume(split_count <= len(payload))
        
        dispatcher = UnifiedAttackDispatcher()
        params = {
            'split_pos': split_pos,
            'split_count': split_count
        }
        packet_info = {
            'src_addr': '127.0.0.1',
            'dst_addr': '127.0.0.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments = dispatcher.apply_split(payload, params, packet_info)
        
        # Verify split_count was used (not split_pos) (Requirement 3.2)
        assert len(segments) == split_count, \
            f"When both split_pos and split_count are specified, " \
            f"split_count should be used. Expected {split_count} fragments, got {len(segments)}"
        
        # Verify fragments reconstruct to original
        reconstructed = b''.join(seg[0] for seg in segments)
        assert reconstructed == payload, \
            "Fragments should reconstruct to original payload"
    
    @given(
        payload=st.binary(min_size=10, max_size=100)
    )
    @settings(max_examples=100, deadline=None)
    def test_split_count_validation_too_small(self, payload):
        """
        Test that split_count < 2 is rejected and falls back to 2.
        
        This verifies Requirement 3.1: split_count must be >= 2.
        """
        dispatcher = UnifiedAttackDispatcher()
        params = {
            'split_count': 1  # Invalid: too small
        }
        packet_info = {
            'src_addr': '127.0.0.1',
            'dst_addr': '127.0.0.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments = dispatcher.apply_split(payload, params, packet_info)
        
        # Should fall back to split_count=2
        assert len(segments) == 2, \
            f"Invalid split_count=1 should fall back to 2, got {len(segments)} fragments"
    
    @given(
        payload=st.binary(min_size=10, max_size=100)
    )
    @settings(max_examples=100, deadline=None)
    def test_split_count_validation_too_large(self, payload):
        """
        Test that split_count > len(payload) is capped to len(payload).
        
        This verifies Requirement 3.1: split_count must be <= len(payload).
        """
        dispatcher = UnifiedAttackDispatcher()
        
        # Try to split into more fragments than bytes
        invalid_split_count = len(payload) + 10
        
        params = {
            'split_count': invalid_split_count
        }
        packet_info = {
            'src_addr': '127.0.0.1',
            'dst_addr': '127.0.0.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments = dispatcher.apply_split(payload, params, packet_info)
        
        # Should be capped to len(payload)
        assert len(segments) == len(payload), \
            f"split_count={invalid_split_count} > payload length {len(payload)} " \
            f"should be capped to {len(payload)}, got {len(segments)} fragments"
