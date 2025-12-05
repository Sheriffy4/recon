"""
Property-based tests for PacketSegment dataclass.

These tests verify correctness properties for type-safe packet segment representation.

Requirements: 6.2, 6.3, 6.4
"""

import pytest
from hypothesis import given, strategies as st, settings

from core.bypass.engine.unified_attack_dispatcher import PacketSegment, AttackConstants


# ============================================================================
# Test Data Strategies
# ============================================================================

@st.composite
def packet_segment_strategy(draw):
    """Generate valid PacketSegment instances for testing."""
    data = draw(st.binary(min_size=1, max_size=1500))
    offset = draw(st.integers(min_value=0, max_value=65535))
    ttl = draw(st.integers(min_value=1, max_value=255))
    is_fake = draw(st.booleans())
    fooling = draw(st.sampled_from([None, 'badsum', 'badseq', 'md5sig']))
    tcp_flags = draw(st.sampled_from(['PA', 'P', 'A', 'S', 'F', 'R']))
    fragment_index = draw(st.integers(min_value=0, max_value=100))
    
    # Generate extra metadata
    extra_keys = draw(st.lists(
        st.text(alphabet=st.characters(whitelist_categories=('Lu', 'Ll')), min_size=1, max_size=10),
        min_size=0,
        max_size=5,
        unique=True
    ))
    extra = {key: draw(st.integers() | st.text() | st.booleans()) for key in extra_keys}
    
    return PacketSegment(
        data=data,
        offset=offset,
        ttl=ttl,
        is_fake=is_fake,
        fooling=fooling,
        tcp_flags=tcp_flags,
        fragment_index=fragment_index,
        extra=extra
    )


# ============================================================================
# Property Tests
# ============================================================================

class TestPacketSegmentProperties:
    """Property-based tests for PacketSegment dataclass."""
    
    @given(segment=packet_segment_strategy())
    @settings(max_examples=100, deadline=None)
    def test_property_17_packet_segment_round_trip(self, segment):
        """
        **Feature: unified-attack-dispatcher, Property 17: PacketSegment round-trip**
        **Validates: Requirements 6.2, 6.3**
        
        Property: For any PacketSegment, converting to tuple and back should
        preserve all fields.
        
        This test verifies that:
        1. to_tuple() creates valid legacy format
        2. from_tuple() reconstructs the segment
        3. All fields are preserved through the round-trip
        4. Extra metadata is preserved
        """
        # Convert to tuple
        tuple_format = segment.to_tuple()
        
        # Verify tuple structure
        assert isinstance(tuple_format, tuple), "to_tuple() should return a tuple"
        assert len(tuple_format) == 3, "Tuple should have 3 elements"
        
        data, offset, options = tuple_format
        assert isinstance(data, bytes), "First element should be bytes"
        assert isinstance(offset, int), "Second element should be int"
        assert isinstance(options, dict), "Third element should be dict"
        
        # Convert back to PacketSegment
        reconstructed = PacketSegment.from_tuple(tuple_format)
        
        # Verify all fields are preserved
        assert reconstructed.data == segment.data, "Data should be preserved"
        assert reconstructed.offset == segment.offset, "Offset should be preserved"
        assert reconstructed.ttl == segment.ttl, "TTL should be preserved"
        assert reconstructed.is_fake == segment.is_fake, "is_fake should be preserved"
        assert reconstructed.fooling == segment.fooling, "Fooling should be preserved"
        assert reconstructed.tcp_flags == segment.tcp_flags, "TCP flags should be preserved"
        assert reconstructed.fragment_index == segment.fragment_index, "Fragment index should be preserved"
        assert reconstructed.extra == segment.extra, "Extra metadata should be preserved"
    
    @given(segment=packet_segment_strategy())
    @settings(max_examples=100, deadline=None)
    def test_property_18_segment_size_accuracy(self, segment):
        """
        **Feature: unified-attack-dispatcher, Property 18: Segment size accuracy**
        **Validates: Requirements 6.4**
        
        Property: For any PacketSegment, the size property should equal len(data).
        
        This test verifies that:
        1. size property returns correct length
        2. size matches len(data) exactly
        3. size is always non-negative
        """
        # Get size from property
        size = segment.size
        
        # Verify size matches data length
        assert size == len(segment.data), \
            f"Size property ({size}) should equal len(data) ({len(segment.data)})"
        
        # Verify size is non-negative
        assert size >= 0, "Size should be non-negative"
        
        # Verify size is consistent across multiple calls
        assert segment.size == segment.size, "Size should be consistent"
    
    @given(
        data=st.binary(min_size=1, max_size=1500),
        offset=st.integers(min_value=0, max_value=65535)
    )
    @settings(max_examples=100, deadline=None)
    def test_minimal_packet_segment_creation(self, data, offset):
        """
        Test that PacketSegment can be created with minimal required fields.
        
        This verifies that default values work correctly.
        """
        segment = PacketSegment(data=data, offset=offset)
        
        # Verify required fields
        assert segment.data == data
        assert segment.offset == offset
        
        # Verify defaults
        assert segment.ttl == 64, "Default TTL should be 64"
        assert segment.is_fake == False, "Default is_fake should be False"
        assert segment.fooling is None, "Default fooling should be None"
        assert segment.tcp_flags == 'PA', "Default tcp_flags should be 'PA'"
        assert segment.fragment_index == 0, "Default fragment_index should be 0"
        assert segment.extra == {}, "Default extra should be empty dict"
    
    @given(
        data=st.binary(min_size=0, max_size=100),
        offset=st.integers(min_value=0, max_value=1000),
        ttl=st.integers(min_value=1, max_value=255)
    )
    @settings(max_examples=100, deadline=None)
    def test_to_tuple_contains_all_metadata(self, data, offset, ttl):
        """
        Test that to_tuple() includes all metadata in options dict.
        
        This verifies that no information is lost in conversion.
        """
        segment = PacketSegment(
            data=data,
            offset=offset,
            ttl=ttl,
            is_fake=True,
            fooling='badsum',
            tcp_flags='PA',
            fragment_index=5,
            extra={'custom_field': 'custom_value'}
        )
        
        data_out, offset_out, options = segment.to_tuple()
        
        # Verify data and offset
        assert data_out == data
        assert offset_out == offset
        
        # Verify all metadata is in options
        assert options['ttl'] == ttl
        assert options['is_fake'] == True
        assert options['fooling'] == 'badsum'
        assert options['tcp_flags'] == 'PA'
        assert options['fragment_index'] == 5
        assert options['custom_field'] == 'custom_value'
    
    @given(
        data=st.binary(min_size=1, max_size=100),
        offset=st.integers(min_value=0, max_value=1000)
    )
    @settings(max_examples=100, deadline=None)
    def test_from_tuple_handles_missing_fields(self, data, offset):
        """
        Test that from_tuple() handles tuples with minimal options.
        
        This verifies backward compatibility with legacy code.
        """
        # Create minimal tuple (only required fields)
        minimal_tuple = (data, offset, {})
        
        segment = PacketSegment.from_tuple(minimal_tuple)
        
        # Verify required fields
        assert segment.data == data
        assert segment.offset == offset
        
        # Verify defaults are applied
        assert segment.ttl == 64
        assert segment.is_fake == False
        assert segment.fooling is None
        assert segment.tcp_flags == 'PA'
        assert segment.fragment_index == 0
        assert segment.extra == {}
    
    def test_from_tuple_rejects_invalid_tuples(self):
        """
        Test that from_tuple() raises ValueError for invalid tuples.
        
        This verifies input validation.
        """
        # Test with wrong number of elements
        with pytest.raises(ValueError, match="Expected tuple of length 3"):
            PacketSegment.from_tuple((b'data', 0))
        
        with pytest.raises(ValueError, match="Expected tuple of length 3"):
            PacketSegment.from_tuple((b'data', 0, {}, 'extra'))
    
    @given(segment=packet_segment_strategy())
    @settings(max_examples=100, deadline=None)
    def test_segment_immutability_after_tuple_conversion(self, segment):
        """
        Test that converting to tuple doesn't modify the original segment.
        
        This verifies that to_tuple() is a pure function.
        """
        # Store original values
        original_data = segment.data
        original_offset = segment.offset
        original_ttl = segment.ttl
        original_extra = segment.extra.copy()
        
        # Convert to tuple
        _ = segment.to_tuple()
        
        # Verify segment is unchanged
        assert segment.data == original_data
        assert segment.offset == original_offset
        assert segment.ttl == original_ttl
        assert segment.extra == original_extra
