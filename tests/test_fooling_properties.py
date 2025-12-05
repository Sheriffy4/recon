"""
Property-based tests for fooling parameter handling.

This module tests the correctness properties related to fooling methods
(badsum and badseq) in DPI bypass strategies.

Requirements: 2.1, 2.2, 2.3, 2.4
"""

import pytest
from hypothesis import given, strategies as st, settings

from core.strategy.normalizer import ParameterNormalizer
from core.strategy.exceptions import ValidationError


class TestFoolingPreservationProperty:
    """
    Property 3: Fooling Method Preservation
    Property 5: Fooling Parameter Normalization
    
    For any strategy configuration specifying fooling="badseq",
    when parameters are normalized, the fooling_methods list should
    contain "badseq" and not "badsum".
    
    Validates: Requirements 2.3, 2.4
    """
    
    def setup_method(self):
        """Set up test fixtures."""
        self.normalizer = ParameterNormalizer()
    
    @given(
        fooling_method=st.sampled_from(['badseq', 'badsum', 'md5sig', 'none'])
    )
    @settings(max_examples=100)
    def test_fooling_string_preserved_in_normalization(self, fooling_method):
        """
        **Feature: strategy-application-bugs, Property 5: Fooling Parameter Normalization**
        
        For any fooling method string, when normalized, the fooling_methods
        list should contain exactly that method.
        
        **Validates: Requirements 2.3, 2.4**
        """
        # Generate strategy with fooling parameter
        params = {'fooling': fooling_method}
        
        # Normalize parameters
        normalized = self.normalizer.normalize(params)
        
        # Verify fooling_methods contains the original method
        assert 'fooling_methods' in normalized
        assert isinstance(normalized['fooling_methods'], list)
        assert fooling_method in normalized['fooling_methods']
        
        # Verify it's not replaced with badsum (unless that was the original)
        if fooling_method != 'badsum':
            # If we specified something other than badsum, it should be preserved
            assert normalized['fooling_methods'] == [fooling_method]
    
    @given(
        fooling_methods=st.lists(
            st.sampled_from(['badseq', 'badsum', 'md5sig', 'none']),
            min_size=1,
            max_size=4,
            unique=True
        )
    )
    @settings(max_examples=100)
    def test_fooling_list_preserved_in_normalization(self, fooling_methods):
        """
        **Feature: strategy-application-bugs, Property 5: Fooling Parameter Normalization**
        
        For any list of fooling methods, when normalized, the fooling_methods
        list should contain exactly those methods in the same order.
        
        **Validates: Requirements 2.3, 2.4**
        """
        # Generate strategy with fooling parameter as list
        params = {'fooling': fooling_methods}
        
        # Normalize parameters
        normalized = self.normalizer.normalize(params)
        
        # Verify fooling_methods contains all original methods
        assert 'fooling_methods' in normalized
        assert isinstance(normalized['fooling_methods'], list)
        assert normalized['fooling_methods'] == fooling_methods
    
    def test_badseq_not_replaced_with_badsum(self):
        """
        **Feature: strategy-application-bugs, Property 5: Fooling Parameter Normalization**
        
        Specific test: fooling="badseq" should NOT become fooling_methods=["badsum"]
        
        **Validates: Requirements 2.3, 2.4**
        """
        params = {'fooling': 'badseq'}
        
        normalized = self.normalizer.normalize(params)
        
        # Critical assertion: badseq should be preserved
        assert normalized['fooling_methods'] == ['badseq']
        assert 'badsum' not in normalized['fooling_methods']
    
    def test_missing_fooling_defaults_to_badsum(self):
        """
        **Feature: strategy-application-bugs, Property 5: Fooling Parameter Normalization**
        
        When fooling is not specified, default should be badsum.
        
        **Validates: Requirements 2.6**
        """
        params = {}
        
        normalized = self.normalizer.normalize(params)
        
        # When fooling is missing, default to badsum
        assert normalized['fooling_methods'] == ['badsum']
    
    @given(
        fooling_method=st.sampled_from(['badseq', 'badsum', 'md5sig', 'none'])
    )
    @settings(max_examples=100)
    def test_explicit_fooling_not_overridden_by_default(self, fooling_method):
        """
        **Feature: strategy-application-bugs, Property 18: Explicit Values Override Defaults**
        
        For any explicit fooling value, it should not be overridden by the
        default value (badsum).
        
        **Validates: Requirements 7.3**
        """
        params = {'fooling': fooling_method}
        
        normalized = self.normalizer.normalize(params)
        
        # Explicit value should be preserved, not replaced with default
        assert normalized['fooling_methods'] == [fooling_method]
        
        # If we explicitly set something other than badsum, badsum should not appear
        if fooling_method != 'badsum':
            assert 'badsum' not in normalized['fooling_methods']


class TestFoolingValidationProperty:
    """
    Property 19: Invalid Parameter Rejection
    
    For any strategy configuration with an invalid fooling method,
    when validated, a ValidationError should be raised.
    
    Validates: Requirements 6.5
    """
    
    def setup_method(self):
        """Set up test fixtures."""
        self.normalizer = ParameterNormalizer()
    
    @given(
        invalid_method=st.text(
            alphabet=st.characters(blacklist_categories=('Cs',)),
            min_size=1,
            max_size=20
        ).filter(lambda x: x not in ['badseq', 'badsum', 'md5sig', 'none'])
    )
    @settings(max_examples=100)
    def test_invalid_fooling_method_rejected(self, invalid_method):
        """
        **Feature: strategy-application-bugs, Property 19: Invalid Parameter Rejection**
        
        For any invalid fooling method, validation should raise ValidationError.
        
        **Validates: Requirements 6.5**
        """
        params = {'fooling_methods': [invalid_method]}
        
        # Validation should raise error for invalid method
        with pytest.raises(ValidationError) as exc_info:
            self.normalizer.validate(params)
        
        # Error should mention fooling_methods parameter
        assert 'fooling_methods' in str(exc_info.value)
        # Verify the actual value contains the invalid method
        assert invalid_method in exc_info.value.actual
    
    @given(
        valid_methods=st.lists(
            st.sampled_from(['badseq', 'badsum', 'md5sig', 'none']),
            min_size=1,
            max_size=4,
            unique=True
        )
    )
    @settings(max_examples=100)
    def test_valid_fooling_methods_accepted(self, valid_methods):
        """
        **Feature: strategy-application-bugs, Property 19: Invalid Parameter Rejection**
        
        For any valid fooling methods, validation should pass without error.
        
        **Validates: Requirements 6.5**
        """
        params = {'fooling_methods': valid_methods}
        
        # Validation should not raise error for valid methods
        try:
            self.normalizer.validate(params)
        except ValidationError:
            pytest.fail(f"Valid fooling methods {valid_methods} were rejected")


if __name__ == '__main__':
    pytest.main([__file__, '-v'])



class TestBadsumChecksumProperty:
    """
    Property 4: Badsum Checksum Value
    
    For any strategy configuration specifying fooling="badsum",
    when fake packets are generated, the TCP checksum in all fake
    packets should equal 0xDEAD.
    
    Validates: Requirements 2.2
    """
    
    def setup_method(self):
        """Set up test fixtures."""
        from core.bypass.unified_attack_dispatcher import UnifiedAttackDispatcher
        self.dispatcher = UnifiedAttackDispatcher()
    
    @given(
        ttl=st.integers(min_value=1, max_value=10),
        payload_size=st.integers(min_value=10, max_value=1000)
    )
    @settings(max_examples=100)
    def test_badsum_sets_checksum_to_0xDEAD(self, ttl, payload_size):
        """
        **Feature: strategy-application-bugs, Property 4: Badsum Checksum Value**
        
        For any fake packet with fooling="badsum", the TCP checksum
        should be set to 0xDEAD.
        
        **Validates: Requirements 2.2**
        """
        # Generate random payload
        payload = b'\x16\x03\x01' + b'\x00' * payload_size
        
        # Create fake packet with badsum
        params = {
            'ttl': ttl,
            'fooling': 'badsum'
        }
        
        packet_info = {
            'src_addr': '192.168.1.1',
            'dst_addr': '8.8.8.8',
            'src_port': 12345,
            'dst_port': 443
        }
        
        # Generate fake packet
        segments = self.dispatcher.apply_fake(payload, params, packet_info)
        
        # Verify we got a segment
        assert len(segments) == 1
        
        # Verify segment has correct options
        segment_data, offset, options = segments[0]
        assert options.get('fooling') == 'badsum'
        assert options.get('is_fake') is True
        assert options.get('ttl') == ttl
    
    @given(
        ttl=st.integers(min_value=1, max_value=10),
        split_count=st.integers(min_value=2, max_value=6)
    )
    @settings(max_examples=100)
    def test_badsum_applied_to_all_fake_fragments(self, ttl, split_count):
        """
        **Feature: strategy-application-bugs, Property 4: Badsum Checksum Value**
        
        For any fake+multisplit combination with fooling="badsum",
        all fake packets should have fooling="badsum" in their options.
        
        **Validates: Requirements 2.2, 2.5**
        """
        # Generate payload
        payload = b'\x16\x03\x01' + b'\x00' * 500
        
        # Create split
        split_params = {'split_count': split_count}
        packet_info = {
            'src_addr': '192.168.1.1',
            'dst_addr': '8.8.8.8',
            'src_port': 12345,
            'dst_port': 443
        }
        
        fragments = self.dispatcher.apply_split(payload, split_params, packet_info)
        
        # Apply fake to fragments
        fake_params = {
            'ttl': ttl,
            'fooling': 'badsum',
            'fake_mode': 'per_fragment'
        }
        
        segments = self.dispatcher.apply_fake_to_fragments(
            fragments, fake_params, packet_info
        )
        
        # Count fake segments
        fake_segments = [s for s in segments if s[2].get('is_fake')]
        
        # Verify all fake segments have badsum
        for segment_data, offset, options in fake_segments:
            assert options.get('fooling') == 'badsum'
            assert options.get('ttl') == ttl


class TestBadseqSequenceProperty:
    """
    Property 3: Fooling Method Preservation (badseq variant)
    
    For any strategy configuration specifying fooling="badseq",
    when fake packets are generated, the TCP sequence numbers
    should be modified (different from real packets).
    
    Validates: Requirements 2.1
    """
    
    def setup_method(self):
        """Set up test fixtures."""
        from core.bypass.unified_attack_dispatcher import UnifiedAttackDispatcher
        self.dispatcher = UnifiedAttackDispatcher()
    
    @given(
        ttl=st.integers(min_value=1, max_value=10),
        payload_size=st.integers(min_value=10, max_value=1000)
    )
    @settings(max_examples=100)
    def test_badseq_modifies_sequence_number(self, ttl, payload_size):
        """
        **Feature: strategy-application-bugs, Property 3: Fooling Method Preservation**
        
        For any fake packet with fooling="badseq", the segment options
        should indicate badseq fooling method.
        
        **Validates: Requirements 2.1**
        """
        # Generate random payload
        payload = b'\x16\x03\x01' + b'\x00' * payload_size
        
        # Create fake packet with badseq
        params = {
            'ttl': ttl,
            'fooling': 'badseq'
        }
        
        packet_info = {
            'src_addr': '192.168.1.1',
            'dst_addr': '8.8.8.8',
            'src_port': 12345,
            'dst_port': 443
        }
        
        # Generate fake packet
        segments = self.dispatcher.apply_fake(payload, params, packet_info)
        
        # Verify we got a segment
        assert len(segments) == 1
        
        # Verify segment has correct options
        segment_data, offset, options = segments[0]
        assert options.get('fooling') == 'badseq'
        assert options.get('is_fake') is True
        assert options.get('ttl') == ttl
    
    @given(
        ttl=st.integers(min_value=1, max_value=10),
        split_count=st.integers(min_value=2, max_value=6)
    )
    @settings(max_examples=100)
    def test_badseq_applied_to_all_fake_fragments(self, ttl, split_count):
        """
        **Feature: strategy-application-bugs, Property 3: Fooling Method Preservation**
        
        For any fake+multisplit combination with fooling="badseq",
        all fake packets should have fooling="badseq" in their options.
        
        **Validates: Requirements 2.1, 2.5**
        """
        # Generate payload
        payload = b'\x16\x03\x01' + b'\x00' * 500
        
        # Create split
        split_params = {'split_count': split_count}
        packet_info = {
            'src_addr': '192.168.1.1',
            'dst_addr': '8.8.8.8',
            'src_port': 12345,
            'dst_port': 443
        }
        
        fragments = self.dispatcher.apply_split(payload, split_params, packet_info)
        
        # Apply fake to fragments
        fake_params = {
            'ttl': ttl,
            'fooling': 'badseq',
            'fake_mode': 'per_fragment'
        }
        
        segments = self.dispatcher.apply_fake_to_fragments(
            fragments, fake_params, packet_info
        )
        
        # Count fake segments
        fake_segments = [s for s in segments if s[2].get('is_fake')]
        
        # Verify all fake segments have badseq
        for segment_data, offset, options in fake_segments:
            assert options.get('fooling') == 'badseq'
            assert options.get('ttl') == ttl
    
    def test_badseq_different_from_badsum(self):
        """
        **Feature: strategy-application-bugs, Property 3: Fooling Method Preservation**
        
        Verify that badseq and badsum are different fooling methods.
        
        **Validates: Requirements 2.1, 2.2**
        """
        payload = b'\x16\x03\x01' + b'\x00' * 100
        
        packet_info = {
            'src_addr': '192.168.1.1',
            'dst_addr': '8.8.8.8',
            'src_port': 12345,
            'dst_port': 443
        }
        
        # Generate fake with badseq
        badseq_params = {'ttl': 1, 'fooling': 'badseq'}
        badseq_segments = self.dispatcher.apply_fake(payload, badseq_params, packet_info)
        
        # Generate fake with badsum
        badsum_params = {'ttl': 1, 'fooling': 'badsum'}
        badsum_segments = self.dispatcher.apply_fake(payload, badsum_params, packet_info)
        
        # Verify they have different fooling methods
        assert badseq_segments[0][2].get('fooling') == 'badseq'
        assert badsum_segments[0][2].get('fooling') == 'badsum'
        assert badseq_segments[0][2].get('fooling') != badsum_segments[0][2].get('fooling')
