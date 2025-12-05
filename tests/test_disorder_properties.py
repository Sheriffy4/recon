"""
Property-based tests for disorder attack implementation.

This module tests the correctness properties for disorder attacks:
- Property 10: Disorder Reverse Ordering
- Property 11: Disorder Applies to All Segments

Requirements: 4.1, 4.2, 4.3
"""

import pytest
from hypothesis import given, strategies as st, settings
from typing import List, Tuple, Dict, Any

# Import the component under test
from core.bypass.unified_attack_dispatcher import UnifiedAttackDispatcher


# Helper strategy to generate segment tuples
@st.composite
def segment_strategy(draw):
    """Generate a valid segment tuple (data, offset, options)."""
    data = draw(st.binary(min_size=1, max_size=20))
    offset = draw(st.integers(min_value=0, max_value=100))
    # Simplified options to avoid slow generation
    is_fake = draw(st.booleans())
    options = {'is_fake': is_fake}
    return (data, offset, options)


@st.composite
def segment_list_strategy(draw):
    """Generate a list of segments."""
    return draw(st.lists(segment_strategy(), min_size=2, max_size=8))


class TestDisorderProperties:
    """Property-based tests for disorder attack."""
    
    @settings(max_examples=100, deadline=None)
    @given(segments=segment_list_strategy())
    def test_property_10_disorder_reverse_ordering(self, segments):
        """
        **Feature: strategy-application-bugs, Property 10: Disorder Reverse Ordering**
        
        For any list of segments, when disorder_method="reverse" is applied,
        the resulting segment order should be the reverse of the original order.
        
        **Validates: Requirements 4.1, 4.3**
        """
        # Arrange
        dispatcher = UnifiedAttackDispatcher()
        params = {'disorder_method': 'reverse'}
        packet_info = {'domain': 'test.com'}
        
        # Act
        reordered = dispatcher.apply_disorder(segments, params, packet_info)
        
        # Assert
        expected = list(reversed(segments))
        assert reordered == expected, (
            f"Disorder reverse failed:\n"
            f"Original: {len(segments)} segments\n"
            f"Expected: {expected}\n"
            f"Got: {reordered}"
        )
    
    @settings(max_examples=100, deadline=None)
    @given(
        fake_segments=segment_list_strategy(),
        real_segments=segment_list_strategy()
    )
    def test_property_11_disorder_applies_to_all_segments(
        self, fake_segments, real_segments
    ):
        """
        **Feature: strategy-application-bugs, Property 11: Disorder Applies to All Segments**
        
        For any combination of fake and real segments, when disorder is applied,
        both fake and real segments should be reordered together (not separately).
        
        **Validates: Requirements 4.2**
        """
        # Arrange
        dispatcher = UnifiedAttackDispatcher()
        
        # Mark segments as fake or real
        marked_fake = [
            (data, offset, {**opts, 'is_fake': True})
            for data, offset, opts in fake_segments
        ]
        marked_real = [
            (data, offset, {**opts, 'is_fake': False})
            for data, offset, opts in real_segments
        ]
        
        # Combine fake and real segments
        all_segments = marked_fake + marked_real
        
        params = {'disorder_method': 'reverse'}
        packet_info = {'domain': 'test.com'}
        
        # Act
        reordered = dispatcher.apply_disorder(all_segments, params, packet_info)
        
        # Assert
        # The reordered list should be the reverse of the combined list
        expected = list(reversed(all_segments))
        assert reordered == expected, (
            f"Disorder did not apply to all segments together:\n"
            f"Original: {len(all_segments)} segments "
            f"({len(marked_fake)} fake + {len(marked_real)} real)\n"
            f"Expected: {expected}\n"
            f"Got: {reordered}"
        )
        
        # Additional check: verify that the relative order of fake and real is preserved
        # when reversed. This ensures they were reordered together, not separately.
        # 
        # If we had [F1, F2, R1, R2, R3] and reversed to [R3, R2, R1, F2, F1],
        # this is correct - we reversed the entire list.
        # 
        # If we had [F1, F2, R1, R2, R3] and got [F2, F1, R3, R2, R1],
        # this would be wrong - we reversed fake and real separately.
        
        # Extract the original order of fake/real flags
        original_flags = [seg[2].get('is_fake', False) for seg in all_segments]
        reordered_flags = [seg[2].get('is_fake', False) for seg in reordered]
        
        # The reordered flags should be the reverse of original flags
        assert reordered_flags == list(reversed(original_flags)), (
            f"Fake/real pattern not properly reversed:\n"
            f"Original pattern: {original_flags}\n"
            f"Expected pattern: {list(reversed(original_flags))}\n"
            f"Got pattern: {reordered_flags}"
        )


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
