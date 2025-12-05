"""
Property-based tests for fake_mode parameter implementation.

This module tests the correctness properties for fake_mode parameter:
- Property 13: Per-Fragment Fake Count
- Property 14: Per-Fragment Fake Parameters
- Property 15: Per-Fragment Fake Positioning

Requirements: 5.1, 5.2, 5.3, 5.4, 5.5
"""

import pytest
from hypothesis import given, strategies as st, settings
from typing import List, Tuple, Dict, Any

from core.bypass.unified_attack_dispatcher import UnifiedAttackDispatcher


# Strategy generators
@st.composite
def fragment_list(draw, min_fragments=2, max_fragments=10):
    """Generate a list of packet fragments."""
    num_fragments = draw(st.integers(min_value=min_fragments, max_value=max_fragments))
    fragments = []
    offset = 0
    
    for i in range(num_fragments):
        # Generate fragment data (10-100 bytes)
        fragment_size = draw(st.integers(min_value=10, max_value=100))
        fragment_data = draw(st.binary(min_size=fragment_size, max_size=fragment_size))
        
        fragments.append((
            fragment_data,
            offset,
            {'tcp_flags': 'PA', 'fragment': i + 1}
        ))
        
        offset += fragment_size
    
    return fragments


@st.composite
def fake_params(draw):
    """Generate fake attack parameters."""
    return {
        'ttl': draw(st.integers(min_value=1, max_value=10)),
        'fooling': draw(st.sampled_from(['badsum', 'badseq'])),
        'fake_mode': 'per_fragment'
    }


# Property 13: Per-Fragment Fake Count
@settings(max_examples=100)
@given(
    fragments=fragment_list(),
    params=fake_params()
)
def test_property_13_per_fragment_fake_count(fragments, params):
    """
    **Feature: strategy-application-bugs, Property 13: Per-Fragment Fake Count**
    
    For any strategy with fake_mode="per_fragment" and N fragments,
    when fake packets are generated, the number of fake packets should equal N.
    
    **Validates: Requirements 5.1, 5.2**
    """
    # Create dispatcher
    dispatcher = UnifiedAttackDispatcher()
    
    # Apply fake to fragments
    result = dispatcher.apply_fake_to_fragments(
        fragments,
        params,
        {'domain': 'test.com'}
    )
    
    # Count fake segments
    fake_count = sum(1 for seg in result if seg[2].get('is_fake', False))
    
    # Verify fake count equals fragment count
    assert fake_count == len(fragments), (
        f"Expected {len(fragments)} fake packets for {len(fragments)} fragments, "
        f"but got {fake_count}"
    )


# Property 14: Per-Fragment Fake Parameters
@settings(max_examples=100)
@given(
    fragments=fragment_list(),
    ttl=st.integers(min_value=1, max_value=10),
    fooling=st.sampled_from(['badsum', 'badseq'])
)
def test_property_14_per_fragment_fake_parameters(fragments, ttl, fooling):
    """
    **Feature: strategy-application-bugs, Property 14: Per-Fragment Fake Parameters**
    
    For any strategy with fake_mode="per_fragment",
    when multiple fake packets are generated,
    all fake packets should have identical TTL and fooling_methods values.
    
    **Validates: Requirements 5.4**
    """
    # Create dispatcher
    dispatcher = UnifiedAttackDispatcher()
    
    params = {
        'ttl': ttl,
        'fooling': fooling,
        'fake_mode': 'per_fragment'
    }
    
    # Apply fake to fragments
    result = dispatcher.apply_fake_to_fragments(
        fragments,
        params,
        {'domain': 'test.com'}
    )
    
    # Extract fake segments
    fake_segments = [seg for seg in result if seg[2].get('is_fake', False)]
    
    # Verify all fakes have same TTL
    ttls = [seg[2].get('ttl') for seg in fake_segments]
    assert all(t == ttl for t in ttls), (
        f"Expected all fakes to have TTL={ttl}, but got: {ttls}"
    )
    
    # Verify all fakes have same fooling method
    fooling_methods = [seg[2].get('fooling') for seg in fake_segments]
    assert all(f == fooling for f in fooling_methods), (
        f"Expected all fakes to have fooling={fooling}, but got: {fooling_methods}"
    )


# Property 15: Per-Fragment Fake Positioning
@settings(max_examples=100)
@given(
    fragments=fragment_list(),
    params=fake_params()
)
def test_property_15_per_fragment_fake_positioning(fragments, params):
    """
    **Feature: strategy-application-bugs, Property 15: Per-Fragment Fake Positioning**
    
    For any strategy with fake_mode="per_fragment",
    when segments are ordered,
    each fake packet should appear immediately before its corresponding real fragment.
    
    **Validates: Requirements 5.5**
    """
    # Create dispatcher
    dispatcher = UnifiedAttackDispatcher()
    
    # Apply fake to fragments
    result = dispatcher.apply_fake_to_fragments(
        fragments,
        params,
        {'domain': 'test.com'}
    )
    
    # Verify interleaving pattern: [fake1, real1, fake2, real2, ...]
    # Expected: 2 * len(fragments) segments
    assert len(result) == 2 * len(fragments), (
        f"Expected {2 * len(fragments)} segments (fake + real for each fragment), "
        f"but got {len(result)}"
    )
    
    # Verify pattern: even indices are fake, odd indices are real
    for i in range(len(fragments)):
        fake_idx = 2 * i
        real_idx = 2 * i + 1
        
        # Check fake segment
        assert result[fake_idx][2].get('is_fake', False), (
            f"Expected segment at index {fake_idx} to be fake, but it's not"
        )
        
        # Check real segment
        assert not result[real_idx][2].get('is_fake', False), (
            f"Expected segment at index {real_idx} to be real, but it's fake"
        )
        
        # Verify they correspond to the same fragment
        fake_fragment_idx = result[fake_idx][2].get('fragment_index')
        real_fragment_idx = result[real_idx][2].get('fragment_index')
        
        assert fake_fragment_idx == real_fragment_idx == i, (
            f"Expected fake and real at indices {fake_idx}, {real_idx} to have "
            f"fragment_index={i}, but got fake={fake_fragment_idx}, real={real_fragment_idx}"
        )


# Additional test: Validate fake_mode parameter
@settings(max_examples=50)
@given(
    fragments=fragment_list(),
    fake_mode=st.sampled_from(['per_fragment', 'per_signature', 'smart', 'single', 'invalid_mode'])
)
def test_fake_mode_validation(fragments, fake_mode):
    """
    Test that fake_mode validation works correctly.
    
    Valid modes should work, invalid modes should default to per_fragment.
    """
    # Create dispatcher
    dispatcher = UnifiedAttackDispatcher()
    
    params = {
        'ttl': 1,
        'fooling': 'badsum',
        'fake_mode': fake_mode
    }
    
    # Apply fake to fragments - should not raise exception
    result = dispatcher.apply_fake_to_fragments(
        fragments,
        params,
        {'domain': 'test.com'}
    )
    
    # Should always return some segments
    assert len(result) > 0, "Expected at least one segment"
    
    # For invalid mode, should default to per_fragment behavior
    if fake_mode == 'invalid_mode':
        # Should have 2 * len(fragments) segments (fake + real for each)
        assert len(result) == 2 * len(fragments), (
            f"Invalid mode should default to per_fragment, "
            f"expected {2 * len(fragments)} segments, got {len(result)}"
        )


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
