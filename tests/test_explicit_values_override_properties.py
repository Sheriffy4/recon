"""
Property-based tests for explicit values override.

This module tests that explicitly configured parameter values
are never overwritten by default values.

Requirements: 7.3
"""

from hypothesis import given, strategies as st, settings, HealthCheck
import pytest

from core.strategy.normalizer import ParameterNormalizer


# Strategy for generating explicit parameter values
@st.composite
def explicit_params(draw):
    """Generate parameters with explicit values that differ from defaults."""
    params = {}
    
    # TTL - explicit value different from any default
    params['ttl'] = draw(st.integers(min_value=1, max_value=255))
    
    # Fooling - explicit value (could be any valid method)
    params['fooling'] = draw(st.sampled_from(['badsum', 'badseq', 'md5sig', 'none']))
    
    # Disorder method - explicit value
    params['disorder_method'] = draw(st.sampled_from(['reverse', 'random', 'swap']))
    
    # Fake mode - explicit value
    params['fake_mode'] = draw(st.sampled_from(['single', 'per_fragment', 'per_signature', 'smart']))
    
    return params


@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
@given(params=explicit_params())
def test_property_18_explicit_values_override_defaults(params):
    """
    **Feature: strategy-application-bugs, Property 18: Explicit Values Override Defaults**
    
    For any parameter with an explicitly configured value, when defaults are applied,
    the explicit value should not be overwritten by the default value.
    
    **Validates: Requirements 7.3**
    """
    normalizer = ParameterNormalizer()
    
    # Store original values
    original_ttl = params['ttl']
    original_fooling = params['fooling']
    original_disorder_method = params['disorder_method']
    original_fake_mode = params['fake_mode']
    
    # Normalize parameters (which applies defaults)
    normalized = normalizer.normalize(params)
    
    # Verify explicit TTL is not overwritten
    assert 'ttl' in normalized, "TTL should be present after normalization"
    assert normalized['ttl'] == original_ttl, (
        f"Explicit TTL value should not be overwritten: "
        f"expected {original_ttl}, got {normalized['ttl']}"
    )
    
    # Verify explicit fooling is not overwritten
    # Note: fooling gets converted to fooling_methods, but original should be preserved
    assert 'fooling' in normalized or 'fooling_methods' in normalized, (
        "Fooling should be present after normalization"
    )
    if 'fooling' in normalized:
        assert normalized['fooling'] == original_fooling, (
            f"Explicit fooling value should not be overwritten: "
            f"expected {original_fooling}, got {normalized['fooling']}"
        )
    if 'fooling_methods' in normalized:
        assert original_fooling in normalized['fooling_methods'], (
            f"Explicit fooling value should be in fooling_methods: "
            f"expected {original_fooling} in {normalized['fooling_methods']}"
        )
    
    # Verify explicit disorder_method is not overwritten
    assert 'disorder_method' in normalized, "disorder_method should be present after normalization"
    assert normalized['disorder_method'] == original_disorder_method, (
        f"Explicit disorder_method value should not be overwritten: "
        f"expected {original_disorder_method}, got {normalized['disorder_method']}"
    )
    
    # Verify explicit fake_mode is not overwritten
    assert 'fake_mode' in normalized, "fake_mode should be present after normalization"
    assert normalized['fake_mode'] == original_fake_mode, (
        f"Explicit fake_mode value should not be overwritten: "
        f"expected {original_fake_mode}, got {normalized['fake_mode']}"
    )


@settings(max_examples=100)
@given(
    ttl=st.integers(min_value=1, max_value=255),
    fooling=st.sampled_from(['badsum', 'badseq', 'md5sig', 'none'])
)
def test_property_18_explicit_ttl_and_fooling_override(ttl, fooling):
    """
    **Feature: strategy-application-bugs, Property 18: Explicit Values Override Defaults**
    
    For any explicit TTL and fooling values, normalization should preserve them
    without applying defaults.
    
    **Validates: Requirements 7.3**
    """
    normalizer = ParameterNormalizer()
    
    # Create params with explicit values
    params = {
        'ttl': ttl,
        'fooling': fooling
    }
    
    # Normalize
    normalized = normalizer.normalize(params)
    
    # Verify TTL is preserved
    assert normalized['ttl'] == ttl, (
        f"Explicit TTL should not be overwritten: expected {ttl}, got {normalized['ttl']}"
    )
    
    # Verify fooling is preserved (either as fooling or in fooling_methods)
    if 'fooling' in normalized:
        assert normalized['fooling'] == fooling, (
            f"Explicit fooling should not be overwritten: expected {fooling}, got {normalized['fooling']}"
        )
    
    if 'fooling_methods' in normalized:
        assert fooling in normalized['fooling_methods'], (
            f"Explicit fooling should be in fooling_methods: expected {fooling} in {normalized['fooling_methods']}"
        )


@settings(max_examples=100)
@given(
    split_pos=st.integers(min_value=1, max_value=100),
    split_count=st.integers(min_value=2, max_value=10)
)
def test_property_18_explicit_split_params_preserved(split_pos, split_count):
    """
    **Feature: strategy-application-bugs, Property 18: Explicit Values Override Defaults**
    
    For any explicit split parameters, normalization should preserve them
    even when there's a conflict (both split_pos and split_count specified).
    
    **Validates: Requirements 7.3**
    """
    normalizer = ParameterNormalizer()
    
    # Test with split_pos only
    params_pos = {'split_pos': split_pos}
    normalized_pos = normalizer.normalize(params_pos)
    assert normalized_pos['split_pos'] == split_pos, (
        f"Explicit split_pos should not be overwritten: expected {split_pos}, got {normalized_pos['split_pos']}"
    )
    
    # Test with split_count only
    params_count = {'split_count': split_count}
    normalized_count = normalizer.normalize(params_count)
    assert normalized_count['split_count'] == split_count, (
        f"Explicit split_count should not be overwritten: expected {split_count}, got {normalized_count['split_count']}"
    )
    
    # Test with both (conflict case) - both should be preserved even though there's a conflict
    params_both = {'split_pos': split_pos, 'split_count': split_count}
    normalized_both = normalizer.normalize(params_both)
    assert normalized_both['split_pos'] == split_pos, (
        f"Explicit split_pos should be preserved even in conflict: expected {split_pos}, got {normalized_both['split_pos']}"
    )
    assert normalized_both['split_count'] == split_count, (
        f"Explicit split_count should be preserved even in conflict: expected {split_count}, got {normalized_both['split_count']}"
    )


@settings(max_examples=50)
@given(params=explicit_params())
def test_property_18_no_default_override_after_validation(params):
    """
    **Feature: strategy-application-bugs, Property 18: Explicit Values Override Defaults**
    
    For any explicit parameters, after normalization and validation,
    the explicit values should remain unchanged.
    
    **Validates: Requirements 7.3**
    """
    normalizer = ParameterNormalizer()
    
    # Store original values
    original_values = params.copy()
    
    # Normalize and validate
    normalized = normalizer.normalize(params)
    normalizer.validate(normalized)
    
    # Verify all original explicit values are still present
    for key, original_value in original_values.items():
        if key == 'fooling':
            # fooling might be converted to fooling_methods
            if 'fooling' in normalized:
                assert normalized['fooling'] == original_value, (
                    f"Explicit {key} should not be overwritten after validation: "
                    f"expected {original_value}, got {normalized[key]}"
                )
            elif 'fooling_methods' in normalized:
                assert original_value in normalized['fooling_methods'], (
                    f"Explicit fooling should be in fooling_methods after validation: "
                    f"expected {original_value} in {normalized['fooling_methods']}"
                )
        else:
            assert key in normalized, f"Explicit parameter {key} should be present after validation"
            assert normalized[key] == original_value, (
                f"Explicit {key} should not be overwritten after validation: "
                f"expected {original_value}, got {normalized[key]}"
            )


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
