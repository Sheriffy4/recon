"""
Property-based tests for parameter preservation.

This module tests that strategy parameters are preserved correctly
throughout the loading and extraction process.

Requirements: 6.1, 7.3
"""

import json
import tempfile
from pathlib import Path
from hypothesis import given, strategies as st, settings, HealthCheck
import pytest

from core.strategy.loader import StrategyLoader
from core.bypass.unified_attack_dispatcher import UnifiedAttackDispatcher


# Strategy for generating valid parameter dictionaries
@st.composite
def strategy_params(draw):
    """Generate valid strategy parameters."""
    params = {}
    
    # TTL parameter (1-255)
    if draw(st.booleans()):
        params['ttl'] = draw(st.integers(min_value=1, max_value=255))
    
    # Fooling parameter
    if draw(st.booleans()):
        params['fooling'] = draw(st.sampled_from(['badsum', 'badseq', 'md5sig', 'none']))
    
    # Split parameters
    if draw(st.booleans()):
        params['split_pos'] = draw(st.integers(min_value=1, max_value=100))
    
    if draw(st.booleans()) and 'split_pos' not in params:
        params['split_count'] = draw(st.integers(min_value=2, max_value=10))
    
    # Disorder parameter
    if draw(st.booleans()):
        params['disorder_method'] = draw(st.sampled_from(['reverse', 'random', 'swap']))
    
    # Fake mode parameter
    if draw(st.booleans()):
        params['fake_mode'] = draw(st.sampled_from(['single', 'per_fragment', 'per_signature', 'smart']))
    
    return params


@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
@given(params=strategy_params())
def test_property_16_parameter_loading_preservation(params):
    """
    **Feature: strategy-application-bugs, Property 16: Parameter Loading Preservation**
    
    For any strategy configuration in domain_rules.json, when parameters are loaded,
    all explicitly specified parameter values should be preserved without modification.
    
    **Validates: Requirements 6.1**
    """
    # Create temporary domain_rules.json with test strategy
    with tempfile.TemporaryDirectory() as tmpdir:
        rules_path = Path(tmpdir) / "domain_rules.json"
        
        # Create domain rules with our test parameters
        domain_rules = {
            "version": "1.0",
            "domain_rules": {
                "test.example.com": {
                    "type": "fake",
                    "attacks": ["fake", "split"],
                    "params": params,
                    "metadata": {}
                }
            }
        }
        
        # Write to file
        with open(rules_path, 'w') as f:
            json.dump(domain_rules, f)
        
        # Load strategy
        loader = StrategyLoader(str(rules_path))
        strategy = loader.find_strategy("test.example.com")
        
        # Verify strategy was loaded
        assert strategy is not None, "Strategy should be loaded"
        
        # Verify all parameters are preserved
        for key, value in params.items():
            assert key in strategy.params, f"Parameter '{key}' should be preserved"
            assert strategy.params[key] == value, (
                f"Parameter '{key}' value should be preserved: "
                f"expected {value}, got {strategy.params[key]}"
            )


@settings(max_examples=100)
@given(params=strategy_params())
def test_property_16_parameter_extraction_preservation(params):
    """
    **Feature: strategy-application-bugs, Property 16: Parameter Loading Preservation**
    
    For any strategy parameters, when extracted for specific attack types,
    all relevant parameter values should be preserved without modification.
    
    **Validates: Requirements 6.1**
    """
    dispatcher = UnifiedAttackDispatcher()
    
    # Test fake attack parameter extraction
    if 'ttl' in params or 'fooling' in params:
        fake_params = dispatcher._extract_attack_params('fake', params)
        
        # Verify TTL is preserved
        if 'ttl' in params:
            assert 'ttl' in fake_params, "TTL should be extracted for fake attack"
            assert fake_params['ttl'] == params['ttl'], (
                f"TTL value should be preserved: "
                f"expected {params['ttl']}, got {fake_params['ttl']}"
            )
        
        # Verify fooling is preserved
        if 'fooling' in params:
            assert 'fooling' in fake_params, "Fooling should be extracted for fake attack"
            assert fake_params['fooling'] == params['fooling'], (
                f"Fooling value should be preserved: "
                f"expected {params['fooling']}, got {fake_params['fooling']}"
            )
    
    # Test split attack parameter extraction
    if 'split_pos' in params or 'split_count' in params:
        split_params = dispatcher._extract_attack_params('split', params)
        
        # Verify split_pos is preserved
        if 'split_pos' in params:
            assert 'split_pos' in split_params, "split_pos should be extracted for split attack"
            assert split_params['split_pos'] == params['split_pos'], (
                f"split_pos value should be preserved: "
                f"expected {params['split_pos']}, got {split_params['split_pos']}"
            )
        
        # Verify split_count is preserved
        if 'split_count' in params:
            assert 'split_count' in split_params, "split_count should be extracted for split attack"
            assert split_params['split_count'] == params['split_count'], (
                f"split_count value should be preserved: "
                f"expected {params['split_count']}, got {split_params['split_count']}"
            )
    
    # Test disorder attack parameter extraction
    if 'disorder_method' in params:
        disorder_params = dispatcher._extract_attack_params('disorder', params)
        
        # Verify disorder_method is preserved
        assert 'disorder_method' in disorder_params, "disorder_method should be extracted for disorder attack"
        assert disorder_params['disorder_method'] == params['disorder_method'], (
            f"disorder_method value should be preserved: "
            f"expected {params['disorder_method']}, got {disorder_params['disorder_method']}"
        )


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
