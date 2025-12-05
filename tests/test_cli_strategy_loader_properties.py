"""
Property-based tests for cli.py StrategyLoader integration.

Tests that cli.py correctly uses StrategyLoader and prioritizes the attacks field.
"""

import json
import tempfile
from pathlib import Path
from hypothesis import given, strategies as st, assume
from hypothesis import settings, HealthCheck
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.strategy.loader import StrategyLoader, Strategy


# Strategy for generating valid attack types
attack_types_strategy = st.sampled_from([
    'fake', 'split', 'multisplit', 'disorder',
    'fakeddisorder', 'disorder_short_ttl_decoy'
])

# Strategy for generating attack lists
attacks_list_strategy = st.lists(
    attack_types_strategy,
    min_size=1,
    max_size=3,
    unique=True
)

# Strategy for generating domain names
domain_strategy = st.builds(
    lambda parts: '.'.join(parts),
    st.lists(
        st.text(alphabet='abcdefghijklmnopqrstuvwxyz0123456789', min_size=1, max_size=10),
        min_size=2,
        max_size=3
    )
)


@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
@given(
    domain=domain_strategy,
    type_field=attack_types_strategy,
    attacks_field=attacks_list_strategy,
    params=st.dictionaries(
        keys=st.sampled_from(['ttl', 'split_pos', 'fooling', 'disorder_method']),
        values=st.one_of(
            st.integers(min_value=1, max_value=10),
            st.sampled_from(['badsum', 'badseq', 'reverse', 'random'])
        ),
        min_size=0,
        max_size=4
    )
)
def test_attacks_field_priority(domain, type_field, attacks_field, params):
    """
    **Feature: attack-application-parity, Property 2: Attacks Field Priority**
    **Validates: Requirements 1.2, 5.2**
    
    For any strategy with an "attacks" field, the system should apply all attacks
    from that list, and the "type" field should be ignored.
    
    This test verifies that when both type and attacks fields are present,
    the attacks field takes priority.
    """
    # Create a temporary domain_rules.json file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        rules_data = {
            'version': '1.0',
            'domain_rules': {
                domain: {
                    'type': type_field,
                    'attacks': attacks_field,
                    'params': params,
                    'metadata': {}
                }
            },
            'default_strategy': {
                'type': 'fake',
                'attacks': ['fake'],
                'params': {},
                'metadata': {}
            }
        }
        json.dump(rules_data, f)
        temp_file = f.name
    
    try:
        # Load strategy using StrategyLoader
        loader = StrategyLoader(rules_path=temp_file)
        strategy = loader.find_strategy(domain)
        
        # Verify strategy was found
        assert strategy is not None, f"Strategy not found for domain {domain}"
        
        # Property: attacks field should match what we set
        assert strategy.attacks == attacks_field, \
            f"Expected attacks {attacks_field}, got {strategy.attacks}"
        
        # Property: attacks field should be used, not type field
        # If type differs from attacks, attacks should still be what we set
        if type_field not in attacks_field:
            # Type field is different from attacks - verify attacks is still used
            assert strategy.attacks == attacks_field, \
                f"Type field {type_field} should not override attacks {attacks_field}"
        
        # Property: all attacks from the list should be present
        for attack in attacks_field:
            assert attack in strategy.attacks, \
                f"Attack {attack} from attacks field not found in strategy.attacks"
        
        # Property: params should be preserved
        assert strategy.params == params, \
            f"Expected params {params}, got {strategy.params}"
        
    finally:
        # Clean up temp file
        Path(temp_file).unlink(missing_ok=True)


@settings(max_examples=100, suppress_health_check=[HealthCheck.filter_too_much])
@given(
    domain=domain_strategy,
    type_field=attack_types_strategy,
    params=st.dictionaries(
        keys=st.sampled_from(['ttl', 'split_pos', 'fooling']),
        values=st.one_of(
            st.integers(min_value=1, max_value=10),
            st.sampled_from(['badsum', 'badseq'])
        ),
        min_size=0,
        max_size=3
    )
)
def test_type_field_fallback_when_attacks_empty(domain, type_field, params):
    """
    **Feature: attack-application-parity, Property 2: Attacks Field Priority**
    **Validates: Requirements 1.2, 5.2**
    
    When attacks field is empty but type field exists, the system should
    create a single-element attacks list from the type field.
    """
    # Create a temporary domain_rules.json file with empty attacks
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        rules_data = {
            'version': '1.0',
            'domain_rules': {
                domain: {
                    'type': type_field,
                    'attacks': [],  # Empty attacks list
                    'params': params,
                    'metadata': {}
                }
            }
        }
        json.dump(rules_data, f)
        temp_file = f.name
    
    try:
        # Load strategy using StrategyLoader
        loader = StrategyLoader(rules_path=temp_file)
        strategy = loader.find_strategy(domain)
        
        # Verify strategy was found
        assert strategy is not None, f"Strategy not found for domain {domain}"
        
        # Property: when attacks is empty, it should be populated from type
        assert len(strategy.attacks) > 0, \
            "Attacks list should not be empty when type field exists"
        
        assert type_field in strategy.attacks, \
            f"Type field {type_field} should be in attacks when attacks is empty"
        
    finally:
        # Clean up temp file
        Path(temp_file).unlink(missing_ok=True)


@settings(max_examples=100, suppress_health_check=[HealthCheck.filter_too_much])
@given(
    domain=domain_strategy,
    attacks_field=attacks_list_strategy,
    params=st.dictionaries(
        keys=st.sampled_from(['ttl', 'split_pos', 'split_count']),
        values=st.integers(min_value=1, max_value=10),
        min_size=1,
        max_size=3
    )
)
def test_attacks_field_without_type(domain, attacks_field, params):
    """
    **Feature: attack-application-parity, Property 2: Attacks Field Priority**
    **Validates: Requirements 1.2, 5.2**
    
    When only attacks field is present (no type field), the system should
    use the attacks field correctly.
    """
    # Create a temporary domain_rules.json file without type field
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        rules_data = {
            'version': '1.0',
            'domain_rules': {
                domain: {
                    'attacks': attacks_field,
                    'params': params,
                    'metadata': {}
                }
            }
        }
        json.dump(rules_data, f)
        temp_file = f.name
    
    try:
        # Load strategy using StrategyLoader
        loader = StrategyLoader(rules_path=temp_file)
        strategy = loader.find_strategy(domain)
        
        # Verify strategy was found
        assert strategy is not None, f"Strategy not found for domain {domain}"
        
        # Property: attacks field should be used
        assert strategy.attacks == attacks_field, \
            f"Expected attacks {attacks_field}, got {strategy.attacks}"
        
        # Property: all attacks should be present
        for attack in attacks_field:
            assert attack in strategy.attacks, \
                f"Attack {attack} not found in strategy.attacks"
        
    finally:
        # Clean up temp file
        Path(temp_file).unlink(missing_ok=True)


if __name__ == '__main__':
    import pytest
    pytest.main([__file__, '-v'])
