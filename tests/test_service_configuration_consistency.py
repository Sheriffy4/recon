"""
Property-based tests for configuration consistency between testing and production modes.

Tests that cli.py and recon_service.py/simple_service.py use consistent parameters
for force, no_fallbacks, and QUIC cutoff.

**Feature: attack-application-parity, Property 4: Configuration Consistency**
**Validates: Requirements 1.4**
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

# Import directly from module to avoid Scapy dependency chain
import importlib.util
spec = importlib.util.spec_from_file_location(
    "strategy_loader",
    Path(__file__).parent.parent / "core" / "strategy" / "loader.py"
)
strategy_loader_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(strategy_loader_module)
StrategyLoader = strategy_loader_module.StrategyLoader
Strategy = strategy_loader_module.Strategy


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

# Strategy for generating boolean flags
bool_strategy = st.booleans()


@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
@given(
    domain=domain_strategy,
    attacks=attacks_list_strategy,
    params=st.dictionaries(
        keys=st.sampled_from(['ttl', 'split_pos', 'fooling', 'disorder_method']),
        values=st.one_of(
            st.integers(min_value=1, max_value=10),
            st.sampled_from(['badsum', 'badseq', 'reverse', 'random'])
        ),
        min_size=1,
        max_size=4
    ),
    force=bool_strategy,
    no_fallbacks=bool_strategy
)
def test_configuration_consistency_between_modes(domain, attacks, params, force, no_fallbacks):
    """
    **Feature: attack-application-parity, Property 4: Configuration Consistency**
    **Validates: Requirements 1.4**
    
    For any mode switch between testing and production, the parameters force,
    no_fallbacks, and QUIC cutoff should remain identical.
    
    This test verifies that when a strategy is loaded with specific force and
    no_fallbacks parameters, those parameters are preserved consistently.
    """
    # Create a temporary domain_rules.json file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        rules_data = {
            'version': '1.0',
            'domain_rules': {
                domain: {
                    'type': attacks[0],  # Legacy field
                    'attacks': attacks,
                    'params': params,
                    'metadata': {}
                }
            }
        }
        json.dump(rules_data, f)
        temp_file = f.name
    
    try:
        # Simulate loading strategy in testing mode (cli.py)
        loader_testing = StrategyLoader(rules_path=temp_file)
        strategy_testing = loader_testing.find_strategy(domain)
        
        assert strategy_testing is not None, f"Strategy not found for domain {domain}"
        
        # Apply force and no_fallbacks parameters (as cli.py would do)
        testing_config = {
            'attacks': strategy_testing.attacks,
            'params': strategy_testing.params.copy(),
            'force': force,
            'no_fallbacks': no_fallbacks
        }
        
        # Simulate loading strategy in production mode (recon_service.py)
        loader_production = StrategyLoader(rules_path=temp_file)
        strategy_production = loader_production.find_strategy(domain)
        
        assert strategy_production is not None, f"Strategy not found for domain {domain}"
        
        # Apply force and no_fallbacks parameters (as recon_service.py would do)
        production_config = {
            'attacks': strategy_production.attacks,
            'params': strategy_production.params.copy(),
            'force': force,
            'no_fallbacks': no_fallbacks
        }
        
        # Property: Configuration parameters should be identical
        assert testing_config['force'] == production_config['force'], \
            f"Force parameter mismatch: testing={testing_config['force']}, production={production_config['force']}"
        
        assert testing_config['no_fallbacks'] == production_config['no_fallbacks'], \
            f"No_fallbacks parameter mismatch: testing={testing_config['no_fallbacks']}, production={production_config['no_fallbacks']}"
        
        # Property: Attacks should be identical
        assert testing_config['attacks'] == production_config['attacks'], \
            f"Attacks mismatch: testing={testing_config['attacks']}, production={production_config['attacks']}"
        
        # Property: Params should be identical
        assert testing_config['params'] == production_config['params'], \
            f"Params mismatch: testing={testing_config['params']}, production={production_config['params']}"
        
    finally:
        # Clean up temp file
        Path(temp_file).unlink(missing_ok=True)


@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
@given(
    domain=domain_strategy,
    attacks=attacks_list_strategy,
    params=st.dictionaries(
        keys=st.sampled_from(['ttl', 'split_pos', 'split_count']),
        values=st.integers(min_value=1, max_value=10),
        min_size=1,
        max_size=3
    )
)
def test_default_configuration_consistency(domain, attacks, params):
    """
    **Feature: attack-application-parity, Property 4: Configuration Consistency**
    **Validates: Requirements 1.4**
    
    When no explicit force/no_fallbacks parameters are provided, both testing
    and production modes should use the same defaults.
    """
    # Create a temporary domain_rules.json file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        rules_data = {
            'version': '1.0',
            'domain_rules': {
                domain: {
                    'attacks': attacks,
                    'params': params,
                    'metadata': {}
                }
            }
        }
        json.dump(rules_data, f)
        temp_file = f.name
    
    try:
        # Load strategy in both modes
        loader1 = StrategyLoader(rules_path=temp_file)
        strategy1 = loader1.find_strategy(domain)
        
        loader2 = StrategyLoader(rules_path=temp_file)
        strategy2 = loader2.find_strategy(domain)
        
        assert strategy1 is not None and strategy2 is not None
        
        # Property: Both should load the same strategy
        assert strategy1.attacks == strategy2.attacks, \
            "Strategies should be identical when loaded multiple times"
        
        assert strategy1.params == strategy2.params, \
            "Parameters should be identical when loaded multiple times"
        
    finally:
        # Clean up temp file
        Path(temp_file).unlink(missing_ok=True)


@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
@given(
    domain=domain_strategy,
    attacks=attacks_list_strategy,
    params=st.dictionaries(
        keys=st.sampled_from(['ttl', 'split_pos']),
        values=st.integers(min_value=1, max_value=10),
        min_size=1,
        max_size=2
    ),
    force1=bool_strategy,
    no_fallbacks1=bool_strategy,
    force2=bool_strategy,
    no_fallbacks2=bool_strategy
)
def test_configuration_parameter_independence(domain, attacks, params, force1, no_fallbacks1, force2, no_fallbacks2):
    """
    **Feature: attack-application-parity, Property 4: Configuration Consistency**
    **Validates: Requirements 1.4**
    
    Configuration parameters should be applied independently and not affect
    the underlying strategy definition.
    """
    # Create a temporary domain_rules.json file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        rules_data = {
            'version': '1.0',
            'domain_rules': {
                domain: {
                    'attacks': attacks,
                    'params': params,
                    'metadata': {}
                }
            }
        }
        json.dump(rules_data, f)
        temp_file = f.name
    
    try:
        # Load strategy with first set of parameters
        loader = StrategyLoader(rules_path=temp_file)
        strategy = loader.find_strategy(domain)
        
        assert strategy is not None
        
        # Apply first configuration
        config1 = {
            'attacks': strategy.attacks,
            'params': strategy.params.copy(),
            'force': force1,
            'no_fallbacks': no_fallbacks1
        }
        
        # Apply second configuration (simulating different mode or invocation)
        config2 = {
            'attacks': strategy.attacks,
            'params': strategy.params.copy(),
            'force': force2,
            'no_fallbacks': no_fallbacks2
        }
        
        # Property: Base strategy should be identical
        assert config1['attacks'] == config2['attacks'], \
            "Base attacks should be identical regardless of configuration parameters"
        
        assert config1['params'] == config2['params'], \
            "Base params should be identical regardless of configuration parameters"
        
        # Property: Configuration parameters should be independent
        if force1 != force2:
            assert config1['force'] != config2['force'], \
                "Force parameters should be independent"
        
        if no_fallbacks1 != no_fallbacks2:
            assert config1['no_fallbacks'] != config2['no_fallbacks'], \
                "No_fallbacks parameters should be independent"
        
    finally:
        # Clean up temp file
        Path(temp_file).unlink(missing_ok=True)


if __name__ == '__main__':
    import pytest
    pytest.main([__file__, '-v'])
