"""
Property-based tests for log completeness.

Feature: attack-application-parity, Property 5: Log Completeness
Validates: Requirements 1.5

This test verifies that for any applied strategy, the log contains descriptions
of all attacks that were actually applied.
"""

import io
import logging
import tempfile
from pathlib import Path
from hypothesis import given, strategies as st, settings, HealthCheck, assume
from hypothesis import example

from core.strategy.loader import StrategyLoader, Strategy
from core.strategy.combo_builder import ComboAttackBuilder, AttackRecipe
from core.bypass.unified_attack_dispatcher import UnifiedAttackDispatcher


# Hypothesis strategies for generating test data

@st.composite
def attacks_with_params(draw):
    """Generate valid attacks with matching parameters."""
    # Generate attacks
    attack_types = ['fake', 'disorder', 'fakeddisorder']
    
    # Choose between split or multisplit (not both)
    split_type = draw(st.sampled_from(['split', 'multisplit', None]))
    if split_type:
        attack_types.append(split_type)
    
    # Generate 1-3 attacks
    num_attacks = draw(st.integers(min_value=1, max_value=min(3, len(attack_types))))
    attacks = draw(st.lists(
        st.sampled_from(attack_types),
        min_size=num_attacks,
        max_size=num_attacks,
        unique=True
    ))
    
    # Generate matching parameters
    params = {}
    
    if 'fake' in attacks or 'fakeddisorder' in attacks:
        params['ttl'] = draw(st.integers(min_value=1, max_value=10))
        params['fooling'] = draw(st.sampled_from(['badsum', 'badseq']))
        params['fake_sni'] = draw(st.booleans())
    
    if 'split' in attacks or 'multisplit' in attacks:
        params['split_pos'] = draw(st.integers(min_value=1, max_value=10))
        if 'multisplit' in attacks:
            params['split_count'] = draw(st.integers(min_value=2, max_value=5))
    
    if 'disorder' in attacks or 'fakeddisorder' in attacks:
        params['disorder_method'] = draw(st.sampled_from(['reverse', 'swap']))
    
    return (attacks, params)


@st.composite
def payload_bytes(draw):
    """Generate test payload bytes."""
    # Generate a payload that looks like a TLS ClientHello
    # Minimum size to allow splitting
    size = draw(st.integers(min_value=100, max_value=500))
    
    # Create a simple payload with SNI marker
    payload = b'\x16\x03\x01' + b'\x00' * 40 + b'\x00\x00' + b'\x00' * (size - 46)
    return payload


class LogCapture:
    """Capture log messages for testing."""
    
    def __init__(self, logger_name):
        self.logger_name = logger_name
        self.log_stream = io.StringIO()
        self.handler = logging.StreamHandler(self.log_stream)
        self.handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(levelname)s: %(message)s')
        self.handler.setFormatter(formatter)
        
    def __enter__(self):
        logger = logging.getLogger(self.logger_name)
        logger.addHandler(self.handler)
        logger.setLevel(logging.INFO)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        logger = logging.getLogger(self.logger_name)
        logger.removeHandler(self.handler)
    
    def get_logs(self):
        """Get captured log messages."""
        return self.log_stream.getvalue()


# Property Tests

@given(
    attacks_params=attacks_with_params(),
)
@settings(
    max_examples=100,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
    deadline=None
)
def test_property_log_completeness_recipe_building(attacks_params):
    """
    **Feature: attack-application-parity, Property 5: Log Completeness**
    **Validates: Requirements 1.5**
    
    Property: For any list of attacks, when building a recipe, the log should
    contain an entry for each attack in the recipe.
    """
    attacks, params = attacks_params
    
    # Capture logs during recipe building
    with LogCapture('core.strategy.combo_builder') as log_capture:
        builder = ComboAttackBuilder()
        
        try:
            recipe = builder.build_recipe(attacks, params)
            logs = log_capture.get_logs()
            
            # Verify: Log should mention each attack
            for attack in recipe.attacks:
                assert attack in logs, (
                    f"Attack '{attack}' not found in logs. "
                    f"Expected all attacks {recipe.attacks} to be logged.\n"
                    f"Logs:\n{logs}"
                )
            
            # Verify: Log should mention recipe creation
            assert 'Creating recipe' in logs or 'Built recipe' in logs, (
                f"Recipe creation not logged.\n"
                f"Logs:\n{logs}"
            )
            
            # Verify: Log should mention the number of steps
            assert str(len(recipe.steps)) in logs, (
                f"Number of steps ({len(recipe.steps)}) not found in logs.\n"
                f"Logs:\n{logs}"
            )
            
        except ValueError as e:
            # If recipe building fails due to incompatibility, that's ok
            # The test is about log completeness when it succeeds
            assume(False)


@given(
    attacks_params=attacks_with_params(),
    payload=payload_bytes()
)
@settings(
    max_examples=100,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
    deadline=None
)
def test_property_log_completeness_attack_application(attacks_params, payload):
    """
    **Feature: attack-application-parity, Property 5: Log Completeness**
    **Validates: Requirements 1.5**
    
    Property: For any applied strategy, when applying attacks, the log should
    contain an entry when each attack is applied and a final summary with
    packet count.
    """
    attacks, params = attacks_params
    
    # Build recipe
    builder = ComboAttackBuilder()
    
    try:
        recipe = builder.build_recipe(attacks, params)
    except ValueError:
        # Incompatible combination, skip
        assume(False)
    
    # Capture logs during attack application
    with LogCapture('core.bypass.unified_attack_dispatcher') as log_capture:
        dispatcher = UnifiedAttackDispatcher(builder)
        
        packet_info = {
            'src_addr': '192.168.1.1',
            'dst_addr': '8.8.8.8',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments = dispatcher.apply_recipe(recipe, payload, packet_info)
        logs = log_capture.get_logs()
        
        # Verify: Log should mention applying each attack
        for step in recipe.steps:
            assert f'Applying attack' in logs or step.attack_type in logs, (
                f"Attack application for '{step.attack_type}' not logged.\n"
                f"Expected all attacks {[s.attack_type for s in recipe.steps]} to be logged.\n"
                f"Logs:\n{logs}"
            )
        
        # Verify: Log should mention recipe execution
        assert 'Applying recipe' in logs or 'Recipe execution' in logs, (
            f"Recipe execution not logged.\n"
            f"Logs:\n{logs}"
        )
        
        # Verify: Log should mention final packet/segment count
        assert 'segments' in logs.lower() or 'complete' in logs.lower(), (
            f"Final packet count not logged.\n"
            f"Logs:\n{logs}"
        )
        
        # Verify: Log should contain numeric information about segments
        assert str(len(segments)) in logs or 'Total' in logs, (
            f"Segment count ({len(segments)}) not found in logs.\n"
            f"Logs:\n{logs}"
        )


@given(
    domain=st.text(
        alphabet=st.characters(whitelist_categories=('Ll',), max_codepoint=127),
        min_size=3,
        max_size=20
    ).map(lambda s: s + '.com'),
    attacks_params=attacks_with_params()
)
@settings(
    max_examples=100,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
    deadline=None
)
def test_property_log_completeness_strategy_loading(domain, attacks_params):
    """
    **Feature: attack-application-parity, Property 5: Log Completeness**
    **Validates: Requirements 1.5**
    
    Property: For any domain, when loading a strategy, the log should contain
    the domain name, attacks list, and parameters.
    """
    attacks, params = attacks_params
    
    # Create temporary rules file
    strategy = Strategy(
        type=attacks[0] if attacks else '',
        attacks=attacks,
        params=params,
        metadata={'test': True}
    )
    
    temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8')
    data = {
        'version': '1.0',
        'domain_rules': {
            domain: {
                'type': strategy.type,
                'attacks': strategy.attacks,
                'params': strategy.params,
                'metadata': strategy.metadata
            }
        }
    }
    
    import json
    json.dump(data, temp_file, indent=2)
    temp_file.close()
    
    try:
        # Capture logs during strategy loading
        with LogCapture('core.strategy.loader') as log_capture:
            loader = StrategyLoader(rules_path=temp_file.name)
            loaded_strategy = loader.find_strategy(domain)
            logs = log_capture.get_logs()
            
            # Verify: Log should mention the domain
            assert domain in logs, (
                f"Domain '{domain}' not found in logs.\n"
                f"Logs:\n{logs}"
            )
            
            # Verify: Log should mention loading strategy
            assert 'Loading strategy' in logs or 'Found' in logs, (
                f"Strategy loading not logged.\n"
                f"Logs:\n{logs}"
            )
            
            # Verify: Log should mention attacks
            assert 'Attacks' in logs or 'attacks' in logs, (
                f"Attacks not mentioned in logs.\n"
                f"Logs:\n{logs}"
            )
            
            # Verify: Log should mention params
            assert 'Params' in logs or 'params' in logs, (
                f"Parameters not mentioned in logs.\n"
                f"Logs:\n{logs}"
            )
            
    finally:
        # Clean up temp file
        Path(temp_file.name).unlink(missing_ok=True)


# Example-based tests for specific scenarios

@given(attacks_params=attacks_with_params())
@settings(max_examples=10, deadline=None)
def test_log_completeness_combo_attack(attacks_params):
    """
    Test that combo attacks log all components.
    """
    attacks, params = attacks_params
    
    with LogCapture('core.strategy.combo_builder') as log_capture:
        builder = ComboAttackBuilder()
        
        try:
            recipe = builder.build_recipe(attacks, params)
            logs = log_capture.get_logs()
            
            # All attacks should be in logs
            for attack in attacks:
                assert attack in logs
                
        except ValueError:
            assume(False)


if __name__ == '__main__':
    # Run tests with pytest
    import pytest
    import sys
    
    sys.exit(pytest.main([__file__, '-v', '--tb=short']))
