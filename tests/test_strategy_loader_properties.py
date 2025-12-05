"""
Property-based tests for StrategyLoader.

Feature: attack-application-parity
Tests correctness properties for domain matching and strategy loading.
"""

import json
import tempfile
from pathlib import Path
from hypothesis import given, strategies as st, settings, HealthCheck
from hypothesis import assume

from core.strategy.loader import StrategyLoader, Strategy


# Hypothesis strategies for generating test data

@st.composite
def domain_name(draw):
    """Generate valid domain names."""
    # Generate 1-3 labels
    num_labels = draw(st.integers(min_value=1, max_value=3))
    labels = []
    for _ in range(num_labels):
        # Each label is 1-10 lowercase letters
        label = draw(st.text(
            alphabet=st.characters(whitelist_categories=('Ll',), max_codepoint=127),
            min_size=1,
            max_size=10
        ))
        labels.append(label)
    return '.'.join(labels)


@st.composite
def strategy_data(draw):
    """Generate valid strategy data."""
    attack_types = ['fake', 'split', 'multisplit', 'disorder', 'fakeddisorder']
    num_attacks = draw(st.integers(min_value=1, max_value=3))
    attacks = draw(st.lists(
        st.sampled_from(attack_types),
        min_size=num_attacks,
        max_size=num_attacks,
        unique=True
    ))
    
    params = {}
    if 'fake' in attacks or 'fakeddisorder' in attacks:
        params['ttl'] = draw(st.integers(min_value=1, max_value=10))
        params['fooling'] = draw(st.sampled_from(['badsum', 'badseq', 'none']))
    
    if 'split' in attacks or 'multisplit' in attacks:
        params['split_pos'] = draw(st.one_of(
            st.integers(min_value=1, max_value=10),
            st.just('sni')
        ))
        if 'multisplit' in attacks:
            params['split_count'] = draw(st.integers(min_value=2, max_value=8))
    
    if 'disorder' in attacks or 'fakeddisorder' in attacks:
        params['disorder_method'] = draw(st.sampled_from(['reverse', 'random']))
    
    return Strategy(
        type=attacks[0] if attacks else '',
        attacks=attacks,
        params=params,
        metadata={'test': True}
    )


def create_temp_rules_file(domain_rules, default_strategy=None):
    """Create a temporary rules file for testing."""
    temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8')
    data = {
        'version': '1.0',
        'domain_rules': {}
    }
    
    for domain, strategy in domain_rules.items():
        data['domain_rules'][domain] = {
            'type': strategy.type,
            'attacks': strategy.attacks,
            'params': strategy.params,
            'metadata': strategy.metadata
        }
    
    if default_strategy:
        data['default_strategy'] = {
            'type': default_strategy.type,
            'attacks': default_strategy.attacks,
            'params': default_strategy.params,
            'metadata': default_strategy.metadata
        }
    
    json.dump(data, temp_file, indent=2)
    temp_file.close()
    return temp_file.name


class TestDomainMatchingPriority:
    """
    **Feature: attack-application-parity, Property 12: Domain Matching Priority**
    **Validates: Requirements 6.1**
    
    Property: For any domain, when both exact match and wildcard rules exist,
    the system should select the exact match.
    """
    
    @given(
        domain=domain_name(),
        exact_strategy=strategy_data(),
        wildcard_strategy=strategy_data()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_exact_match_priority_over_wildcard(self, domain, exact_strategy, wildcard_strategy):
        """
        Test that exact domain match has priority over wildcard match.
        
        For any domain with both exact and wildcard rules, exact match should win.
        """
        # Ensure strategies are different
        assume(exact_strategy.attacks != wildcard_strategy.attacks)
        
        # Create rules with both exact and wildcard
        wildcard_domain = f"*.{domain}"
        domain_rules = {
            domain: exact_strategy,
            wildcard_domain: wildcard_strategy
        }
        
        # Create temp file and loader
        rules_file = create_temp_rules_file(domain_rules)
        try:
            loader = StrategyLoader(rules_file)
            loader.load_rules()
            
            # Find strategy for domain
            found_strategy = loader.find_strategy(domain)
            
            # Assert: exact match should be returned
            assert found_strategy is not None, f"No strategy found for {domain}"
            assert found_strategy.attacks == exact_strategy.attacks, \
                f"Expected exact match attacks {exact_strategy.attacks}, got {found_strategy.attacks}"
        finally:
            Path(rules_file).unlink()
    
    @given(
        subdomain=domain_name(),
        parent_domain=domain_name(),
        exact_strategy=strategy_data(),
        parent_strategy=strategy_data()
    )
    @settings(max_examples=100)
    def test_exact_match_priority_over_parent(self, subdomain, parent_domain, exact_strategy, parent_strategy):
        """
        Test that exact domain match has priority over parent domain match.
        
        For any subdomain with both exact and parent rules, exact match should win.
        """
        # Ensure strategies are different
        assume(exact_strategy.attacks != parent_strategy.attacks)
        
        # Create full subdomain
        full_domain = f"{subdomain}.{parent_domain}"
        
        # Create rules with both exact and parent
        domain_rules = {
            full_domain: exact_strategy,
            parent_domain: parent_strategy
        }
        
        # Create temp file and loader
        rules_file = create_temp_rules_file(domain_rules)
        try:
            loader = StrategyLoader(rules_file)
            loader.load_rules()
            
            # Find strategy for full domain
            found_strategy = loader.find_strategy(full_domain)
            
            # Assert: exact match should be returned
            assert found_strategy is not None, f"No strategy found for {full_domain}"
            assert found_strategy.attacks == exact_strategy.attacks, \
                f"Expected exact match attacks {exact_strategy.attacks}, got {found_strategy.attacks}"
        finally:
            Path(rules_file).unlink()
    
    @given(
        subdomain=domain_name(),
        parent_domain=domain_name(),
        wildcard_strategy=strategy_data(),
        parent_strategy=strategy_data()
    )
    @settings(max_examples=100)
    def test_wildcard_priority_over_parent(self, subdomain, parent_domain, wildcard_strategy, parent_strategy):
        """
        Test that wildcard match has priority over parent domain match.
        
        For any subdomain with both wildcard and parent rules, wildcard should win.
        """
        # Ensure strategies are different
        assume(wildcard_strategy.attacks != parent_strategy.attacks)
        
        # Create full subdomain
        full_domain = f"{subdomain}.{parent_domain}"
        wildcard_domain = f"*.{parent_domain}"
        
        # Create rules with both wildcard and parent
        domain_rules = {
            wildcard_domain: wildcard_strategy,
            parent_domain: parent_strategy
        }
        
        # Create temp file and loader
        rules_file = create_temp_rules_file(domain_rules)
        try:
            loader = StrategyLoader(rules_file)
            loader.load_rules()
            
            # Find strategy for full domain
            found_strategy = loader.find_strategy(full_domain)
            
            # Assert: wildcard match should be returned
            assert found_strategy is not None, f"No strategy found for {full_domain}"
            assert found_strategy.attacks == wildcard_strategy.attacks, \
                f"Expected wildcard match attacks {wildcard_strategy.attacks}, got {found_strategy.attacks}"
        finally:
            Path(rules_file).unlink()


class TestDefaultStrategyFallback:
    """
    **Feature: attack-application-parity, Property 13: Default Strategy Fallback**
    **Validates: Requirements 6.4**
    
    Property: For any domain without any matching rules, the system should use
    the default_strategy.
    """
    
    @given(
        domain=domain_name(),
        default_strategy=strategy_data()
    )
    @settings(max_examples=100)
    def test_default_strategy_when_no_match(self, domain, default_strategy):
        """
        Test that default strategy is used when no rules match.
        
        For any domain with no matching rules, default_strategy should be returned.
        """
        # Create rules file with only default strategy (no domain rules)
        domain_rules = {}
        
        # Create temp file and loader
        rules_file = create_temp_rules_file(domain_rules, default_strategy)
        try:
            loader = StrategyLoader(rules_file)
            loader.load_rules()
            
            # Find strategy for domain
            found_strategy = loader.find_strategy(domain)
            
            # Assert: default strategy should be returned
            assert found_strategy is not None, f"No strategy found for {domain}"
            assert found_strategy.attacks == default_strategy.attacks, \
                f"Expected default strategy attacks {default_strategy.attacks}, got {found_strategy.attacks}"
        finally:
            Path(rules_file).unlink()
    
    @given(
        domain=domain_name(),
        other_domain=domain_name(),
        other_strategy=strategy_data(),
        default_strategy=strategy_data()
    )
    @settings(max_examples=100)
    def test_default_strategy_when_other_rules_exist(self, domain, other_domain, other_strategy, default_strategy):
        """
        Test that default strategy is used even when other domain rules exist.
        
        For any domain with no matching rule but other rules exist, default should be used.
        """
        # Ensure domains are different
        assume(domain != other_domain)
        assume(not domain.endswith(f".{other_domain}"))  # domain is not subdomain of other_domain
        assume(not other_domain.endswith(f".{domain}"))  # other_domain is not subdomain of domain
        
        # Ensure strategies are different
        assume(other_strategy.attacks != default_strategy.attacks)
        
        # Create rules with only other_domain
        domain_rules = {
            other_domain: other_strategy
        }
        
        # Create temp file and loader
        rules_file = create_temp_rules_file(domain_rules, default_strategy)
        try:
            loader = StrategyLoader(rules_file)
            loader.load_rules()
            
            # Find strategy for domain (not other_domain)
            found_strategy = loader.find_strategy(domain)
            
            # Assert: default strategy should be returned
            assert found_strategy is not None, f"No strategy found for {domain}"
            assert found_strategy.attacks == default_strategy.attacks, \
                f"Expected default strategy attacks {default_strategy.attacks}, got {found_strategy.attacks}"
        finally:
            Path(rules_file).unlink()
    
    @given(
        domain=domain_name()
    )
    @settings(max_examples=100)
    def test_none_when_no_default_and_no_match(self, domain):
        """
        Test that None is returned when no rules match and no default exists.
        
        For any domain with no matching rules and no default, None should be returned.
        """
        # Create rules file with no domain rules and no default
        domain_rules = {}
        
        # Create temp file and loader
        rules_file = create_temp_rules_file(domain_rules, default_strategy=None)
        try:
            loader = StrategyLoader(rules_file)
            loader.load_rules()
            
            # Find strategy for domain
            found_strategy = loader.find_strategy(domain)
            
            # Assert: None should be returned
            assert found_strategy is None, \
                f"Expected None for {domain} with no rules and no default, got {found_strategy}"
        finally:
            Path(rules_file).unlink()
