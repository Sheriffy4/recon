"""
Property-based tests for strategy name normalization.

Tests that strategy name normalization is idempotent and handles equivalence correctly.

Feature: pcap-validator-combo-detection
Property 5: Strategy name normalization idempotence
Requirements: 5.4, 5.5
"""

import pytest
from hypothesis import given, strategies as st, assume
from core.validation.strategy_name_normalizer import StrategyNameNormalizer


# Strategy for generating attack names
attack_names = st.sampled_from([
    'fake', 'split', 'disorder', 'multisplit', 'seqovl',
    'badseq', 'badsum', 'ttl_manipulation'
])


# Strategy for generating strategy names with various formats
@st.composite
def strategy_names(draw):
    """Generate valid strategy names in various formats."""
    # Choose format
    format_type = draw(st.sampled_from(['single', 'combo', 'smart_combo']))
    
    if format_type == 'single':
        # Single attack
        attack = draw(attack_names)
        return attack
    elif format_type == 'combo':
        # combo_X_Y format
        num_attacks = draw(st.integers(min_value=2, max_value=4))
        attacks = [draw(attack_names) for _ in range(num_attacks)]
        return 'combo_' + '_'.join(attacks)
    else:
        # smart_combo_X_Y format
        num_attacks = draw(st.integers(min_value=2, max_value=4))
        attacks = [draw(attack_names) for _ in range(num_attacks)]
        return 'smart_combo_' + '_'.join(attacks)


# Strategy for generating pairs of equivalent strategy names
@st.composite
def equivalent_strategy_pairs(draw):
    """Generate pairs of strategy names that should be equivalent."""
    # Generate base attacks
    num_attacks = draw(st.integers(min_value=1, max_value=3))
    attacks = [draw(attack_names) for _ in range(num_attacks)]
    
    # Create two versions that should be equivalent
    # Version 1: Use multisplit
    attacks_v1 = ['multisplit' if a == 'split' else a for a in attacks]
    
    # Version 2: Use split
    attacks_v2 = ['split' if a == 'multisplit' else a for a in attacks]
    
    # Randomly shuffle order for version 2
    import random
    attacks_v2_shuffled = attacks_v2.copy()
    random.shuffle(attacks_v2_shuffled)
    
    # Choose prefixes
    prefix1 = draw(st.sampled_from(['', 'combo_', 'smart_combo_']))
    prefix2 = draw(st.sampled_from(['', 'combo_', 'smart_combo_']))
    
    # Build strategy names
    if len(attacks_v1) == 1:
        strategy1 = attacks_v1[0]
        strategy2 = attacks_v2_shuffled[0]
    else:
        strategy1 = prefix1 + '_'.join(attacks_v1) if prefix1 else '_'.join(attacks_v1)
        strategy2 = prefix2 + '_'.join(attacks_v2_shuffled) if prefix2 else '_'.join(attacks_v2_shuffled)
    
    return strategy1, strategy2


class TestStrategyNameNormalizerProperties:
    """Property-based tests for strategy name normalization."""
    
    @given(strategy_names())
    def test_normalization_is_idempotent(self, strategy_name):
        """
        **Feature: pcap-validator-combo-detection, Property 5: Strategy name normalization idempotence**
        
        For any strategy name, normalizing it twice should produce the same
        result as normalizing it once: normalize(normalize(x)) == normalize(x)
        
        **Validates: Requirements 5.4, 5.5**
        """
        # Normalize once
        normalized_once = StrategyNameNormalizer.normalize(strategy_name)
        
        # Normalize twice
        normalized_twice = StrategyNameNormalizer.normalize(normalized_once)
        
        # Should be the same
        assert normalized_once == normalized_twice, \
            f"Normalization not idempotent: normalize('{strategy_name}') = '{normalized_once}', " \
            f"but normalize(normalize('{strategy_name}')) = '{normalized_twice}'"
    
    @given(equivalent_strategy_pairs())
    def test_equivalent_strategies_normalize_to_same_value(self, strategy_pair):
        """
        **Feature: pcap-validator-combo-detection, Property 5: Strategy name normalization idempotence**
        
        For any pair of strategy names that differ only in:
        - multisplit vs split
        - attack order
        - prefix conventions
        
        They should normalize to the same value.
        
        **Validates: Requirements 5.4, 5.5**
        """
        strategy1, strategy2 = strategy_pair
        
        # Normalize both
        normalized1 = StrategyNameNormalizer.normalize(strategy1)
        normalized2 = StrategyNameNormalizer.normalize(strategy2)
        
        # Should be equal
        assert normalized1 == normalized2, \
            f"Expected equivalent strategies to normalize to same value: " \
            f"'{strategy1}' → '{normalized1}', '{strategy2}' → '{normalized2}'"
    
    @given(equivalent_strategy_pairs())
    def test_are_equivalent_returns_true_for_equivalent_pairs(self, strategy_pair):
        """
        **Feature: pcap-validator-combo-detection, Property 5: Strategy name normalization idempotence**
        
        For any pair of equivalent strategy names, are_equivalent should return True.
        
        **Validates: Requirements 5.4, 5.5**
        """
        strategy1, strategy2 = strategy_pair
        
        # Should be equivalent
        assert StrategyNameNormalizer.are_equivalent(strategy1, strategy2), \
            f"Expected strategies to be equivalent: '{strategy1}' and '{strategy2}'"
    
    @given(strategy_names())
    def test_strategy_is_equivalent_to_itself(self, strategy_name):
        """
        **Feature: pcap-validator-combo-detection, Property 5: Strategy name normalization idempotence**
        
        For any strategy name, it should be equivalent to itself.
        
        **Validates: Requirements 5.4, 5.5**
        """
        assert StrategyNameNormalizer.are_equivalent(strategy_name, strategy_name), \
            f"Strategy should be equivalent to itself: '{strategy_name}'"
    
    @given(strategy_names())
    def test_normalized_name_has_no_prefix(self, strategy_name):
        """
        **Feature: pcap-validator-combo-detection, Property 5: Strategy name normalization idempotence**
        
        For any strategy name, the normalized version should not contain
        'smart_combo_' or 'combo_' prefixes.
        
        **Validates: Requirements 5.1**
        """
        # Skip special values
        assume(strategy_name not in ('none', 'unknown', ''))
        
        normalized = StrategyNameNormalizer.normalize(strategy_name)
        
        # Should not have prefixes
        assert not normalized.startswith('smart_combo_'), \
            f"Normalized name should not have 'smart_combo_' prefix: '{normalized}'"
        assert not normalized.startswith('combo_'), \
            f"Normalized name should not have 'combo_' prefix: '{normalized}'"
    
    @given(strategy_names())
    def test_multisplit_normalizes_to_split(self, strategy_name):
        """
        **Feature: pcap-validator-combo-detection, Property 5: Strategy name normalization idempotence**
        
        For any strategy name containing 'multisplit', the normalized version
        should contain 'split' instead.
        
        **Validates: Requirements 5.3**
        """
        # Only test if strategy contains multisplit
        assume('multisplit' in strategy_name)
        
        normalized = StrategyNameNormalizer.normalize(strategy_name)
        
        # Should not contain multisplit
        assert 'multisplit' not in normalized, \
            f"Normalized name should not contain 'multisplit': '{normalized}'"
        
        # Should contain split (unless it was the only attack and got replaced)
        # Actually, multisplit should always become split
        assert 'split' in normalized, \
            f"Normalized name should contain 'split' when original had 'multisplit': '{normalized}'"
    
    @given(st.sampled_from(['', 'none', 'unknown']))
    def test_special_values_are_preserved(self, special_value):
        """
        **Feature: pcap-validator-combo-detection, Property 5: Strategy name normalization idempotence**
        
        For special values (empty, 'none', 'unknown'), normalization should
        preserve them as-is.
        
        **Validates: Requirements 5.2**
        """
        normalized = StrategyNameNormalizer.normalize(special_value)
        
        assert normalized == special_value, \
            f"Special value should be preserved: '{special_value}' → '{normalized}'"
    
    @given(strategy_names(), strategy_names())
    def test_are_equivalent_is_symmetric(self, strategy1, strategy2):
        """
        **Feature: pcap-validator-combo-detection, Property 5: Strategy name normalization idempotence**
        
        For any two strategy names, are_equivalent should be symmetric:
        are_equivalent(A, B) == are_equivalent(B, A)
        
        **Validates: Requirements 5.4, 5.5**
        """
        result1 = StrategyNameNormalizer.are_equivalent(strategy1, strategy2)
        result2 = StrategyNameNormalizer.are_equivalent(strategy2, strategy1)
        
        assert result1 == result2, \
            f"are_equivalent should be symmetric: " \
            f"are_equivalent('{strategy1}', '{strategy2}') = {result1}, " \
            f"but are_equivalent('{strategy2}', '{strategy1}') = {result2}"
    
    @given(strategy_names())
    def test_normalized_attacks_are_sorted(self, strategy_name):
        """
        **Feature: pcap-validator-combo-detection, Property 5: Strategy name normalization idempotence**
        
        For any strategy name with multiple attacks, the normalized version
        should have attacks in sorted order.
        
        **Validates: Requirements 5.5**
        """
        # Skip special values and single attacks
        assume(strategy_name not in ('none', 'unknown', ''))
        assume('_' in strategy_name or strategy_name in ['fake', 'split', 'disorder', 'multisplit', 'seqovl', 'badseq', 'badsum', 'ttl_manipulation'])
        
        normalized = StrategyNameNormalizer.normalize(strategy_name)
        
        # Skip special values
        if normalized in ('none', 'unknown', ''):
            return
        
        # Skip special combos like 'fakeddisorder'
        if normalized == 'fakeddisorder':
            return
        
        # Split into components
        components = normalized.split('_')
        
        # If multiple components, they should be sorted
        if len(components) > 1:
            sorted_components = sorted(components)
            assert components == sorted_components, \
                f"Normalized attacks should be sorted: '{normalized}' has {components}, expected {sorted_components}"


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--hypothesis-show-statistics'])
