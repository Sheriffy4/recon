"""
Property-based tests for PCAPAnalyzer combo strategy detection.

Tests that combo strategy reconstruction works correctly across all inputs.

Feature: pcap-validator-combo-detection
Properties: 1, 2, 3
Requirements: 1.1, 1.3, 1.5, 2.1, 3.1, 3.2, 3.3, 3.5
"""

import pytest
from hypothesis import given, strategies as st, assume
from core.pcap.analyzer import PCAPAnalyzer, CORE_ATTACKS_ORDER, FOOLING_LABELS


# Strategy for generating attack names
core_attack_names = st.sampled_from(['fake', 'split', 'disorder', 'multisplit', 'seqovl'])
fooling_attack_names = st.sampled_from(['badsum', 'badseq', 'ttl_manipulation'])
all_attack_names = st.sampled_from([
    'fake', 'split', 'disorder', 'multisplit', 'seqovl',
    'badsum', 'badseq', 'ttl_manipulation'
])


@st.composite
def attack_lists(draw, min_attacks=1, max_attacks=5, include_fooling=True):
    """Generate lists of attack names."""
    num_attacks = draw(st.integers(min_value=min_attacks, max_value=max_attacks))
    
    if include_fooling:
        attacks = [draw(all_attack_names) for _ in range(num_attacks)]
    else:
        attacks = [draw(core_attack_names) for _ in range(num_attacks)]
    
    return attacks


@st.composite
def core_attack_with_fooling(draw):
    """Generate a core attack paired with a fooling attack."""
    core = draw(core_attack_names)
    fooling = draw(fooling_attack_names)
    return [core, fooling]


class TestComboStrategyReconstructionProperties:
    """Property-based tests for combo strategy reconstruction."""
    
    @given(st.lists(st.sampled_from(['fake', 'disorder', 'seqovl']), min_size=2, max_size=4))
    def test_combo_strategy_reconstruction_is_order_independent(self, attacks):
        """
        **Feature: pcap-validator-combo-detection, Property 1: Combo strategy reconstruction correctness**
        
        For any list of detected attacks, the strategy_type should be the same
        regardless of the order in which attacks appear in the input list.
        
        Note: This test uses a constrained set of attacks (fake, disorder, seqovl)
        to avoid edge cases with split/multisplit equivalence.
        
        **Validates: Requirements 1.1, 1.3, 1.5**
        """
        # Skip if only one unique attack
        assume(len(set(attacks)) > 1)
        
        analyzer = PCAPAnalyzer()
        
        # Get strategy type for original order
        strategy_type1, combo_attacks1 = analyzer._determine_strategy_type_from_attacks(attacks)
        
        # Shuffle the attacks
        import random
        shuffled_attacks = attacks.copy()
        random.shuffle(shuffled_attacks)
        
        # Get strategy type for shuffled order
        strategy_type2, combo_attacks2 = analyzer._determine_strategy_type_from_attacks(shuffled_attacks)
        
        # Should produce the same strategy type
        assert strategy_type1 == strategy_type2, \
            f"Strategy type should be order-independent: " \
            f"attacks={attacks} → '{strategy_type1}', " \
            f"shuffled={shuffled_attacks} → '{strategy_type2}'"
        
        # Combo attacks should be the same (as sets, since order is normalized)
        assert set(combo_attacks1) == set(combo_attacks2), \
            f"Combo attacks should be the same: " \
            f"attacks={attacks} → {combo_attacks1}, " \
            f"shuffled={shuffled_attacks} → {combo_attacks2}"
    
    @given(attack_lists(min_attacks=1, max_attacks=5))
    def test_fooling_attacks_are_filtered_from_strategy_name(self, attacks):
        """
        **Feature: pcap-validator-combo-detection, Property 1: Combo strategy reconstruction correctness**
        
        For any list of detected attacks, fooling attacks (badsum, badseq, seqovl, ttl_manipulation)
        should be filtered out from the strategy name.
        
        **Validates: Requirements 1.1, 1.3, 1.5**
        """
        analyzer = PCAPAnalyzer()
        
        strategy_type, combo_attacks = analyzer._determine_strategy_type_from_attacks(attacks)
        
        # If we have a strategy type, it should not contain fooling attack names
        if strategy_type and strategy_type not in ('none', 'unknown'):
            for fooling in FOOLING_LABELS:
                # Check if fooling attack is in the strategy name
                # (unless it's the ONLY attack detected)
                main_attacks = [a for a in attacks if a not in FOOLING_LABELS]
                if main_attacks:  # If there are non-fooling attacks
                    assert fooling not in strategy_type, \
                        f"Fooling attack '{fooling}' should not appear in strategy type: " \
                        f"attacks={attacks} → strategy_type='{strategy_type}'"
        
        # Combo attacks should not contain fooling attacks
        for attack in combo_attacks:
            assert attack not in FOOLING_LABELS, \
                f"Combo attacks should not contain fooling attacks: " \
                f"attacks={attacks} → combo_attacks={combo_attacks}, " \
                f"but '{attack}' is a fooling attack"
    
    @given(attack_lists(min_attacks=1, max_attacks=5))
    def test_duplicates_are_removed(self, attacks):
        """
        **Feature: pcap-validator-combo-detection, Property 1: Combo strategy reconstruction correctness**
        
        For any list of detected attacks with duplicates, the strategy_type
        should only include each attack once.
        
        **Validates: Requirements 1.1, 1.3, 1.5**
        """
        analyzer = PCAPAnalyzer()
        
        # Add some duplicates
        attacks_with_dupes = attacks + attacks[:min(2, len(attacks))]
        
        strategy_type, combo_attacks = analyzer._determine_strategy_type_from_attacks(attacks_with_dupes)
        
        # Combo attacks should have no duplicates
        assert len(combo_attacks) == len(set(combo_attacks)), \
            f"Combo attacks should not contain duplicates: " \
            f"attacks={attacks_with_dupes} → combo_attacks={combo_attacks}"
        
        # If strategy type is a combo, count underscores to verify no duplicates
        if strategy_type and strategy_type.startswith('smart_combo_'):
            parts = strategy_type.replace('smart_combo_', '').split('_')
            assert len(parts) == len(set(parts)), \
                f"Strategy type should not contain duplicate attacks: " \
                f"attacks={attacks_with_dupes} → strategy_type='{strategy_type}'"
    
    @given(attack_lists(min_attacks=2, max_attacks=5, include_fooling=False))
    def test_attacks_are_sorted_by_priority(self, attacks):
        """
        **Feature: pcap-validator-combo-detection, Property 1: Combo strategy reconstruction correctness**
        
        For any list of detected attacks, the strategy_type should have attacks
        sorted according to CORE_ATTACKS_ORDER priority.
        
        **Validates: Requirements 1.1, 1.3, 1.5**
        """
        # Skip if all attacks are the same
        assume(len(set(attacks)) > 1)
        
        analyzer = PCAPAnalyzer()
        
        strategy_type, combo_attacks = analyzer._determine_strategy_type_from_attacks(attacks)
        
        # If we have multiple combo attacks, they should be sorted by priority
        if len(combo_attacks) > 1:
            # Get priorities
            priorities = [CORE_ATTACKS_ORDER.get(a, 99) for a in combo_attacks]
            
            # Should be in ascending order
            assert priorities == sorted(priorities), \
                f"Combo attacks should be sorted by priority: " \
                f"attacks={attacks} → combo_attacks={combo_attacks}, " \
                f"priorities={priorities}, expected={sorted(priorities)}"
    
    @given(st.just([]))
    def test_empty_list_returns_none(self, attacks):
        """
        **Feature: pcap-validator-combo-detection, Property 1: Combo strategy reconstruction correctness**
        
        For an empty list of attacks, the strategy_type should be None.
        
        **Validates: Requirements 1.1, 1.3, 1.5**
        """
        analyzer = PCAPAnalyzer()
        
        strategy_type, combo_attacks = analyzer._determine_strategy_type_from_attacks(attacks)
        
        assert strategy_type is None, \
            f"Empty attack list should return None: strategy_type='{strategy_type}'"
        assert combo_attacks == [], \
            f"Empty attack list should return empty combo_attacks: combo_attacks={combo_attacks}"
    
    @given(st.just(['fake', 'disorder']))
    def test_fake_disorder_special_case(self, attacks):
        """
        **Feature: pcap-validator-combo-detection, Property 1: Combo strategy reconstruction correctness**
        
        For the special case of fake + disorder (in any order), the strategy_type
        should be 'fakeddisorder'.
        
        **Validates: Requirements 1.1, 1.3, 1.5**
        """
        analyzer = PCAPAnalyzer()
        
        # Test both orders
        for attack_order in [['fake', 'disorder'], ['disorder', 'fake']]:
            strategy_type, combo_attacks = analyzer._determine_strategy_type_from_attacks(attack_order)
            
            assert strategy_type == 'fakeddisorder', \
                f"fake + disorder should produce 'fakeddisorder': " \
                f"attacks={attack_order} → strategy_type='{strategy_type}'"
    
    @given(attack_lists(min_attacks=2, max_attacks=5, include_fooling=False))
    def test_multiple_attacks_produce_smart_combo(self, attacks):
        """
        **Feature: pcap-validator-combo-detection, Property 1: Combo strategy reconstruction correctness**
        
        For any list with multiple core attacks (excluding fake+disorder special case),
        the strategy_type should start with 'smart_combo_'.
        
        **Validates: Requirements 1.1, 1.3, 1.5**
        """
        # Skip if only one unique attack
        assume(len(set(attacks)) > 1)
        
        # Skip fake+disorder special case
        assume(set(attacks) != {'fake', 'disorder'})
        
        analyzer = PCAPAnalyzer()
        
        strategy_type, combo_attacks = analyzer._determine_strategy_type_from_attacks(attacks)
        
        assert strategy_type.startswith('smart_combo_'), \
            f"Multiple attacks should produce 'smart_combo_' prefix: " \
            f"attacks={attacks} → strategy_type='{strategy_type}'"
    
    @given(core_attack_names)
    def test_single_attack_returns_attack_name(self, attack):
        """
        **Feature: pcap-validator-combo-detection, Property 1: Combo strategy reconstruction correctness**
        
        For a single core attack, the strategy_type should be the attack name itself.
        
        **Validates: Requirements 1.1, 1.3, 1.5**
        """
        analyzer = PCAPAnalyzer()
        
        strategy_type, combo_attacks = analyzer._determine_strategy_type_from_attacks([attack])
        
        assert strategy_type == attack, \
            f"Single attack should return attack name: " \
            f"attacks=['{attack}'] → strategy_type='{strategy_type}'"
        
        assert combo_attacks == [attack], \
            f"Single attack should return attack in combo_attacks: " \
            f"attacks=['{attack}'] → combo_attacks={combo_attacks}"


class TestFoolingAttackAttributionProperties:
    """Property-based tests for fooling attack attribution."""
    
    @given(core_attack_with_fooling())
    def test_fooling_attacks_filtered_with_core_attack(self, attacks):
        """
        **Feature: pcap-validator-combo-detection, Property 2: Fooling attack attribution**
        
        For any combination of core attack + fooling attack, the fooling attack
        should be filtered from the strategy name.
        
        **Validates: Requirements 2.1**
        """
        analyzer = PCAPAnalyzer()
        
        strategy_type, combo_attacks = analyzer._determine_strategy_type_from_attacks(attacks)
        
        # Get the core and fooling attacks
        core = [a for a in attacks if a not in FOOLING_LABELS]
        fooling = [a for a in attacks if a in FOOLING_LABELS]
        
        # Strategy type should only contain core attacks
        for f in fooling:
            assert f not in strategy_type, \
                f"Fooling attack '{f}' should not appear in strategy type: " \
                f"attacks={attacks} → strategy_type='{strategy_type}'"
        
        # Combo attacks should only contain core attacks
        for attack in combo_attacks:
            assert attack not in FOOLING_LABELS, \
                f"Combo attacks should not contain fooling attacks: " \
                f"attacks={attacks} → combo_attacks={combo_attacks}"
    
    @given(fooling_attack_names)
    def test_only_fooling_attacks_returns_first_attack(self, fooling):
        """
        **Feature: pcap-validator-combo-detection, Property 2: Fooling attack attribution**
        
        For a list containing only fooling attacks, the strategy_type should be
        the first fooling attack.
        
        **Validates: Requirements 2.1**
        """
        analyzer = PCAPAnalyzer()
        
        attacks = [fooling]
        strategy_type, combo_attacks = analyzer._determine_strategy_type_from_attacks(attacks)
        
        assert strategy_type == fooling, \
            f"Only fooling attacks should return first attack: " \
            f"attacks={attacks} → strategy_type='{strategy_type}'"
        
        assert combo_attacks == [], \
            f"Only fooling attacks should return empty combo_attacks: " \
            f"attacks={attacks} → combo_attacks={combo_attacks}"
    
    @given(st.lists(core_attack_names, min_size=1, max_size=3), st.lists(fooling_attack_names, min_size=1, max_size=3))
    def test_mixed_core_and_fooling_filters_fooling(self, core_attacks, fooling_attacks):
        """
        **Feature: pcap-validator-combo-detection, Property 2: Fooling attack attribution**
        
        For any mix of core and fooling attacks, only core attacks should appear
        in the strategy name.
        
        **Validates: Requirements 2.1**
        """
        analyzer = PCAPAnalyzer()
        
        attacks = core_attacks + fooling_attacks
        strategy_type, combo_attacks = analyzer._determine_strategy_type_from_attacks(attacks)
        
        # All combo attacks should be core attacks
        for attack in combo_attacks:
            assert attack not in FOOLING_LABELS, \
                f"Combo attacks should only contain core attacks: " \
                f"attacks={attacks} → combo_attacks={combo_attacks}, " \
                f"but '{attack}' is a fooling attack"
        
        # Strategy type should not contain fooling attack names
        for fooling in fooling_attacks:
            assert fooling not in strategy_type, \
                f"Strategy type should not contain fooling attacks: " \
                f"attacks={attacks} → strategy_type='{strategy_type}', " \
                f"but contains '{fooling}'"


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--hypothesis-show-statistics'])



class TestPCAPAnalyzerResultCompletenessProperties:
    """Property-based tests for PCAPAnalyzer result completeness."""
    
    @given(attack_lists(min_attacks=0, max_attacks=5))
    def test_result_always_has_strategy_type_and_combo_attacks(self, attacks):
        """
        **Feature: pcap-validator-combo-detection, Property 3: PCAPAnalyzer result completeness**
        
        For any list of detected attacks, _determine_strategy_type_from_attacks
        must return a tuple with both strategy_type and combo_attacks.
        
        **Validates: Requirements 3.1, 3.2, 3.3, 3.5**
        """
        analyzer = PCAPAnalyzer()
        
        result = analyzer._determine_strategy_type_from_attacks(attacks)
        
        # Should return a tuple
        assert isinstance(result, tuple), \
            f"Result should be a tuple: attacks={attacks} → result={result}"
        
        # Should have exactly 2 elements
        assert len(result) == 2, \
            f"Result should have 2 elements: attacks={attacks} → result={result}"
        
        strategy_type, combo_attacks = result
        
        # combo_attacks should always be a list
        assert isinstance(combo_attacks, list), \
            f"combo_attacks should be a list: attacks={attacks} → combo_attacks={combo_attacks}"
    
    @given(attack_lists(min_attacks=0, max_attacks=5))
    def test_strategy_type_none_only_when_no_attacks(self, attacks):
        """
        **Feature: pcap-validator-combo-detection, Property 3: PCAPAnalyzer result completeness**
        
        For any list of detected attacks, strategy_type should be None only
        when the attack list is empty.
        
        **Validates: Requirements 3.1, 3.2, 3.3, 3.5**
        """
        analyzer = PCAPAnalyzer()
        
        strategy_type, combo_attacks = analyzer._determine_strategy_type_from_attacks(attacks)
        
        if not attacks:
            # Empty list should return None
            assert strategy_type is None, \
                f"Empty attack list should return None: attacks={attacks} → strategy_type='{strategy_type}'"
        else:
            # Non-empty list should return a strategy type
            assert strategy_type is not None, \
                f"Non-empty attack list should return strategy_type: attacks={attacks} → strategy_type='{strategy_type}'"
    
    @given(attack_lists(min_attacks=1, max_attacks=5))
    def test_combo_attacks_contains_only_non_fooling_attacks(self, attacks):
        """
        **Feature: pcap-validator-combo-detection, Property 3: PCAPAnalyzer result completeness**
        
        For any list of detected attacks, combo_attacks should only contain
        non-fooling attacks (not badsum, badseq, seqovl, ttl_manipulation).
        
        **Validates: Requirements 3.1, 3.2, 3.3, 3.5**
        """
        analyzer = PCAPAnalyzer()
        
        strategy_type, combo_attacks = analyzer._determine_strategy_type_from_attacks(attacks)
        
        # Get main attacks (non-fooling)
        main_attacks = [a for a in attacks if a not in FOOLING_LABELS]
        
        if main_attacks:
            # If there are main attacks, combo_attacks should only contain them
            for attack in combo_attacks:
                assert attack not in FOOLING_LABELS, \
                    f"combo_attacks should not contain fooling attacks: " \
                    f"attacks={attacks} → combo_attacks={combo_attacks}, " \
                    f"but '{attack}' is a fooling attack"
        else:
            # If only fooling attacks, combo_attacks should be empty
            assert combo_attacks == [], \
                f"combo_attacks should be empty when only fooling attacks present: " \
                f"attacks={attacks} → combo_attacks={combo_attacks}"
    
    @given(attack_lists(min_attacks=1, max_attacks=5))
    def test_combo_attacks_is_subset_of_detected_attacks(self, attacks):
        """
        **Feature: pcap-validator-combo-detection, Property 3: PCAPAnalyzer result completeness**
        
        For any list of detected attacks, combo_attacks should be a subset
        of the detected attacks (after filtering fooling attacks).
        
        **Validates: Requirements 3.1, 3.2, 3.3, 3.5**
        """
        analyzer = PCAPAnalyzer()
        
        strategy_type, combo_attacks = analyzer._determine_strategy_type_from_attacks(attacks)
        
        # Get main attacks (non-fooling)
        main_attacks = [a for a in attacks if a not in FOOLING_LABELS]
        
        # combo_attacks should be a subset of main_attacks
        for attack in combo_attacks:
            assert attack in main_attacks, \
                f"combo_attacks should be subset of main attacks: " \
                f"attacks={attacks} → main_attacks={main_attacks}, " \
                f"combo_attacks={combo_attacks}, but '{attack}' not in main_attacks"
    
    @given(attack_lists(min_attacks=2, max_attacks=5, include_fooling=False))
    def test_strategy_type_contains_all_combo_attacks(self, attacks):
        """
        **Feature: pcap-validator-combo-detection, Property 3: PCAPAnalyzer result completeness**
        
        For any list of detected attacks, if strategy_type is a combo,
        it should contain all attacks from combo_attacks.
        
        **Validates: Requirements 3.1, 3.2, 3.3, 3.5**
        """
        # Skip if only one unique attack
        assume(len(set(attacks)) > 1)
        
        # Skip fake+disorder special case
        assume(set(attacks) != {'fake', 'disorder'})
        
        analyzer = PCAPAnalyzer()
        
        strategy_type, combo_attacks = analyzer._determine_strategy_type_from_attacks(attacks)
        
        # If strategy_type is a combo, it should contain all combo_attacks
        if strategy_type and strategy_type.startswith('smart_combo_'):
            strategy_parts = strategy_type.replace('smart_combo_', '').split('_')
            
            for attack in combo_attacks:
                assert attack in strategy_parts, \
                    f"strategy_type should contain all combo_attacks: " \
                    f"attacks={attacks} → strategy_type='{strategy_type}', " \
                    f"combo_attacks={combo_attacks}, but '{attack}' not in strategy_type"


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--hypothesis-show-statistics'])
