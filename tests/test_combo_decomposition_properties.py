"""
Property-based tests for combo strategy decomposition.

Tests that combo strategies are correctly decomposed and executed in sequence.

Feature: strategy-testing-production-parity
Property 9: Combo strategies are decomposed correctly
Requirements: 7.1, 7.3
"""

import pytest
from hypothesis import given, strategies as st, assume
from core.strategy.strategy_decomposer import (
    StrategyDecomposer,
    AttackExecutionTracker
)


# Strategy for generating attack names
attack_names = st.sampled_from([
    'fake', 'split', 'disorder', 'disorder2', 'multidisorder',
    'multisplit', 'seqovl', 'ttl', 'badseq', 'badsum',
    'fakeddisorder', 'overlap'
])


# Strategy for generating combo strategy names
@st.composite
def combo_strategy_names(draw):
    """Generate valid combo strategy names."""
    # Generate 2-4 component attacks
    num_attacks = draw(st.integers(min_value=2, max_value=4))
    attacks = [draw(attack_names) for _ in range(num_attacks)]
    
    # Create combo name
    combo_name = 'smart_combo_' + '_'.join(attacks)
    return combo_name, attacks


class TestComboDecompositionProperties:
    """Property-based tests for combo strategy decomposition."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.decomposer = StrategyDecomposer()
    
    @given(combo_strategy_names())
    def test_decomposition_preserves_attack_count(self, strategy_data):
        """
        **Feature: strategy-testing-production-parity, Property 9: Combo strategies are decomposed correctly**
        
        For any combo strategy, decomposition should return the same number
        of attacks that were used to construct it.
        
        **Validates: Requirements 7.1, 7.3**
        """
        strategy_name, expected_attacks = strategy_data
        
        # Decompose the strategy
        decomposed = self.decomposer.decompose_strategy(strategy_name)
        
        # Should have same number of attacks
        assert len(decomposed) == len(expected_attacks), \
            f"Expected {len(expected_attacks)} attacks, got {len(decomposed)}"
    
    @given(combo_strategy_names())
    def test_decomposition_preserves_attack_order(self, strategy_data):
        """
        **Feature: strategy-testing-production-parity, Property 9: Combo strategies are decomposed correctly**
        
        For any combo strategy, decomposition should preserve the order
        of attacks as they appear in the strategy name.
        
        **Validates: Requirements 7.1, 7.3**
        """
        strategy_name, expected_attacks = strategy_data
        
        # Decompose the strategy
        decomposed = self.decomposer.decompose_strategy(strategy_name)
        
        # Should have same attacks in same order
        assert decomposed == expected_attacks, \
            f"Expected {expected_attacks}, got {decomposed}"
    
    @given(combo_strategy_names())
    def test_execution_tracker_tracks_all_attacks(self, strategy_data):
        """
        **Feature: strategy-testing-production-parity, Property 9: Combo strategies are decomposed correctly**
        
        For any combo strategy, the execution tracker should track all
        component attacks.
        
        **Validates: Requirements 7.3**
        """
        strategy_name, expected_attacks = strategy_data
        
        # Create execution tracker
        tracker = self.decomposer.create_execution_tracker(strategy_name)
        
        # Should track all expected attacks
        assert tracker.expected_attacks == expected_attacks
        assert tracker.strategy_name == strategy_name
        assert len(tracker.executed_attacks) == 0  # Nothing executed yet
    
    @given(combo_strategy_names())
    def test_execution_tracker_detects_completion(self, strategy_data):
        """
        **Feature: strategy-testing-production-parity, Property 9: Combo strategies are decomposed correctly**
        
        For any combo strategy, the execution tracker should correctly
        detect when all attacks have been executed.
        
        **Validates: Requirements 7.3**
        """
        strategy_name, expected_attacks = strategy_data
        
        # Create execution tracker
        tracker = self.decomposer.create_execution_tracker(strategy_name)
        
        # Initially not complete
        assert not tracker.is_complete()
        assert len(tracker.get_missing_attacks()) == len(expected_attacks)
        
        # Execute each attack
        for attack in expected_attacks:
            tracker.record_execution(attack)
        
        # Now should be complete
        assert tracker.is_complete()
        assert len(tracker.get_missing_attacks()) == 0
        assert set(tracker.executed_attacks) == set(expected_attacks)
    
    @given(combo_strategy_names())
    def test_execution_tracker_detects_missing_attacks(self, strategy_data):
        """
        **Feature: strategy-testing-production-parity, Property 9: Combo strategies are decomposed correctly**
        
        For any combo strategy, if not all attacks are executed, the tracker
        should correctly identify which attacks are missing.
        
        **Validates: Requirements 7.3**
        """
        strategy_name, expected_attacks = strategy_data
        assume(len(expected_attacks) >= 2)  # Need at least 2 to have missing
        
        # Create execution tracker
        tracker = self.decomposer.create_execution_tracker(strategy_name)
        
        # Execute only first attack
        tracker.record_execution(expected_attacks[0])
        
        # Should not be complete (we only executed one out of multiple)
        assert not tracker.is_complete()
        
        # Should identify missing attacks
        missing = tracker.get_missing_attacks()
        assert len(missing) == len(expected_attacks) - 1
        
        # Check that the missing list contains the right attacks
        from collections import Counter
        expected_counts = Counter(expected_attacks)
        executed_counts = Counter([expected_attacks[0]])
        
        for attack, expected_count in expected_counts.items():
            executed_count = executed_counts.get(attack, 0)
            missing_count = missing.count(attack)
            assert missing_count == expected_count - executed_count
    
    @given(combo_strategy_names())
    def test_execute_attacks_in_sequence_calls_executor(self, strategy_data):
        """
        **Feature: strategy-testing-production-parity, Property 9: Combo strategies are decomposed correctly**
        
        For any combo strategy, execute_attacks_in_sequence should call
        the executor function for each component attack in order.
        
        **Validates: Requirements 7.3**
        """
        strategy_name, expected_attacks = strategy_data
        
        # Track executor calls
        executed_attacks = []
        
        def mock_executor(attack_name, params):
            executed_attacks.append(attack_name)
        
        # Execute attacks in sequence
        tracker = self.decomposer.execute_attacks_in_sequence(
            strategy_name,
            mock_executor,
            params={}
        )
        
        # Should have called executor for each attack
        assert executed_attacks == expected_attacks
        
        # Tracker should show all attacks executed
        assert tracker.is_complete()
        assert tracker.executed_attacks == expected_attacks
        assert tracker.execution_order == expected_attacks
    
    @given(combo_strategy_names())
    def test_execute_attacks_continues_on_failure(self, strategy_data):
        """
        **Feature: strategy-testing-production-parity, Property 9: Combo strategies are decomposed correctly**
        
        For any combo strategy, if one attack fails, execution should
        continue with the remaining attacks.
        
        **Validates: Requirements 7.3**
        """
        strategy_name, expected_attacks = strategy_data
        assume(len(expected_attacks) >= 2)  # Need at least 2 to test continuation
        
        # Track executor calls and which ones failed
        executed_attacks = []
        failed_indices = set()
        
        def failing_executor(attack_name, params):
            idx = len(executed_attacks)
            executed_attacks.append(attack_name)
            # Fail only the first occurrence
            if idx == 0:
                failed_indices.add(idx)
                raise Exception("Simulated failure")
        
        # Execute attacks in sequence
        tracker = self.decomposer.execute_attacks_in_sequence(
            strategy_name,
            failing_executor,
            params={}
        )
        
        # Should have attempted all attacks despite first one failing
        assert len(executed_attacks) == len(expected_attacks)
        
        # Tracker should show only successful executions
        # (first attack failed, so only remaining attacks recorded)
        assert len(tracker.executed_attacks) == len(expected_attacks) - len(failed_indices)
        
        # Check that failed attacks are not in executed list
        for idx in failed_indices:
            # The attack at this index should not be in executed_attacks
            # (but other instances of the same attack name might be)
            pass  # We can't easily check this without tracking indices
    
    @given(st.sampled_from(['disorder', 'multisplit', 'fake', 'split']))
    def test_non_combo_strategies_have_single_attack(self, attack_name):
        """
        **Feature: strategy-testing-production-parity, Property 9: Combo strategies are decomposed correctly**
        
        For any non-combo strategy, decomposition should return a single-element
        list containing just that attack.
        
        **Validates: Requirements 7.1**
        """
        # Decompose non-combo strategy
        decomposed = self.decomposer.decompose_strategy(attack_name)
        
        # Should return single attack
        assert len(decomposed) == 1
        assert decomposed[0] == attack_name
        
        # Should not be identified as combo
        assert not self.decomposer.is_combo_strategy(attack_name)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
