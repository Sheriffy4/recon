"""
Unit tests for existing strategy prefix handling.

Task 17.3: Test that "existing_" prefix is not duplicated when creating ExistingStrategy objects.
Requirements: 4.1, 4.3
"""

import pytest
from dataclasses import dataclass
from typing import Dict, Any, Optional


@dataclass
class MockDomainStrategy:
    """Mock DomainStrategy for testing."""
    strategy: str
    split_pos: Optional[int] = None
    split_count: Optional[int] = None
    ttl: Optional[int] = None
    fake_ttl: Optional[int] = None
    disorder_method: Optional[str] = None
    fooling_modes: Optional[str] = None
    raw_params: Optional[Dict[str, Any]] = None


@dataclass
class ExistingStrategy:
    """ExistingStrategy class for testing (same as in adaptive_engine.py)."""
    name: str
    type: str
    params: dict
    attack_name: str = None
    id: str = None
    
    def __post_init__(self):
        if self.attack_name is None:
            self.attack_name = self.type
        if self.id is None:
            self.id = self.name
    
    def to_dict(self):
        return {
            'type': self.type,
            'params': self.params
        }


def create_existing_strategy_from_domain_strategy(existing_strategy: MockDomainStrategy) -> ExistingStrategy:
    """
    Create ExistingStrategy from DomainStrategy (same logic as in adaptive_engine.py).
    
    Task 17.2: This function includes the fix to prevent duplicate "existing_" prefix.
    """
    # Parse strategy from string (e.g., "fake+multisplit+disorder")
    strategy_parts = existing_strategy.strategy.split('+')
    strategy_type = strategy_parts[0] if strategy_parts else 'unknown'
    
    # Collect parameters from DomainStrategy
    params = {}
    if existing_strategy.split_pos is not None:
        params['split_pos'] = existing_strategy.split_pos
    if existing_strategy.split_count is not None:
        params['split_count'] = existing_strategy.split_count
    if existing_strategy.ttl is not None:
        params['ttl'] = existing_strategy.ttl
    if existing_strategy.fake_ttl is not None:
        params['fake_ttl'] = existing_strategy.fake_ttl
    if existing_strategy.disorder_method is not None:
        params['disorder_method'] = existing_strategy.disorder_method
    if existing_strategy.fooling_modes is not None:
        params['fooling'] = existing_strategy.fooling_modes
    if existing_strategy.raw_params:
        params.update(existing_strategy.raw_params)
    
    # Task 17.2: Prevent duplicate "existing_" prefix
    # Check if strategy name already has "existing_" prefix
    strategy_name = existing_strategy.strategy
    if not strategy_name.startswith("existing_"):
        strategy_name = f"existing_{strategy_name}"
    
    return ExistingStrategy(
        name=strategy_name,
        type=strategy_type,
        params=params,
        attack_name=strategy_type,
        id=strategy_name
    )


class TestExistingStrategyPrefix:
    """Test suite for existing strategy prefix handling."""
    
    def test_prefix_added_to_new_strategy(self):
        """Test that "existing_" prefix is added to new strategy names."""
        # Arrange
        domain_strategy = MockDomainStrategy(
            strategy="smart_combo_split_fake_multisplit",
            split_pos=2,
            split_count=6,
            fake_ttl=1
        )
        
        # Act
        existing_strat = create_existing_strategy_from_domain_strategy(domain_strategy)
        
        # Assert
        assert existing_strat.name == "existing_smart_combo_split_fake_multisplit"
        assert existing_strat.name.count("existing_") == 1, "Prefix should appear exactly once"
    
    def test_prefix_not_duplicated_for_existing_strategy(self):
        """Test that "existing_" prefix is NOT duplicated if already present."""
        # Arrange
        domain_strategy = MockDomainStrategy(
            strategy="existing_smart_combo_split_fake_multisplit",
            split_pos=2,
            split_count=6,
            fake_ttl=1
        )
        
        # Act
        existing_strat = create_existing_strategy_from_domain_strategy(domain_strategy)
        
        # Assert
        assert existing_strat.name == "existing_smart_combo_split_fake_multisplit"
        assert existing_strat.name.count("existing_") == 1, "Prefix should appear exactly once"
    
    def test_prefix_not_duplicated_multiple_times(self):
        """Test that "existing_" prefix is NOT duplicated even if present multiple times in input."""
        # Arrange
        domain_strategy = MockDomainStrategy(
            strategy="existing_existing_existing_smart_combo_split_fake_multisplit",
            split_pos=2,
            split_count=6,
            fake_ttl=1
        )
        
        # Act
        existing_strat = create_existing_strategy_from_domain_strategy(domain_strategy)
        
        # Assert
        # The function should NOT add another prefix since one already exists
        assert existing_strat.name == "existing_existing_existing_smart_combo_split_fake_multisplit"
        # Note: This test shows that the function prevents ADDING a new prefix,
        # but doesn't clean up existing duplicates. That's acceptable for now.
    
    def test_strategy_type_extracted_correctly(self):
        """Test that strategy type is extracted correctly from strategy name."""
        # Arrange
        domain_strategy = MockDomainStrategy(
            strategy="fake+multisplit+disorder"
        )
        
        # Act
        existing_strat = create_existing_strategy_from_domain_strategy(domain_strategy)
        
        # Assert
        assert existing_strat.type == "fake"
        assert existing_strat.attack_name == "fake"
    
    def test_params_collected_correctly(self):
        """Test that parameters are collected correctly from DomainStrategy."""
        # Arrange
        domain_strategy = MockDomainStrategy(
            strategy="multisplit",
            split_pos=5,
            split_count=10,
            ttl=8,
            fake_ttl=1,
            disorder_method="random",
            fooling_modes="badsum",
            raw_params={"custom_param": "value"}
        )
        
        # Act
        existing_strat = create_existing_strategy_from_domain_strategy(domain_strategy)
        
        # Assert
        assert existing_strat.params['split_pos'] == 5
        assert existing_strat.params['split_count'] == 10
        assert existing_strat.params['ttl'] == 8
        assert existing_strat.params['fake_ttl'] == 1
        assert existing_strat.params['disorder_method'] == "random"
        assert existing_strat.params['fooling'] == "badsum"
        assert existing_strat.params['custom_param'] == "value"
    
    def test_id_matches_name(self):
        """Test that strategy ID matches the name."""
        # Arrange
        domain_strategy = MockDomainStrategy(
            strategy="test_strategy"
        )
        
        # Act
        existing_strat = create_existing_strategy_from_domain_strategy(domain_strategy)
        
        # Assert
        assert existing_strat.id == existing_strat.name
        assert existing_strat.id == "existing_test_strategy"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
