"""
Unit tests for strategy decomposition.

Tests the parsing of combo strategy names into component attacks.

Feature: strategy-testing-production-parity
Requirements: 7.1, 7.2
"""

import pytest
from core.strategy.strategy_decomposer import StrategyDecomposer, decompose_strategy


class TestStrategyDecomposition:
    """Test suite for strategy decomposition functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.decomposer = StrategyDecomposer()
    
    def test_smart_combo_split_fake_decomposition(self):
        """
        Verify smart_combo_split_fake → ['split', 'fake']
        
        **Validates: Requirements 7.2**
        """
        # Test the specific case from the requirements
        result = self.decomposer.decompose_strategy('smart_combo_split_fake')
        assert result == ['split', 'fake'], f"Expected ['split', 'fake'], got {result}"
    
    def test_smart_combo_fake_split_decomposition(self):
        """Test smart_combo_fake_split → ['fake', 'split']"""
        result = self.decomposer.decompose_strategy('smart_combo_fake_split')
        assert result == ['fake', 'split']
    
    def test_smart_combo_multisplit_disorder(self):
        """Test smart_combo_multisplit_disorder → ['multisplit', 'disorder']"""
        result = self.decomposer.decompose_strategy('smart_combo_multisplit_disorder')
        assert result == ['multisplit', 'disorder']
    
    def test_smart_combo_single_attack(self):
        """Test smart_combo_split → ['split']"""
        result = self.decomposer.decompose_strategy('smart_combo_split')
        assert result == ['split']
    
    def test_existing_smart_combo_prefix(self):
        """Test existing_smart_combo_split_fake → ['split', 'fake']"""
        result = self.decomposer.decompose_strategy('existing_smart_combo_split_fake')
        assert result == ['split', 'fake']
    
    def test_non_combo_strategy(self):
        """Test regular attack names are returned as-is"""
        result = self.decomposer.decompose_strategy('disorder')
        assert result == ['disorder']
        
        result = self.decomposer.decompose_strategy('multisplit')
        assert result == ['multisplit']
    
    def test_empty_strategy_name(self):
        """Test empty strategy name returns empty list"""
        result = self.decomposer.decompose_strategy('')
        assert result == []
    
    def test_none_strategy_name(self):
        """Test None strategy name returns empty list"""
        result = self.decomposer.decompose_strategy(None)
        assert result == []
    
    def test_is_combo_strategy(self):
        """Test combo strategy detection"""
        assert self.decomposer.is_combo_strategy('smart_combo_split_fake') is True
        assert self.decomposer.is_combo_strategy('existing_smart_combo_split_fake') is True
        assert self.decomposer.is_combo_strategy('disorder') is False
        assert self.decomposer.is_combo_strategy('') is False
        assert self.decomposer.is_combo_strategy(None) is False
    
    def test_get_attack_count(self):
        """Test attack count calculation"""
        assert self.decomposer.get_attack_count('smart_combo_split_fake') == 2
        assert self.decomposer.get_attack_count('smart_combo_multisplit_disorder_fake') == 3
        assert self.decomposer.get_attack_count('disorder') == 1
        assert self.decomposer.get_attack_count('') == 0
    
    def test_convenience_function(self):
        """Test the convenience function works correctly"""
        result = decompose_strategy('smart_combo_split_fake')
        assert result == ['split', 'fake']
    
    def test_unknown_attack_components(self):
        """Test handling of unknown attack components"""
        # Should still parse but log warning
        result = self.decomposer.decompose_strategy('smart_combo_unknown_fake')
        assert 'unknown' in result
        assert 'fake' in result
    
    def test_three_component_combo(self):
        """Test three-component combo strategy"""
        result = self.decomposer.decompose_strategy('smart_combo_fake_multisplit_disorder')
        assert result == ['fake', 'multisplit', 'disorder']
    
    def test_four_component_combo(self):
        """Test four-component combo strategy"""
        result = self.decomposer.decompose_strategy('smart_combo_fake_split_disorder_seqovl')
        assert result == ['fake', 'split', 'disorder', 'seqovl']


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
