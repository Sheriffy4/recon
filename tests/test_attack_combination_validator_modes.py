#!/usr/bin/env python3
"""
Unit tests for AttackCombinationValidator execution modes.

Tests the difference between naive and integrated execution models
for attack combinations, particularly fake + split/multisplit.
"""

import pytest
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from core.bypass.engine.attack_combination_validator import AttackCombinationValidator


class TestAttackCombinationValidatorModes:
    """Test execution model modes for attack combination validator."""
    
    def test_naive_blocks_fake_with_split(self):
        """Test that naive mode blocks fake+split combination."""
        validator = AttackCombinationValidator()  # default naive
        result = validator.validate_combination(["fake", "split"])
        
        assert not result.valid, "Naive mode should block fake+split"
        assert "naive mode" in result.reason.lower() or "conflict" in result.reason.lower()
        assert result.recommendation is not None
    
    def test_naive_blocks_fake_with_multisplit(self):
        """Test that naive mode blocks fake+multisplit combination."""
        validator = AttackCombinationValidator()  # default naive
        result = validator.validate_combination(["fake", "multisplit"])
        
        assert not result.valid, "Naive mode should block fake+multisplit"
        assert "naive mode" in result.reason.lower() or "conflict" in result.reason.lower()
    
    def test_integrated_allows_fake_with_split(self):
        """Test that integrated mode allows fake+split combination."""
        validator = AttackCombinationValidator(execution_model="integrated")
        result = validator.validate_combination(["fake", "split"])
        
        assert result.valid, "Integrated mode should allow fake+split"
        assert "integrated" in result.reason.lower()
        assert "UnifiedAttackDispatcher" in result.recommendation or "integrated" in result.recommendation.lower()
    
    def test_integrated_allows_fake_with_multisplit(self):
        """Test that integrated mode allows fake+multisplit combination."""
        validator = AttackCombinationValidator(execution_model="integrated")
        result = validator.validate_combination(["fake", "multisplit"])
        
        assert result.valid, "Integrated mode should allow fake+multisplit"
        assert "integrated" in result.reason.lower()
    
    def test_both_modes_block_split_plus_multisplit(self):
        """Test that both modes block split+multisplit (duplicate fragmentation)."""
        # Test integrated mode
        validator_integrated = AttackCombinationValidator(execution_model="integrated")
        result_integrated = validator_integrated.validate_combination(["split", "multisplit"])
        
        assert not result_integrated.valid, "Integrated mode should block split+multisplit"
        assert "multisplit" in result_integrated.reason.lower() and "split" in result_integrated.reason.lower()
        
        # Test naive mode
        validator_naive = AttackCombinationValidator(execution_model="naive")
        result_naive = validator_naive.validate_combination(["split", "multisplit"])
        
        assert not result_naive.valid, "Naive mode should block split+multisplit"
        assert "multisplit" in result_naive.reason.lower() and "split" in result_naive.reason.lower()
    
    def test_both_modes_allow_fake_disorder(self):
        """Test that both modes allow fake+disorder (valid combination)."""
        # Test integrated mode
        validator_integrated = AttackCombinationValidator(execution_model="integrated")
        result_integrated = validator_integrated.validate_combination(["fake", "disorder"])
        
        assert result_integrated.valid, "Integrated mode should allow fake+disorder"
        
        # Test naive mode
        validator_naive = AttackCombinationValidator(execution_model="naive")
        result_naive = validator_naive.validate_combination(["fake", "disorder"])
        
        assert result_naive.valid, "Naive mode should allow fake+disorder"
    
    def test_both_modes_allow_multisplit_disorder(self):
        """Test that both modes allow multisplit+disorder (valid combination)."""
        # Test integrated mode
        validator_integrated = AttackCombinationValidator(execution_model="integrated")
        result_integrated = validator_integrated.validate_combination(["multisplit", "disorder"])
        
        assert result_integrated.valid, "Integrated mode should allow multisplit+disorder"
        
        # Test naive mode
        validator_naive = AttackCombinationValidator(execution_model="naive")
        result_naive = validator_naive.validate_combination(["multisplit", "disorder"])
        
        assert result_naive.valid, "Naive mode should allow multisplit+disorder"
    
    def test_naive_recommends_alternative_for_fake_split(self):
        """Test that naive mode recommends alternative for fake+split."""
        validator = AttackCombinationValidator()  # default naive
        recommended = validator.get_recommended_combination(["fake", "split"])
        
        assert recommended is not None, "Should provide recommendation"
        assert "fake" in recommended, "Should keep fake in recommendation"
        assert "split" not in recommended, "Should remove split from recommendation"
    
    def test_integrated_no_recommendation_for_fake_split(self):
        """Test that integrated mode doesn't recommend alternative for fake+split."""
        validator = AttackCombinationValidator(execution_model="integrated")
        recommended = validator.get_recommended_combination(["fake", "split"])
        
        # In integrated mode, fake+split is valid, so no recommendation needed
        assert recommended is None, "Integrated mode should not recommend alternative for valid combo"
    
    def test_execution_model_attribute(self):
        """Test that execution_model attribute is set correctly."""
        validator_naive = AttackCombinationValidator()
        assert validator_naive.execution_model == "naive"
        
        validator_integrated = AttackCombinationValidator(execution_model="integrated")
        assert validator_integrated.execution_model == "integrated"
    
    def test_complex_combination_with_fake_multisplit_disorder(self):
        """Test complex combination: fake+multisplit+disorder."""
        # Naive mode should block it
        validator_naive = AttackCombinationValidator()
        result_naive = validator_naive.validate_combination(["fake", "multisplit", "disorder"])
        assert not result_naive.valid, "Naive mode should block fake+multisplit+disorder"
        
        # Integrated mode should allow it
        validator_integrated = AttackCombinationValidator(execution_model="integrated")
        result_integrated = validator_integrated.validate_combination(["fake", "multisplit", "disorder"])
        assert result_integrated.valid, "Integrated mode should allow fake+multisplit+disorder"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
