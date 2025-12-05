"""
Test ComboAttackBuilder integration into cli.py and recon_service.py.

This test verifies that:
1. ComboAttackBuilder is properly integrated into both testing and service modes
2. Attack recipes are built correctly from strategy dictionaries
3. Incompatible combinations are detected and handled
4. Both modes use identical recipe building logic

Requirements: 2.1, 2.5, 2.6
"""

import pytest
import sys
from pathlib import Path

# Add recon directory to path
recon_dir = Path(__file__).parent.parent
sys.path.insert(0, str(recon_dir))

# Import directly from the module to avoid full core import
try:
    from core.strategy.combo_builder import ComboAttackBuilder, AttackRecipe, ValidationResult
    COMBO_BUILDER_AVAILABLE = True
except ImportError as e:
    COMBO_BUILDER_AVAILABLE = False
    print(f"ComboAttackBuilder not available: {e}")


@pytest.mark.skipif(not COMBO_BUILDER_AVAILABLE, reason="ComboAttackBuilder not available")
class TestComboAttackIntegration:
    """Test ComboAttackBuilder integration."""
    
    def test_build_recipe_from_strategy_dict(self):
        """Test building recipe from strategy dictionary (Requirement 2.1)."""
        strategy_dict = {
            'attacks': ['fake', 'multisplit', 'disorder'],
            'params': {
                'ttl': 3,
                'split_pos': 2,
                'split_count': 3,
                'disorder_method': 'reverse'
            }
        }
        
        builder = ComboAttackBuilder()
        recipe = builder.build_recipe(
            strategy_dict['attacks'],
            strategy_dict['params']
        )
        
        assert recipe is not None
        assert len(recipe.steps) == 3
        assert recipe.steps[0].attack_type == 'fake'
        assert recipe.steps[1].attack_type == 'multisplit'
        assert recipe.steps[2].attack_type == 'disorder'
    
    def test_incompatible_combination_detection(self):
        """Test detection of incompatible attack combinations (Requirement 2.6)."""
        strategy_dict = {
            'attacks': ['split', 'multisplit'],  # Incompatible!
            'params': {
                'split_pos': 2
            }
        }
        
        builder = ComboAttackBuilder()
        
        with pytest.raises(ValueError) as exc_info:
            builder.build_recipe(
                strategy_dict['attacks'],
                strategy_dict['params']
            )
        
        assert 'Incompatible' in str(exc_info.value)
    
    def test_all_valid_combos_supported(self):
        """Test that all valid combinations are supported (Requirement 2.5)."""
        valid_combos = [
            ['fake'],
            ['split'],
            ['multisplit'],
            ['disorder'],
            ['fake', 'split'],
            ['fake', 'multisplit'],
            ['fake', 'disorder'],
            ['split', 'disorder'],
            ['multisplit', 'disorder'],
            ['fake', 'split', 'disorder'],
            ['fake', 'multisplit', 'disorder'],
        ]
        
        builder = ComboAttackBuilder()
        
        for attacks in valid_combos:
            params = {
                'ttl': 3,
                'split_pos': 2,
                'split_count': 3,
                'disorder_method': 'reverse'
            }
            
            # Should not raise exception
            recipe = builder.build_recipe(attacks, params)
            assert recipe is not None
            assert len(recipe.steps) == len(attacks)
    
    def test_recipe_attack_order(self):
        """Test that attacks are ordered correctly: fake → split → disorder (Requirement 2.1)."""
        strategy_dict = {
            'attacks': ['disorder', 'fake', 'multisplit'],  # Wrong order
            'params': {
                'ttl': 3,
                'split_pos': 2,
                'split_count': 3,
                'disorder_method': 'reverse'
            }
        }
        
        builder = ComboAttackBuilder()
        recipe = builder.build_recipe(
            strategy_dict['attacks'],
            strategy_dict['params']
        )
        
        # Should be reordered to: fake → multisplit → disorder
        assert recipe.steps[0].attack_type == 'fake'
        assert recipe.steps[1].attack_type == 'multisplit'
        assert recipe.steps[2].attack_type == 'disorder'
    
    def test_cli_build_attack_recipe_function(self):
        """Test the build_attack_recipe helper function from cli.py."""
        try:
            from cli import build_attack_recipe, COMBO_ATTACK_BUILDER_AVAILABLE
            
            if not COMBO_ATTACK_BUILDER_AVAILABLE:
                pytest.skip("ComboAttackBuilder not available in cli.py")
            
            strategy_dict = {
                'attacks': ['fake', 'split'],
                'params': {
                    'ttl': 3,
                    'split_pos': 2
                }
            }
            
            recipe = build_attack_recipe(strategy_dict)
            
            assert recipe is not None
            assert len(recipe.steps) == 2
            assert recipe.steps[0].attack_type == 'fake'
            assert recipe.steps[1].attack_type == 'split'
            
        except ImportError:
            pytest.skip("cli.py not available for testing")
    
    def test_service_build_attack_recipe_method(self):
        """Test the build_attack_recipe method from recon_service.py."""
        try:
            from recon_service import DPIBypassService, COMBO_ATTACK_BUILDER_AVAILABLE
            
            if not COMBO_ATTACK_BUILDER_AVAILABLE:
                pytest.skip("ComboAttackBuilder not available in recon_service.py")
            
            service = DPIBypassService()
            
            strategy_dict = {
                'attacks': ['fake', 'disorder'],
                'params': {
                    'ttl': 3,
                    'disorder_method': 'reverse'
                }
            }
            
            recipe = service.build_attack_recipe(strategy_dict)
            
            assert recipe is not None
            assert len(recipe.steps) == 2
            assert recipe.steps[0].attack_type == 'fake'
            assert recipe.steps[1].attack_type == 'disorder'
            
        except ImportError:
            pytest.skip("recon_service.py not available for testing")
    
    def test_error_handling_for_incompatible_combos(self):
        """Test error handling for incompatible combinations (Requirement 2.6)."""
        try:
            from cli import build_attack_recipe, COMBO_ATTACK_BUILDER_AVAILABLE
            
            if not COMBO_ATTACK_BUILDER_AVAILABLE:
                pytest.skip("ComboAttackBuilder not available in cli.py")
            
            strategy_dict = {
                'attacks': ['split', 'multisplit'],  # Incompatible!
                'params': {}
            }
            
            # Should return None instead of raising exception
            recipe = build_attack_recipe(strategy_dict)
            assert recipe is None
            
        except ImportError:
            pytest.skip("cli.py not available for testing")


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
