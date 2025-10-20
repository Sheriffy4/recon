#!/usr/bin/env python3
"""
Test parameter validation integration between CLI, UnifiedStrategyLoader, and AttackRegistry.

This test verifies that parameter validation is properly integrated across all components.
"""

import sys
import os
import unittest
from unittest.mock import patch, MagicMock

# Add current directory to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

# Test imports
try:
    from core.bypass.attacks.attack_registry import AttackRegistry, get_attack_registry
    from core.unified_strategy_loader import UnifiedStrategyLoader
    from cli import SimpleEvolutionarySearcher
    IMPORTS_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Some imports failed: {e}")
    IMPORTS_AVAILABLE = False


class TestParameterValidationIntegration(unittest.TestCase):
    """Test parameter validation integration across components."""
    
    def setUp(self):
        """Set up test fixtures."""
        if not IMPORTS_AVAILABLE:
            self.skipTest("Required imports not available")
        
        self.registry = AttackRegistry()
        self.loader = UnifiedStrategyLoader(debug=True)
        self.searcher = SimpleEvolutionarySearcher()
    
    def test_attack_registry_validation(self):
        """Test AttackRegistry parameter validation."""
        # Test valid parameters
        valid_params = {"split_pos": 3, "ttl": 4}
        result = self.registry.validate_parameters("fakeddisorder", valid_params)
        self.assertTrue(result.is_valid, f"Valid parameters should pass: {result.error_message}")
        
        # Test invalid TTL
        invalid_params = {"split_pos": 3, "ttl": 300}  # TTL > 255
        result = self.registry.validate_parameters("fakeddisorder", invalid_params)
        self.assertFalse(result.is_valid, "Invalid TTL should fail validation")
        
        # Test missing required parameter for seqovl
        missing_params = {"split_pos": 3}  # Missing overlap_size
        result = self.registry.validate_parameters("seqovl", missing_params)
        self.assertFalse(result.is_valid, "Missing required parameter should fail validation")
        
        # Test invalid fooling method
        invalid_fooling = {"ttl": 3, "fooling": ["invalid_method"]}
        result = self.registry.validate_parameters("fakeddisorder", invalid_fooling)
        self.assertFalse(result.is_valid, "Invalid fooling method should fail validation")
    
    def test_cli_validation_integration(self):
        """Test CLI parameter validation integration with AttackRegistry."""
        # Test valid parameters
        valid_genes = {"type": "fakeddisorder", "split_pos": 3, "ttl": 4}
        validated = self.searcher._validate_attack_parameters("fakeddisorder", valid_genes)
        
        self.assertIn("split_pos", validated)
        self.assertIn("ttl", validated)
        self.assertEqual(validated["split_pos"], 3)
        self.assertEqual(validated["ttl"], 4)
        
        # Test parameter correction
        invalid_genes = {"type": "fakeddisorder", "split_pos": 3, "ttl": 300}  # TTL too high
        validated = self.searcher._validate_attack_parameters("fakeddisorder", invalid_genes)
        
        # Should either correct the TTL or use default
        self.assertIn("ttl", validated)
        self.assertLessEqual(validated["ttl"], 255)
        
        # Test seqovl with overlap_size
        seqovl_genes = {"type": "seqovl", "split_pos": 3, "overlap_size": 20, "ttl": 3}
        validated = self.searcher._validate_attack_parameters("seqovl", seqovl_genes)
        
        self.assertIn("overlap_size", validated)
        self.assertEqual(validated["overlap_size"], 20)
    
    def test_unified_strategy_loader_validation(self):
        """Test UnifiedStrategyLoader validation integration with AttackRegistry."""
        # Test valid strategy dict
        valid_strategy_dict = {
            "type": "fakeddisorder",
            "params": {"split_pos": 3, "ttl": 4}
        }
        
        strategy = self.loader.load_strategy(valid_strategy_dict)
        self.assertEqual(strategy.type, "fakeddisorder")
        self.assertIn("split_pos", strategy.params)
        self.assertIn("ttl", strategy.params)
        
        # Test strategy validation
        is_valid = self.loader.validate_strategy(strategy)
        self.assertTrue(is_valid, "Valid strategy should pass validation")
        
        # Test invalid strategy
        invalid_strategy_dict = {
            "type": "seqovl",
            "params": {"split_pos": 3}  # Missing overlap_size
        }
        
        # Should raise validation error
        with self.assertRaises(Exception):
            strategy = self.loader.load_strategy(invalid_strategy_dict)
            self.loader.validate_strategy(strategy)
    
    def test_registry_enhancement_in_loader(self):
        """Test that UnifiedStrategyLoader is enhanced with AttackRegistry data."""
        # Check that known_attacks includes registry attacks
        registry_attacks = self.registry.list_attacks()
        
        for attack_type in registry_attacks:
            self.assertIn(attack_type, self.loader.known_attacks, 
                         f"Attack type {attack_type} should be in loader's known_attacks")
        
        # Check that required_params includes registry metadata
        for attack_type in registry_attacks:
            metadata = self.registry.get_attack_metadata(attack_type)
            if metadata and metadata.required_params:
                self.assertIn(attack_type, self.loader.required_params,
                             f"Attack type {attack_type} should have required_params")
                self.assertEqual(self.loader.required_params[attack_type], metadata.required_params,
                               f"Required params should match for {attack_type}")
    
    def test_parameter_normalization_with_registry(self):
        """Test parameter normalization using registry metadata."""
        # Test that optional parameters are added from registry
        minimal_params = {"split_pos": 3}
        
        normalized = self.loader._normalize_params_with_registry("fakeddisorder", minimal_params)
        
        # Should include the original parameter
        self.assertIn("split_pos", normalized)
        self.assertEqual(normalized["split_pos"], 3)
        
        # May include optional parameters with defaults from registry
        metadata = self.registry.get_attack_metadata("fakeddisorder")
        if metadata:
            for param_name, default_value in metadata.optional_params.items():
                if param_name not in minimal_params:
                    self.assertIn(param_name, normalized,
                                 f"Optional parameter {param_name} should be added")
                    self.assertEqual(normalized[param_name], default_value,
                                   f"Default value should be set for {param_name}")
    
    def test_fallback_validation(self):
        """Test that fallback validation works when AttackRegistry is not available."""
        # Mock AttackRegistry to raise an exception
        with patch('core.bypass.attacks.attack_registry.get_attack_registry') as mock_registry:
            mock_registry.side_effect = ImportError("AttackRegistry not available")
            
            # CLI validation should fall back to legacy validation
            genes = {"type": "fakeddisorder", "split_pos": 3, "ttl": 4}
            validated = self.searcher._validate_attack_parameters("fakeddisorder", genes)
            
            self.assertIn("split_pos", validated)
            self.assertIn("ttl", validated)
            
            # UnifiedStrategyLoader validation should fall back to legacy validation
            strategy_dict = {"type": "fakeddisorder", "params": {"split_pos": 3, "ttl": 4}}
            strategy = self.loader.load_strategy(strategy_dict)
            
            # Should not raise an exception
            is_valid = self.loader.validate_strategy(strategy)
            self.assertTrue(is_valid)
    
    def test_special_parameter_values(self):
        """Test validation of special parameter values like 'cipher', 'sni', 'midsld'."""
        # Test special split_pos values
        special_values = ["cipher", "sni", "midsld"]
        
        for special_value in special_values:
            params = {"split_pos": special_value, "ttl": 3}
            result = self.registry.validate_parameters("fakeddisorder", params)
            self.assertTrue(result.is_valid, 
                           f"Special split_pos value '{special_value}' should be valid")
        
        # Test invalid special value
        invalid_params = {"split_pos": "invalid_special", "ttl": 3}
        result = self.registry.validate_parameters("fakeddisorder", invalid_params)
        self.assertFalse(result.is_valid, "Invalid special split_pos should fail validation")
    
    def test_positions_parameter_validation(self):
        """Test validation of positions parameter for multisplit attacks."""
        # Test valid positions
        valid_params = {"positions": [1, 3, 5]}
        result = self.registry.validate_parameters("multisplit", valid_params)
        self.assertTrue(result.is_valid, "Valid positions should pass validation")
        
        # Test invalid positions (not a list)
        invalid_params = {"positions": "not_a_list"}
        result = self.registry.validate_parameters("multisplit", invalid_params)
        self.assertFalse(result.is_valid, "Non-list positions should fail validation")
        
        # Test positions with invalid values
        invalid_positions = {"positions": [1, "invalid", 5]}
        result = self.registry.validate_parameters("multisplit", invalid_positions)
        self.assertFalse(result.is_valid, "Positions with invalid values should fail validation")


def run_validation_tests():
    """Run parameter validation integration tests."""
    if not IMPORTS_AVAILABLE:
        print("❌ Required imports not available, skipping tests")
        return False
    
    print("🧪 Running parameter validation integration tests...")
    
    # Create test suite
    suite = unittest.TestLoader().loadTestsFromTestCase(TestParameterValidationIntegration)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    if result.wasSuccessful():
        print(f"✅ All {result.testsRun} parameter validation tests passed!")
        return True
    else:
        print(f"❌ {len(result.failures)} failures, {len(result.errors)} errors out of {result.testsRun} tests")
        
        # Print details
        for test, traceback in result.failures:
            print(f"FAILURE: {test}")
            print(traceback)
        
        for test, traceback in result.errors:
            print(f"ERROR: {test}")
            print(traceback)
        
        return False


if __name__ == "__main__":
    success = run_validation_tests()
    sys.exit(0 if success else 1)