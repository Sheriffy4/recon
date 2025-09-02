#!/usr/bin/env python3
"""
Unit tests for TTL parameter parsing in strategy interpreter.

This test suite covers all aspects of TTL parameter handling as required by task 1:
- TTL parameter extraction logic in interpret_strategy() function
- Parameter mapping to ensure TTL value reaches the bypass engine
- Edge cases and validation
"""

import unittest
import sys
import os
import logging

# Add recon directory to path
recon_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if recon_dir not in sys.path:
    sys.path.insert(0, recon_dir)

from core.strategy_interpreter import interpret_strategy

# Suppress logging during tests
logging.getLogger().setLevel(logging.CRITICAL)

class TestTTLParameterParsing(unittest.TestCase):
    """Test TTL parameter parsing in strategy interpreter."""
    
    def test_ttl_parameter_extraction_basic(self):
        """Test basic TTL parameter extraction from strategy strings."""
        
        # Test case 1: Simple fake strategy with TTL=64
        strategy = "--dpi-desync=fake --dpi-desync-ttl=64"
        result = interpret_strategy(strategy)
        
        self.assertNotIn('error', result)
        self.assertEqual(result['params']['ttl'], 64)
        
        # Test case 2: Fakeddisorder strategy with TTL=1
        strategy = "--dpi-desync=fakeddisorder --dpi-desync-ttl=1"
        result = interpret_strategy(strategy)
        
        self.assertNotIn('error', result)
        self.assertEqual(result['params']['ttl'], 1)
        
        # Test case 3: Combined fake,fakeddisorder with TTL=32
        strategy = "--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=32"
        result = interpret_strategy(strategy)
        
        self.assertNotIn('error', result)
        self.assertEqual(result['params']['ttl'], 32)
    
    def test_ttl_parameter_extraction_complex(self):
        """Test TTL parameter extraction from complex strategy strings."""
        
        # The exact failing command from requirements
        strategy = "--dpi-desync=fake,fakeddisorder --dpi-desync-split-seqovl=1 --dpi-desync-autottl=2 --dpi-desync-fake-http=PAYLOADTLS --dpi-desync-fake-tls=PAYLOADTLS --dpi-desync-fooling=badseq,md5sig --dpi-desync-ttl=64"
        result = interpret_strategy(strategy)
        
        self.assertNotIn('error', result)
        self.assertEqual(result['params']['ttl'], 64)
        self.assertEqual(result['params']['autottl'], 2)
        self.assertEqual(result['params']['overlap_size'], 1)
        self.assertIn('badseq', result['params']['fooling'])
        self.assertIn('md5sig', result['params']['fooling'])
    
    def test_ttl_parameter_validation(self):
        """Test TTL parameter validation for valid ranges."""
        
        # Test valid TTL values
        valid_ttls = [1, 64, 128, 255]
        
        for ttl in valid_ttls:
            strategy = f"--dpi-desync=fake --dpi-desync-ttl={ttl}"
            result = interpret_strategy(strategy)
            
            self.assertNotIn('error', result)
            self.assertEqual(result['params']['ttl'], ttl)
    
    def test_ttl_parameter_edge_cases(self):
        """Test TTL parameter edge cases and boundary conditions."""
        
        # Test minimum valid TTL
        strategy = "--dpi-desync=fake --dpi-desync-ttl=1"
        result = interpret_strategy(strategy)
        self.assertEqual(result['params']['ttl'], 1)
        
        # Test maximum valid TTL
        strategy = "--dpi-desync=fake --dpi-desync-ttl=255"
        result = interpret_strategy(strategy)
        self.assertEqual(result['params']['ttl'], 255)
        
        # Test common TTL values
        common_ttls = [64, 128, 255]
        for ttl in common_ttls:
            strategy = f"--dpi-desync=fake,fakeddisorder --dpi-desync-ttl={ttl}"
            result = interpret_strategy(strategy)
            self.assertEqual(result['params']['ttl'], ttl)
    
    def test_autottl_parameter_extraction(self):
        """Test AutoTTL parameter extraction and handling."""
        
        # Test AutoTTL without explicit TTL
        strategy = "--dpi-desync=fake,fakeddisorder --dpi-desync-autottl=2"
        result = interpret_strategy(strategy)
        
        self.assertNotIn('error', result)
        self.assertEqual(result['params']['autottl'], 2)
        
        # Test AutoTTL with explicit TTL (both should be preserved)
        strategy = "--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=64 --dpi-desync-autottl=3"
        result = interpret_strategy(strategy)
        
        self.assertNotIn('error', result)
        self.assertEqual(result['params']['ttl'], 64)
        self.assertEqual(result['params']['autottl'], 3)
    
    def test_ttl_parameter_mapping_to_bypass_engine(self):
        """Test that TTL parameters are correctly mapped for bypass engine."""
        
        strategy = "--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=64"
        result = interpret_strategy(strategy)
        
        # Verify structure expected by bypass engine
        self.assertIn('type', result)
        self.assertIn('params', result)
        self.assertIn('ttl', result['params'])
        
        # Verify TTL is accessible via params.get("ttl")
        params = result['params']
        ttl = params.get('ttl')
        self.assertEqual(ttl, 64)
        
        # Verify attack type is correctly set
        self.assertEqual(result['type'], 'fakeddisorder')
    
    def test_ttl_default_behavior(self):
        """Test TTL default behavior when not specified."""
        
        # Test strategy without TTL parameter
        strategy = "--dpi-desync=fake,fakeddisorder"
        result = interpret_strategy(strategy)
        
        self.assertNotIn('error', result)
        
        # For fakeddisorder, default TTL should be 1 (zapret compatible)
        if result['type'] == 'fakeddisorder':
            self.assertEqual(result['params']['ttl'], 1)
    
    def test_ttl_parameter_with_different_attack_types(self):
        """Test TTL parameter handling with different attack types."""
        
        attack_types = [
            ("fake", "--dpi-desync=fake --dpi-desync-ttl=64"),
            ("fakeddisorder", "--dpi-desync=fakeddisorder --dpi-desync-ttl=64"),
            ("fake,fakeddisorder", "--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=64"),
        ]
        
        for attack_name, strategy in attack_types:
            with self.subTest(attack=attack_name):
                result = interpret_strategy(strategy)
                
                self.assertNotIn('error', result)
                self.assertEqual(result['params']['ttl'], 64)
    
    def test_ttl_parameter_with_fooling_methods(self):
        """Test TTL parameter handling with different fooling methods."""
        
        fooling_methods = [
            "badseq",
            "badsum", 
            "md5sig",
            "badseq,md5sig",
            "badsum,badseq",
            "md5sig,badsum,badseq"
        ]
        
        for fooling in fooling_methods:
            with self.subTest(fooling=fooling):
                strategy = f"--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=64 --dpi-desync-fooling={fooling}"
                result = interpret_strategy(strategy)
                
                self.assertNotIn('error', result)
                self.assertEqual(result['params']['ttl'], 64)
                self.assertIn('fooling', result['params'])
    
    def test_ttl_parameter_preservation_through_pipeline(self):
        """Test that TTL parameter is preserved through the interpretation pipeline."""
        
        # Test with fixed parser (fake,fakeddisorder)
        strategy = "--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=64"
        result = interpret_strategy(strategy)
        
        self.assertEqual(result.get('_parser_used'), 'fixed')
        self.assertEqual(result['params']['ttl'], 64)
        
        # Test with legacy parser (fake only)
        strategy = "--dpi-desync=fake --dpi-desync-ttl=64"
        result = interpret_strategy(strategy)
        
        self.assertEqual(result.get('_parser_used'), 'legacy')
        self.assertEqual(result['params']['ttl'], 64)
    
    def test_ttl_parameter_with_other_parameters(self):
        """Test TTL parameter interaction with other strategy parameters."""
        
        strategy = "--dpi-desync=fake,fakeddisorder --dpi-desync-split-seqovl=336 --dpi-desync-split-pos=76 --dpi-desync-ttl=64 --dpi-desync-repeats=2"
        result = interpret_strategy(strategy)
        
        self.assertNotIn('error', result)
        
        # Verify all parameters are correctly parsed
        params = result['params']
        self.assertEqual(params['ttl'], 64)
        self.assertEqual(params['overlap_size'], 336)
        self.assertEqual(params['split_pos'], 76)
        self.assertEqual(params.get('repeats'), 2)
    
    def test_ttl_parameter_error_handling(self):
        """Test error handling for invalid TTL parameters."""
        
        # Note: The current implementation doesn't validate TTL ranges in the parser
        # Invalid values are handled in the bypass engine
        # This test ensures the parser doesn't crash on unusual values
        
        unusual_values = ["0", "256", "999", "-1"]
        
        for value in unusual_values:
            with self.subTest(ttl=value):
                strategy = f"--dpi-desync=fake --dpi-desync-ttl={value}"
                result = interpret_strategy(strategy)
                
                # Should not crash, even with unusual values
                self.assertNotIn('error', result)
                # The value should be parsed as integer
                self.assertIsInstance(result['params']['ttl'], int)


class TestTTLParameterIntegration(unittest.TestCase):
    """Integration tests for TTL parameter handling."""
    
    def test_original_failing_command(self):
        """Test the exact command that was failing in the requirements."""
        
        failing_command = "--dpi-desync=fake,fakeddisorder --dpi-desync-split-seqovl=1 --dpi-desync-autottl=2 --dpi-desync-fake-http=PAYLOADTLS --dpi-desync-fake-tls=PAYLOADTLS --dpi-desync-fooling=badseq,md5sig --dpi-desync-ttl=64"
        
        result = interpret_strategy(failing_command)
        
        # Should not have errors
        self.assertNotIn('error', result)
        
        # Should correctly parse TTL=64
        self.assertEqual(result['params']['ttl'], 64)
        
        # Should correctly parse other parameters
        self.assertEqual(result['params']['autottl'], 2)
        self.assertEqual(result['params']['overlap_size'], 1)
        self.assertEqual(result['params']['fake_http'], 'PAYLOADTLS')
        self.assertEqual(result['params']['fake_tls'], 'PAYLOADTLS')
        self.assertIn('badseq', result['params']['fooling'])
        self.assertIn('md5sig', result['params']['fooling'])
        
        # Should map to fakeddisorder attack
        self.assertEqual(result['type'], 'fakeddisorder')
    
    def test_zapret_compatibility_commands(self):
        """Test commands that should be compatible with original zapret."""
        
        zapret_commands = [
            "--dpi-desync=fake,fakeddisorder --dpi-desync-split-seqovl=336 --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig,badsum,badseq --dpi-desync-repeats=1 --dpi-desync-split-pos=76 --dpi-desync-ttl=1",
            "--dpi-desync=fake --dpi-desync-ttl=4 --dpi-desync-fooling=badsum",
            "--dpi-desync=fakeddisorder --dpi-desync-ttl=1 --dpi-desync-split-seqovl=336",
        ]
        
        for command in zapret_commands:
            with self.subTest(command=command):
                result = interpret_strategy(command)
                
                self.assertNotIn('error', result)
                self.assertIn('ttl', result['params'])
                self.assertIsInstance(result['params']['ttl'], int)
                self.assertGreaterEqual(result['params']['ttl'], 1)
                self.assertLessEqual(result['params']['ttl'], 255)


if __name__ == '__main__':
    # Configure test output
    unittest.main(verbosity=2)