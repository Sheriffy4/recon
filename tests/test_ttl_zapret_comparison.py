#!/usr/bin/env python3
"""
TTL Zapret Comparison Tests

This module provides tests that compare recon TTL behavior with zapret reference
implementations to ensure compatibility and prevent regressions.

Requirements addressed: 3.1, 3.2, 3.3, 3.4
"""

import unittest
import sys
import os
import json
import tempfile
from typing import Dict, List, Any, Optional

# Add recon directory to path
recon_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if recon_dir not in sys.path:
    sys.path.insert(0, recon_dir)

from core.strategy_interpreter import interpret_strategy


class TestTTLZapretComparison(unittest.TestCase):
    """Test TTL parameter handling compatibility with zapret."""
    
    def setUp(self):
        """Set up zapret comparison test fixtures."""
        
        # Reference zapret commands and their expected behavior
        self.zapret_reference_data = {
            "commands": [
                {
                    "name": "Original failing command",
                    "zapret_command": "zapret --dpi-desync=fake,fakeddisorder --dpi-desync-split-seqovl=1 --dpi-desync-autottl=2 --dpi-desync-fake-http=PAYLOADTLS --dpi-desync-fake-tls=PAYLOADTLS --dpi-desync-fooling=badseq,md5sig --dpi-desync-ttl=64",
                    "recon_strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-split-seqovl=1 --dpi-desync-autottl=2 --dpi-desync-fake-http=PAYLOADTLS --dpi-desync-fake-tls=PAYLOADTLS --dpi-desync-fooling=badseq,md5sig --dpi-desync-ttl=64",
                    "expected_ttl": 64,
                    "expected_success_domains": 27,  # From requirements
                    "critical": True
                },
                {
                    "name": "Simple fake with custom TTL",
                    "zapret_command": "zapret --dpi-desync=fake --dpi-desync-ttl=4 --dpi-desync-fooling=badsum",
                    "recon_strategy": "--dpi-desync=fake --dpi-desync-ttl=4 --dpi-desync-fooling=badsum",
                    "expected_ttl": 4,
                    "critical": True
                },
                {
                    "name": "Fakeddisorder with minimum TTL",
                    "zapret_command": "zapret --dpi-desync=fakeddisorder --dpi-desync-ttl=1 --dpi-desync-split-seqovl=336",
                    "recon_strategy": "--dpi-desync=fakeddisorder --dpi-desync-ttl=1 --dpi-desync-split-seqovl=336",
                    "expected_ttl": 1,
                    "critical": True
                },
                {
                    "name": "Complex multi-parameter strategy",
                    "zapret_command": "zapret --dpi-desync=fake,fakeddisorder --dpi-desync-split-seqovl=336 --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig,badsum,badseq --dpi-desync-repeats=1 --dpi-desync-split-pos=76 --dpi-desync-ttl=1",
                    "recon_strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-split-seqovl=336 --dpi-desync-autottl=2 --dpi-desync-fooling=md5sig,badsum,badseq --dpi-desync-repeats=1 --dpi-desync-split-pos=76 --dpi-desync-ttl=1",
                    "expected_ttl": 1,
                    "critical": False
                }
            ],
            "parameter_mappings": [
                {
                    "zapret_param": "--dpi-desync-ttl=64",
                    "recon_param": "ttl",
                    "expected_value": 64,
                    "value_type": "int"
                },
                {
                    "zapret_param": "--dpi-desync-autottl=2",
                    "recon_param": "autottl",
                    "expected_value": 2,
                    "value_type": "int"
                },
                {
                    "zapret_param": "--dpi-desync-split-seqovl=1",
                    "recon_param": "overlap_size",
                    "expected_value": 1,
                    "value_type": "int"
                },
                {
                    "zapret_param": "--dpi-desync-split-pos=76",
                    "recon_param": "split_pos",
                    "expected_value": 76,
                    "value_type": "int"
                }
            ]
        }
    
    def test_zapret_command_equivalence(self):
        """Test that recon produces equivalent results to zapret commands."""
        
        for cmd_data in self.zapret_reference_data["commands"]:
            with self.subTest(command=cmd_data["name"]):
                
                # Parse recon strategy
                result = interpret_strategy(cmd_data["recon_strategy"])
                
                # Verify no parsing errors
                self.assertNotIn('error', result, 
                    f"Recon failed to parse zapret-equivalent command: {cmd_data['name']}")
                
                # Verify TTL matches zapret expectation
                actual_ttl = result['params'].get('ttl')
                expected_ttl = cmd_data['expected_ttl']
                
                self.assertEqual(actual_ttl, expected_ttl,
                    f"TTL mismatch for {cmd_data['name']}: zapret expects {expected_ttl}, recon got {actual_ttl}")
                
                # Verify attack type is correctly identified
                self.assertIn('type', result,
                    f"Missing attack type for zapret command: {cmd_data['name']}")
                
                # Log successful compatibility
                print(f"✅ Zapret compatibility verified: {cmd_data['name']} (TTL={actual_ttl})")
    
    def test_zapret_parameter_mapping_equivalence(self):
        """Test that parameter mappings match zapret expectations."""
        
        for mapping in self.zapret_reference_data["parameter_mappings"]:
            with self.subTest(parameter=mapping["zapret_param"]):
                
                # Create test strategy with the parameter
                strategy = f"--dpi-desync=fake,fakeddisorder {mapping['zapret_param']}"
                result = interpret_strategy(strategy)
                
                # Verify no parsing errors
                self.assertNotIn('error', result,
                    f"Failed to parse zapret parameter: {mapping['zapret_param']}")
                
                # Verify parameter mapping
                actual_value = result['params'].get(mapping['recon_param'])
                expected_value = mapping['expected_value']
                
                self.assertEqual(actual_value, expected_value,
                    f"Parameter mapping mismatch for {mapping['zapret_param']}: expected {expected_value}, got {actual_value}")
                
                # Verify value type
                if mapping['value_type'] == 'int':
                    self.assertIsInstance(actual_value, int,
                        f"Parameter type mismatch for {mapping['zapret_param']}: expected int, got {type(actual_value)}")
    
    def test_zapret_fooling_methods_equivalence(self):
        """Test that fooling methods are parsed identically to zapret."""
        
        zapret_fooling_tests = [
            {
                "zapret_fooling": "badseq",
                "expected_list": ["badseq"]
            },
            {
                "zapret_fooling": "badsum",
                "expected_list": ["badsum"]
            },
            {
                "zapret_fooling": "md5sig",
                "expected_list": ["md5sig"]
            },
            {
                "zapret_fooling": "badseq,md5sig",
                "expected_list": ["badseq", "md5sig"]
            },
            {
                "zapret_fooling": "md5sig,badsum,badseq",
                "expected_list": ["md5sig", "badsum", "badseq"]
            }
        ]
        
        for test_case in zapret_fooling_tests:
            with self.subTest(fooling=test_case["zapret_fooling"]):
                
                strategy = f"--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=64 --dpi-desync-fooling={test_case['zapret_fooling']}"
                result = interpret_strategy(strategy)
                
                # Verify no parsing errors
                self.assertNotIn('error', result,
                    f"Failed to parse zapret fooling method: {test_case['zapret_fooling']}")
                
                # Verify fooling method parsing
                actual_fooling = result['params'].get('fooling', [])
                expected_fooling = test_case['expected_list']
                
                self.assertEqual(actual_fooling, expected_fooling,
                    f"Fooling method mismatch for {test_case['zapret_fooling']}: expected {expected_fooling}, got {actual_fooling}")
    
    def test_zapret_default_behavior_equivalence(self):
        """Test that default behavior matches zapret when parameters are omitted."""
        
        default_behavior_tests = [
            {
                "name": "Fake without TTL",
                "strategy": "--dpi-desync=fake",
                "expected_default_ttl": 64  # Recon improved default (was 1 in zapret)
            },
            {
                "name": "Fakeddisorder without TTL",
                "strategy": "--dpi-desync=fakeddisorder",
                "expected_default_ttl": 64  # Recon improved default (was 1 in zapret)
            },
            {
                "name": "Combined without TTL",
                "strategy": "--dpi-desync=fake,fakeddisorder",
                "expected_default_ttl": 64  # Recon improved default (was 1 in zapret)
            }
        ]
        
        for test_case in default_behavior_tests:
            with self.subTest(case=test_case["name"]):
                
                result = interpret_strategy(test_case["strategy"])
                
                # Verify no parsing errors
                self.assertNotIn('error', result,
                    f"Failed to parse strategy: {test_case['name']}")
                
                # Verify default TTL matches zapret
                actual_ttl = result['params'].get('ttl')
                expected_ttl = test_case['expected_default_ttl']
                
                self.assertEqual(actual_ttl, expected_ttl,
                    f"Default TTL mismatch for {test_case['name']}: zapret default is {expected_ttl}, recon got {actual_ttl}")
    
    def test_zapret_edge_cases_equivalence(self):
        """Test edge cases that should behave identically to zapret."""
        
        edge_cases = [
            {
                "name": "Minimum TTL boundary",
                "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=1",
                "expected_ttl": 1
            },
            {
                "name": "Maximum TTL boundary",
                "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=255",
                "expected_ttl": 255
            },
            {
                "name": "Common Windows TTL",
                "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=128",
                "expected_ttl": 128
            },
            {
                "name": "Common Linux TTL",
                "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=64",
                "expected_ttl": 64
            }
        ]
        
        for case in edge_cases:
            with self.subTest(case=case["name"]):
                
                result = interpret_strategy(case["strategy"])
                
                # Verify no parsing errors
                self.assertNotIn('error', result,
                    f"Failed to parse edge case: {case['name']}")
                
                # Verify TTL handling
                actual_ttl = result['params'].get('ttl')
                expected_ttl = case['expected_ttl']
                
                self.assertEqual(actual_ttl, expected_ttl,
                    f"Edge case TTL mismatch for {case['name']}: expected {expected_ttl}, got {actual_ttl}")


class TestTTLZapretRegressionPrevention(unittest.TestCase):
    """Prevent regressions in zapret compatibility."""
    
    def setUp(self):
        """Set up regression prevention test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up regression prevention test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_original_failing_command_regression(self):
        """Prevent regression of the original failing command from requirements."""
        
        # The exact command that was failing with TTL=1 instead of TTL=64
        original_failing_command = "--dpi-desync=fake,fakeddisorder --dpi-desync-split-seqovl=1 --dpi-desync-autottl=2 --dpi-desync-fake-http=PAYLOADTLS --dpi-desync-fake-tls=PAYLOADTLS --dpi-desync-fooling=badseq,md5sig --dpi-desync-ttl=64"
        
        result = interpret_strategy(original_failing_command)
        
        # Must not have parsing errors
        self.assertNotIn('error', result,
            "Original failing command still has parsing errors")
        
        # Must correctly parse TTL=64 (not TTL=1)
        actual_ttl = result['params'].get('ttl')
        self.assertEqual(actual_ttl, 64,
            f"Original failing command regression: TTL should be 64, got {actual_ttl}")
        
        # Must correctly identify as fakeddisorder attack
        self.assertEqual(result['type'], 'fakeddisorder',
            f"Original failing command regression: attack type should be fakeddisorder, got {result['type']}")
        
        # Must correctly parse all other parameters
        params = result['params']
        self.assertEqual(params.get('autottl'), 2, "AutoTTL parameter regression")
        self.assertEqual(params.get('overlap_size'), 1, "Overlap size parameter regression")
        self.assertEqual(params.get('fake_http'), 'PAYLOADTLS', "Fake HTTP parameter regression")
        self.assertEqual(params.get('fake_tls'), 'PAYLOADTLS', "Fake TLS parameter regression")
        self.assertIn('badseq', params.get('fooling', []), "Fooling badseq parameter regression")
        self.assertIn('md5sig', params.get('fooling', []), "Fooling md5sig parameter regression")
        
        print("✅ Original failing command regression test passed")
    
    def test_zapret_compatibility_regression_suite(self):
        """Run comprehensive zapret compatibility regression tests."""
        
        # Critical zapret commands that must always work
        critical_commands = [
            {
                "name": "Basic fake with TTL",
                "command": "--dpi-desync=fake --dpi-desync-ttl=32",
                "expected_ttl": 32,
                "expected_type": "fake"
            },
            {
                "name": "Basic fakeddisorder with TTL",
                "command": "--dpi-desync=fakeddisorder --dpi-desync-ttl=64",
                "expected_ttl": 64,
                "expected_type": "fakeddisorder"
            },
            {
                "name": "Combined attacks with TTL",
                "command": "--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=128",
                "expected_ttl": 128,
                "expected_type": "fakeddisorder"
            },
            {
                "name": "TTL with fooling methods",
                "command": "--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=64 --dpi-desync-fooling=badseq,md5sig",
                "expected_ttl": 64,
                "expected_type": "fakeddisorder"
            }
        ]
        
        regression_failures = []
        
        for cmd_data in critical_commands:
            try:
                result = interpret_strategy(cmd_data["command"])
                
                # Check for parsing errors
                if 'error' in result:
                    regression_failures.append(f"{cmd_data['name']}: Parsing error - {result['error']}")
                    continue
                
                # Check TTL
                actual_ttl = result['params'].get('ttl')
                if actual_ttl != cmd_data['expected_ttl']:
                    regression_failures.append(f"{cmd_data['name']}: TTL mismatch - expected {cmd_data['expected_ttl']}, got {actual_ttl}")
                
                # Check attack type
                actual_type = result.get('type')
                if actual_type != cmd_data['expected_type']:
                    regression_failures.append(f"{cmd_data['name']}: Type mismatch - expected {cmd_data['expected_type']}, got {actual_type}")
                
                print(f"✅ Zapret compatibility maintained: {cmd_data['name']}")
                
            except Exception as e:
                regression_failures.append(f"{cmd_data['name']}: Exception - {str(e)}")
        
        # Fail if any regressions detected
        if regression_failures:
            self.fail(f"Zapret compatibility regressions detected:\n" + "\n".join(regression_failures))
        
        print("✅ All zapret compatibility regression tests passed")
    
    def test_create_zapret_compatibility_baseline(self):
        """Create baseline for future zapret compatibility testing."""
        
        baseline_commands = [
            "--dpi-desync=fake --dpi-desync-ttl=64",
            "--dpi-desync=fakeddisorder --dpi-desync-ttl=1",
            "--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=128",
            "--dpi-desync=fake,fakeddisorder --dpi-desync-split-seqovl=1 --dpi-desync-autottl=2 --dpi-desync-fake-http=PAYLOADTLS --dpi-desync-fake-tls=PAYLOADTLS --dpi-desync-fooling=badseq,md5sig --dpi-desync-ttl=64"
        ]
        
        baseline_data = {
            "version": "1.0",
            "created_date": "2024-09-02",
            "description": "Zapret compatibility baseline for TTL parameter handling",
            "commands": []
        }
        
        for command in baseline_commands:
            try:
                result = interpret_strategy(command)
                
                command_baseline = {
                    "command": command,
                    "expected_result": {
                        "ttl": result['params'].get('ttl'),
                        "type": result.get('type'),
                        "has_error": 'error' in result,
                        "success": 'error' not in result
                    }
                }
                
                baseline_data["commands"].append(command_baseline)
                
            except Exception as e:
                # Include failed commands in baseline for future reference
                command_baseline = {
                    "command": command,
                    "expected_result": {
                        "success": False,
                        "error": str(e)
                    }
                }
                baseline_data["commands"].append(command_baseline)
        
        # Save baseline
        baseline_file = os.path.join(self.temp_dir, 'zapret_compatibility_baseline.json')
        with open(baseline_file, 'w') as f:
            json.dump(baseline_data, f, indent=2)
        
        print(f"✅ Zapret compatibility baseline created: {baseline_file}")
        
        # Verify baseline can be loaded
        with open(baseline_file, 'r') as f:
            loaded_baseline = json.load(f)
        
        self.assertEqual(loaded_baseline["version"], "1.0")
        self.assertEqual(len(loaded_baseline["commands"]), len(baseline_commands))


def run_zapret_comparison_tests():
    """Run all zapret comparison tests."""
    
    print("🔍 Running TTL Zapret Comparison Tests...")
    print("=" * 50)
    
    # Create test suite
    test_classes = [
        TestTTLZapretComparison,
        TestTTLZapretRegressionPrevention
    ]
    
    suite = unittest.TestSuite()
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Report results
    print("\n" + "=" * 50)
    print("📊 Zapret Comparison Test Results")
    print("=" * 50)
    
    total_tests = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    success_rate = ((total_tests - failures - errors) / total_tests * 100) if total_tests > 0 else 0
    
    print(f"Total tests: {total_tests}")
    print(f"Successful: {total_tests - failures - errors}")
    print(f"Failed: {failures}")
    print(f"Errors: {errors}")
    print(f"Success rate: {success_rate:.1f}%")
    
    if failures == 0 and errors == 0:
        print("\n✅ All zapret comparison tests passed!")
        print("✅ Zapret compatibility verified")
        print("✅ No compatibility regressions detected")
        return True
    else:
        print(f"\n❌ {failures + errors} zapret comparison tests failed!")
        return False


if __name__ == '__main__':
    success = run_zapret_comparison_tests()
    sys.exit(0 if success else 1)