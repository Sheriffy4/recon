"""
Test TCP Attack Parameter Mappings

This test verifies that all 25 TCP attacks can be instantiated with mapped parameters.
"""

import sys
import logging
from pathlib import Path

# Add recon to path
sys.path.insert(0, str(Path(__file__).parent))

from core.attack_parameter_mapper import ParameterMapper, ParameterMappingError
from core.bypass.attacks.registry import AttackRegistry

# Load all attacks
from load_all_attacks import load_all_attacks

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load attacks into registry
try:
    load_all_attacks()
    logger.info(f"Loaded {len(AttackRegistry.list_attacks())} attacks into registry")
except Exception as e:
    logger.error(f"Failed to load attacks: {e}")


# TCP attacks to test (25 total)
# These names match the attack.name property
TCP_ATTACKS = [
    # Stateful attacks
    'fake_disorder',
    'tcp_multidisorder',
    'tcp_seqovl',
    'tcp_timing_manipulation',
    
    # Race attacks
    'badsum_race',
    'low_ttl_poisoning',
    'cache_confusion_race',
    'md5sig_race',
    'drip_feed',
    
    # Manipulation attacks
    'tcp_window_scaling',
    'tcp_options_modification',
    'tcp_sequence_manipulation',
    'tcp_window_manipulation',
    'tcp_fragmentation',
    'urgent_pointer_manipulation',
    'tcp_options_padding',
    'tcp_multisplit',
    'tcp_timestamp_manipulation',
    'tcp_wssize_limit',
    
    # Fooling attacks
    'badsum_fooling',
    'md5sig_fooling',
    'badseq_fooling',
    'ttl_manipulation',
    
    # Timing attacks
    'timing_based_evasion',
    'burst_timing_evasion',
]


def test_tcp_attack_instantiation():
    """Test that all TCP attacks can be instantiated with mapped parameters."""
    mapper = ParameterMapper()
    results = {
        'passed': [],
        'failed': [],
        'errors': []
    }
    
    logger.info("=" * 80)
    logger.info("Testing TCP Attack Parameter Mappings")
    logger.info("=" * 80)
    
    for attack_name in TCP_ATTACKS:
        logger.info(f"\nTesting: {attack_name}")
        
        try:
            # Get attack class from registry
            attack_class = AttackRegistry.get(attack_name)
            if not attack_class:
                logger.error(f"  ❌ Attack not found in registry")
                results['failed'].append(attack_name)
                results['errors'].append(f"{attack_name}: Not in registry")
                continue
            
            # Test with empty parameters (most attacks take no constructor params)
            test_params = {}
            mapped_params = mapper.map_parameters(attack_name, test_params, attack_class)
            
            # Try to instantiate
            try:
                if mapped_params:
                    attack = attack_class(**mapped_params)
                else:
                    attack = attack_class()
                
                logger.info(f"  ✓ Instantiated successfully with params: {mapped_params}")
                results['passed'].append(attack_name)
            
            except TypeError as e:
                # Some attacks might require specific config objects
                logger.warning(f"  ⚠ Instantiation failed: {e}")
                logger.info(f"  → Trying with None config...")
                
                # Try with None config for stateful/race attacks
                if 'config' in str(e):
                    try:
                        attack = attack_class(config=None)
                        logger.info(f"  ✓ Instantiated with config=None")
                        results['passed'].append(attack_name)
                    except Exception as e2:
                        logger.error(f"  ❌ Still failed: {e2}")
                        results['failed'].append(attack_name)
                        results['errors'].append(f"{attack_name}: {e2}")
                else:
                    results['failed'].append(attack_name)
                    results['errors'].append(f"{attack_name}: {e}")
        
        except Exception as e:
            logger.error(f"  ❌ Error: {e}")
            results['failed'].append(attack_name)
            results['errors'].append(f"{attack_name}: {e}")
    
    # Print summary
    logger.info("\n" + "=" * 80)
    logger.info("SUMMARY")
    logger.info("=" * 80)
    logger.info(f"Total TCP attacks tested: {len(TCP_ATTACKS)}")
    logger.info(f"Passed: {len(results['passed'])}")
    logger.info(f"Failed: {len(results['failed'])}")
    
    if results['passed']:
        logger.info("\n✓ Passed attacks:")
        for attack in results['passed']:
            logger.info(f"  - {attack}")
    
    if results['failed']:
        logger.info("\n❌ Failed attacks:")
        for attack in results['failed']:
            logger.info(f"  - {attack}")
    
    if results['errors']:
        logger.info("\nErrors:")
        for error in results['errors']:
            logger.info(f"  - {error}")
    
    return results


def test_parameter_mapping_with_values():
    """Test parameter mapping with actual values."""
    mapper = ParameterMapper()
    
    logger.info("\n" + "=" * 80)
    logger.info("Testing Parameter Mapping with Values")
    logger.info("=" * 80)
    
    test_cases = [
        {
            'attack': 'fake_disorder',
            'params': {'split_pos': 2, 'fake_ttl': 8},
            'expected': {'split_pos': 2, 'fake_ttl': 8}
        },
        {
            'attack': 'tcp_multidisorder',
            'params': {'split_positions': [2, 4], 'fake_ttl': 8},
            'expected': {'split_positions': [2, 4], 'fake_ttl': 8}
        },
        {
            'attack': 'tcp_seqovl',
            'params': {'overlap_size': 4},
            'expected': {'overlap_size': 4}
        },
        {
            'attack': 'badsum_race',
            'params': {'race_window_ms': 10},
            'expected': {'race_window_ms': 10}
        },
        {
            'attack': 'tcp_window_scaling',
            'params': {},
            'expected': {}
        },
    ]
    
    passed = 0
    failed = 0
    
    for test_case in test_cases:
        attack = test_case['attack']
        params = test_case['params']
        expected = test_case['expected']
        
        logger.info(f"\nTest: {attack}")
        logger.info(f"  Input params: {params}")
        
        try:
            mapped = mapper.map_parameters(attack, params)
            logger.info(f"  Mapped params: {mapped}")
            logger.info(f"  Expected: {expected}")
            
            if mapped == expected:
                logger.info("  ✓ PASS")
                passed += 1
            else:
                logger.error("  ❌ FAIL - Mapping mismatch")
                failed += 1
        
        except Exception as e:
            logger.error(f"  ❌ FAIL - Error: {e}")
            failed += 1
    
    logger.info(f"\nParameter mapping tests: {passed} passed, {failed} failed")
    return passed, failed


def test_parameter_validation():
    """Test parameter validation."""
    mapper = ParameterMapper()
    
    logger.info("\n" + "=" * 80)
    logger.info("Testing Parameter Validation")
    logger.info("=" * 80)
    
    test_cases = [
        {
            'attack': 'fake_disorder',
            'params': {'split_pos': 2, 'fake_ttl': 8},
            'should_pass': True
        },
        {
            'attack': 'fake_disorder',
            'params': {'invalid_param': 123},
            'should_pass': False
        },
        {
            'attack': 'tcp_window_scaling',
            'params': {},
            'should_pass': True
        },
    ]
    
    passed = 0
    failed = 0
    
    for test_case in test_cases:
        attack = test_case['attack']
        params = test_case['params']
        should_pass = test_case['should_pass']
        
        logger.info(f"\nTest: {attack} with {params}")
        
        errors = mapper.validate_parameters(attack, params)
        has_errors = len(errors) > 0
        
        if should_pass and not has_errors:
            logger.info("  ✓ PASS - Valid parameters")
            passed += 1
        elif not should_pass and has_errors:
            logger.info(f"  ✓ PASS - Correctly detected errors: {errors}")
            passed += 1
        else:
            logger.error(f"  ❌ FAIL - Expected {'valid' if should_pass else 'invalid'}, got {'invalid' if has_errors else 'valid'}")
            if errors:
                logger.error(f"     Errors: {errors}")
            failed += 1
    
    logger.info(f"\nValidation tests: {passed} passed, {failed} failed")
    return passed, failed


def main():
    """Run all tests."""
    logger.info("Starting TCP Attack Parameter Mapping Tests")
    logger.info("=" * 80)
    
    # Test 1: Instantiation
    instantiation_results = test_tcp_attack_instantiation()
    
    # Test 2: Parameter mapping with values
    mapping_passed, mapping_failed = test_parameter_mapping_with_values()
    
    # Test 3: Parameter validation
    validation_passed, validation_failed = test_parameter_validation()
    
    # Final summary
    logger.info("\n" + "=" * 80)
    logger.info("FINAL SUMMARY")
    logger.info("=" * 80)
    logger.info(f"TCP Attack Instantiation: {len(instantiation_results['passed'])}/{len(TCP_ATTACKS)} passed")
    logger.info(f"Parameter Mapping: {mapping_passed} passed, {mapping_failed} failed")
    logger.info(f"Parameter Validation: {validation_passed} passed, {validation_failed} failed")
    
    total_tests = len(TCP_ATTACKS) + mapping_passed + mapping_failed + validation_passed + validation_failed
    total_passed = len(instantiation_results['passed']) + mapping_passed + validation_passed
    
    logger.info(f"\nOverall: {total_passed}/{total_tests} tests passed")
    
    success = (len(instantiation_results['failed']) == 0 and mapping_failed == 0 and validation_failed == 0)
    
    if success:
        logger.info("\n✓ ALL TESTS PASSED!")
        return 0
    else:
        logger.error("\n❌ SOME TESTS FAILED")
        return 1


if __name__ == '__main__':
    sys.exit(main())
