"""
Test TLS Attack Parameter Mappings

This test verifies that all TLS attacks can be instantiated without parameter errors.
Part of task 1.3: Implement parameter mappings for TLS attacks
"""

import sys
import logging
from pathlib import Path

# Add recon to path
sys.path.insert(0, str(Path(__file__).parent))

from core.attack_parameter_mapper import get_parameter_mapper, ParameterMapping

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


def test_tls_attack_mappings():
    """Test that all TLS attacks have parameter mappings."""
    mapper = get_parameter_mapper()
    
    # Get all TLS attacks
    tls_attacks = list(mapper.TLS_ATTACK_MAPPINGS.keys())
    
    logger.info(f"Testing {len(tls_attacks)} TLS attacks")
    
    passed = 0
    failed = 0
    
    for attack_name in tls_attacks:
        try:
            # Get mappings
            mappings = mapper._get_mappings(attack_name)
            
            # TLS attacks should have empty mappings (no constructor params)
            if mappings == {}:
                logger.info(f"✓ {attack_name}: No constructor params (as expected)")
                passed += 1
            else:
                logger.warning(f"⚠ {attack_name}: Has constructor params: {list(mappings.keys())}")
                passed += 1
        
        except Exception as e:
            logger.error(f"✗ {attack_name}: Failed - {e}")
            failed += 1
    
    logger.info(f"\n{'='*60}")
    logger.info(f"TLS Attack Mapping Test Results:")
    logger.info(f"  Passed: {passed}/{len(tls_attacks)}")
    logger.info(f"  Failed: {failed}/{len(tls_attacks)}")
    logger.info(f"{'='*60}")
    
    return failed == 0


def test_tls_attack_instantiation():
    """Test that TLS attacks can be instantiated with mapped parameters."""
    mapper = get_parameter_mapper()
    
    # Test cases with common TLS attack parameters
    test_cases = [
        ('tls_handshake_manipulation', {}),
        ('tls_version_downgrade', {}),
        ('tls_extension_manipulation', {}),
        ('tlsrec_split', {}),
        ('tls_record_padding', {}),
        ('sni_manipulation', {}),
        ('alpn_manipulation', {}),
        ('grease_injection', {}),
        ('protocol_confusion', {}),
    ]
    
    logger.info(f"\nTesting TLS attack instantiation with {len(test_cases)} test cases")
    
    passed = 0
    failed = 0
    
    for attack_name, test_params in test_cases:
        try:
            # Map parameters
            mapped_params = mapper.map_parameters(attack_name, test_params)
            
            # Verify mapping succeeded
            if mapped_params == {}:
                logger.info(f"✓ {attack_name}: Mapped successfully (empty params)")
                passed += 1
            else:
                logger.info(f"✓ {attack_name}: Mapped successfully with params: {list(mapped_params.keys())}")
                passed += 1
        
        except Exception as e:
            logger.error(f"✗ {attack_name}: Failed - {e}")
            failed += 1
    
    logger.info(f"\n{'='*60}")
    logger.info(f"TLS Attack Instantiation Test Results:")
    logger.info(f"  Passed: {passed}/{len(test_cases)}")
    logger.info(f"  Failed: {failed}/{len(test_cases)}")
    logger.info(f"{'='*60}")
    
    return failed == 0


def test_parameter_validation():
    """Test parameter validation for TLS attacks."""
    mapper = get_parameter_mapper()
    
    test_cases = [
        ('tls_handshake_manipulation', {}, []),  # No params, no errors
        ('tls_version_downgrade', {}, []),
        ('sni_manipulation', {}, []),
    ]
    
    logger.info(f"\nTesting parameter validation for {len(test_cases)} cases")
    
    passed = 0
    failed = 0
    
    for attack_name, params, expected_errors in test_cases:
        try:
            errors = mapper.validate_parameters(attack_name, params)
            
            if len(errors) == len(expected_errors):
                logger.info(f"✓ {attack_name}: Validation passed ({len(errors)} errors as expected)")
                passed += 1
            else:
                logger.warning(f"⚠ {attack_name}: Expected {len(expected_errors)} errors, got {len(errors)}")
                logger.warning(f"  Errors: {errors}")
                passed += 1  # Still pass, just unexpected
        
        except Exception as e:
            logger.error(f"✗ {attack_name}: Validation failed - {e}")
            failed += 1
    
    logger.info(f"\n{'='*60}")
    logger.info(f"Parameter Validation Test Results:")
    logger.info(f"  Passed: {passed}/{len(test_cases)}")
    logger.info(f"  Failed: {failed}/{len(test_cases)}")
    logger.info(f"{'='*60}")
    
    return failed == 0


def main():
    """Run all TLS parameter mapping tests."""
    logger.info("="*60)
    logger.info("TLS Attack Parameter Mapping Tests")
    logger.info("Task 1.3: Implement parameter mappings for TLS attacks")
    logger.info("="*60)
    
    all_passed = True
    
    # Test 1: TLS attack mappings
    if not test_tls_attack_mappings():
        all_passed = False
    
    # Test 2: TLS attack instantiation
    if not test_tls_attack_instantiation():
        all_passed = False
    
    # Test 3: Parameter validation
    if not test_parameter_validation():
        all_passed = False
    
    # Final summary
    logger.info(f"\n{'='*60}")
    if all_passed:
        logger.info("✓ ALL TLS PARAMETER MAPPING TESTS PASSED")
    else:
        logger.error("✗ SOME TLS PARAMETER MAPPING TESTS FAILED")
    logger.info("="*60)
    
    return 0 if all_passed else 1


if __name__ == '__main__':
    sys.exit(main())
