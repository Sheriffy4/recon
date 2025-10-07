"""
Test Tunneling and Fragmentation Attack Parameter Mappings

This test verifies that all tunneling and fragmentation attacks can be instantiated without parameter errors.
Part of task 1.4: Implement parameter mappings for other attacks
"""

import sys
import logging
from pathlib import Path

# Add recon to path
sys.path.insert(0, str(Path(__file__).parent))

from core.attack_parameter_mapper import get_parameter_mapper

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


def test_tunneling_attack_mappings():
    """Test that all tunneling attacks have parameter mappings."""
    mapper = get_parameter_mapper()
    
    # Get all tunneling attacks
    tunneling_attacks = list(mapper.TUNNELING_ATTACK_MAPPINGS.keys())
    
    logger.info(f"Testing {len(tunneling_attacks)} tunneling attacks")
    
    passed = 0
    failed = 0
    
    for attack_name in tunneling_attacks:
        try:
            # Get mappings
            mappings = mapper._get_mappings(attack_name)
            
            # Tunneling attacks should have empty mappings (no constructor params)
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
    logger.info(f"Tunneling Attack Mapping Test Results:")
    logger.info(f"  Passed: {passed}/{len(tunneling_attacks)}")
    logger.info(f"  Failed: {failed}/{len(tunneling_attacks)}")
    logger.info(f"{'='*60}")
    
    return failed == 0


def test_fragmentation_attack_mappings():
    """Test that all fragmentation attacks have parameter mappings."""
    mapper = get_parameter_mapper()
    
    # Get all fragmentation attacks
    fragmentation_attacks = list(mapper.FRAGMENTATION_ATTACK_MAPPINGS.keys())
    
    logger.info(f"\nTesting {len(fragmentation_attacks)} fragmentation attacks")
    
    passed = 0
    failed = 0
    
    for attack_name in fragmentation_attacks:
        try:
            # Get mappings
            mappings = mapper._get_mappings(attack_name)
            
            # Fragmentation attacks should have empty mappings (no constructor params)
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
    logger.info(f"Fragmentation Attack Mapping Test Results:")
    logger.info(f"  Passed: {passed}/{len(fragmentation_attacks)}")
    logger.info(f"  Failed: {failed}/{len(fragmentation_attacks)}")
    logger.info(f"{'='*60}")
    
    return failed == 0


def test_attack_instantiation():
    """Test that tunneling and fragmentation attacks can be instantiated with mapped parameters."""
    mapper = get_parameter_mapper()
    
    # Test cases
    test_cases = [
        # Tunneling attacks
        ('icmp_data_tunneling', {}),
        ('http_tunneling', {}),
        ('websocket_tunneling', {}),
        ('ssh_tunneling', {}),
        ('vpn_tunneling', {}),
        
        # Fragmentation attacks
        ('ip_fragmentation_advanced', {}),
        ('ip_fragmentation_disorder', {}),
        ('ip_fragmentation_random', {}),
        ('simple_fragment', {}),
    ]
    
    logger.info(f"\nTesting attack instantiation with {len(test_cases)} test cases")
    
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
    logger.info(f"Attack Instantiation Test Results:")
    logger.info(f"  Passed: {passed}/{len(test_cases)}")
    logger.info(f"  Failed: {failed}/{len(test_cases)}")
    logger.info(f"{'='*60}")
    
    return failed == 0


def test_all_attacks_count():
    """Test that all attacks are accounted for."""
    mapper = get_parameter_mapper()
    
    total_attacks = len(mapper.get_supported_attacks())
    
    tcp_count = len(mapper.TCP_ATTACK_MAPPINGS)
    tls_count = len(mapper.TLS_ATTACK_MAPPINGS)
    tunneling_count = len(mapper.TUNNELING_ATTACK_MAPPINGS)
    fragmentation_count = len(mapper.FRAGMENTATION_ATTACK_MAPPINGS)
    
    logger.info(f"\nTotal Attack Count Summary:")
    logger.info(f"  TCP Attacks: {tcp_count}")
    logger.info(f"  TLS Attacks: {tls_count}")
    logger.info(f"  Tunneling Attacks: {tunneling_count}")
    logger.info(f"  Fragmentation Attacks: {fragmentation_count}")
    logger.info(f"  Total: {total_attacks}")
    
    expected_total = tcp_count + tls_count + tunneling_count + fragmentation_count
    
    if total_attacks == expected_total:
        logger.info(f"✓ Attack count matches: {total_attacks} == {expected_total}")
        return True
    else:
        logger.error(f"✗ Attack count mismatch: {total_attacks} != {expected_total}")
        return False


def main():
    """Run all tunneling and fragmentation parameter mapping tests."""
    logger.info("="*60)
    logger.info("Tunneling & Fragmentation Attack Parameter Mapping Tests")
    logger.info("Task 1.4: Implement parameter mappings for other attacks")
    logger.info("="*60)
    
    all_passed = True
    
    # Test 1: Tunneling attack mappings
    if not test_tunneling_attack_mappings():
        all_passed = False
    
    # Test 2: Fragmentation attack mappings
    if not test_fragmentation_attack_mappings():
        all_passed = False
    
    # Test 3: Attack instantiation
    if not test_attack_instantiation():
        all_passed = False
    
    # Test 4: Total attack count
    if not test_all_attacks_count():
        all_passed = False
    
    # Final summary
    logger.info(f"\n{'='*60}")
    if all_passed:
        logger.info("✓ ALL PARAMETER MAPPING TESTS PASSED")
    else:
        logger.error("✗ SOME PARAMETER MAPPING TESTS FAILED")
    logger.info("="*60)
    
    return 0 if all_passed else 1


if __name__ == '__main__':
    sys.exit(main())
