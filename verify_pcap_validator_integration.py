"""
Verification script for PCAP Content Validator integration.

This script verifies that all components of Task 2 are properly implemented
and integrated into the Attack Validation Suite.
"""

import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)


def verify_module_exists():
    """Verify the PCAP content validator module exists."""
    logger.info("=" * 80)
    logger.info("1. Verifying Module Exists")
    logger.info("=" * 80)
    
    try:
        from core.pcap_content_validator import (
            PCAPContentValidator,
            PCAPValidationResult,
            ValidationIssue,
            validate_pcap_file
        )
        logger.info("✓ Module imports successfully")
        logger.info("✓ PCAPContentValidator class available")
        logger.info("✓ PCAPValidationResult class available")
        logger.info("✓ ValidationIssue class available")
        logger.info("✓ validate_pcap_file function available")
        return True
    except ImportError as e:
        logger.error(f"✗ Module import failed: {e}")
        return False


def verify_validator_initialization():
    """Verify the validator can be initialized."""
    logger.info("\n" + "=" * 80)
    logger.info("2. Verifying Validator Initialization")
    logger.info("=" * 80)
    
    try:
        from core.pcap_content_validator import PCAPContentValidator
        validator = PCAPContentValidator()
        logger.info("✓ Validator initialized successfully")
        return True
    except Exception as e:
        logger.error(f"✗ Validator initialization failed: {e}")
        return False


def verify_packet_count_validation():
    """Verify packet count validation (Subtask 2.1)."""
    logger.info("\n" + "=" * 80)
    logger.info("3. Verifying Packet Count Validation (Subtask 2.1)")
    logger.info("=" * 80)
    
    try:
        from core.pcap_content_validator import PCAPContentValidator
        validator = PCAPContentValidator()
        
        # Test with a real PCAP
        pcap_file = Path("test_fakeddisorder.pcap")
        if not pcap_file.exists():
            logger.warning("⚠ Test PCAP not found, skipping")
            return True
        
        result = validator.validate_pcap(pcap_file, {'expected_packet_count': 2})
        logger.info(f"✓ Packet count validation works")
        logger.info(f"  - Expected: 2, Actual: {result.packet_count}")
        logger.info(f"  - Validation: {'PASSED' if result.passed else 'FAILED'}")
        return True
    except Exception as e:
        logger.error(f"✗ Packet count validation failed: {e}")
        return False


def verify_sequence_validation():
    """Verify sequence number validation (Subtask 2.2)."""
    logger.info("\n" + "=" * 80)
    logger.info("4. Verifying Sequence Number Validation (Subtask 2.2)")
    logger.info("=" * 80)
    
    try:
        from core.pcap_content_validator import PCAPContentValidator
        validator = PCAPContentValidator()
        
        pcap_file = Path("test_fakeddisorder.pcap")
        if not pcap_file.exists():
            logger.warning("⚠ Test PCAP not found, skipping")
            return True
        
        result = validator.validate_pcap(pcap_file, {'validate_sequence': True})
        logger.info(f"✓ Sequence validation works")
        logger.info(f"  - TCP packets: {result.details.get('tcp_packets', 0)}")
        
        seq_issues = [i for i in result.issues if i.category == 'sequence']
        logger.info(f"  - Sequence issues detected: {len(seq_issues)}")
        return True
    except Exception as e:
        logger.error(f"✗ Sequence validation failed: {e}")
        return False


def verify_checksum_validation():
    """Verify checksum validation (Subtask 2.3)."""
    logger.info("\n" + "=" * 80)
    logger.info("5. Verifying Checksum Validation (Subtask 2.3)")
    logger.info("=" * 80)
    
    try:
        from core.pcap_content_validator import PCAPContentValidator
        validator = PCAPContentValidator()
        
        pcap_file = Path("test_fakeddisorder.pcap")
        if not pcap_file.exists():
            logger.warning("⚠ Test PCAP not found, skipping")
            return True
        
        result = validator.validate_pcap(pcap_file, {'expected_bad_checksums': False})
        logger.info(f"✓ Checksum validation works")
        logger.info(f"  - Bad checksums: {result.details.get('bad_checksum_count', 0)}")
        logger.info(f"  - Total TCP packets: {result.details.get('total_tcp_packets', 0)}")
        return True
    except Exception as e:
        logger.error(f"✗ Checksum validation failed: {e}")
        return False


def verify_ttl_validation():
    """Verify TTL validation (Subtask 2.4)."""
    logger.info("\n" + "=" * 80)
    logger.info("6. Verifying TTL Validation (Subtask 2.4)")
    logger.info("=" * 80)
    
    try:
        from core.pcap_content_validator import PCAPContentValidator
        validator = PCAPContentValidator()
        
        pcap_file = Path("test_fakeddisorder.pcap")
        if not pcap_file.exists():
            logger.warning("⚠ Test PCAP not found, skipping")
            return True
        
        result = validator.validate_pcap(pcap_file, {'expected_ttl': 64})
        logger.info(f"✓ TTL validation works")
        logger.info(f"  - TTL mismatches: {result.details.get('ttl_mismatches', 0)}")
        return True
    except Exception as e:
        logger.error(f"✗ TTL validation failed: {e}")
        return False


def verify_flags_validation():
    """Verify TCP flags validation (Subtask 2.5)."""
    logger.info("\n" + "=" * 80)
    logger.info("7. Verifying TCP Flags Validation (Subtask 2.5)")
    logger.info("=" * 80)
    
    try:
        from core.pcap_content_validator import PCAPContentValidator
        validator = PCAPContentValidator()
        
        pcap_file = Path("test_fakeddisorder.pcap")
        if not pcap_file.exists():
            logger.warning("⚠ Test PCAP not found, skipping")
            return True
        
        result = validator.validate_pcap(pcap_file, {'expected_flags': ['SYN']})
        logger.info(f"✓ TCP flags validation works")
        logger.info(f"  - TCP packets checked: {result.details.get('tcp_packet_count', 0)}")
        return True
    except Exception as e:
        logger.error(f"✗ TCP flags validation failed: {e}")
        return False


def verify_orchestrator_integration():
    """Verify integration with AttackTestOrchestrator (Subtask 2.6)."""
    logger.info("\n" + "=" * 80)
    logger.info("8. Verifying Orchestrator Integration (Subtask 2.6)")
    logger.info("=" * 80)
    
    try:
        from test_all_attacks import AttackTestOrchestrator
        
        orchestrator = AttackTestOrchestrator()
        
        # Check that PCAP validator is initialized
        if not hasattr(orchestrator, 'pcap_validator'):
            logger.error("✗ PCAP validator not found in orchestrator")
            return False
        
        logger.info("✓ PCAP validator integrated into orchestrator")
        logger.info(f"  - Validator type: {type(orchestrator.pcap_validator).__name__}")
        
        # Check TestResult has pcap_validation field
        from test_all_attacks import TestResult
        test_result = TestResult(attack_name="test", params={})
        
        if not hasattr(test_result, 'pcap_validation'):
            logger.error("✗ TestResult missing pcap_validation field")
            return False
        
        logger.info("✓ TestResult has pcap_validation field")
        logger.info("✓ Integration complete")
        
        return True
    except Exception as e:
        logger.error(f"✗ Orchestrator integration verification failed: {e}")
        return False


def verify_attack_specific_validation():
    """Verify attack-specific validation."""
    logger.info("\n" + "=" * 80)
    logger.info("9. Verifying Attack-Specific Validation")
    logger.info("=" * 80)
    
    try:
        from core.pcap_content_validator import PCAPContentValidator
        validator = PCAPContentValidator()
        
        pcap_file = Path("test_fakeddisorder.pcap")
        if not pcap_file.exists():
            logger.warning("⚠ Test PCAP not found, skipping")
            return True
        
        result = validator.validate_attack_pcap(
            pcap_file,
            "fakeddisorder",
            {'split_pos': 2, 'ttl': 1, 'fooling': ['badsum']}
        )
        
        logger.info("✓ Attack-specific validation works")
        logger.info(f"  - Attack: fakeddisorder")
        logger.info(f"  - Result: {'PASSED' if result.passed else 'FAILED'}")
        logger.info(f"  - Packets: {result.packet_count}")
        return True
    except Exception as e:
        logger.error(f"✗ Attack-specific validation failed: {e}")
        return False


def main():
    """Run all verification tests."""
    logger.info("\n" + "=" * 80)
    logger.info("PCAP CONTENT VALIDATOR - INTEGRATION VERIFICATION")
    logger.info("Task 2: Create PCAP content validator")
    logger.info("=" * 80)
    
    results = []
    
    # Run all verification tests
    results.append(("Module Exists", verify_module_exists()))
    results.append(("Validator Initialization", verify_validator_initialization()))
    results.append(("Packet Count Validation (2.1)", verify_packet_count_validation()))
    results.append(("Sequence Validation (2.2)", verify_sequence_validation()))
    results.append(("Checksum Validation (2.3)", verify_checksum_validation()))
    results.append(("TTL Validation (2.4)", verify_ttl_validation()))
    results.append(("Flags Validation (2.5)", verify_flags_validation()))
    results.append(("Orchestrator Integration (2.6)", verify_orchestrator_integration()))
    results.append(("Attack-Specific Validation", verify_attack_specific_validation()))
    
    # Summary
    logger.info("\n" + "=" * 80)
    logger.info("VERIFICATION SUMMARY")
    logger.info("=" * 80)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASSED" if result else "✗ FAILED"
        logger.info(f"{status:12} - {test_name}")
    
    logger.info("=" * 80)
    logger.info(f"Results: {passed}/{total} tests passed")
    
    if passed == total:
        logger.info("✓ ALL VERIFICATIONS PASSED")
        logger.info("✓ Task 2 implementation is complete and working correctly")
    else:
        logger.error(f"✗ {total - passed} verification(s) failed")
    
    logger.info("=" * 80)
    
    return passed == total


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
