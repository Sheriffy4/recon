"""
Test script for PCAP Content Validator

Tests the PCAP content validation functionality with sample PCAPs.
"""

import logging
from pathlib import Path
from core.pcap_content_validator import PCAPContentValidator, validate_pcap_file

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def test_basic_validation():
    """Test basic PCAP validation."""
    logger.info("=" * 80)
    logger.info("Testing Basic PCAP Validation")
    logger.info("=" * 80)
    
    validator = PCAPContentValidator()
    
    # Test with a sample PCAP file
    test_pcaps = [
        Path("zapret.pcap"),
        Path("recon_x.pcap"),
        Path("test_fakeddisorder.pcap"),
        Path("out2.pcap"),
        Path("test_multisplit.pcap")
    ]
    
    for pcap_file in test_pcaps:
        if not pcap_file.exists():
            logger.warning(f"PCAP file not found: {pcap_file}")
            continue
        
        logger.info(f"\nValidating: {pcap_file}")
        logger.info("-" * 80)
        
        try:
            result = validator.validate_pcap(pcap_file)
            
            logger.info(f"Validation Result: {'PASSED' if result.passed else 'FAILED'}")
            logger.info(f"Packet Count: {result.packet_count}")
            logger.info(f"Issues: {len(result.issues)}")
            logger.info(f"Warnings: {len(result.warnings)}")
            
            if result.issues:
                logger.info("\nIssues Found:")
                for issue in result.issues[:5]:  # Show first 5
                    logger.info(f"  - {issue}")
            
            if result.warnings:
                logger.info("\nWarnings:")
                for warning in result.warnings[:3]:  # Show first 3
                    logger.info(f"  - {warning}")
            
            logger.info(f"\nDetails: {result.details}")
            
        except Exception as e:
            logger.error(f"Error validating {pcap_file}: {e}", exc_info=True)


def test_attack_specific_validation():
    """Test attack-specific PCAP validation."""
    logger.info("\n" + "=" * 80)
    logger.info("Testing Attack-Specific PCAP Validation")
    logger.info("=" * 80)
    
    validator = PCAPContentValidator()
    
    # Test fakeddisorder attack
    pcap_file = Path("test_fakeddisorder.pcap")
    if pcap_file.exists():
        logger.info(f"\nValidating fakeddisorder attack PCAP: {pcap_file}")
        logger.info("-" * 80)
        
        attack_params = {
            'split_pos': 2,
            'ttl': 1,
            'fooling': ['badsum']
        }
        
        result = validator.validate_attack_pcap(
            pcap_file,
            'fakeddisorder',
            attack_params
        )
        
        logger.info(result.get_summary())
    else:
        logger.warning(f"Test PCAP not found: {pcap_file}")


def test_packet_count_validation():
    """Test packet count validation."""
    logger.info("\n" + "=" * 80)
    logger.info("Testing Packet Count Validation")
    logger.info("=" * 80)
    
    validator = PCAPContentValidator()
    
    pcap_file = Path("zapret.pcap")
    if not pcap_file.exists():
        logger.warning(f"PCAP file not found: {pcap_file}")
        return
    
    # Test with expected packet count
    attack_spec = {
        'expected_packet_count': 10  # Intentionally wrong to test validation
    }
    
    result = validator.validate_pcap(pcap_file, attack_spec)
    
    logger.info(f"Expected: {attack_spec['expected_packet_count']} packets")
    logger.info(f"Actual: {result.packet_count} packets")
    logger.info(f"Validation: {'PASSED' if result.passed else 'FAILED'}")
    
    if result.issues:
        logger.info("\nIssues:")
        for issue in result.issues:
            logger.info(f"  - {issue}")


def test_checksum_validation():
    """Test checksum validation."""
    logger.info("\n" + "=" * 80)
    logger.info("Testing Checksum Validation")
    logger.info("=" * 80)
    
    validator = PCAPContentValidator()
    
    pcap_file = Path("zapret.pcap")
    if not pcap_file.exists():
        logger.warning(f"PCAP file not found: {pcap_file}")
        return
    
    # Test expecting bad checksums
    attack_spec = {
        'expected_bad_checksums': True
    }
    
    result = validator.validate_pcap(pcap_file, attack_spec)
    
    logger.info(f"Expected bad checksums: {attack_spec['expected_bad_checksums']}")
    logger.info(f"Bad checksums found: {result.details.get('bad_checksum_count', 0)}")
    logger.info(f"Total TCP packets: {result.details.get('total_tcp_packets', 0)}")
    logger.info(f"Validation: {'PASSED' if result.passed else 'FAILED'}")


def test_ttl_validation():
    """Test TTL validation."""
    logger.info("\n" + "=" * 80)
    logger.info("Testing TTL Validation")
    logger.info("=" * 80)
    
    validator = PCAPContentValidator()
    
    pcap_file = Path("zapret.pcap")
    if not pcap_file.exists():
        logger.warning(f"PCAP file not found: {pcap_file}")
        return
    
    # Test with expected TTL
    attack_spec = {
        'expected_ttl': 64
    }
    
    result = validator.validate_pcap(pcap_file, attack_spec)
    
    logger.info(f"Expected TTL: {attack_spec['expected_ttl']}")
    logger.info(f"TTL mismatches: {result.details.get('ttl_mismatches', 0)}")
    logger.info(f"Validation: {'PASSED' if result.passed else 'FAILED'}")
    
    if result.issues:
        logger.info("\nTTL Issues:")
        for issue in [i for i in result.issues if i.category == 'ttl'][:3]:
            logger.info(f"  - {issue}")


def test_sequence_validation():
    """Test sequence number validation."""
    logger.info("\n" + "=" * 80)
    logger.info("Testing Sequence Number Validation")
    logger.info("=" * 80)
    
    validator = PCAPContentValidator()
    
    pcap_file = Path("zapret.pcap")
    if not pcap_file.exists():
        logger.warning(f"PCAP file not found: {pcap_file}")
        return
    
    # Test with sequence validation enabled
    attack_spec = {
        'validate_sequence': True
    }
    
    result = validator.validate_pcap(pcap_file, attack_spec)
    
    logger.info(f"Packet count: {result.packet_count}")
    logger.info(f"TCP packets: {result.details.get('tcp_packets', 0)}")
    
    sequence_issues = [i for i in result.issues if i.category == 'sequence']
    logger.info(f"Sequence issues: {len(sequence_issues)}")
    
    if sequence_issues:
        logger.info("\nSequence Issues:")
        for issue in sequence_issues[:5]:
            logger.info(f"  - {issue}")


def test_convenience_function():
    """Test convenience function."""
    logger.info("\n" + "=" * 80)
    logger.info("Testing Convenience Function")
    logger.info("=" * 80)
    
    pcap_file = Path("zapret.pcap")
    if not pcap_file.exists():
        logger.warning(f"PCAP file not found: {pcap_file}")
        return
    
    result = validate_pcap_file(pcap_file)
    
    logger.info(result.get_summary())


def main():
    """Run all tests."""
    logger.info("Starting PCAP Content Validator Tests")
    logger.info("=" * 80)
    
    try:
        test_basic_validation()
        test_attack_specific_validation()
        test_packet_count_validation()
        test_checksum_validation()
        test_ttl_validation()
        test_sequence_validation()
        test_convenience_function()
        
        logger.info("\n" + "=" * 80)
        logger.info("All tests completed!")
        logger.info("=" * 80)
        
    except Exception as e:
        logger.error(f"Test failed: {e}", exc_info=True)


if __name__ == "__main__":
    main()
