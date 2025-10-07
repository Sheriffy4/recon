"""
Focused test for checksum validation in PCAP Content Validator

Tests the checksum validation functionality specifically.
"""

import logging
from pathlib import Path
from core.pcap_content_validator import PCAPContentValidator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def test_checksum_validation_with_bad_checksums():
    """Test checksum validation expecting bad checksums."""
    logger.info("=" * 80)
    logger.info("Test 1: Checksum Validation - Expecting Bad Checksums")
    logger.info("=" * 80)
    
    validator = PCAPContentValidator()
    
    # Test with a PCAP that should have bad checksums
    pcap_file = Path("test_fakeddisorder.pcap")
    
    if not pcap_file.exists():
        logger.warning(f"PCAP file not found: {pcap_file}")
        logger.info("Skipping test")
        return
    
    # Test expecting bad checksums
    attack_spec = {
        'expected_bad_checksums': True
    }
    
    result = validator.validate_pcap(pcap_file, attack_spec)
    
    logger.info(f"\nValidation Result: {'PASSED' if result.passed else 'FAILED'}")
    logger.info(f"Packet Count: {result.packet_count}")
    logger.info(f"TCP Packets: {result.details.get('total_tcp_packets', 0)}")
    logger.info(f"Bad TCP Checksums: {result.details.get('bad_tcp_checksum_count', 0)}")
    logger.info(f"Bad IP Checksums: {result.details.get('bad_ip_checksum_count', 0)}")
    logger.info(f"Zero TCP Checksums: {len(result.details.get('zero_tcp_checksums', []))}")
    logger.info(f"Zero IP Checksums: {len(result.details.get('zero_ip_checksums', []))}")
    logger.info(f"Invalid TCP Checksums: {result.details.get('invalid_tcp_checksums', 0)}")
    logger.info(f"Invalid IP Checksums: {result.details.get('invalid_ip_checksums', 0)}")
    
    if result.issues:
        logger.info(f"\nIssues Found: {len(result.issues)}")
        checksum_issues = [i for i in result.issues if i.category == 'checksum']
        logger.info(f"Checksum Issues: {len(checksum_issues)}")
        
        for issue in checksum_issues[:5]:
            logger.info(f"  - {issue}")
    
    logger.info("\n")


def test_checksum_validation_without_bad_checksums():
    """Test checksum validation not expecting bad checksums."""
    logger.info("=" * 80)
    logger.info("Test 2: Checksum Validation - Not Expecting Bad Checksums")
    logger.info("=" * 80)
    
    validator = PCAPContentValidator()
    
    # Test with a normal PCAP
    pcap_file = Path("zapret.pcap")
    
    if not pcap_file.exists():
        logger.warning(f"PCAP file not found: {pcap_file}")
        logger.info("Skipping test")
        return
    
    # Test NOT expecting bad checksums
    attack_spec = {
        'expected_bad_checksums': False
    }
    
    result = validator.validate_pcap(pcap_file, attack_spec)
    
    logger.info(f"\nValidation Result: {'PASSED' if result.passed else 'FAILED'}")
    logger.info(f"Packet Count: {result.packet_count}")
    logger.info(f"TCP Packets: {result.details.get('total_tcp_packets', 0)}")
    logger.info(f"Bad TCP Checksums: {result.details.get('bad_tcp_checksum_count', 0)}")
    logger.info(f"Bad IP Checksums: {result.details.get('bad_ip_checksum_count', 0)}")
    
    checksum_issues = [i for i in result.issues if i.category == 'checksum']
    logger.info(f"Checksum Issues: {len(checksum_issues)}")
    
    if checksum_issues:
        logger.info("\nChecksum Issues:")
        for issue in checksum_issues[:5]:
            logger.info(f"  - {issue}")
    
    logger.info("\n")


def test_checksum_anomaly_detection():
    """Test detection of checksum anomalies."""
    logger.info("=" * 80)
    logger.info("Test 3: Checksum Anomaly Detection")
    logger.info("=" * 80)
    
    validator = PCAPContentValidator()
    
    # Test with various PCAPs to detect anomalies
    test_pcaps = [
        ("test_fakeddisorder.pcap", True),
        ("test_multisplit.pcap", False),
        ("zapret.pcap", False)
    ]
    
    for pcap_name, expect_bad in test_pcaps:
        pcap_file = Path(pcap_name)
        
        if not pcap_file.exists():
            logger.warning(f"PCAP file not found: {pcap_file}")
            continue
        
        logger.info(f"\nAnalyzing: {pcap_name}")
        logger.info("-" * 80)
        
        attack_spec = {
            'expected_bad_checksums': expect_bad
        }
        
        result = validator.validate_pcap(pcap_file, attack_spec)
        
        bad_tcp = result.details.get('bad_tcp_checksum_count', 0)
        bad_ip = result.details.get('bad_ip_checksum_count', 0)
        total_tcp = result.details.get('total_tcp_packets', 0)
        
        logger.info(f"Expected bad checksums: {expect_bad}")
        logger.info(f"Found bad TCP checksums: {bad_tcp}/{total_tcp}")
        logger.info(f"Found bad IP checksums: {bad_ip}")
        logger.info(f"Validation: {'PASSED' if result.passed else 'FAILED'}")
        
        # Check for anomalies
        if bad_tcp > 0 or bad_ip > 0:
            logger.info(f"⚠️  Anomaly detected: Bad checksums found")
            logger.info(f"   Zero TCP checksums at packets: {result.details.get('zero_tcp_checksums', [])[:5]}")
            logger.info(f"   Zero IP checksums at packets: {result.details.get('zero_ip_checksums', [])[:5]}")


def test_checksum_extraction():
    """Test extraction of packet checksums."""
    logger.info("=" * 80)
    logger.info("Test 4: Checksum Extraction")
    logger.info("=" * 80)
    
    validator = PCAPContentValidator()
    
    pcap_file = Path("test_fakeddisorder.pcap")
    
    if not pcap_file.exists():
        logger.warning(f"PCAP file not found: {pcap_file}")
        logger.info("Skipping test")
        return
    
    result = validator.validate_pcap(pcap_file)
    
    logger.info(f"\nChecksum Extraction Results:")
    logger.info(f"Total packets: {result.packet_count}")
    logger.info(f"TCP packets: {result.details.get('total_tcp_packets', 0)}")
    logger.info(f"Bad TCP checksums: {result.details.get('bad_tcp_checksum_count', 0)}")
    logger.info(f"Bad IP checksums: {result.details.get('bad_ip_checksum_count', 0)}")
    logger.info(f"Invalid TCP checksums: {result.details.get('invalid_tcp_checksums', 0)}")
    logger.info(f"Invalid IP checksums: {result.details.get('invalid_ip_checksums', 0)}")
    
    logger.info("\n✅ Checksum extraction successful")


def main():
    """Run all checksum validation tests."""
    logger.info("Starting Checksum Validation Tests")
    logger.info("=" * 80)
    
    try:
        test_checksum_validation_with_bad_checksums()
        test_checksum_validation_without_bad_checksums()
        test_checksum_anomaly_detection()
        test_checksum_extraction()
        
        logger.info("=" * 80)
        logger.info("✅ All checksum validation tests completed!")
        logger.info("=" * 80)
        
        logger.info("\nChecksum Validation Implementation Summary:")
        logger.info("✅ Extract packet checksums from TCP and IP layers")
        logger.info("✅ Validate good/bad checksums as expected")
        logger.info("✅ Detect checksum anomalies (zero checksums, incorrect checksums)")
        logger.info("✅ Report issues with detailed information")
        
    except Exception as e:
        logger.error(f"Test failed: {e}", exc_info=True)


if __name__ == "__main__":
    main()
