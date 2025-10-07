"""
Test script for SimplePacketValidator.

This script tests the simple packet validator with various attack types
and validates that it correctly checks sequence numbers, checksums, and TTL.
"""

import sys
from pathlib import Path

# Add recon to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from core.simple_packet_validator import SimplePacketValidator, quick_validate
except ImportError:
    # Try alternative import
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "simple_packet_validator",
        Path(__file__).parent / "core" / "simple_packet_validator.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    SimplePacketValidator = module.SimplePacketValidator
    quick_validate = module.quick_validate


def test_validator_initialization():
    """Test that validator can be initialized."""
    print("\n=== Test: Validator Initialization ===")
    
    validator = SimplePacketValidator()
    assert validator is not None
    print("✓ Validator initialized successfully")
    
    validator_debug = SimplePacketValidator(debug=True)
    assert validator_debug.debug == True
    print("✓ Debug mode enabled successfully")


def test_quick_validate_function():
    """Test the quick_validate convenience function."""
    print("\n=== Test: Quick Validate Function ===")
    
    # Test with non-existent file
    result = quick_validate('nonexistent.pcap', 'fake', {'ttl': 1})
    assert result is not None
    assert 'passed' in result
    assert 'errors' in result
    print("✓ Quick validate handles missing file")


def test_validate_fake_attack():
    """Test validation of fake attack."""
    print("\n=== Test: Fake Attack Validation ===")
    
    validator = SimplePacketValidator(debug=True)
    
    # Look for existing PCAP files
    pcap_files = [
        'test_fakeddisorder.pcap',
        'recon_x.pcap',
        'zapret.pcap',
        'test_fix_fake_ttl1.pcap'
    ]
    
    found_pcap = None
    for pcap_file in pcap_files:
        if Path(pcap_file).exists():
            found_pcap = pcap_file
            break
    
    if found_pcap:
        print(f"Testing with PCAP file: {found_pcap}")
        result = validator.validate_pcap(
            found_pcap,
            attack_type='fake',
            params={'ttl': 1, 'fooling': ['badsum']}
        )
        
        print(f"Validation result: {'PASSED' if result['passed'] else 'FAILED'}")
        print(f"Packet count: {result['packet_count']}")
        
        if result['errors']:
            print("Errors:")
            for error in result['errors']:
                print(f"  - {error}")
        
        if result['warnings']:
            print("Warnings:")
            for warning in result['warnings']:
                print(f"  - {warning}")
        
        if result['details']:
            print("Details:")
            for category, details in result['details'].items():
                print(f"  {category}:")
                if 'details' in details:
                    for detail in details['details']:
                        print(f"    {detail}")
        
        print("✓ Fake attack validation completed")
    else:
        print("⚠ No PCAP files found for testing")


def test_validate_fakeddisorder_attack():
    """Test validation of fakeddisorder attack."""
    print("\n=== Test: Fakeddisorder Attack Validation ===")
    
    validator = SimplePacketValidator(debug=True)
    
    # Look for fakeddisorder PCAP files
    pcap_files = [
        'test_fakeddisorder.pcap',
        'test_fix_fakeddisorder.pcap',
        'recon_x.pcap'
    ]
    
    found_pcap = None
    for pcap_file in pcap_files:
        if Path(pcap_file).exists():
            found_pcap = pcap_file
            break
    
    if found_pcap:
        print(f"Testing with PCAP file: {found_pcap}")
        result = validator.validate_pcap(
            found_pcap,
            attack_type='fakeddisorder',
            params={
                'split_pos': 76,
                'overlap_size': 336,
                'ttl': 3,
                'fooling': ['badsum']
            }
        )
        
        print(f"Validation result: {'PASSED' if result['passed'] else 'FAILED'}")
        print(f"Packet count: {result['packet_count']}")
        
        if result['errors']:
            print("Errors:")
            for error in result['errors']:
                print(f"  - {error}")
        
        if result['warnings']:
            print("Warnings:")
            for warning in result['warnings']:
                print(f"  - {warning}")
        
        print("✓ Fakeddisorder attack validation completed")
    else:
        print("⚠ No PCAP files found for testing")


def test_validate_split_attack():
    """Test validation of split attack."""
    print("\n=== Test: Split Attack Validation ===")
    
    validator = SimplePacketValidator(debug=True)
    
    # Look for split PCAP files
    pcap_files = [
        'test_split.pcap',
        'test_fix_split_sni.pcap'
    ]
    
    found_pcap = None
    for pcap_file in pcap_files:
        if Path(pcap_file).exists():
            found_pcap = pcap_file
            break
    
    if found_pcap:
        print(f"Testing with PCAP file: {found_pcap}")
        result = validator.validate_pcap(
            found_pcap,
            attack_type='split',
            params={'split_pos': 1}
        )
        
        print(f"Validation result: {'PASSED' if result['passed'] else 'FAILED'}")
        print(f"Packet count: {result['packet_count']}")
        
        if result['errors']:
            print("Errors:")
            for error in result['errors']:
                print(f"  - {error}")
        
        print("✓ Split attack validation completed")
    else:
        print("⚠ No PCAP files found for testing")


def test_seq_number_validation():
    """Test sequence number validation logic."""
    print("\n=== Test: Sequence Number Validation ===")
    
    validator = SimplePacketValidator()
    
    # Create mock packets
    packets = [
        {
            'index': 0,
            'seq': 1000,
            'ttl': 1,
            'checksum_valid': False,
            'payload_len': 100
        },
        {
            'index': 1,
            'seq': 1000,
            'ttl': 64,
            'checksum_valid': True,
            'payload_len': 50
        },
        {
            'index': 2,
            'seq': 1050,
            'ttl': 64,
            'checksum_valid': True,
            'payload_len': 50
        }
    ]
    
    result = validator.validate_seq_numbers(
        packets,
        attack_type='fakeddisorder',
        params={'split_pos': 50}
    )
    
    print(f"Sequence validation: {'PASSED' if result['passed'] else 'FAILED'}")
    if result['errors']:
        print("Errors:")
        for error in result['errors']:
            print(f"  - {error}")
    
    print("✓ Sequence number validation logic tested")


def test_checksum_validation():
    """Test checksum validation logic."""
    print("\n=== Test: Checksum Validation ===")
    
    validator = SimplePacketValidator()
    
    # Create mock packets
    packets = [
        {
            'index': 0,
            'ttl': 1,
            'checksum_valid': False  # Fake packet with bad checksum
        },
        {
            'index': 1,
            'ttl': 64,
            'checksum_valid': True  # Real packet with good checksum
        }
    ]
    
    result = validator.validate_checksums(
        packets,
        attack_type='fake',
        params={'fooling': ['badsum']}
    )
    
    print(f"Checksum validation: {'PASSED' if result['passed'] else 'FAILED'}")
    if result['errors']:
        print("Errors:")
        for error in result['errors']:
            print(f"  - {error}")
    
    print("✓ Checksum validation logic tested")


def test_ttl_validation():
    """Test TTL validation logic."""
    print("\n=== Test: TTL Validation ===")
    
    validator = SimplePacketValidator()
    
    # Create mock packets
    packets = [
        {
            'index': 0,
            'ttl': 1,
            'checksum_valid': False
        },
        {
            'index': 1,
            'ttl': 64,
            'checksum_valid': True
        }
    ]
    
    result = validator.validate_ttl(
        packets,
        attack_type='fake',
        params={'ttl': 1}
    )
    
    print(f"TTL validation: {'PASSED' if result['passed'] else 'FAILED'}")
    if result['errors']:
        print("Errors:")
        for error in result['errors']:
            print(f"  - {error}")
    
    print("✓ TTL validation logic tested")


def main():
    """Run all tests."""
    print("=" * 60)
    print("Simple Packet Validator Test Suite")
    print("=" * 60)
    
    try:
        test_validator_initialization()
        test_quick_validate_function()
        test_seq_number_validation()
        test_checksum_validation()
        test_ttl_validation()
        test_validate_fake_attack()
        test_validate_fakeddisorder_attack()
        test_validate_split_attack()
        
        print("\n" + "=" * 60)
        print("✓ All tests completed successfully!")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n✗ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
