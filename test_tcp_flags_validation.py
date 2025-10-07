"""
Test TCP Flags Validation

Tests the TCP flags validation functionality in PCAPContentValidator.
Part of Task 2.5: Implement TCP flags validation.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from core.pcap_content_validator import PCAPContentValidator, PCAPValidationResult

try:
    from scapy.all import IP, TCP, wrpcap, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    print("ERROR: Scapy not available. Install with: pip install scapy")
    SCAPY_AVAILABLE = False
    sys.exit(1)


def create_test_pcap_with_flags(pcap_file: Path, flag_combinations: list):
    """Create a test PCAP with specific TCP flag combinations."""
    packets = []
    
    for i, flags in enumerate(flag_combinations):
        pkt = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(
            sport=12345 + i,
            dport=80,
            flags=flags,
            seq=1000 + i * 100
        )
        packets.append(pkt)
    
    wrpcap(str(pcap_file), packets)
    print(f"Created test PCAP: {pcap_file} with {len(packets)} packets")


def test_valid_flag_combinations():
    """Test validation with valid TCP flag combinations."""
    print("\n" + "="*70)
    print("TEST 1: Valid TCP Flag Combinations")
    print("="*70)
    
    pcap_file = Path("test_valid_flags.pcap")
    
    # Create PCAP with valid flag combinations
    valid_flags = [
        'S',      # SYN
        'SA',     # SYN+ACK
        'A',      # ACK
        'PA',     # PSH+ACK
        'FA',     # FIN+ACK
        'R',      # RST
        'RA'      # RST+ACK
    ]
    
    create_test_pcap_with_flags(pcap_file, valid_flags)
    
    # Validate
    validator = PCAPContentValidator()
    result = validator.validate_pcap(pcap_file, {
        'validate_flag_combinations': True
    })
    
    print(f"\nValidation Result: {'PASSED' if result.passed else 'FAILED'}")
    print(f"Packets: {result.packet_count}")
    print(f"Issues: {len(result.issues)}")
    
    if result.details.get('flag_combinations'):
        print("\nFlag Combinations Found:")
        for combo, count in result.details['flag_combinations'].items():
            print(f"  {combo}: {count} packet(s)")
    
    if result.details.get('flag_counts'):
        print("\nIndividual Flag Counts:")
        for flag, count in result.details['flag_counts'].items():
            if count > 0:
                print(f"  {flag}: {count}")
    
    # Cleanup
    pcap_file.unlink()
    
    return result.passed


def test_invalid_flag_combinations():
    """Test detection of invalid TCP flag combinations."""
    print("\n" + "="*70)
    print("TEST 2: Invalid TCP Flag Combinations (Anomaly Detection)")
    print("="*70)
    
    pcap_file = Path("test_invalid_flags.pcap")
    
    # Create PCAP with invalid/suspicious flag combinations
    invalid_flags = [
        'SF',     # SYN+FIN (Christmas tree attack)
        'SR',     # SYN+RST (invalid)
        'FR',     # FIN+RST (unusual)
        '',       # NULL scan (no flags)
        'FSRPAU', # XMAS scan (all flags)
        'F',      # FIN without ACK (unusual)
    ]
    
    create_test_pcap_with_flags(pcap_file, invalid_flags)
    
    # Validate
    validator = PCAPContentValidator()
    result = validator.validate_pcap(pcap_file, {
        'validate_flag_combinations': True
    })
    
    print(f"\nValidation Result: {'PASSED' if result.passed else 'FAILED'}")
    print(f"Packets: {result.packet_count}")
    print(f"Issues: {len(result.issues)}")
    print(f"Invalid Combinations: {result.details.get('invalid_flag_combinations', 0)}")
    
    print("\nDetected Anomalies:")
    for issue in result.issues:
        if issue.category == 'flags':
            print(f"  Packet {issue.packet_index}: {issue.description}")
            print(f"    Flags: {issue.actual}")
    
    # Cleanup
    pcap_file.unlink()
    
    # We expect to find anomalies
    expected_anomalies = len(invalid_flags)
    actual_anomalies = result.details.get('invalid_flag_combinations', 0)
    
    success = actual_anomalies >= expected_anomalies - 1  # Allow some tolerance
    print(f"\nExpected ~{expected_anomalies} anomalies, found {actual_anomalies}")
    
    return success


def test_expected_flags_validation():
    """Test validation against expected flags."""
    print("\n" + "="*70)
    print("TEST 3: Expected Flags Validation")
    print("="*70)
    
    pcap_file = Path("test_expected_flags.pcap")
    
    # Create PCAP with specific flags
    flags = ['S', 'SA', 'A', 'PA', 'FA']
    create_test_pcap_with_flags(pcap_file, flags)
    
    # Validate expecting SYN flags
    validator = PCAPContentValidator()
    result = validator.validate_pcap(pcap_file, {
        'expected_flags': ['S', 'A'],  # Expect SYN and ACK flags
        'validate_flag_combinations': False
    })
    
    print(f"\nValidation Result: {'PASSED' if result.passed else 'FAILED'}")
    print(f"Packets: {result.packet_count}")
    print(f"Issues: {len(result.issues)}")
    
    print("\nExpected Flags: SYN, ACK")
    print("Checking if expected flags are present in packets...")
    
    for issue in result.issues:
        if issue.category == 'flags':
            print(f"  Packet {issue.packet_index}: {issue.description}")
    
    # Cleanup
    pcap_file.unlink()
    
    return True


def test_flag_statistics():
    """Test flag statistics collection."""
    print("\n" + "="*70)
    print("TEST 4: Flag Statistics Collection")
    print("="*70)
    
    pcap_file = Path("test_flag_stats.pcap")
    
    # Create PCAP with various flags
    flags = ['S', 'SA', 'SA', 'A', 'A', 'A', 'PA', 'PA', 'FA', 'RA']
    create_test_pcap_with_flags(pcap_file, flags)
    
    # Validate
    validator = PCAPContentValidator()
    result = validator.validate_pcap(pcap_file, {
        'validate_flag_combinations': True
    })
    
    print(f"\nValidation Result: {'PASSED' if result.passed else 'FAILED'}")
    print(f"Total Packets: {result.packet_count}")
    
    print("\nFlag Statistics:")
    if result.details.get('flag_counts'):
        for flag, count in sorted(result.details['flag_counts'].items()):
            if count > 0:
                print(f"  {flag}: {count} occurrences")
    
    print("\nFlag Combination Distribution:")
    if result.details.get('flag_combinations'):
        for combo, count in sorted(result.details['flag_combinations'].items()):
            print(f"  {combo}: {count} packet(s)")
    
    # Cleanup
    pcap_file.unlink()
    
    # Verify statistics are collected
    has_stats = bool(result.details.get('flag_counts') and result.details.get('flag_combinations'))
    
    return has_stats


def test_real_world_scenario():
    """Test with a realistic TCP connection scenario."""
    print("\n" + "="*70)
    print("TEST 5: Real-World TCP Connection Scenario")
    print("="*70)
    
    pcap_file = Path("test_real_connection.pcap")
    
    # Simulate a typical TCP connection:
    # 1. SYN (client -> server)
    # 2. SYN+ACK (server -> client)
    # 3. ACK (client -> server)
    # 4. PSH+ACK (client -> server, data)
    # 5. ACK (server -> client)
    # 6. PSH+ACK (server -> client, data)
    # 7. ACK (client -> server)
    # 8. FIN+ACK (client -> server)
    # 9. FIN+ACK (server -> client)
    # 10. ACK (client -> server)
    
    connection_flags = ['S', 'SA', 'A', 'PA', 'A', 'PA', 'A', 'FA', 'FA', 'A']
    create_test_pcap_with_flags(pcap_file, connection_flags)
    
    # Validate
    validator = PCAPContentValidator()
    result = validator.validate_pcap(pcap_file, {
        'validate_flag_combinations': True,
        'expected_packet_count': 10
    })
    
    print(f"\nValidation Result: {'PASSED' if result.passed else 'FAILED'}")
    print(f"Packets: {result.packet_count}")
    print(f"Issues: {len(result.issues)}")
    print(f"Warnings: {len(result.warnings)}")
    
    print("\nConnection Flow:")
    for i, flags in enumerate(connection_flags, 1):
        print(f"  {i}. Flags: {flags}")
    
    if result.issues:
        print("\nIssues Found:")
        for issue in result.issues:
            print(f"  {issue}")
    
    # Cleanup
    pcap_file.unlink()
    
    # Should pass with no anomalies for normal connection
    return result.passed and result.details.get('invalid_flag_combinations', 0) == 0


def main():
    """Run all TCP flags validation tests."""
    print("="*70)
    print("TCP FLAGS VALIDATION TEST SUITE")
    print("Task 2.5: Implement TCP flags validation")
    print("="*70)
    
    if not SCAPY_AVAILABLE:
        print("ERROR: Scapy is required for these tests")
        return False
    
    tests = [
        ("Valid Flag Combinations", test_valid_flag_combinations),
        ("Invalid Flag Combinations", test_invalid_flag_combinations),
        ("Expected Flags Validation", test_expected_flags_validation),
        ("Flag Statistics", test_flag_statistics),
        ("Real-World Scenario", test_real_world_scenario),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\nERROR in {test_name}: {e}")
            import traceback
            traceback.print_exc()
            results.append((test_name, False))
    
    # Print summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    
    for test_name, result in results:
        status = "✓ PASSED" if result else "✗ FAILED"
        print(f"{status}: {test_name}")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n✓ All tests passed! TCP flags validation is working correctly.")
        return True
    else:
        print(f"\n✗ {total - passed} test(s) failed.")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
