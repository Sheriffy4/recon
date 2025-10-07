"""
Test suite for PacketValidator.

This test verifies that the PacketValidator correctly validates packets
for various DPI bypass attacks.
"""

import struct
import tempfile
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from core.packet_validator import (
    PacketValidator,
    ValidationResult,
    ValidationSeverity,
    PacketData,
    validate_pcap,
    generate_diff_report
)


def create_test_pcap(packets_data: list, output_file: str):
    """
    Create a test PCAP file with specified packets.
    
    Args:
        packets_data: List of packet specifications
        output_file: Output PCAP file path
    """
    with open(output_file, 'wb') as f:
        # Write PCAP global header
        magic = 0xa1b2c3d4
        version_major = 2
        version_minor = 4
        thiszone = 0
        sigfigs = 0
        snaplen = 65535
        network = 1  # Ethernet
        
        global_header = struct.pack('<IHHIIII', magic, version_major, version_minor,
                                   thiszone, sigfigs, snaplen, network)
        f.write(global_header)
        
        # Write packets
        for i, pkt_spec in enumerate(packets_data):
            # Create packet
            packet = create_packet(pkt_spec)
            
            # Write packet record header
            ts_sec = int(pkt_spec.get('timestamp', 1000000000 + i))
            ts_usec = 0
            caplen = len(packet)
            origlen = len(packet)
            
            packet_header = struct.pack('<IIII', ts_sec, ts_usec, caplen, origlen)
            f.write(packet_header)
            f.write(packet)


def create_packet(spec: dict) -> bytes:
    """
    Create a packet from specification.
    
    Args:
        spec: Packet specification
    
    Returns:
        Raw packet bytes
    """
    # Ethernet header (14 bytes)
    eth_dst = b'\xff\xff\xff\xff\xff\xff'
    eth_src = b'\x00\x00\x00\x00\x00\x00'
    eth_type = b'\x08\x00'  # IPv4
    ethernet = eth_dst + eth_src + eth_type
    
    # IP header (20 bytes)
    version_ihl = 0x45  # IPv4, 20 bytes
    tos = 0
    total_length = 40 + len(spec.get('payload', b''))  # IP + TCP + payload
    identification = 0x1234
    flags_fragment = 0
    ttl = spec.get('ttl', 64)
    protocol = 6  # TCP
    checksum = 0  # Will calculate later
    src_ip = spec.get('src_ip', '192.168.1.100')
    dst_ip = spec.get('dst_ip', '162.159.140.229')
    
    # Convert IPs to bytes
    src_ip_bytes = bytes(map(int, src_ip.split('.')))
    dst_ip_bytes = bytes(map(int, dst_ip.split('.')))
    
    ip_header = struct.pack('!BBHHHBBH', version_ihl, tos, total_length,
                           identification, flags_fragment, ttl, protocol, checksum)
    ip_header += src_ip_bytes + dst_ip_bytes
    
    # Calculate IP checksum
    ip_checksum = calculate_checksum(ip_header)
    ip_header = ip_header[:10] + struct.pack('!H', ip_checksum) + ip_header[12:]
    
    # TCP header (20 bytes)
    src_port = spec.get('src_port', 12345)
    dst_port = spec.get('dst_port', 443)
    seq_num = spec.get('sequence_num', 1000)
    ack_num = spec.get('ack_num', 2000)
    header_len_flags = (5 << 12) | 0x018  # 20 bytes, PSH+ACK
    window = spec.get('window_size', 65535)
    tcp_checksum = 0  # Will calculate later
    urgent = 0
    
    tcp_header = struct.pack('!HHLLHHHH', src_port, dst_port, seq_num, ack_num,
                            header_len_flags, window, tcp_checksum, urgent)
    
    # Payload
    payload = spec.get('payload', b'')
    
    # Calculate TCP checksum
    if spec.get('bad_checksum', False):
        # Use invalid checksum
        tcp_checksum = 0x0000
    else:
        # Calculate proper checksum
        pseudo_header = src_ip_bytes + dst_ip_bytes + struct.pack('!BBH', 0, 6, len(tcp_header) + len(payload))
        tcp_checksum = calculate_checksum(pseudo_header + tcp_header + payload)
    
    tcp_header = tcp_header[:16] + struct.pack('!H', tcp_checksum) + tcp_header[18:]
    
    return ethernet + ip_header + tcp_header + payload


def calculate_checksum(data: bytes) -> int:
    """Calculate Internet checksum."""
    if len(data) % 2 == 1:
        data += b'\x00'
    
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
    
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    
    return ~checksum & 0xFFFF


def test_fake_attack_validation():
    """Test validation of fake attack."""
    print("\n=== Testing Fake Attack Validation ===")
    
    # Create test PCAP with fake attack
    packets = [
        {
            'ttl': 3,
            'sequence_num': 1000,
            'payload': b'FAKE',
            'bad_checksum': True
        },
        {
            'ttl': 64,
            'sequence_num': 1000,
            'payload': b'REAL',
            'bad_checksum': False
        }
    ]
    
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
        pcap_file = f.name
    
    try:
        create_test_pcap(packets, pcap_file)
        
        # Validate
        result = validate_pcap('fake', {'ttl': 3, 'fooling': ['badsum']}, pcap_file, debug=True)
        
        print(f"Validation passed: {result.passed}")
        print(f"Packet count: {result.packet_count}")
        print(f"Critical issues: {len(result.get_critical_issues())}")
        print(f"Errors: {len(result.get_errors())}")
        print(f"Warnings: {len(result.get_warnings())}")
        
        # Print details
        for detail in result.details:
            status = "✓" if detail.passed else "❌"
            print(f"{status} {detail.aspect}: {detail.message}")
        
        return result.passed
    
    finally:
        Path(pcap_file).unlink(missing_ok=True)


def test_fakeddisorder_validation():
    """Test validation of fakeddisorder attack."""
    print("\n=== Testing Fakeddisorder Attack Validation ===")
    
    # Create test PCAP with fakeddisorder attack
    packets = [
        {
            'ttl': 3,
            'sequence_num': 1000,
            'payload': b'FAKE' * 10,
            'bad_checksum': True
        },
        {
            'ttl': 64,
            'sequence_num': 1020,  # Part 2 (higher seq)
            'payload': b'PART2' * 10,
            'bad_checksum': False
        },
        {
            'ttl': 64,
            'sequence_num': 1000,  # Part 1 (lower seq)
            'payload': b'PART1' * 4,
            'bad_checksum': False
        }
    ]
    
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
        pcap_file = f.name
    
    try:
        create_test_pcap(packets, pcap_file)
        
        # Validate
        result = validate_pcap('fakeddisorder', 
                             {'ttl': 3, 'split_pos': 20, 'fooling': ['badsum']}, 
                             pcap_file, debug=True)
        
        print(f"Validation passed: {result.passed}")
        print(f"Packet count: {result.packet_count}")
        print(f"Critical issues: {len(result.get_critical_issues())}")
        print(f"Errors: {len(result.get_errors())}")
        print(f"Warnings: {len(result.get_warnings())}")
        
        # Print details
        for detail in result.details:
            status = "✓" if detail.passed else "❌"
            print(f"{status} {detail.aspect}: {detail.message}")
        
        return result.passed
    
    finally:
        Path(pcap_file).unlink(missing_ok=True)


def test_split_validation():
    """Test validation of split attack."""
    print("\n=== Testing Split Attack Validation ===")
    
    # Create test PCAP with split attack
    packets = [
        {
            'ttl': 64,
            'sequence_num': 1000,
            'payload': b'PART1',
            'bad_checksum': False
        },
        {
            'ttl': 64,
            'sequence_num': 1005,
            'payload': b'PART2',
            'bad_checksum': False
        }
    ]
    
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
        pcap_file = f.name
    
    try:
        create_test_pcap(packets, pcap_file)
        
        # Validate
        result = validate_pcap('split', {'split_pos': 5}, pcap_file, debug=True)
        
        print(f"Validation passed: {result.passed}")
        print(f"Packet count: {result.packet_count}")
        print(f"Critical issues: {len(result.get_critical_issues())}")
        print(f"Errors: {len(result.get_errors())}")
        print(f"Warnings: {len(result.get_warnings())}")
        
        # Print details
        for detail in result.details:
            status = "✓" if detail.passed else "❌"
            print(f"{status} {detail.aspect}: {detail.message}")
        
        return result.passed
    
    finally:
        Path(pcap_file).unlink(missing_ok=True)


def test_visual_diff():
    """Test visual diff generation."""
    print("\n=== Testing Visual Diff Generation ===")
    
    validator = PacketValidator()
    
    # Create expected packets
    expected = [
        {'ttl': 3, 'sequence_num': 1000, 'checksum_valid': False, 'payload_length': 40},
        {'ttl': 64, 'sequence_num': 1000, 'checksum_valid': True, 'payload_length': 100}
    ]
    
    # Create actual packets
    actual = [
        PacketData(
            index=0, timestamp=1000000000.0,
            src_ip='192.168.1.100', dst_ip='162.159.140.229',
            src_port=12345, dst_port=443,
            sequence_num=1000, ack_num=2000,
            ttl=3, flags=['PSH', 'ACK'], window_size=65535,
            checksum=0x0000, checksum_valid=False,
            payload=b'FAKE' * 10, payload_length=40,
            raw_data=b''
        ),
        PacketData(
            index=1, timestamp=1000000001.0,
            src_ip='192.168.1.100', dst_ip='162.159.140.229',
            src_port=12345, dst_port=443,
            sequence_num=1000, ack_num=2000,
            ttl=64, flags=['PSH', 'ACK'], window_size=65535,
            checksum=0x1234, checksum_valid=True,
            payload=b'REAL' * 25, payload_length=100,
            raw_data=b''
        )
    ]
    
    # Generate text diff
    text_diff = validator.generate_visual_diff(expected, actual, 'text')
    print("\n--- Text Diff ---")
    print(text_diff[:500])  # Print first 500 chars
    
    # Generate HTML diff
    html_diff = validator.generate_visual_diff(expected, actual, 'html')
    print("\n--- HTML Diff (first 300 chars) ---")
    print(html_diff[:300])
    
    return True


def main():
    """Run all tests."""
    print("=" * 80)
    print("PacketValidator Test Suite")
    print("=" * 80)
    
    tests = [
        ("Fake Attack Validation", test_fake_attack_validation),
        ("Fakeddisorder Attack Validation", test_fakeddisorder_validation),
        ("Split Attack Validation", test_split_validation),
        ("Visual Diff Generation", test_visual_diff)
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            passed = test_func()
            results.append((test_name, passed))
        except Exception as e:
            print(f"\n❌ Test '{test_name}' failed with exception: {e}")
            import traceback
            traceback.print_exc()
            results.append((test_name, False))
    
    # Print summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    
    for test_name, passed in results:
        status = "✓ PASSED" if passed else "❌ FAILED"
        print(f"{status}: {test_name}")
    
    total = len(results)
    passed_count = sum(1 for _, p in results if p)
    print(f"\nTotal: {passed_count}/{total} tests passed")
    
    return passed_count == total


if __name__ == '__main__':
    success = main()
    exit(0 if success else 1)
