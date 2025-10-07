#!/usr/bin/env python3
"""
Test script for PatternRecognizer functionality.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.pcap_analysis.pattern_recognizer import (
    PatternRecognizer, EvasionPattern, FakePacketPattern, Anomaly,
    PacketRole, EvasionTechnique, AnomalyType
)
from core.pcap_analysis.packet_info import PacketInfo, TLSInfo
from core.pcap_analysis.strategy_config import StrategyConfig


def create_test_packets():
    """Create test packet data for pattern recognition testing."""
    packets = []
    
    # Create a fake packet (TTL=64, bad checksum) - WRONG TTL for recon
    fake_packet = PacketInfo(
        timestamp=1000.0,
        src_ip="192.168.1.100",
        dst_ip="1.1.1.1",
        src_port=12345,
        dst_port=443,
        sequence_num=0,
        ack_num=0,
        ttl=64,  # WRONG TTL - should be 3 like zapret
        flags=['PSH', 'ACK'],
        payload_length=0,
        checksum=0x1234,
        checksum_valid=False  # Bad checksum
    )
    packets.append(fake_packet)
    
    # Create a real ClientHello packet
    client_hello_payload = bytes.fromhex(
        "160301005a010000560303" + "00" * 32 + "00" +  # TLS header + random + session_id_len
        "0014" +  # cipher_suites_len
        "c02fc02bc030c02cc028c027c014c013" +  # cipher suites
        "01" + "00" +  # compression_methods + extensions_len
        "001d" +  # extensions length
        "0000" + "0015" +  # server_name extension
        "0013" + "00" + "11" + "0000" + "0e" + "782e636f6d"  # SNI: x.com
    )
    
    real_packet = PacketInfo(
        timestamp=1000.001,
        src_ip="192.168.1.100",
        dst_ip="1.1.1.1",
        src_port=12345,
        dst_port=443,
        sequence_num=1000,
        ack_num=1,
        ttl=64,  # Normal TTL
        flags=['PSH', 'ACK'],
        payload_length=len(client_hello_payload),
        payload=client_hello_payload,
        checksum=0x5678,
        checksum_valid=True
    )
    packets.append(real_packet)
    
    # Create split segments
    split_segment1 = PacketInfo(
        timestamp=1000.002,
        src_ip="192.168.1.100",
        dst_ip="1.1.1.1",
        src_port=12345,
        dst_port=443,
        sequence_num=1001,
        ack_num=1,
        ttl=64,
        flags=['PSH', 'ACK'],
        payload_length=3,
        payload=b"GET",
        checksum=0x9abc,
        checksum_valid=True
    )
    packets.append(split_segment1)
    
    split_segment2 = PacketInfo(
        timestamp=1000.003,
        src_ip="192.168.1.100",
        dst_ip="1.1.1.1",
        src_port=12345,
        dst_port=443,
        sequence_num=1004,
        ack_num=1,
        ttl=64,
        flags=['PSH', 'ACK'],
        payload_length=20,
        payload=b" / HTTP/1.1\r\nHost: ",
        checksum=0xdef0,
        checksum_valid=True
    )
    packets.append(split_segment2)
    
    return packets


def create_zapret_reference_packets():
    """Create reference zapret packets for comparison."""
    packets = []
    
    # Zapret fake packet with correct parameters
    fake_packet1 = PacketInfo(
        timestamp=2000.0,
        src_ip="192.168.1.100",
        dst_ip="1.1.1.1",
        src_port=12345,
        dst_port=443,
        sequence_num=0,  # Zero sequence for badseq
        ack_num=0,
        ttl=3,  # Correct TTL
        flags=['PSH', 'ACK'],
        payload_length=0,
        checksum=0x0000,
        checksum_valid=False  # Bad checksum for badsum
    )
    packets.append(fake_packet1)
    
    # Second fake packet (zapret sends more fake packets)
    fake_packet2 = PacketInfo(
        timestamp=2000.0005,
        src_ip="192.168.1.100",
        dst_ip="1.1.1.1",
        src_port=12345,
        dst_port=443,
        sequence_num=0,  # Zero sequence for badseq
        ack_num=0,
        ttl=3,  # Correct TTL
        flags=['PSH', 'ACK'],
        payload_length=0,
        checksum=0x0000,
        checksum_valid=False  # Bad checksum for badsum
    )
    packets.append(fake_packet2)
    
    # Zapret real packet
    real_packet = PacketInfo(
        timestamp=2000.001,
        src_ip="192.168.1.100",
        dst_ip="1.1.1.1",
        src_port=12345,
        dst_port=443,
        sequence_num=1000,
        ack_num=1,
        ttl=64,
        flags=['PSH', 'ACK'],
        payload_length=100,
        payload=b"x" * 100,
        checksum=0x1234,
        checksum_valid=True
    )
    packets.append(real_packet)
    
    return packets


def test_fake_packet_detection():
    """Test fake packet pattern detection."""
    print("Testing fake packet detection...")
    
    recognizer = PatternRecognizer()
    packets = create_test_packets()
    
    fake_patterns = recognizer.detect_fake_packet_patterns(packets)
    
    print(f"Detected {len(fake_patterns)} packet patterns")
    
    fake_count = sum(1 for fp in fake_patterns if fp.is_fake)
    print(f"Identified {fake_count} fake packets")
    
    for i, fp in enumerate(fake_patterns):
        if fp.is_fake:
            print(f"  Fake packet {i}: TTL={fp.packet.ttl}, indicators={fp.fake_indicators}, confidence={fp.confidence:.2f}")
    
    # Verify fake packet detection
    assert fake_count >= 1, "Should detect at least one fake packet"
    
    fake_packet = next(fp for fp in fake_patterns if fp.is_fake)
    assert 'bad_checksum' in fake_packet.fake_indicators, "Should detect bad checksum"
    assert 'zero_sequence' in fake_packet.fake_indicators, "Should detect zero sequence"
    
    print("✓ Fake packet detection test passed")


def test_real_packet_detection():
    """Test real packet pattern detection."""
    print("\nTesting real packet detection...")
    
    recognizer = PatternRecognizer()
    packets = create_test_packets()
    
    real_packets = recognizer.detect_real_packet_patterns(packets)
    
    print(f"Detected {len(real_packets)} real packets")
    
    for packet in real_packets:
        print(f"  Real packet: TTL={packet.ttl}, seq={packet.sequence_num}, payload_len={packet.payload_length}")
    
    # Verify real packet detection
    assert len(real_packets) >= 2, "Should detect at least 2 real packets"
    
    # Check that real packets have proper characteristics
    for packet in real_packets:
        assert packet.ttl > 5, "Real packets should have normal TTL"
        assert packet.checksum_valid, "Real packets should have valid checksum"
    
    print("✓ Real packet detection test passed")


def test_evasion_pattern_recognition():
    """Test DPI evasion pattern recognition."""
    print("\nTesting evasion pattern recognition...")
    
    recognizer = PatternRecognizer()
    packets = create_test_packets()
    
    patterns = recognizer.recognize_dpi_evasion_patterns(packets)
    
    print(f"Detected {len(patterns)} evasion patterns")
    
    techniques = set()
    for pattern in patterns:
        techniques.add(pattern.technique)
        print(f"  {pattern.technique.value}: {pattern.description} (confidence: {pattern.confidence:.2f})")
    
    # Verify pattern detection
    assert EvasionTechnique.CHECKSUM_CORRUPTION in techniques, "Should detect checksum corruption"
    assert EvasionTechnique.FAKE_PACKET_INJECTION in techniques, "Should detect fake packet injection"
    
    print("✓ Evasion pattern recognition test passed")


def test_packet_role_classification():
    """Test packet role classification."""
    print("\nTesting packet role classification...")
    
    recognizer = PatternRecognizer()
    packets = create_test_packets()
    
    roles = recognizer.classify_packet_roles(packets)
    
    print(f"Classified {len(roles)} packet roles")
    
    role_counts = {}
    for i, role in roles.items():
        role_counts[role] = role_counts.get(role, 0) + 1
        print(f"  Packet {i}: {role.value}")
    
    # Verify role classification
    assert PacketRole.FAKE_PACKET in role_counts, "Should classify fake packets"
    assert PacketRole.REAL_PACKET in role_counts, "Should classify real packets"
    
    print("✓ Packet role classification test passed")


def test_anomaly_detection():
    """Test anomaly detection between recon and zapret patterns."""
    print("\nTesting anomaly detection...")
    
    recognizer = PatternRecognizer()
    
    # Create recon packets (with issues)
    recon_packets = create_test_packets()
    
    # Create zapret reference packets (correct)
    zapret_packets = create_zapret_reference_packets()
    
    # Recognize patterns
    recon_patterns = recognizer.recognize_dpi_evasion_patterns(recon_packets)
    zapret_patterns = recognizer.recognize_dpi_evasion_patterns(zapret_packets)
    
    # Detect anomalies
    anomalies = recognizer.detect_anomalies(recon_patterns, zapret_patterns, recon_packets, zapret_packets)
    
    print(f"Detected {len(anomalies)} anomalies")
    
    for anomaly in anomalies:
        print(f"  {anomaly.anomaly_type.value}: {anomaly.description}")
        print(f"    Severity: {anomaly.severity}, Confidence: {anomaly.confidence:.2f}")
        print(f"    Fix: {anomaly.fix_suggestion}")
    
    # Verify anomaly detection
    assert len(anomalies) > 0, "Should detect anomalies between recon and zapret"
    
    print("✓ Anomaly detection test passed")


def test_zapret_compliance_validation():
    """Test zapret compliance validation."""
    print("\nTesting zapret compliance validation...")
    
    recognizer = PatternRecognizer()
    
    # Create expected strategy
    expected_strategy = StrategyConfig(
        dpi_desync="fake,fakeddisorder",
        split_pos=3,
        ttl=3,
        fooling=['badsum', 'badseq']
    )
    
    # Test with compliant packets
    compliant_packets = create_zapret_reference_packets()
    compliance_score = recognizer.validate_zapret_compliance(compliant_packets, expected_strategy)
    
    print(f"Compliance score for zapret packets: {compliance_score:.2f}")
    
    # Test with non-compliant packets
    non_compliant_packets = create_test_packets()
    non_compliance_score = recognizer.validate_zapret_compliance(non_compliant_packets, expected_strategy)
    
    print(f"Compliance score for recon packets: {non_compliance_score:.2f}")
    
    # Verify compliance validation
    assert compliance_score > non_compliance_score, "Zapret packets should have higher compliance score"
    
    print("✓ Zapret compliance validation test passed")


def test_bypass_technique_identification():
    """Test bypass technique identification."""
    print("\nTesting bypass technique identification...")
    
    recognizer = PatternRecognizer({'confidence_threshold': 0.5})  # Lower threshold
    packets = create_test_packets()
    
    patterns = recognizer.recognize_dpi_evasion_patterns(packets)
    techniques = recognizer.identify_bypass_techniques(patterns)
    
    print(f"Identified {len(techniques)} bypass techniques:")
    for technique in techniques:
        print(f"  - {technique.value}")
    
    print(f"Pattern confidences:")
    for pattern in patterns:
        print(f"  - {pattern.technique.value}: {pattern.confidence:.2f}")
    
    # Verify technique identification
    assert len(techniques) > 0, "Should identify bypass techniques"
    assert EvasionTechnique.FAKE_PACKET_INJECTION in techniques, "Should identify fake packet injection"
    
    print("✓ Bypass technique identification test passed")


def main():
    """Run all pattern recognizer tests."""
    print("Running PatternRecognizer tests...\n")
    
    try:
        test_fake_packet_detection()
        test_real_packet_detection()
        test_evasion_pattern_recognition()
        test_packet_role_classification()
        test_anomaly_detection()
        test_zapret_compliance_validation()
        test_bypass_technique_identification()
        
        print("\n" + "="*50)
        print("✅ All PatternRecognizer tests passed!")
        print("Pattern recognition and anomaly detection system is working correctly.")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)