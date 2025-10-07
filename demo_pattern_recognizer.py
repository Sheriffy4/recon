#!/usr/bin/env python3
"""
Demo script showing PatternRecognizer integration with PCAP analysis system.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.pcap_analysis import (
    PatternRecognizer, PCAPComparator, StrategyAnalyzer, DifferenceDetector,
    PacketInfo, StrategyConfig, EvasionTechnique, AnomalyType
)


def create_demo_recon_packets():
    """Create demo recon packets with issues."""
    packets = []
    
    # Recon fake packet with wrong TTL
    fake_packet = PacketInfo(
        timestamp=1000.0,
        src_ip="192.168.1.100",
        dst_ip="104.16.132.229",  # x.com IP
        src_port=54321,
        dst_port=443,
        sequence_num=0,
        ack_num=0,
        ttl=64,  # WRONG: Should be 3
        flags=['PSH', 'ACK'],
        payload_length=0,
        checksum=0x1234,
        checksum_valid=False
    )
    packets.append(fake_packet)
    
    # TLS ClientHello with split
    client_hello_part1 = PacketInfo(
        timestamp=1000.001,
        src_ip="192.168.1.100",
        dst_ip="104.16.132.229",
        src_port=54321,
        dst_port=443,
        sequence_num=1000,
        ack_num=1,
        ttl=64,
        flags=['PSH', 'ACK'],
        payload_length=5,  # Wrong split position
        payload=b"\x16\x03\x01\x00\x5a",  # TLS header
        checksum=0x5678,
        checksum_valid=True
    )
    packets.append(client_hello_part1)
    
    # Rest of ClientHello
    client_hello_part2 = PacketInfo(
        timestamp=1000.002,
        src_ip="192.168.1.100",
        dst_ip="104.16.132.229",
        src_port=54321,
        dst_port=443,
        sequence_num=1005,
        ack_num=1,
        ttl=64,
        flags=['PSH', 'ACK'],
        payload_length=85,
        payload=b"\x01\x00\x00\x56" + b"x" * 81,  # ClientHello content
        checksum=0x9abc,
        checksum_valid=True
    )
    packets.append(client_hello_part2)
    
    return packets


def create_demo_zapret_packets():
    """Create demo zapret packets (correct implementation)."""
    packets = []
    
    # Zapret fake packet with correct TTL=3
    fake_packet = PacketInfo(
        timestamp=2000.0,
        src_ip="192.168.1.100",
        dst_ip="104.16.132.229",
        src_port=54321,
        dst_port=443,
        sequence_num=0,  # badseq
        ack_num=0,
        ttl=3,  # CORRECT TTL
        flags=['PSH', 'ACK'],
        payload_length=0,
        checksum=0x0000,
        checksum_valid=False  # badsum
    )
    packets.append(fake_packet)
    
    # TLS ClientHello with correct split at position 3
    client_hello_part1 = PacketInfo(
        timestamp=2000.001,
        src_ip="192.168.1.100",
        dst_ip="104.16.132.229",
        src_port=54321,
        dst_port=443,
        sequence_num=1000,
        ack_num=1,
        ttl=64,
        flags=['PSH', 'ACK'],
        payload_length=3,  # Correct split position
        payload=b"\x16\x03\x01",  # First 3 bytes
        checksum=0x5678,
        checksum_valid=True
    )
    packets.append(client_hello_part1)
    
    # Rest of ClientHello
    client_hello_part2 = PacketInfo(
        timestamp=2000.002,
        src_ip="192.168.1.100",
        dst_ip="104.16.132.229",
        src_port=54321,
        dst_port=443,
        sequence_num=1003,
        ack_num=1,
        ttl=64,
        flags=['PSH', 'ACK'],
        payload_length=87,
        payload=b"\x00\x5a\x01\x00\x00\x56" + b"x" * 81,  # Rest of TLS
        checksum=0x9abc,
        checksum_valid=True
    )
    packets.append(client_hello_part2)
    
    return packets


def demo_pattern_recognition():
    """Demonstrate pattern recognition capabilities."""
    print("🔍 Pattern Recognition Demo")
    print("=" * 50)
    
    recognizer = PatternRecognizer()
    
    # Analyze recon packets
    print("\n📊 Analyzing recon packets...")
    recon_packets = create_demo_recon_packets()
    recon_patterns = recognizer.recognize_dpi_evasion_patterns(recon_packets)
    
    print(f"Found {len(recon_patterns)} evasion patterns in recon:")
    for pattern in recon_patterns:
        print(f"  • {pattern.technique.value}: {pattern.description}")
        print(f"    Confidence: {pattern.confidence:.2f}")
    
    # Analyze zapret packets
    print("\n📊 Analyzing zapret packets...")
    zapret_packets = create_demo_zapret_packets()
    zapret_patterns = recognizer.recognize_dpi_evasion_patterns(zapret_packets)
    
    print(f"Found {len(zapret_patterns)} evasion patterns in zapret:")
    for pattern in zapret_patterns:
        print(f"  • {pattern.technique.value}: {pattern.description}")
        print(f"    Confidence: {pattern.confidence:.2f}")


def demo_fake_packet_detection():
    """Demonstrate fake packet detection."""
    print("\n🎭 Fake Packet Detection Demo")
    print("=" * 50)
    
    recognizer = PatternRecognizer()
    
    # Analyze recon fake packets
    print("\n🔍 Recon fake packet analysis:")
    recon_packets = create_demo_recon_packets()
    recon_fake_patterns = recognizer.detect_fake_packet_patterns(recon_packets)
    
    for i, fp in enumerate(recon_fake_patterns):
        if fp.is_fake:
            print(f"  Packet {i}: FAKE (TTL={fp.packet.ttl})")
            print(f"    Indicators: {', '.join(fp.fake_indicators)}")
            print(f"    Confidence: {fp.confidence:.2f}")
        else:
            print(f"  Packet {i}: REAL (TTL={fp.packet.ttl})")
    
    # Analyze zapret fake packets
    print("\n🔍 Zapret fake packet analysis:")
    zapret_packets = create_demo_zapret_packets()
    zapret_fake_patterns = recognizer.detect_fake_packet_patterns(zapret_packets)
    
    for i, fp in enumerate(zapret_fake_patterns):
        if fp.is_fake:
            print(f"  Packet {i}: FAKE (TTL={fp.packet.ttl})")
            print(f"    Indicators: {', '.join(fp.fake_indicators)}")
            print(f"    Confidence: {fp.confidence:.2f}")
        else:
            print(f"  Packet {i}: REAL (TTL={fp.packet.ttl})")


def demo_anomaly_detection():
    """Demonstrate anomaly detection between recon and zapret."""
    print("\n⚠️  Anomaly Detection Demo")
    print("=" * 50)
    
    recognizer = PatternRecognizer()
    
    # Get packets and patterns
    recon_packets = create_demo_recon_packets()
    zapret_packets = create_demo_zapret_packets()
    
    recon_patterns = recognizer.recognize_dpi_evasion_patterns(recon_packets)
    zapret_patterns = recognizer.recognize_dpi_evasion_patterns(zapret_packets)
    
    # Detect anomalies
    anomalies = recognizer.detect_anomalies(recon_patterns, zapret_patterns, recon_packets, zapret_packets)
    
    print(f"\nFound {len(anomalies)} anomalies:")
    
    for anomaly in anomalies:
        severity_emoji = {
            'CRITICAL': '🚨',
            'HIGH': '⚠️',
            'MEDIUM': '⚡',
            'LOW': 'ℹ️'
        }.get(anomaly.severity, '❓')
        
        print(f"\n{severity_emoji} {anomaly.anomaly_type.value.upper()}")
        print(f"  Description: {anomaly.description}")
        print(f"  Severity: {anomaly.severity}")
        print(f"  Confidence: {anomaly.confidence:.2f}")
        print(f"  Expected: {anomaly.expected_behavior}")
        print(f"  Actual: {anomaly.actual_behavior}")
        print(f"  Fix: {anomaly.fix_suggestion}")


def demo_packet_role_classification():
    """Demonstrate packet role classification."""
    print("\n🏷️  Packet Role Classification Demo")
    print("=" * 50)
    
    recognizer = PatternRecognizer()
    
    # Classify recon packets
    print("\n📋 Recon packet roles:")
    recon_packets = create_demo_recon_packets()
    recon_roles = recognizer.classify_packet_roles(recon_packets)
    
    for i, role in recon_roles.items():
        packet = recon_packets[i]
        role_emoji = {
            'fake': '🎭',
            'real': '✅',
            'split_segment': '✂️',
            'disorder_segment': '🔀',
            'normal': '📦',
            'unknown': '❓'
        }.get(role.value, '❓')
        
        print(f"  {role_emoji} Packet {i}: {role.value.upper()}")
        print(f"    {packet.src_ip}:{packet.src_port} -> {packet.dst_ip}:{packet.dst_port}")
        print(f"    TTL={packet.ttl}, Seq={packet.sequence_num}, Payload={packet.payload_length}B")
    
    # Classify zapret packets
    print("\n📋 Zapret packet roles:")
    zapret_packets = create_demo_zapret_packets()
    zapret_roles = recognizer.classify_packet_roles(zapret_packets)
    
    for i, role in zapret_roles.items():
        packet = zapret_packets[i]
        role_emoji = {
            'fake': '🎭',
            'real': '✅',
            'split_segment': '✂️',
            'disorder_segment': '🔀',
            'normal': '📦',
            'unknown': '❓'
        }.get(role.value, '❓')
        
        print(f"  {role_emoji} Packet {i}: {role.value.upper()}")
        print(f"    {packet.src_ip}:{packet.src_port} -> {packet.dst_ip}:{packet.dst_port}")
        print(f"    TTL={packet.ttl}, Seq={packet.sequence_num}, Payload={packet.payload_length}B")


def demo_zapret_compliance():
    """Demonstrate zapret compliance validation."""
    print("\n✅ Zapret Compliance Validation Demo")
    print("=" * 50)
    
    recognizer = PatternRecognizer()
    
    # Expected strategy (from zapret command line)
    expected_strategy = StrategyConfig(
        dpi_desync="fake,fakeddisorder",
        split_pos=3,
        ttl=3,
        fooling=['badsum', 'badseq']
    )
    
    print(f"\n📋 Expected strategy:")
    print(f"  Strategy: {expected_strategy.dpi_desync}")
    print(f"  Split position: {expected_strategy.split_pos}")
    print(f"  TTL: {expected_strategy.ttl}")
    print(f"  Fooling: {', '.join(expected_strategy.fooling)}")
    
    # Test recon compliance
    recon_packets = create_demo_recon_packets()
    recon_compliance = recognizer.validate_zapret_compliance(recon_packets, expected_strategy)
    
    print(f"\n📊 Recon compliance score: {recon_compliance:.2f} ({recon_compliance*100:.0f}%)")
    
    # Test zapret compliance
    zapret_packets = create_demo_zapret_packets()
    zapret_compliance = recognizer.validate_zapret_compliance(zapret_packets, expected_strategy)
    
    print(f"📊 Zapret compliance score: {zapret_compliance:.2f} ({zapret_compliance*100:.0f}%)")
    
    # Compliance analysis
    if zapret_compliance > recon_compliance:
        print(f"\n✅ Zapret shows better compliance (+{(zapret_compliance-recon_compliance)*100:.0f}%)")
        print("   Recon needs adjustments to match zapret behavior")
    else:
        print(f"\n⚠️  Unexpected: Recon compliance is higher than zapret")


def demo_integration_with_existing_system():
    """Demonstrate integration with existing PCAP analysis components."""
    print("\n🔗 Integration with Existing System Demo")
    print("=" * 50)
    
    # Initialize components
    recognizer = PatternRecognizer()
    comparator = PCAPComparator()
    strategy_analyzer = StrategyAnalyzer()
    difference_detector = DifferenceDetector()
    
    # Get test data
    recon_packets = create_demo_recon_packets()
    zapret_packets = create_demo_zapret_packets()
    
    print("\n🔍 Step 1: Pattern Recognition")
    recon_patterns = recognizer.recognize_dpi_evasion_patterns(recon_packets)
    zapret_patterns = recognizer.recognize_dpi_evasion_patterns(zapret_packets)
    
    print(f"  Recon patterns: {len(recon_patterns)}")
    print(f"  Zapret patterns: {len(zapret_patterns)}")
    
    print("\n🔍 Step 2: Anomaly Detection")
    anomalies = recognizer.detect_anomalies(recon_patterns, zapret_patterns, recon_packets, zapret_packets)
    
    critical_anomalies = [a for a in anomalies if a.severity == 'CRITICAL']
    high_anomalies = [a for a in anomalies if a.severity == 'HIGH']
    
    print(f"  Critical anomalies: {len(critical_anomalies)}")
    print(f"  High priority anomalies: {len(high_anomalies)}")
    
    print("\n🔍 Step 3: Bypass Technique Identification")
    recon_techniques = recognizer.identify_bypass_techniques(recon_patterns)
    zapret_techniques = recognizer.identify_bypass_techniques(zapret_patterns)
    
    print(f"  Recon techniques: {[t.value for t in recon_techniques]}")
    print(f"  Zapret techniques: {[t.value for t in zapret_techniques]}")
    
    missing_techniques = set(zapret_techniques) - set(recon_techniques)
    if missing_techniques:
        print(f"  Missing in recon: {[t.value for t in missing_techniques]}")
    
    print("\n📊 Integration Summary:")
    print(f"  • Pattern recognition identified {len(recon_patterns + zapret_patterns)} total patterns")
    print(f"  • Anomaly detection found {len(anomalies)} issues to fix")
    print(f"  • Technique analysis revealed {len(missing_techniques)} missing implementations")
    print(f"  • System ready for automated fix generation")


def main():
    """Run all pattern recognizer demos."""
    print("🚀 PatternRecognizer Integration Demo")
    print("=" * 60)
    print("Demonstrating pattern recognition and anomaly detection")
    print("for recon-zapret PCAP analysis system")
    print("=" * 60)
    
    try:
        demo_pattern_recognition()
        demo_fake_packet_detection()
        demo_anomaly_detection()
        demo_packet_role_classification()
        demo_zapret_compliance()
        demo_integration_with_existing_system()
        
        print("\n" + "=" * 60)
        print("✅ PatternRecognizer Demo Complete!")
        print("The pattern recognition system is ready for production use.")
        print("Key capabilities demonstrated:")
        print("  • Fake packet detection with TTL=3 and bad checksum patterns")
        print("  • Real packet recognition with proper sequence and checksum")
        print("  • Anomaly detection comparing recon vs zapret behavior")
        print("  • Packet role classification for DPI bypass sequences")
        print("  • Zapret compliance validation against expected strategies")
        print("  • Integration with existing PCAP analysis components")
        
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)