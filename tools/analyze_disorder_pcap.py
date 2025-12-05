#!/usr/bin/env python3
"""
PCAP Analysis Script for Disorder Attack Comparison

This script analyzes captured PCAP files to compare disorder attack
implementation between CLI and Service modes.
"""

import sys
import os
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import dataclass

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from scapy.all import rdpcap, TCP, IP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("WARNING: scapy not available, using raw packet engine")
    from core.packet.raw_packet_engine import RawPacketEngine


@dataclass
class PacketInfo:
    """Information about a captured packet."""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    seq: int
    ack: int
    flags: int
    payload_len: int
    payload_preview: str


def analyze_pcap_with_scapy(pcap_file: str) -> List[PacketInfo]:
    """Analyze PCAP file using scapy."""
    packets = rdpcap(pcap_file)
    packet_info = []
    
    for pkt in packets:
        if TCP in pkt and IP in pkt:
            tcp = pkt[TCP]
            ip = pkt[IP]
            
            payload = bytes(tcp.payload) if tcp.payload else b""
            
            info = PacketInfo(
                timestamp=float(pkt.time),
                src_ip=ip.src,
                dst_ip=ip.dst,
                src_port=tcp.sport,
                dst_port=tcp.dport,
                seq=tcp.seq,
                ack=tcp.ack,
                flags=tcp.flags,
                payload_len=len(payload),
                payload_preview=payload[:20].hex() if payload else ""
            )
            packet_info.append(info)
    
    return packet_info


def analyze_pcap_with_raw_engine(pcap_file: str) -> List[PacketInfo]:
    """Analyze PCAP file using raw packet engine."""
    engine = RawPacketEngine()
    packets = engine.read_pcap(pcap_file)
    packet_info = []
    
    for pkt in packets:
        if pkt.get("protocol") == "TCP":
            info = PacketInfo(
                timestamp=pkt.get("timestamp", 0.0),
                src_ip=pkt.get("src_ip", ""),
                dst_ip=pkt.get("dst_ip", ""),
                src_port=pkt.get("src_port", 0),
                dst_port=pkt.get("dst_port", 0),
                seq=pkt.get("seq", 0),
                ack=pkt.get("ack", 0),
                flags=pkt.get("flags", 0),
                payload_len=len(pkt.get("payload", b"")),
                payload_preview=pkt.get("payload", b"")[:20].hex()
            )
            packet_info.append(info)
    
    return packet_info


def analyze_disorder_pattern(packets: List[PacketInfo]) -> Dict[str, Any]:
    """Analyze packet order to detect disorder pattern."""
    analysis = {
        "total_packets": len(packets),
        "packets_with_payload": 0,
        "disorder_detected": False,
        "packet_order": [],
        "sequence_analysis": []
    }
    
    # Find packets with payload (data segments)
    data_packets = [p for p in packets if p.payload_len > 0]
    analysis["packets_with_payload"] = len(data_packets)
    
    if len(data_packets) >= 2:
        # Check if packets are out of order
        for i in range(len(data_packets) - 1):
            curr = data_packets[i]
            next_pkt = data_packets[i + 1]
            
            # If next packet has lower sequence number, disorder detected
            if next_pkt.seq < curr.seq:
                analysis["disorder_detected"] = True
                analysis["packet_order"].append({
                    "index": i,
                    "first_seq": curr.seq,
                    "second_seq": next_pkt.seq,
                    "out_of_order": True
                })
            else:
                analysis["packet_order"].append({
                    "index": i,
                    "first_seq": curr.seq,
                    "second_seq": next_pkt.seq,
                    "out_of_order": False
                })
    
    # Analyze sequence numbers
    for i, pkt in enumerate(data_packets):
        analysis["sequence_analysis"].append({
            "packet_index": i,
            "seq": pkt.seq,
            "payload_len": pkt.payload_len,
            "flags": hex(pkt.flags),
            "timestamp": pkt.timestamp
        })
    
    return analysis


def compare_pcaps(cli_pcap: str, service_pcap: str) -> Dict[str, Any]:
    """Compare disorder patterns between CLI and Service mode PCAPs."""
    print(f"\n=== Analyzing CLI Mode PCAP: {cli_pcap} ===")
    
    if SCAPY_AVAILABLE:
        cli_packets = analyze_pcap_with_scapy(cli_pcap)
    else:
        cli_packets = analyze_pcap_with_raw_engine(cli_pcap)
    
    cli_analysis = analyze_disorder_pattern(cli_packets)
    
    print(f"CLI packets: {cli_analysis['total_packets']}")
    print(f"CLI data packets: {cli_analysis['packets_with_payload']}")
    print(f"CLI disorder detected: {cli_analysis['disorder_detected']}")
    
    print(f"\n=== Analyzing Service Mode PCAP: {service_pcap} ===")
    
    if SCAPY_AVAILABLE:
        service_packets = analyze_pcap_with_scapy(service_pcap)
    else:
        service_packets = analyze_pcap_with_raw_engine(service_pcap)
    
    service_analysis = analyze_disorder_pattern(service_packets)
    
    print(f"Service packets: {service_analysis['total_packets']}")
    print(f"Service data packets: {service_analysis['packets_with_payload']}")
    print(f"Service disorder detected: {service_analysis['disorder_detected']}")
    
    # Compare
    comparison = {
        "cli_analysis": cli_analysis,
        "service_analysis": service_analysis,
        "differences": []
    }
    
    if cli_analysis["disorder_detected"] != service_analysis["disorder_detected"]:
        comparison["differences"].append(
            f"Disorder detection mismatch: CLI={cli_analysis['disorder_detected']}, "
            f"Service={service_analysis['disorder_detected']}"
        )
    
    if cli_analysis["packets_with_payload"] != service_analysis["packets_with_payload"]:
        comparison["differences"].append(
            f"Packet count mismatch: CLI={cli_analysis['packets_with_payload']}, "
            f"Service={service_analysis['packets_with_payload']}"
        )
    
    return comparison


def main():
    """Main analysis workflow."""
    import glob
    
    # Find PCAP files
    pcap_dir = "disorder_audit_pcaps"
    cli_pcaps = glob.glob(f"{pcap_dir}/disorder_cli_*.pcap")
    service_pcaps = glob.glob(f"{pcap_dir}/disorder_service_*.pcap")
    
    if not cli_pcaps or not service_pcaps:
        print("ERROR: No PCAP files found. Run capture_disorder_pcap.py first.")
        return
    
    # Use most recent files
    cli_pcap = sorted(cli_pcaps)[-1]
    service_pcap = sorted(service_pcaps)[-1]
    
    print("=== Disorder Attack PCAP Analysis ===")
    print(f"CLI PCAP: {cli_pcap}")
    print(f"Service PCAP: {service_pcap}")
    
    # Compare
    comparison = compare_pcaps(cli_pcap, service_pcap)
    
    print("\n=== Comparison Results ===")
    if comparison["differences"]:
        print("\nDIFFERENCES FOUND:")
        for diff in comparison["differences"]:
            print(f"  - {diff}")
    else:
        print("\nNo significant differences detected.")
    
    # Save results
    import json
    output_file = "disorder_audit_comparison.json"
    with open(output_file, "w") as f:
        json.dump(comparison, f, indent=2, default=str)
    
    print(f"\nDetailed results saved to: {output_file}")


if __name__ == "__main__":
    main()
