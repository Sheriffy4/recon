#!/usr/bin/env python3
"""
PCAP Analysis Script for Seqovl Attack Comparison

This script analyzes captured PCAP files to compare seqovl attack
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
    ttl: int
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
                ttl=ip.ttl,
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
                ttl=pkt.get("ttl", 0),
                payload_len=len(pkt.get("payload", b"")),
                payload_preview=pkt.get("payload", b"")[:20].hex()
            )
            packet_info.append(info)
    
    return packet_info


def analyze_seqovl_pattern(packets: List[PacketInfo]) -> Dict[str, Any]:
    """Analyze packets to detect seqovl pattern."""
    analysis = {
        "total_packets": len(packets),
        "packets_with_payload": 0,
        "seqovl_detected": False,
        "fake_packet": None,
        "real_packet": None,
        "overlap_analysis": {},
        "sequence_analysis": []
    }
    
    # Find packets with payload (data segments)
    data_packets = [p for p in packets if p.payload_len > 0]
    analysis["packets_with_payload"] = len(data_packets)
    
    if len(data_packets) >= 2:
        # Look for seqovl pattern: fake packet (low TTL) + real packet
        for i in range(len(data_packets) - 1):
            curr = data_packets[i]
            next_pkt = data_packets[i + 1]
            
            # Check if first packet has low TTL (fake packet indicator)
            if curr.ttl <= 3:
                # Check if sequences overlap
                curr_end = curr.seq + curr.payload_len
                next_end = next_pkt.seq + next_pkt.payload_len
                
                # Overlap exists if fake packet range intersects with real packet range
                has_overlap = (curr.seq < next_end and curr_end > next_pkt.seq)
                
                if has_overlap:
                    analysis["seqovl_detected"] = True
                    analysis["fake_packet"] = {
                        "index": i,
                        "seq": curr.seq,
                        "seq_end": curr_end,
                        "payload_len": curr.payload_len,
                        "ttl": curr.ttl,
                        "flags": hex(curr.flags),
                        "timestamp": curr.timestamp
                    }
                    analysis["real_packet"] = {
                        "index": i + 1,
                        "seq": next_pkt.seq,
                        "seq_end": next_end,
                        "payload_len": next_pkt.payload_len,
                        "ttl": next_pkt.ttl,
                        "flags": hex(next_pkt.flags),
                        "timestamp": next_pkt.timestamp
                    }
                    
                    # Calculate overlap
                    overlap_start = max(curr.seq, next_pkt.seq)
                    overlap_end = min(curr_end, next_end)
                    overlap_size = overlap_end - overlap_start
                    
                    analysis["overlap_analysis"] = {
                        "overlap_start_seq": overlap_start,
                        "overlap_end_seq": overlap_end,
                        "overlap_size": overlap_size,
                        "fake_range": f"{curr.seq}-{curr_end}",
                        "real_range": f"{next_pkt.seq}-{next_end}",
                        "overlap_percentage": (overlap_size / curr.payload_len * 100) if curr.payload_len > 0 else 0
                    }
                    
                    break
    
    # Analyze all sequence numbers
    for i, pkt in enumerate(data_packets):
        analysis["sequence_analysis"].append({
            "packet_index": i,
            "seq": pkt.seq,
            "seq_end": pkt.seq + pkt.payload_len,
            "payload_len": pkt.payload_len,
            "ttl": pkt.ttl,
            "flags": hex(pkt.flags),
            "timestamp": pkt.timestamp,
            "is_likely_fake": pkt.ttl <= 3
        })
    
    return analysis


def compare_pcaps(cli_pcap: str, service_pcap: str) -> Dict[str, Any]:
    """Compare seqovl patterns between CLI and Service mode PCAPs."""
    print(f"\n=== Analyzing CLI Mode PCAP: {cli_pcap} ===")
    
    if SCAPY_AVAILABLE:
        cli_packets = analyze_pcap_with_scapy(cli_pcap)
    else:
        cli_packets = analyze_pcap_with_raw_engine(cli_pcap)
    
    cli_analysis = analyze_seqovl_pattern(cli_packets)
    
    print(f"CLI packets: {cli_analysis['total_packets']}")
    print(f"CLI data packets: {cli_analysis['packets_with_payload']}")
    print(f"CLI seqovl detected: {cli_analysis['seqovl_detected']}")
    
    if cli_analysis['seqovl_detected']:
        print(f"CLI fake packet TTL: {cli_analysis['fake_packet']['ttl']}")
        print(f"CLI overlap size: {cli_analysis['overlap_analysis']['overlap_size']} bytes")
    
    print(f"\n=== Analyzing Service Mode PCAP: {service_pcap} ===")
    
    if SCAPY_AVAILABLE:
        service_packets = analyze_pcap_with_scapy(service_pcap)
    else:
        service_packets = analyze_pcap_with_raw_engine(service_pcap)
    
    service_analysis = analyze_seqovl_pattern(service_packets)
    
    print(f"Service packets: {service_analysis['total_packets']}")
    print(f"Service data packets: {service_analysis['packets_with_payload']}")
    print(f"Service seqovl detected: {service_analysis['seqovl_detected']}")
    
    if service_analysis['seqovl_detected']:
        print(f"Service fake packet TTL: {service_analysis['fake_packet']['ttl']}")
        print(f"Service overlap size: {service_analysis['overlap_analysis']['overlap_size']} bytes")
    
    # Compare
    comparison = {
        "cli_analysis": cli_analysis,
        "service_analysis": service_analysis,
        "differences": []
    }
    
    if cli_analysis["seqovl_detected"] != service_analysis["seqovl_detected"]:
        comparison["differences"].append(
            f"Seqovl detection mismatch: CLI={cli_analysis['seqovl_detected']}, "
            f"Service={service_analysis['seqovl_detected']}"
        )
    
    if cli_analysis["seqovl_detected"] and service_analysis["seqovl_detected"]:
        # Compare fake packet TTL
        cli_ttl = cli_analysis['fake_packet']['ttl']
        service_ttl = service_analysis['fake_packet']['ttl']
        if cli_ttl != service_ttl:
            comparison["differences"].append(
                f"Fake packet TTL mismatch: CLI={cli_ttl}, Service={service_ttl}"
            )
        
        # Compare overlap size
        cli_overlap = cli_analysis['overlap_analysis']['overlap_size']
        service_overlap = service_analysis['overlap_analysis']['overlap_size']
        if cli_overlap != service_overlap:
            comparison["differences"].append(
                f"Overlap size mismatch: CLI={cli_overlap}, Service={service_overlap}"
            )
        
        # Compare fake packet payload length
        cli_fake_len = cli_analysis['fake_packet']['payload_len']
        service_fake_len = service_analysis['fake_packet']['payload_len']
        if cli_fake_len != service_fake_len:
            comparison["differences"].append(
                f"Fake packet length mismatch: CLI={cli_fake_len}, Service={service_fake_len}"
            )
        
        # Compare real packet payload length
        cli_real_len = cli_analysis['real_packet']['payload_len']
        service_real_len = service_analysis['real_packet']['payload_len']
        if cli_real_len != service_real_len:
            comparison["differences"].append(
                f"Real packet length mismatch: CLI={cli_real_len}, Service={service_real_len}"
            )
    
    return comparison


def main():
    """Main analysis workflow."""
    import glob
    
    # Find PCAP files
    pcap_dir = "seqovl_audit_pcaps"
    cli_pcaps = glob.glob(f"{pcap_dir}/seqovl_cli_*.pcap")
    service_pcaps = glob.glob(f"{pcap_dir}/seqovl_service_*.pcap")
    
    if not cli_pcaps or not service_pcaps:
        print("ERROR: No PCAP files found. Run capture_seqovl_pcap.py first.")
        return
    
    # Use most recent files
    cli_pcap = sorted(cli_pcaps)[-1]
    service_pcap = sorted(service_pcaps)[-1]
    
    print("=== Seqovl Attack PCAP Analysis ===")
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
    output_file = "seqovl_audit_comparison.json"
    with open(output_file, "w") as f:
        json.dump(comparison, f, indent=2, default=str)
    
    print(f"\nDetailed results saved to: {output_file}")


if __name__ == "__main__":
    main()
