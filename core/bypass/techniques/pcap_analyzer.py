#!/usr/bin/env python3
"""
PCAP analysis utilities for attack primitives validation.

This module provides functions for comparing PCAP files and analyzing
packet differences between different implementations.
"""

import logging
from pathlib import Path
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

try:
    from scapy.all import rdpcap, IP, TCP

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def compare_pcap_files(
    zapret_path: str = "zapret.pcap", recon_path: str = "out2.pcap"
) -> Dict[str, Any]:
    """
    Compare two PCAP files for differences.

    Args:
        zapret_path: Path to zapret PCAP file
        recon_path: Path to recon PCAP file

    Returns:
        Dictionary with analysis results or error information
    """
    if not SCAPY_AVAILABLE:
        return {"error": "Scapy not available for PCAP analysis"}

    logger.info("  Comparing PCAP files...")

    zapret_pcap = Path(zapret_path)
    recon_pcap = Path(recon_path)

    if not zapret_pcap.exists():
        return {"error": f"{zapret_path} not found"}

    if not recon_pcap.exists():
        return {"error": f"{recon_path} not found"}

    try:
        zapret_packets = rdpcap(str(zapret_pcap))
        recon_packets = rdpcap(str(recon_pcap))

        # Analyze packet structure differences
        analysis = analyze_packet_differences(zapret_packets, recon_packets)
        return analysis

    except IOError as e:
        return {"error": f"Failed to read PCAP file: {str(e)}"}
    except Exception as e:
        return {"error": f"PCAP analysis failed: {str(e)}"}


def analyze_packet_differences(zapret_packets, recon_packets) -> Dict[str, Any]:
    """
    Analyze differences between two sets of packets.

    Args:
        zapret_packets: Packets from zapret implementation
        recon_packets: Packets from recon implementation

    Returns:
        Dictionary with categorized differences
    """
    if not SCAPY_AVAILABLE:
        return {"error": "Scapy not available"}

    differences = {
        "ip_header_diffs": [],
        "tcp_header_diffs": [],
        "tcp_options_diffs": [],
        "timing_diffs": [],
        "checksum_diffs": [],
    }

    # Find TLS handshake packets for comparison
    zapret_tls = [p for p in zapret_packets if TCP in p and p[TCP].dport == 443]
    recon_tls = [p for p in recon_packets if TCP in p and p[TCP].dport == 443]

    if not zapret_tls or not recon_tls:
        return {"error": "No TLS packets found for comparison"}

    # Compare first few packets
    for i in range(min(3, len(zapret_tls), len(recon_tls))):
        z_pkt = zapret_tls[i]
        r_pkt = recon_tls[i]

        # IP header comparison
        ip_diffs = compare_ip_headers(z_pkt, r_pkt, i)
        differences["ip_header_diffs"].extend(ip_diffs)

        # TCP header comparison
        tcp_diffs = compare_tcp_headers(z_pkt, r_pkt, i)
        differences["tcp_header_diffs"].extend(tcp_diffs)

        # TCP options comparison
        opt_diffs = compare_tcp_options(z_pkt, r_pkt, i)
        differences["tcp_options_diffs"].extend(opt_diffs)

    return differences


def compare_ip_headers(z_pkt, r_pkt, packet_index: int) -> List[str]:
    """
    Compare IP headers between two packets.

    Args:
        z_pkt: Zapret packet
        r_pkt: Recon packet
        packet_index: Index for error messages

    Returns:
        List of difference descriptions
    """
    if not SCAPY_AVAILABLE:
        return []

    diffs = []

    if IP in z_pkt and IP in r_pkt:
        z_ip = z_pkt[IP]
        r_ip = r_pkt[IP]

        if z_ip.id != r_ip.id:
            diffs.append(
                f"Packet {packet_index}: IP ID differs (zapret: {z_ip.id}, recon: {r_ip.id})"
            )

        if z_ip.flags != r_ip.flags:
            diffs.append(
                f"Packet {packet_index}: IP flags differ (zapret: {z_ip.flags}, recon: {r_ip.flags})"
            )

        if z_ip.ttl != r_ip.ttl:
            diffs.append(
                f"Packet {packet_index}: TTL differs (zapret: {z_ip.ttl}, recon: {r_ip.ttl})"
            )

    return diffs


def compare_tcp_headers(z_pkt, r_pkt, packet_index: int) -> List[str]:
    """
    Compare TCP headers between two packets.

    Args:
        z_pkt: Zapret packet
        r_pkt: Recon packet
        packet_index: Index for error messages

    Returns:
        List of difference descriptions
    """
    if not SCAPY_AVAILABLE:
        return []

    diffs = []

    if TCP in z_pkt and TCP in r_pkt:
        z_tcp = z_pkt[TCP]
        r_tcp = r_pkt[TCP]

        if z_tcp.window != r_tcp.window:
            diffs.append(
                f"Packet {packet_index}: Window size differs "
                f"(zapret: {z_tcp.window}, recon: {r_tcp.window})"
            )

        if z_tcp.flags != r_tcp.flags:
            diffs.append(
                f"Packet {packet_index}: TCP flags differ "
                f"(zapret: {z_tcp.flags}, recon: {r_tcp.flags})"
            )

    return diffs


def compare_tcp_options(z_pkt, r_pkt, packet_index: int) -> List[str]:
    """
    Compare TCP options between two packets.

    Args:
        z_pkt: Zapret packet
        r_pkt: Recon packet
        packet_index: Index for error messages

    Returns:
        List of difference descriptions
    """
    if not SCAPY_AVAILABLE:
        return []

    diffs = []

    if TCP in z_pkt and TCP in r_pkt:
        z_tcp = z_pkt[TCP]
        r_tcp = r_pkt[TCP]

        z_options = getattr(z_tcp, "options", [])
        r_options = getattr(r_tcp, "options", [])

        if len(z_options) != len(r_options):
            diffs.append(
                f"Packet {packet_index}: TCP options count differs "
                f"(zapret: {len(z_options)}, recon: {len(r_options)})"
            )

    return diffs
