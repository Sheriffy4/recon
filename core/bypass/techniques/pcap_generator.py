#!/usr/bin/env python3
"""
PCAP generation utilities for attack primitives testing.

This module provides functions for generating test PCAP files
demonstrating various attack techniques.
"""

import logging
from pathlib import Path
from typing import Dict, Any

logger = logging.getLogger(__name__)

try:
    from scapy.all import IP, TCP, wrpcap

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def generate_test_pcaps(payload: bytes, output_dir: Path = Path(".")) -> Dict[str, Any]:
    """
    Generate test PCAP files for all attack types.

    Args:
        payload: Test payload to use
        output_dir: Directory to save PCAP files

    Returns:
        Dictionary with paths to generated files or error information
    """
    if not SCAPY_AVAILABLE:
        return {"error": "Scapy not available for PCAP generation"}

    logger.info("🔍 Generating test PCAP files...")

    results = {}

    try:
        # Generate fakeddisorder PCAP
        fakeddisorder_pcap = generate_fakeddisorder_pcap(
            payload, output_dir / "test_fakeddisorder.pcap"
        )
        results["fakeddisorder_pcap"] = fakeddisorder_pcap

        # Generate multisplit PCAP
        multisplit_pcap = generate_multisplit_pcap(payload, output_dir / "test_multisplit.pcap")
        results["multisplit_pcap"] = multisplit_pcap

        # Generate seqovl PCAP
        seqovl_pcap = generate_seqovl_pcap(payload, output_dir / "test_seqovl.pcap")
        results["seqovl_pcap"] = seqovl_pcap

    except Exception as e:
        results["error"] = f"PCAP generation failed: {str(e)}"

    return results


def generate_fakeddisorder_pcap(payload: bytes, output_path: Path) -> str:
    """
    Generate PCAP demonstrating fakeddisorder attack.

    Args:
        payload: Test payload
        output_path: Path to save PCAP file

    Returns:
        Path to generated PCAP file
    """
    from core.bypass.techniques.primitives import BypassTechniques

    if not SCAPY_AVAILABLE:
        raise ImportError("Scapy not available")

    packets = []

    # Simulate fakeddisorder attack
    segments = BypassTechniques.apply_fakeddisorder(
        payload=payload,
        split_pos=20,
        overlap_size=5,
        fake_ttl=1,
        fooling_methods=["badsum"],
    )

    base_seq = 1000

    for i, (seg_payload, offset, opts) in enumerate(segments):
        pkt = (
            IP(dst="192.168.1.100", ttl=opts.get("ttl", 64))
            / TCP(dport=443, seq=base_seq + offset, flags=opts.get("tcp_flags", 0x18))
            / seg_payload
        )

        # Apply fooling if specified
        if opts.get("corrupt_tcp_checksum"):
            pkt[TCP].chksum = 0xDEAD

        packets.append(pkt)

    pcap_path = str(output_path)
    wrpcap(pcap_path, packets)

    return pcap_path


def generate_multisplit_pcap(payload: bytes, output_path: Path) -> str:
    """
    Generate PCAP demonstrating multisplit attack.

    Args:
        payload: Test payload
        output_path: Path to save PCAP file

    Returns:
        Path to generated PCAP file
    """
    from core.bypass.techniques.primitives import BypassTechniques

    if not SCAPY_AVAILABLE:
        raise ImportError("Scapy not available")

    packets = []

    segments = BypassTechniques.apply_multisplit(payload, [10, 20, 30])

    base_seq = 2000

    for seg_payload, offset in segments:
        pkt = (
            IP(dst="192.168.1.100")
            / TCP(dport=443, seq=base_seq + offset, flags=0x18)
            / seg_payload
        )

        packets.append(pkt)

    pcap_path = str(output_path)
    wrpcap(pcap_path, packets)

    return pcap_path


def generate_seqovl_pcap(payload: bytes, output_path: Path) -> str:
    """
    Generate PCAP demonstrating seqovl attack.

    Args:
        payload: Test payload
        output_path: Path to save PCAP file

    Returns:
        Path to generated PCAP file
    """
    from core.bypass.techniques.primitives import BypassTechniques

    if not SCAPY_AVAILABLE:
        raise ImportError("Scapy not available")

    packets = []

    segments = BypassTechniques.apply_seqovl(payload, split_pos=15, overlap_size=5)

    base_seq = 3000

    for seg_payload, offset in segments:
        pkt = (
            IP(dst="192.168.1.100")
            / TCP(dport=443, seq=base_seq + offset, flags=0x18)
            / seg_payload
        )

        packets.append(pkt)

    pcap_path = str(output_path)
    wrpcap(pcap_path, packets)

    return pcap_path
