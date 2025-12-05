#!/usr/bin/env python3
"""
Seqovl Attack Audit Tool

This tool audits the application of seqovl (sequence overlap) attacks in both 
CLI and Service modes to identify differences in implementation and sequence overlap.

Task: 1.1.4 Аудит seqovl атак
Requirements: 13.1
"""

import sys
import os
import json
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.bypass.techniques.primitives import BypassTechniques


@dataclass
class SeqovlCallSite:
    """Information about a seqovl attack call site."""
    file_path: str
    line_number: int
    function_name: str
    mode: str  # "cli" or "service"
    context: str  # surrounding code
    parameters: Dict[str, Any]


@dataclass
class SeqovlAuditResult:
    """Results of seqovl attack audit."""
    primitive_analysis: Dict[str, Any]
    cli_call_sites: List[SeqovlCallSite]
    service_call_sites: List[SeqovlCallSite]
    differences: List[str]
    recommendations: List[str]


class SeqovlAttackAuditor:
    """Auditor for seqovl attack implementation and usage."""
    
    def __init__(self):
        self.logger = logging.getLogger("SeqovlAuditor")
        self.results = SeqovlAuditResult(
            primitive_analysis={},
            cli_call_sites=[],
            service_call_sites=[],
            differences=[],
            recommendations=[]
        )
    
    def analyze_primitive_implementation(self) -> Dict[str, Any]:
        """
        Analyze the apply_seqovl implementation in primitives.py.
        
        Returns:
            Dictionary with analysis results
        """
        self.logger.info("Analyzing apply_seqovl primitive implementation...")
        
        analysis = {
            "function": "BypassTechniques.apply_seqovl",
            "location": "core/bypass/techniques/primitives.py",
            "signature": "apply_seqovl(payload: bytes, split_pos: int, overlap_size: int, fake_ttl: int, fooling_methods: Optional[List[str]] = None, **kwargs)",
            "behavior": {
                "sends_fake_overlap": True,
                "sends_real_full": True,
                "fake_packet_contains": "overlapping portion",
                "real_packet_contains": "full payload (CRITICAL)",
                "uses_low_ttl": True,
                "tcp_flags": {
                    "fake": "0x18 (PSH+ACK)",
                    "real": "0x18 (PSH+ACK)"
                },
                "delays": {
                    "fake": "5ms",
                    "real": "0ms"
                }
            },
            "parameters": {
                "payload": "Original data",
                "split_pos": "Position for overlap calculation",
                "overlap_size": "Size of overlap in bytes (must be > 0 and <= split_pos)",
                "fake_ttl": "TTL for fake packet (typically 1-3)",
                "fooling_methods": "DPI fooling methods for fake packet (default: ['badsum'])"
            },
            "overlap_calculation": {
                "start_offset": "max(0, split_pos - overlap_size)",
                "end_offset": "min(len(payload), split_pos + overlap_size)",
                "overlap_part": "payload[start_offset:end_offset]",
                "real_full": "payload (complete original data)"
            },
            "return_format": "List[Tuple[bytes, int, dict]] - [(overlap_part, start_offset, opts_fake), (real_full, 0, opts_real)]"
        }
        
        # Test the function with sample data
        test_payload = b"Hello World Test Data For Seqovl Attack"
        test_split_pos = 10
        test_overlap_size = 5
        test_fake_ttl = 3
        
        try:
            recipe = BypassTechniques.apply_seqovl(
                test_payload, 
                test_split_pos, 
                test_overlap_size, 
                test_fake_ttl
            )
            
            analysis["test_execution"] = {
                "success": True,
                "input_payload_len": len(test_payload),
                "split_pos": test_split_pos,
                "overlap_size": test_overlap_size,
                "fake_ttl": test_fake_ttl,
                "output_segments": len(recipe),
                "segments": []
            }
            
            for i, (data, offset, opts) in enumerate(recipe):
                segment_info = {
                    "index": i,
                    "data_len": len(data),
                    "offset": offset,
                    "is_fake": opts.get("is_fake", False),
                    "ttl": opts.get("ttl"),
                    "tcp_flags": hex(opts.get("tcp_flags", 0x18)),
                    "delay_ms": opts.get("delay_ms_after", 0),
                    "fooling": []
                }
                
                # Check fooling methods
                if opts.get("corrupt_tcp_checksum"):
                    segment_info["fooling"].append("badsum")
                if opts.get("seq_extra"):
                    segment_info["fooling"].append("badseq")
                if opts.get("add_md5sig_option"):
                    segment_info["fooling"].append("md5sig")
                
                analysis["test_execution"]["segments"].append(segment_info)
            
            # Verify seqovl pattern
            if len(recipe) == 2:
                fake_data, fake_offset, fake_opts = recipe[0]
                real_data, real_offset, real_opts = recipe[1]
                
                # Calculate expected overlap
                expected_start = max(0, test_split_pos - test_overlap_size)
                expected_end = min(len(test_payload), test_split_pos + test_overlap_size)
                expected_overlap_len = expected_end - expected_start
                
                analysis["test_execution"]["overlap_verification"] = {
                    "fake_is_fake": fake_opts.get("is_fake", False),
                    "fake_has_ttl": fake_opts.get("ttl") is not None,
                    "fake_ttl_value": fake_opts.get("ttl"),
                    "fake_offset": fake_offset,
                    "fake_len": len(fake_data),
                    "expected_fake_offset": expected_start,
                    "expected_fake_len": expected_overlap_len,
                    "real_is_full": len(real_data) == len(test_payload),
                    "real_offset": real_offset,
                    "real_len": len(real_data),
                    "pattern_correct": (
                        fake_opts.get("is_fake", False) and
                        fake_opts.get("ttl") == test_fake_ttl and
                        len(real_data) == len(test_payload) and
                        real_offset == 0
                    )
                }
                
                # Check if overlap actually overlaps
                fake_end = fake_offset + len(fake_data)
                real_end = real_offset + len(real_data)
                has_overlap = (fake_offset < real_end and fake_end > real_offset)
                
                analysis["test_execution"]["overlap_verification"]["has_actual_overlap"] = has_overlap
                analysis["test_execution"]["overlap_verification"]["overlap_range"] = {
                    "fake_range": f"{fake_offset}-{fake_end}",
                    "real_range": f"{real_offset}-{real_end}"
                }
                
        except Exception as e:
            analysis["test_execution"] = {
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__
            }
            self.logger.error(f"Test execution failed: {e}", exc_info=True)
        
        self.results.primitive_analysis = analysis
        return analysis
    
    def find_seqovl_call_sites(self) -> Tuple[List[SeqovlCallSite], List[SeqovlCallSite]]:
        """
        Find all places where seqovl attacks are called in both modes.
        
        Returns:
            Tuple of (cli_call_sites, service_call_sites)
        """
        self.logger.info("Searching for seqovl attack call sites...")
        
        cli_sites = []
        service_sites = []
        
        # Based on code analysis, seqovl is called through:
        # 1. Attack registry (_create_seqovl_handler)
        # 2. UnifiedBypassEngine
        # 3. Strategy execution in both modes
        
        # CLI mode call sites
        cli_sites.append(SeqovlCallSite(
            file_path="core/bypass/attacks/attack_registry.py",
            line_number=816,
            function_name="_create_seqovl_handler",
            mode="cli",
            context="Attack registry handler for seqovl",
            parameters={
                "split_pos": "from context.params (default: 3)",
                "overlap_size": "from context.params (default: 1)",
                "fake_ttl": "from context.params (default: 3)",
                "fooling_methods": "from context.params (default: ['badsum'])"
            }
        ))
        
        cli_sites.append(SeqovlCallSite(
            file_path="core/cli/adaptive_cli_wrapper.py",
            line_number=0,
            function_name="test_strategy",
            mode="cli",
            context="Testing mode uses UnifiedBypassEngine with attack registry",
            parameters={"from_strategy": "parsed from strategy string"}
        ))
        
        cli_sites.append(SeqovlCallSite(
            file_path="core/adaptive_engine.py",
            line_number=0,
            function_name="apply_strategy",
            mode="cli",
            context="Adaptive engine applies strategies during testing",
            parameters={"from_strategy": "strategy configuration"}
        ))
        
        # Service mode call sites
        service_sites.append(SeqovlCallSite(
            file_path="core/bypass/attacks/attack_registry.py",
            line_number=816,
            function_name="_create_seqovl_handler",
            mode="service",
            context="Same attack registry handler used in service mode",
            parameters={
                "split_pos": "from domain_strategies.json",
                "overlap_size": "from domain_strategies.json",
                "fake_ttl": "from domain_strategies.json",
                "fooling_methods": "from domain_strategies.json"
            }
        ))
        
        service_sites.append(SeqovlCallSite(
            file_path="recon_service.py",
            line_number=0,
            function_name="process_packet",
            mode="service",
            context="Service mode applies strategies to live traffic",
            parameters={"from_domain_strategies": "loaded at startup"}
        ))
        
        service_sites.append(SeqovlCallSite(
            file_path="core/unified_bypass_engine.py",
            line_number=0,
            function_name="apply_bypass",
            mode="service",
            context="Unified bypass engine processes packets with attack registry",
            parameters={"from_strategy": "strategy from domain_strategies.json"}
        ))
        
        self.results.cli_call_sites = cli_sites
        self.results.service_call_sites = service_sites
        
        return cli_sites, service_sites
    
    def compare_implementations(self) -> List[str]:
        """
        Compare seqovl attack implementation between modes.
        
        Returns:
            List of identified differences
        """
        self.logger.info("Comparing seqovl implementations between modes...")
        
        differences = []
        
        # Check if both modes use the same primitive
        differences.append(
            "ANALYSIS NEEDED: Verify both modes call BypassTechniques.apply_seqovl() "
            "through the same attack registry handler"
        )
        
        # Check parameter passing
        differences.append(
            "ANALYSIS NEEDED: Verify split_pos calculation is identical in both modes"
        )
        
        differences.append(
            "ANALYSIS NEEDED: Verify overlap_size parameter is passed correctly in both modes"
        )
        
        differences.append(
            "ANALYSIS NEEDED: Verify fake_ttl parameter is consistent between modes"
        )
        
        # Check overlap calculation
        differences.append(
            "ANALYSIS NEEDED: Verify overlap calculation (start_offset, end_offset) "
            "produces identical results in both modes"
        )
        
        # Check packet content
        differences.append(
            "CRITICAL: Verify fake packet contains overlapping portion at correct offset"
        )
        
        differences.append(
            "CRITICAL: Verify real packet contains FULL payload (not partial)"
        )
        
        # Check sequence numbers
        differences.append(
            "ANALYSIS NEEDED: Verify TCP sequence numbers are set correctly for overlap"
        )
        
        differences.append(
            "ANALYSIS NEEDED: Verify fake packet sequence number creates actual overlap "
            "with real packet sequence number"
        )
        
        # Check TTL
        differences.append(
            "ANALYSIS NEEDED: Verify fake packet TTL is low enough (1-3) to expire "
            "before reaching server"
        )
        
        # Check fooling methods
        differences.append(
            "ANALYSIS NEEDED: Verify fooling methods (badsum, badseq, md5sig) are "
            "applied correctly in both modes"
        )
        
        self.results.differences = differences
        return differences
    
    def generate_pcap_capture_script(self) -> str:
        """
        Generate a script to capture PCAP traffic for seqovl attacks.
        
        Returns:
            Path to generated script
        """
        self.logger.info("Generating PCAP capture script...")
        
        script_content = '''#!/usr/bin/env python3
"""
PCAP Capture Script for Seqovl Attack Analysis

This script captures network traffic during seqovl attack execution
in both CLI and Service modes for comparison.
"""

import sys
import os
import time
import subprocess
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.pcap.temporary_capturer import TemporaryCapturer


def capture_cli_mode_seqovl(domain: str, output_dir: str):
    """Capture PCAP during CLI mode seqovl attack."""
    print(f"\\n=== Capturing CLI Mode Seqovl Attack for {domain} ===")
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_file = os.path.join(output_dir, f"seqovl_cli_{domain}_{timestamp}.pcap")
    
    # Start PCAP capture
    capturer = TemporaryCapturer(
        filter_expr=f"host {domain} and tcp",
        output_file=pcap_file
    )
    
    try:
        capturer.start()
        print(f"Started capture to {pcap_file}")
        
        # Run CLI mode test with seqovl strategy
        print("Running CLI mode test...")
        cmd = [
            sys.executable, "cli.py", "auto",
            "--domain", domain,
            "--strategy", "seqovl",
            "--split-pos", "10",
            "--overlap-size", "5",
            "--ttl", "3"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        print(f"CLI test completed: {result.returncode}")
        
        # Wait for packets to be captured
        time.sleep(2)
        
    finally:
        capturer.stop()
        print(f"Capture saved to {pcap_file}")
    
    return pcap_file


def capture_service_mode_seqovl(domain: str, output_dir: str):
    """Capture PCAP during Service mode seqovl attack."""
    print(f"\\n=== Capturing Service Mode Seqovl Attack for {domain} ===")
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_file = os.path.join(output_dir, f"seqovl_service_{domain}_{timestamp}.pcap")
    
    # Start PCAP capture
    capturer = TemporaryCapturer(
        filter_expr=f"host {domain} and tcp",
        output_file=pcap_file
    )
    
    try:
        capturer.start()
        print(f"Started capture to {pcap_file}")
        
        # Trigger service mode by making a request to the domain
        print("Triggering service mode...")
        import requests
        try:
            requests.get(f"https://{domain}", timeout=10)
        except:
            pass  # We just want to trigger the bypass
        
        # Wait for packets to be captured
        time.sleep(2)
        
    finally:
        capturer.stop()
        print(f"Capture saved to {pcap_file}")
    
    return pcap_file


def main():
    """Main capture workflow."""
    # Create output directory
    output_dir = "seqovl_audit_pcaps"
    os.makedirs(output_dir, exist_ok=True)
    
    # Test domain
    test_domain = "example.com"  # Replace with actual blocked domain
    
    print("=== Seqovl Attack PCAP Capture ===")
    print(f"Domain: {test_domain}")
    print(f"Output: {output_dir}")
    
    # Capture CLI mode
    cli_pcap = capture_cli_mode_seqovl(test_domain, output_dir)
    
    # Capture Service mode
    service_pcap = capture_service_mode_seqovl(test_domain, output_dir)
    
    print("\\n=== Capture Complete ===")
    print(f"CLI PCAP: {cli_pcap}")
    print(f"Service PCAP: {service_pcap}")
    print("\\nNext steps:")
    print("1. Analyze PCAPs with: python tools/analyze_seqovl_pcap.py")
    print("2. Compare sequence overlap between modes")
    print("3. Verify fake packet offset and real packet completeness")


if __name__ == "__main__":
    main()
'''
        
        script_path = "tools/capture_seqovl_pcap.py"
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(script_content)
        
        self.logger.info(f"Generated PCAP capture script: {script_path}")
        return script_path
    
    def generate_pcap_analysis_script(self) -> str:
        """
        Generate a script to analyze captured PCAP files.
        
        Returns:
            Path to generated script
        """
        self.logger.info("Generating PCAP analysis script...")
        
        script_content = '''#!/usr/bin/env python3
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
    print(f"\\n=== Analyzing CLI Mode PCAP: {cli_pcap} ===")
    
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
    
    print(f"\\n=== Analyzing Service Mode PCAP: {service_pcap} ===")
    
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
    
    print("\\n=== Comparison Results ===")
    if comparison["differences"]:
        print("\\nDIFFERENCES FOUND:")
        for diff in comparison["differences"]:
            print(f"  - {diff}")
    else:
        print("\\nNo significant differences detected.")
    
    # Save results
    import json
    output_file = "seqovl_audit_comparison.json"
    with open(output_file, "w") as f:
        json.dump(comparison, f, indent=2, default=str)
    
    print(f"\\nDetailed results saved to: {output_file}")


if __name__ == "__main__":
    main()
'''
        
        script_path = "tools/analyze_seqovl_pcap.py"
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(script_content)
        
        self.logger.info(f"Generated PCAP analysis script: {script_path}")
        return script_path
    
    def generate_recommendations(self) -> List[str]:
        """
        Generate recommendations based on audit findings.
        
        Returns:
            List of recommendations
        """
        self.logger.info("Generating recommendations...")
        
        recommendations = [
            "1. Verify both CLI and Service modes use BypassTechniques.apply_seqovl() "
            "from core/bypass/techniques/primitives.py through attack registry",
            
            "2. Ensure split_pos parameter is calculated identically in both modes",
            
            "3. Verify overlap_size parameter is passed correctly from strategy configuration",
            
            "4. Ensure fake_ttl parameter is consistent between modes (typically 1-3)",
            
            "5. CRITICAL: Verify fake packet contains overlapping portion at correct offset "
            "(start_offset = max(0, split_pos - overlap_size))",
            
            "6. CRITICAL: Verify real packet contains FULL payload, not partial "
            "(this is requirement for seqovl to work correctly)",
            
            "7. Verify overlap calculation produces identical results in both modes: "
            "start_offset = max(0, split_pos - overlap_size), "
            "end_offset = min(len(payload), split_pos + overlap_size)",
            
            "8. Capture PCAP traffic in both modes using tools/capture_seqovl_pcap.py",
            
            "9. Analyze captured PCAPs using tools/analyze_seqovl_pcap.py to compare "
            "sequence overlap and packet content",
            
            "10. Verify TCP sequence numbers create actual overlap between fake and real packets",
            
            "11. Ensure fake packet TTL is low enough (1-3) to expire before reaching server",
            
            "12. Verify fooling methods (badsum, badseq, md5sig) are applied correctly",
            
            "13. Document any differences found in overlap calculation or packet content",
            
            "14. If differences exist, trace the code path from strategy loading to "
            "packet transmission in both modes",
            
            "15. Ensure UnifiedBypassEngine and attack registry apply seqovl consistently",
            
            "16. Add logging to track seqovl attack parameters (split_pos, overlap_size, "
            "fake_ttl) in both modes",
            
            "17. Create integration tests that verify seqovl attack parity between modes",
            
            "18. Test with various overlap_size values (1, 5, 10, 50) to ensure "
            "calculation is correct in all cases",
            
            "19. Verify that overlap_size validation (must be > 0 and <= split_pos) "
            "works correctly in both modes",
            
            "20. Ensure that when overlap_size is adjusted due to validation, "
            "both modes adjust it identically"
        ]
        
        self.results.recommendations = recommendations
        return recommendations
    
    def run_audit(self) -> SeqovlAuditResult:
        """
        Run complete seqovl attack audit.
        
        Returns:
            Complete audit results
        """
        self.logger.info("Starting seqovl attack audit...")
        
        # 1. Analyze primitive implementation
        self.analyze_primitive_implementation()
        
        # 2. Find call sites
        self.find_seqovl_call_sites()
        
        # 3. Compare implementations
        self.compare_implementations()
        
        # 4. Generate PCAP capture tools
        self.generate_pcap_capture_script()
        self.generate_pcap_analysis_script()
        
        # 5. Generate recommendations
        self.generate_recommendations()
        
        self.logger.info("Seqovl attack audit complete")
        return self.results
    
    def save_report(self, output_file: str):
        """Save audit report to file."""
        report = {
            "audit_type": "seqovl_attack",
            "primitive_analysis": self.results.primitive_analysis,
            "cli_call_sites": [asdict(site) for site in self.results.cli_call_sites],
            "service_call_sites": [asdict(site) for site in self.results.service_call_sites],
            "differences": self.results.differences,
            "recommendations": self.results.recommendations
        }
        
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"Report saved to {output_file}")


def main():
    """Main entry point."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    print("=" * 80)
    print("Seqovl Attack Audit Tool")
    print("Task: 1.1.4 Аудит seqovl атак")
    print("=" * 80)
    
    auditor = SeqovlAttackAuditor()
    results = auditor.run_audit()
    
    # Save report
    output_file = "seqovl_audit_report.json"
    auditor.save_report(output_file)
    
    # Print summary
    print("\n" + "=" * 80)
    print("AUDIT SUMMARY")
    print("=" * 80)
    
    print("\n1. Primitive Analysis:")
    print(f"   Function: {results.primitive_analysis.get('function', 'N/A')}")
    print(f"   Location: {results.primitive_analysis.get('location', 'N/A')}")
    
    if "test_execution" in results.primitive_analysis:
        test = results.primitive_analysis["test_execution"]
        print(f"   Test: {'✓ PASSED' if test.get('success') else '✗ FAILED'}")
        if test.get("success"):
            print(f"   Segments: {test.get('output_segments', 0)}")
            if "overlap_verification" in test:
                ov = test["overlap_verification"]
                print(f"   Pattern: {'✓ CORRECT' if ov.get('pattern_correct') else '✗ INCORRECT'}")
                print(f"   Overlap: {'✓ YES' if ov.get('has_actual_overlap') else '✗ NO'}")
                print(f"   Real packet full: {'✓ YES' if ov.get('real_is_full') else '✗ NO'}")
    
    print(f"\n2. Call Sites Found:")
    print(f"   CLI mode: {len(results.cli_call_sites)} locations")
    print(f"   Service mode: {len(results.service_call_sites)} locations")
    
    print(f"\n3. Analysis Items:")
    print(f"   {len(results.differences)} items need verification")
    
    print(f"\n4. Recommendations:")
    print(f"   {len(results.recommendations)} action items")
    
    print(f"\n5. Generated Tools:")
    print("   ✓ tools/capture_seqovl_pcap.py - PCAP capture script")
    print("   ✓ tools/analyze_seqovl_pcap.py - PCAP analysis script")
    
    print(f"\n6. Report:")
    print(f"   Saved to: {output_file}")
    
    print("\n" + "=" * 80)
    print("NEXT STEPS")
    print("=" * 80)
    print("\n1. Review the generated report: seqovl_audit_report.json")
    print("2. Capture PCAP traffic:")
    print("   python tools/capture_seqovl_pcap.py")
    print("3. Analyze captured PCAPs:")
    print("   python tools/analyze_seqovl_pcap.py")
    print("4. Compare sequence overlap between CLI and Service modes")
    print("5. Verify fake packet offset and real packet completeness")
    print("6. Document any differences found")
    print("\n" + "=" * 80)


if __name__ == "__main__":
    main()
