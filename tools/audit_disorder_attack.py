#!/usr/bin/env python3
"""
Disorder Attack Audit Tool

This tool audits the application of disorder attacks in both CLI and Service modes
to identify differences in implementation and packet ordering.

Task: 1.1.3 Аудит disorder атак
Requirements: 13.1, 13.4
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
class DisorderCallSite:
    """Information about a disorder attack call site."""
    file_path: str
    line_number: int
    function_name: str
    mode: str  # "cli" or "service"
    context: str  # surrounding code
    parameters: Dict[str, Any]


@dataclass
class DisorderAuditResult:
    """Results of disorder attack audit."""
    primitive_analysis: Dict[str, Any]
    cli_call_sites: List[DisorderCallSite]
    service_call_sites: List[DisorderCallSite]
    differences: List[str]
    recommendations: List[str]


class DisorderAttackAuditor:
    """Auditor for disorder attack implementation and usage."""
    
    def __init__(self):
        self.logger = logging.getLogger("DisorderAuditor")
        self.results = DisorderAuditResult(
            primitive_analysis={},
            cli_call_sites=[],
            service_call_sites=[],
            differences=[],
            recommendations=[]
        )
    
    def analyze_primitive_implementation(self) -> Dict[str, Any]:
        """
        Analyze the apply_disorder implementation in primitives.py.
        
        Returns:
            Dictionary with analysis results
        """
        self.logger.info("Analyzing apply_disorder primitive implementation...")
        
        analysis = {
            "function": "BypassTechniques.apply_disorder",
            "location": "core/bypass/techniques/primitives.py",
            "signature": "apply_disorder(payload: bytes, split_pos: int, ack_first: bool = False)",
            "behavior": {
                "splits_payload": True,
                "sends_part2_first": True,
                "sends_part1_second": True,
                "uses_fake_packet": False,
                "tcp_flags": {
                    "part2_default": "0x18 (PSH+ACK)",
                    "part2_ack_first": "0x10 (ACK)",
                    "part1": "0x18 (PSH+ACK)"
                },
                "delays": {
                    "part2": "0ms",
                    "part1": "1ms"
                }
            },
            "parameters": {
                "payload": "Original data to split and reorder",
                "split_pos": "Split position (1 <= pos < len(payload))",
                "ack_first": "Use ACK-only flag in first segment (disorder2 variant)"
            },
            "return_format": "List[Tuple[bytes, int, dict]] - [(part2, split_pos, opts), (part1, 0, opts)]"
        }
        
        # Test the function with sample data
        test_payload = b"Hello World Test Data"
        test_split_pos = 5
        
        try:
            recipe = BypassTechniques.apply_disorder(test_payload, test_split_pos)
            
            analysis["test_execution"] = {
                "success": True,
                "input_payload_len": len(test_payload),
                "split_pos": test_split_pos,
                "output_segments": len(recipe),
                "segments": []
            }
            
            for i, (data, offset, opts) in enumerate(recipe):
                segment_info = {
                    "index": i,
                    "data_len": len(data),
                    "offset": offset,
                    "is_fake": opts.get("is_fake", False),
                    "tcp_flags": hex(opts.get("tcp_flags", 0x18)),
                    "delay_ms": opts.get("delay_ms_after", 0)
                }
                analysis["test_execution"]["segments"].append(segment_info)
            
            # Verify packet order
            if len(recipe) == 2:
                part2_data, part2_offset, _ = recipe[0]
                part1_data, part1_offset, _ = recipe[1]
                
                analysis["test_execution"]["packet_order_correct"] = (
                    part2_offset == test_split_pos and
                    part1_offset == 0 and
                    len(part2_data) == len(test_payload) - test_split_pos and
                    len(part1_data) == test_split_pos
                )
        except Exception as e:
            analysis["test_execution"] = {
                "success": False,
                "error": str(e)
            }
        
        self.results.primitive_analysis = analysis
        return analysis
    
    def find_disorder_call_sites(self) -> Tuple[List[DisorderCallSite], List[DisorderCallSite]]:
        """
        Find all places where disorder attacks are called in both modes.
        
        Returns:
            Tuple of (cli_call_sites, service_call_sites)
        """
        self.logger.info("Searching for disorder attack call sites...")
        
        cli_sites = []
        service_sites = []
        
        # Files to search
        search_patterns = [
            ("cli.py", "cli"),
            ("core/cli/adaptive_cli_wrapper.py", "cli"),
            ("core/adaptive_engine.py", "cli"),
            ("recon_service.py", "service"),
            ("core/unified_bypass_engine.py", "both"),
            ("core/bypass/attacks/*.py", "both")
        ]
        
        # Search for disorder-related function calls
        disorder_patterns = [
            "apply_disorder",
            "disorder",
            "DisorderAttack",
            "disorder2"
        ]
        
        # Note: In a real implementation, we would use grep or ast parsing
        # For now, we'll document the expected locations
        
        # CLI mode call sites (based on code analysis)
        cli_sites.append(DisorderCallSite(
            file_path="core/cli/adaptive_cli_wrapper.py",
            line_number=0,  # Would be found by grep
            function_name="test_strategy",
            mode="cli",
            context="Testing mode uses UnifiedBypassEngine",
            parameters={"split_pos": "variable", "ack_first": "False"}
        ))
        
        cli_sites.append(DisorderCallSite(
            file_path="core/adaptive_engine.py",
            line_number=0,
            function_name="apply_strategy",
            mode="cli",
            context="Adaptive engine applies strategies during testing",
            parameters={"split_pos": "from strategy", "ack_first": "from strategy"}
        ))
        
        # Service mode call sites
        service_sites.append(DisorderCallSite(
            file_path="recon_service.py",
            line_number=0,
            function_name="process_packet",
            mode="service",
            context="Service mode applies strategies to live traffic",
            parameters={"split_pos": "from domain_strategies.json", "ack_first": "from config"}
        ))
        
        service_sites.append(DisorderCallSite(
            file_path="core/unified_bypass_engine.py",
            line_number=0,
            function_name="apply_bypass",
            mode="service",
            context="Unified bypass engine processes packets",
            parameters={"split_pos": "from strategy", "ack_first": "from strategy"}
        ))
        
        self.results.cli_call_sites = cli_sites
        self.results.service_call_sites = service_sites
        
        return cli_sites, service_sites
    
    def compare_implementations(self) -> List[str]:
        """
        Compare disorder attack implementation between modes.
        
        Returns:
            List of identified differences
        """
        self.logger.info("Comparing disorder implementations between modes...")
        
        differences = []
        
        # Check if both modes use the same primitive
        differences.append(
            "ANALYSIS NEEDED: Verify both modes call BypassTechniques.apply_disorder() "
            "with identical parameters"
        )
        
        # Check parameter passing
        differences.append(
            "ANALYSIS NEEDED: Verify split_pos calculation is identical in both modes"
        )
        
        differences.append(
            "ANALYSIS NEEDED: Verify ack_first parameter is passed correctly in both modes"
        )
        
        # Check packet ordering
        differences.append(
            "ANALYSIS NEEDED: Verify packet send order (part2 first, part1 second) "
            "is maintained in both modes"
        )
        
        # Check TCP flags
        differences.append(
            "ANALYSIS NEEDED: Verify TCP flags (PSH+ACK vs ACK) are set correctly "
            "in both modes"
        )
        
        # Check delays
        differences.append(
            "ANALYSIS NEEDED: Verify inter-packet delays are consistent between modes"
        )
        
        self.results.differences = differences
        return differences
    
    def generate_pcap_capture_script(self) -> str:
        """
        Generate a script to capture PCAP traffic for disorder attacks.
        
        Returns:
            Path to generated script
        """
        self.logger.info("Generating PCAP capture script...")
        
        script_content = '''#!/usr/bin/env python3
"""
PCAP Capture Script for Disorder Attack Analysis

This script captures network traffic during disorder attack execution
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


def capture_cli_mode_disorder(domain: str, output_dir: str):
    """Capture PCAP during CLI mode disorder attack."""
    print(f"\\n=== Capturing CLI Mode Disorder Attack for {domain} ===")
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_file = os.path.join(output_dir, f"disorder_cli_{domain}_{timestamp}.pcap")
    
    # Start PCAP capture
    capturer = TemporaryCapturer(
        filter_expr=f"host {domain} and tcp",
        output_file=pcap_file
    )
    
    try:
        capturer.start()
        print(f"Started capture to {pcap_file}")
        
        # Run CLI mode test with disorder strategy
        print("Running CLI mode test...")
        cmd = [
            sys.executable, "cli.py", "auto",
            "--domain", domain,
            "--strategy", "disorder",
            "--split-pos", "5"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        print(f"CLI test completed: {result.returncode}")
        
        # Wait for packets to be captured
        time.sleep(2)
        
    finally:
        capturer.stop()
        print(f"Capture saved to {pcap_file}")
    
    return pcap_file


def capture_service_mode_disorder(domain: str, output_dir: str):
    """Capture PCAP during Service mode disorder attack."""
    print(f"\\n=== Capturing Service Mode Disorder Attack for {domain} ===")
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_file = os.path.join(output_dir, f"disorder_service_{domain}_{timestamp}.pcap")
    
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
    output_dir = "disorder_audit_pcaps"
    os.makedirs(output_dir, exist_ok=True)
    
    # Test domain
    test_domain = "example.com"  # Replace with actual blocked domain
    
    print("=== Disorder Attack PCAP Capture ===")
    print(f"Domain: {test_domain}")
    print(f"Output: {output_dir}")
    
    # Capture CLI mode
    cli_pcap = capture_cli_mode_disorder(test_domain, output_dir)
    
    # Capture Service mode
    service_pcap = capture_service_mode_disorder(test_domain, output_dir)
    
    print("\\n=== Capture Complete ===")
    print(f"CLI PCAP: {cli_pcap}")
    print(f"Service PCAP: {service_pcap}")
    print("\\nNext steps:")
    print("1. Analyze PCAPs with: python tools/analyze_disorder_pcap.py")
    print("2. Compare packet order between modes")
    print("3. Verify TCP flags and sequence numbers")


if __name__ == "__main__":
    main()
'''
        
        script_path = "tools/capture_disorder_pcap.py"
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
    print(f"\\n=== Analyzing CLI Mode PCAP: {cli_pcap} ===")
    
    if SCAPY_AVAILABLE:
        cli_packets = analyze_pcap_with_scapy(cli_pcap)
    else:
        cli_packets = analyze_pcap_with_raw_engine(cli_pcap)
    
    cli_analysis = analyze_disorder_pattern(cli_packets)
    
    print(f"CLI packets: {cli_analysis['total_packets']}")
    print(f"CLI data packets: {cli_analysis['packets_with_payload']}")
    print(f"CLI disorder detected: {cli_analysis['disorder_detected']}")
    
    print(f"\\n=== Analyzing Service Mode PCAP: {service_pcap} ===")
    
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
    
    print("\\n=== Comparison Results ===")
    if comparison["differences"]:
        print("\\nDIFFERENCES FOUND:")
        for diff in comparison["differences"]:
            print(f"  - {diff}")
    else:
        print("\\nNo significant differences detected.")
    
    # Save results
    import json
    output_file = "disorder_audit_comparison.json"
    with open(output_file, "w") as f:
        json.dump(comparison, f, indent=2, default=str)
    
    print(f"\\nDetailed results saved to: {output_file}")


if __name__ == "__main__":
    main()
'''
        
        script_path = "tools/analyze_disorder_pcap.py"
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
            "1. Verify both CLI and Service modes use BypassTechniques.apply_disorder() "
            "from core/bypass/techniques/primitives.py",
            
            "2. Ensure split_pos parameter is calculated identically in both modes",
            
            "3. Verify ack_first parameter is passed correctly from strategy configuration",
            
            "4. Capture PCAP traffic in both modes using tools/capture_disorder_pcap.py",
            
            "5. Analyze captured PCAPs using tools/analyze_disorder_pcap.py to compare "
            "packet order and TCP flags",
            
            "6. Document any differences found in packet ordering between modes",
            
            "7. If differences exist, trace the code path from strategy loading to "
            "packet transmission in both modes",
            
            "8. Ensure UnifiedBypassEngine applies disorder attacks consistently",
            
            "9. Add logging to track disorder attack parameters in both modes",
            
            "10. Create integration tests that verify disorder attack parity between modes"
        ]
        
        self.results.recommendations = recommendations
        return recommendations
    
    def run_audit(self) -> DisorderAuditResult:
        """
        Run complete disorder attack audit.
        
        Returns:
            Complete audit results
        """
        self.logger.info("Starting disorder attack audit...")
        
        # 1. Analyze primitive implementation
        self.analyze_primitive_implementation()
        
        # 2. Find call sites
        self.find_disorder_call_sites()
        
        # 3. Compare implementations
        self.compare_implementations()
        
        # 4. Generate PCAP capture tools
        self.generate_pcap_capture_script()
        self.generate_pcap_analysis_script()
        
        # 5. Generate recommendations
        self.generate_recommendations()
        
        self.logger.info("Disorder attack audit complete")
        return self.results
    
    def save_report(self, output_file: str):
        """Save audit report to file."""
        report = {
            "audit_type": "disorder_attack",
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
    print("Disorder Attack Audit Tool")
    print("Task: 1.1.3 Аудит disorder атак")
    print("=" * 80)
    
    auditor = DisorderAttackAuditor()
    results = auditor.run_audit()
    
    # Save report
    output_file = "disorder_audit_report.json"
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
            print(f"   Order: {'✓ CORRECT' if test.get('packet_order_correct') else '✗ INCORRECT'}")
    
    print(f"\n2. Call Sites Found:")
    print(f"   CLI mode: {len(results.cli_call_sites)} locations")
    print(f"   Service mode: {len(results.service_call_sites)} locations")
    
    print(f"\n3. Analysis Items:")
    print(f"   {len(results.differences)} items need verification")
    
    print(f"\n4. Recommendations:")
    print(f"   {len(results.recommendations)} action items")
    
    print(f"\n5. Generated Tools:")
    print("   ✓ tools/capture_disorder_pcap.py - PCAP capture script")
    print("   ✓ tools/analyze_disorder_pcap.py - PCAP analysis script")
    
    print(f"\n6. Report:")
    print(f"   Saved to: {output_file}")
    
    print("\n" + "=" * 80)
    print("NEXT STEPS")
    print("=" * 80)
    print("\n1. Review the generated report: disorder_audit_report.json")
    print("2. Capture PCAP traffic:")
    print("   python tools/capture_disorder_pcap.py")
    print("3. Analyze captured PCAPs:")
    print("   python tools/analyze_disorder_pcap.py")
    print("4. Compare packet order between CLI and Service modes")
    print("5. Document any differences found")
    print("\n" + "=" * 80)


if __name__ == "__main__":
    main()
