#!/usr/bin/env python3
"""
Comprehensive PCAP Verification Tool
Независимая верификация PCAP-анализа для задачи fakeddisorder-ttl-fix

This tool performs detailed byte-by-byte comparison of zapret.pcap and out2.pcap
to identify any differences in packet structure, timing, and behavior.
"""

import sys
import os
import json
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
import struct

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP
    from scapy.layers.tls import TLS
    from scapy.utils import rdpcap
    SCAPY_AVAILABLE = True
except ImportError:
    print("Warning: Scapy not available. Some features will be limited.")
    SCAPY_AVAILABLE = False

class ComprehensivePcapVerifier:
    """Comprehensive PCAP verification and analysis tool"""
    
    def __init__(self, zapret_pcap: str = "zapret.pcap", recon_pcap: str = "out2.pcap"):
        self.zapret_pcap = zapret_pcap
        self.recon_pcap = recon_pcap
        self.analysis_results = {
            "timestamp": datetime.now().isoformat(),
            "files": {
                "zapret": zapret_pcap,
                "recon": recon_pcap
            },
            "analysis": {}
        }
        
    def verify_files_exist(self) -> bool:
        """Verify that both PCAP files exist"""
        if not os.path.exists(self.zapret_pcap):
            print(f"Error: {self.zapret_pcap} not found")
            return False
        if not os.path.exists(self.recon_pcap):
            print(f"Error: {self.recon_pcap} not found")
            return False
        return True
    
    def load_pcap_files(self) -> Tuple[Optional[List], Optional[List]]:
        """Load both PCAP files using Scapy"""
        if not SCAPY_AVAILABLE:
            print("Scapy not available - cannot load PCAP files")
            return None, None
            
        try:
            print(f"Loading {self.zapret_pcap}...")
            zapret_packets = rdpcap(self.zapret_pcap)
            print(f"Loaded {len(zapret_packets)} packets from zapret.pcap")
            
            print(f"Loading {self.recon_pcap}...")
            recon_packets = rdpcap(self.recon_pcap)
            print(f"Loaded {len(recon_packets)} packets from out2.pcap")
            
            return zapret_packets, recon_packets
        except Exception as e:
            print(f"Error loading PCAP files: {e}")
            return None, None
    
    def find_matching_flows(self, zapret_packets: List, recon_packets: List) -> Dict[str, Dict]:
        """Find matching TCP flows between zapret and recon captures"""
        print("\n=== Finding Matching TCP Flows ===")
        
        zapret_flows = {}
        recon_flows = {}
        
        # Extract flows from zapret
        for i, pkt in enumerate(zapret_packets):
            if IP in pkt and TCP in pkt:
                flow_key = f"{pkt[IP].src}:{pkt[TCP].sport}->{pkt[IP].dst}:{pkt[TCP].dport}"
                if flow_key not in zapret_flows:
                    zapret_flows[flow_key] = []
                zapret_flows[flow_key].append((i, pkt))
        
        # Extract flows from recon
        for i, pkt in enumerate(recon_packets):
            if IP in pkt and TCP in pkt:
                flow_key = f"{pkt[IP].src}:{pkt[TCP].sport}->{pkt[IP].dst}:{pkt[TCP].dport}"
                if flow_key not in recon_flows:
                    recon_flows[flow_key] = []
                recon_flows[flow_key].append((i, pkt))
        
        print(f"Found {len(zapret_flows)} flows in zapret.pcap")
        print(f"Found {len(recon_flows)} flows in out2.pcap")
        
        # Find matching flows (by destination)
        matching_flows = {}
        for zapret_flow in zapret_flows:
            # Extract destination from flow key
            dest = zapret_flow.split('->')[1]
            for recon_flow in recon_flows:
                if recon_flow.endswith(dest):
                    matching_flows[zapret_flow] = {
                        'zapret': zapret_flows[zapret_flow],
                        'recon': recon_flows[recon_flow],
                        'recon_flow_key': recon_flow
                    }
                    print(f"Matched flow: {zapret_flow} <-> {recon_flow}")
                    break
        
        self.analysis_results["analysis"]["matching_flows"] = len(matching_flows)
        return matching_flows
    
    def analyze_packet_headers(self, zapret_pkt, recon_pkt, pkt_num: int) -> Dict:
        """Detailed analysis of IP and TCP headers"""
        analysis = {
            "packet_number": pkt_num,
            "ip_header": {},
            "tcp_header": {},
            "differences": []
        }
        
        if IP not in zapret_pkt or IP not in recon_pkt:
            analysis["differences"].append("Missing IP layer in one of the packets")
            return analysis
        
        # IP Header Analysis
        zapret_ip = zapret_pkt[IP]
        recon_ip = recon_pkt[IP]
        
        ip_fields = ['version', 'ihl', 'tos', 'len', 'id', 'flags', 'frag', 'ttl', 'proto', 'chksum']
        for field in ip_fields:
            zapret_val = getattr(zapret_ip, field, None)
            recon_val = getattr(recon_ip, field, None)
            analysis["ip_header"][field] = {
                "zapret": zapret_val,
                "recon": recon_val,
                "match": zapret_val == recon_val
            }
            if zapret_val != recon_val:
                analysis["differences"].append(f"IP.{field}: zapret={zapret_val}, recon={recon_val}")
        
        # TCP Header Analysis
        if TCP in zapret_pkt and TCP in recon_pkt:
            zapret_tcp = zapret_pkt[TCP]
            recon_tcp = recon_pkt[TCP]
            
            tcp_fields = ['sport', 'dport', 'seq', 'ack', 'dataofs', 'reserved', 'flags', 'window', 'chksum', 'urgptr']
            for field in tcp_fields:
                zapret_val = getattr(zapret_tcp, field, None)
                recon_val = getattr(recon_tcp, field, None)
                analysis["tcp_header"][field] = {
                    "zapret": zapret_val,
                    "recon": recon_val,
                    "match": zapret_val == recon_val
                }
                if zapret_val != recon_val:
                    analysis["differences"].append(f"TCP.{field}: zapret={zapret_val}, recon={recon_val}")
        
        return analysis
    
    def analyze_tcp_options(self, zapret_pkt, recon_pkt) -> Dict:
        """Deep analysis of TCP options"""
        analysis = {
            "zapret_options": [],
            "recon_options": [],
            "differences": []
        }
        
        if TCP not in zapret_pkt or TCP not in recon_pkt:
            return analysis
        
        # Extract TCP options
        zapret_tcp = zapret_pkt[TCP]
        recon_tcp = recon_pkt[TCP]
        
        if hasattr(zapret_tcp, 'options'):
            analysis["zapret_options"] = zapret_tcp.options
        if hasattr(recon_tcp, 'options'):
            analysis["recon_options"] = recon_tcp.options
        
        # Compare options
        if analysis["zapret_options"] != analysis["recon_options"]:
            analysis["differences"].append("TCP options differ")
            analysis["differences"].append(f"Zapret options: {analysis['zapret_options']}")
            analysis["differences"].append(f"Recon options: {analysis['recon_options']}")
        
        return analysis
    
    def analyze_timing(self, zapret_flow: List, recon_flow: List) -> Dict:
        """Analyze packet timing and intervals"""
        analysis = {
            "zapret_timing": [],
            "recon_timing": [],
            "timing_differences": []
        }
        
        # Extract timestamps
        for i, (pkt_idx, pkt) in enumerate(zapret_flow[:4]):  # First 4 packets
            analysis["zapret_timing"].append({
                "packet": i,
                "timestamp": float(pkt.time),
                "relative_time": float(pkt.time) - float(zapret_flow[0][1].time) if i > 0 else 0.0
            })
        
        for i, (pkt_idx, pkt) in enumerate(recon_flow[:4]):  # First 4 packets
            analysis["recon_timing"].append({
                "packet": i,
                "timestamp": float(pkt.time),
                "relative_time": float(pkt.time) - float(recon_flow[0][1].time) if i > 0 else 0.0
            })
        
        # Calculate timing differences
        min_len = min(len(analysis["zapret_timing"]), len(analysis["recon_timing"]))
        for i in range(1, min_len):  # Skip first packet (reference)
            zapret_delta = analysis["zapret_timing"][i]["relative_time"]
            recon_delta = analysis["recon_timing"][i]["relative_time"]
            diff = abs(zapret_delta - recon_delta)
            analysis["timing_differences"].append({
                "packet": i,
                "zapret_delta_ms": zapret_delta * 1000,
                "recon_delta_ms": recon_delta * 1000,
                "difference_ms": diff * 1000
            })
        
        return analysis
    
    def check_tcp_retransmissions(self, flow_packets: List) -> Dict:
        """Check for TCP retransmissions in the flow"""
        analysis = {
            "retransmissions_found": [],
            "os_retransmissions": []
        }
        
        seen_seq_numbers = {}
        
        for i, (pkt_idx, pkt) in enumerate(flow_packets):
            if TCP in pkt:
                seq = pkt[TCP].seq
                ttl = pkt[IP].ttl if IP in pkt else None
                
                if seq in seen_seq_numbers:
                    # Potential retransmission
                    prev_pkt_info = seen_seq_numbers[seq]
                    retrans_info = {
                        "seq_number": seq,
                        "first_packet": prev_pkt_info,
                        "retrans_packet": {
                            "index": i,
                            "ttl": ttl,
                            "timestamp": float(pkt.time)
                        }
                    }
                    analysis["retransmissions_found"].append(retrans_info)
                    
                    # Check if this looks like OS retransmission (TTL=128 on Windows)
                    if ttl == 128:
                        analysis["os_retransmissions"].append(retrans_info)
                else:
                    seen_seq_numbers[seq] = {
                        "index": i,
                        "ttl": ttl,
                        "timestamp": float(pkt.time)
                    }
        
        return analysis
    
    def analyze_rst_packets(self, flow_packets: List) -> Dict:
        """Analyze RST packets and their sources"""
        analysis = {
            "rst_packets": [],
            "rst_sources": {}
        }
        
        for i, (pkt_idx, pkt) in enumerate(flow_packets):
            if TCP in pkt and pkt[TCP].flags & 0x04:  # RST flag
                rst_info = {
                    "packet_index": i,
                    "source_ip": pkt[IP].src if IP in pkt else None,
                    "dest_ip": pkt[IP].dst if IP in pkt else None,
                    "timestamp": float(pkt.time),
                    "seq": pkt[TCP].seq,
                    "ack": pkt[TCP].ack
                }
                analysis["rst_packets"].append(rst_info)
                
                # Categorize RST source
                src = rst_info["source_ip"]
                if src not in analysis["rst_sources"]:
                    analysis["rst_sources"][src] = 0
                analysis["rst_sources"][src] += 1
        
        return analysis
    
    def export_raw_bytes(self, pkt, filename: str):
        """Export raw packet bytes for hex analysis"""
        try:
            with open(filename, 'wb') as f:
                f.write(bytes(pkt))
            print(f"Exported raw bytes to {filename}")
        except Exception as e:
            print(f"Error exporting raw bytes: {e}")
    
    def perform_comprehensive_analysis(self) -> Dict:
        """Perform comprehensive PCAP analysis"""
        print("=== Comprehensive PCAP Verification ===")
        print(f"Analyzing {self.zapret_pcap} vs {self.recon_pcap}")
        
        if not self.verify_files_exist():
            return self.analysis_results
        
        if not SCAPY_AVAILABLE:
            print("Scapy not available - analysis limited")
            return self.analysis_results
        
        # Load PCAP files
        zapret_packets, recon_packets = self.load_pcap_files()
        if not zapret_packets or not recon_packets:
            return self.analysis_results
        
        # Find matching flows
        matching_flows = self.find_matching_flows(zapret_packets, recon_packets)
        
        if not matching_flows:
            print("No matching flows found!")
            return self.analysis_results
        
        # Analyze first matching flow in detail
        first_flow_key = list(matching_flows.keys())[0]
        first_flow = matching_flows[first_flow_key]
        
        print(f"\n=== Analyzing Flow: {first_flow_key} ===")
        
        zapret_flow = first_flow['zapret']
        recon_flow = first_flow['recon']
        
        flow_analysis = {
            "flow_key": first_flow_key,
            "packet_count": {
                "zapret": len(zapret_flow),
                "recon": len(recon_flow)
            },
            "packet_analysis": [],
            "timing_analysis": {},
            "tcp_options_analysis": [],
            "retransmission_analysis": {},
            "rst_analysis": {}
        }
        
        # Analyze first 4 packets in detail
        max_packets = min(4, len(zapret_flow), len(recon_flow))
        for i in range(max_packets):
            zapret_pkt = zapret_flow[i][1]
            recon_pkt = recon_flow[i][1]
            
            print(f"\nAnalyzing packet {i+1}...")
            
            # Header analysis
            header_analysis = self.analyze_packet_headers(zapret_pkt, recon_pkt, i+1)
            flow_analysis["packet_analysis"].append(header_analysis)
            
            # TCP options analysis
            options_analysis = self.analyze_tcp_options(zapret_pkt, recon_pkt)
            flow_analysis["tcp_options_analysis"].append(options_analysis)
            
            # Export raw bytes for manual inspection
            self.export_raw_bytes(zapret_pkt, f"zapret_packet_{i+1}.bin")
            self.export_raw_bytes(recon_pkt, f"recon_packet_{i+1}.bin")
        
        # Timing analysis
        print("\nAnalyzing timing...")
        flow_analysis["timing_analysis"] = self.analyze_timing(zapret_flow, recon_flow)
        
        # Retransmission analysis
        print("Checking for retransmissions...")
        flow_analysis["retransmission_analysis"] = self.check_tcp_retransmissions(recon_flow)
        
        # RST analysis
        print("Analyzing RST packets...")
        flow_analysis["rst_analysis"] = self.analyze_rst_packets(recon_flow)
        
        self.analysis_results["analysis"]["flow_analysis"] = flow_analysis
        
        return self.analysis_results
    
    def generate_report(self) -> str:
        """Generate comprehensive analysis report"""
        report = []
        report.append("=" * 80)
        report.append("COMPREHENSIVE PCAP VERIFICATION REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {self.analysis_results['timestamp']}")
        report.append(f"Zapret PCAP: {self.analysis_results['files']['zapret']}")
        report.append(f"Recon PCAP: {self.analysis_results['files']['recon']}")
        report.append("")
        
        if "flow_analysis" not in self.analysis_results["analysis"]:
            report.append("ERROR: No flow analysis available")
            return "\n".join(report)
        
        flow = self.analysis_results["analysis"]["flow_analysis"]
        
        report.append(f"FLOW ANALYZED: {flow['flow_key']}")
        report.append(f"Packet count - Zapret: {flow['packet_count']['zapret']}, Recon: {flow['packet_count']['recon']}")
        report.append("")
        
        # Packet-by-packet analysis
        report.append("PACKET-BY-PACKET ANALYSIS:")
        report.append("-" * 40)
        for pkt_analysis in flow["packet_analysis"]:
            report.append(f"Packet {pkt_analysis['packet_number']}:")
            if pkt_analysis["differences"]:
                for diff in pkt_analysis["differences"]:
                    report.append(f"  DIFFERENCE: {diff}")
            else:
                report.append("  No differences found")
            report.append("")
        
        # Timing analysis
        if flow["timing_analysis"]["timing_differences"]:
            report.append("TIMING ANALYSIS:")
            report.append("-" * 40)
            for timing in flow["timing_analysis"]["timing_differences"]:
                report.append(f"Packet {timing['packet']}: Zapret={timing['zapret_delta_ms']:.3f}ms, "
                            f"Recon={timing['recon_delta_ms']:.3f}ms, Diff={timing['difference_ms']:.3f}ms")
            report.append("")
        
        # Retransmission analysis
        if flow["retransmission_analysis"]["retransmissions_found"]:
            report.append("RETRANSMISSION ANALYSIS:")
            report.append("-" * 40)
            report.append(f"Total retransmissions found: {len(flow['retransmission_analysis']['retransmissions_found'])}")
            report.append(f"OS retransmissions (TTL=128): {len(flow['retransmission_analysis']['os_retransmissions'])}")
            
            if flow["retransmission_analysis"]["os_retransmissions"]:
                report.append("WARNING: OS retransmissions detected - this may indicate timing issues!")
            report.append("")
        
        # RST analysis
        if flow["rst_analysis"]["rst_packets"]:
            report.append("RST PACKET ANALYSIS:")
            report.append("-" * 40)
            report.append(f"Total RST packets: {len(flow['rst_analysis']['rst_packets'])}")
            for src, count in flow["rst_analysis"]["rst_sources"].items():
                report.append(f"RST from {src}: {count} packets")
            report.append("")
        
        # Summary and conclusions
        report.append("SUMMARY AND CONCLUSIONS:")
        report.append("-" * 40)
        
        total_differences = sum(len(pkt["differences"]) for pkt in flow["packet_analysis"])
        if total_differences == 0:
            report.append("✓ No packet header differences found")
        else:
            report.append(f"✗ {total_differences} packet header differences found")
        
        if flow["retransmission_analysis"]["os_retransmissions"]:
            report.append("✗ OS retransmissions detected - timing issue likely")
        else:
            report.append("✓ No OS retransmissions detected")
        
        if flow["rst_analysis"]["rst_packets"]:
            report.append(f"⚠ {len(flow['rst_analysis']['rst_packets'])} RST packets found")
        else:
            report.append("✓ No RST packets found")
        
        return "\n".join(report)
    
    def save_results(self, filename: str = "pcap_verification_results.json"):
        """Save analysis results to JSON file"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.analysis_results, f, indent=2, ensure_ascii=False)
            print(f"Results saved to {filename}")
        except Exception as e:
            print(f"Error saving results: {e}")

def main():
    """Main function"""
    verifier = ComprehensivePcapVerifier()
    
    # Perform comprehensive analysis
    results = verifier.perform_comprehensive_analysis()
    
    # Generate and display report
    report = verifier.generate_report()
    print("\n" + report)
    
    # Save results
    verifier.save_results()
    
    # Save report
    with open("pcap_verification_report.txt", 'w', encoding='utf-8') as f:
        f.write(report)
    print("\nReport saved to pcap_verification_report.txt")

if __name__ == "__main__":
    main()