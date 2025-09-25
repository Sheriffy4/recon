#!/usr/bin/env python3
"""
Analyze current PCAP issues to identify why strategies are failing.
This script performs detailed analysis of out2.pcap to find packet construction problems.
"""

import json
import struct
import logging
from collections import defaultdict
from typing import Dict, List, Tuple, Optional, Any
from scapy.all import rdpcap, IP, TCP, Raw
import os
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

class PCAPAnalyzer:
    """Comprehensive PCAP analyzer for identifying packet construction issues"""
    
    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path
        self.packets = []
        self.flows = defaultdict(list)
        self.issues = []
        
    def load_pcap(self) -> bool:
        """Load PCAP file and organize packets by flow"""
        try:
            if not os.path.exists(self.pcap_path):
                logger.error(f"PCAP file not found: {self.pcap_path}")
                return False
                
            logger.info(f"Loading PCAP: {self.pcap_path}")
            self.packets = rdpcap(self.pcap_path)
            logger.info(f"Loaded {len(self.packets)} packets")
            
            # Organize packets by flow
            for pkt in self.packets:
                if IP in pkt and TCP in pkt:
                    flow_key = self._get_flow_key(pkt)
                    self.flows[flow_key].append(pkt)
            
            logger.info(f"Found {len(self.flows)} flows")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load PCAP: {e}")
            return False
    
    def _get_flow_key(self, pkt) -> Tuple[str, int, str, int]:
        """Get flow key for packet"""
        ip = pkt[IP]
        tcp = pkt[TCP]
        return (ip.src, tcp.sport, ip.dst, tcp.dport)
    
    def analyze_packet_construction(self) -> Dict[str, Any]:
        """Analyze packet construction issues"""
        logger.info("Analyzing packet construction...")
        
        analysis = {
            "total_packets": len(self.packets),
            "total_flows": len(self.flows),
            "construction_issues": [],
            "checksum_issues": [],
            "sni_issues": [],
            "sequence_issues": [],
            "timing_issues": []
        }
        
        for flow_key, flow_packets in self.flows.items():
            flow_analysis = self._analyze_flow(flow_key, flow_packets)
            
            # Collect issues
            if flow_analysis.get("checksum_issues"):
                analysis["checksum_issues"].extend(flow_analysis["checksum_issues"])
            if flow_analysis.get("sni_issues"):
                analysis["sni_issues"].extend(flow_analysis["sni_issues"])
            if flow_analysis.get("sequence_issues"):
                analysis["sequence_issues"].extend(flow_analysis["sequence_issues"])
            if flow_analysis.get("construction_issues"):
                analysis["construction_issues"].extend(flow_analysis["construction_issues"])
        
        return analysis
    
    def _analyze_flow(self, flow_key: Tuple, packets: List) -> Dict[str, Any]:
        """Analyze individual flow for issues"""
        flow_analysis = {
            "flow_key": flow_key,
            "packet_count": len(packets),
            "checksum_issues": [],
            "sni_issues": [],
            "sequence_issues": [],
            "construction_issues": [],
            "fake_packets": [],
            "real_packets": []
        }
        
        # Sort packets by time
        packets.sort(key=lambda p: p.time)
        
        # Analyze each packet
        for i, pkt in enumerate(packets):
            pkt_analysis = self._analyze_packet(pkt, i)
            
            # Classify as fake or real based on characteristics
            if self._is_likely_fake_packet(pkt):
                flow_analysis["fake_packets"].append(pkt_analysis)
            else:
                flow_analysis["real_packets"].append(pkt_analysis)
            
            # Check for issues
            if pkt_analysis.get("checksum_invalid") and not pkt_analysis.get("checksum_intentionally_bad"):
                flow_analysis["checksum_issues"].append({
                    "packet_index": i,
                    "issue": "Invalid checksum (not intentionally corrupted)",
                    "details": pkt_analysis
                })
            
            if pkt_analysis.get("sni_extraction_failed"):
                flow_analysis["sni_issues"].append({
                    "packet_index": i,
                    "issue": "SNI extraction failed",
                    "details": pkt_analysis
                })
        
        # Analyze sequence number patterns
        self._analyze_sequence_patterns(flow_analysis)
        
        # Analyze fake/real packet relationships
        self._analyze_fake_real_relationships(flow_analysis)
        
        return flow_analysis
    
    def _analyze_packet(self, pkt, index: int) -> Dict[str, Any]:
        """Analyze individual packet"""
        analysis = {
            "index": index,
            "time": float(pkt.time),
            "size": len(pkt)
        }
        
        if IP in pkt:
            ip = pkt[IP]
            analysis.update({
                "src_ip": ip.src,
                "dst_ip": ip.dst,
                "ttl": ip.ttl,
                "ip_id": ip.id,
                "ip_flags": ip.flags
            })
        
        if TCP in pkt:
            tcp = pkt[TCP]
            analysis.update({
                "src_port": tcp.sport,
                "dst_port": tcp.dport,
                "seq": tcp.seq,
                "ack": tcp.ack,
                "flags": tcp.flags,
                "window": tcp.window,
                "tcp_options": self._extract_tcp_options(tcp)
            })
            
            # Analyze checksum
            analysis.update(self._analyze_tcp_checksum(pkt))
        
        if Raw in pkt:
            payload = bytes(pkt[Raw])
            analysis.update({
                "payload_size": len(payload),
                "is_tls": self._is_tls_packet(payload),
                "is_client_hello": self._is_tls_client_hello(payload)
            })
            
            if analysis["is_client_hello"]:
                sni_analysis = self._analyze_sni(payload)
                analysis.update(sni_analysis)
        
        return analysis
    
    def _is_likely_fake_packet(self, pkt) -> bool:
        """Determine if packet is likely a fake packet based on characteristics"""
        if not (IP in pkt and TCP in pkt):
            return False
        
        # Fake packets typically have:
        # - Low TTL (<=8)
        # - Bad checksums
        # - Specific flag patterns
        
        ip = pkt[IP]
        tcp = pkt[TCP]
        
        # Low TTL is a strong indicator
        if ip.ttl <= 8:
            return True
        
        # Check for intentionally bad checksum
        if self._has_intentionally_bad_checksum(pkt):
            return True
        
        # Check for specific flag patterns (fake packets often don't have PSH)
        if Raw in pkt and not (tcp.flags & 0x08):  # No PSH flag
            return True
        
        return False
    
    def _analyze_tcp_checksum(self, pkt) -> Dict[str, Any]:
        """Analyze TCP checksum"""
        if not (IP in pkt and TCP in pkt):
            return {}
        
        try:
            # Calculate expected checksum
            ip_bytes = bytes(pkt[IP])
            ip_hl = (ip_bytes[0] & 0x0F) * 4
            tcp_start = ip_hl
            tcp_hl = ((ip_bytes[tcp_start + 12] >> 4) & 0x0F) * 4
            if tcp_hl < 20:
                tcp_hl = 20
            
            # Extract actual checksum
            actual_checksum = struct.unpack("!H", ip_bytes[tcp_start+16:tcp_start+18])[0]
            
            # Calculate expected checksum
            expected_checksum = self._calculate_tcp_checksum(ip_bytes, tcp_start, tcp_hl)
            
            is_valid = actual_checksum == expected_checksum
            is_intentionally_bad = actual_checksum in [0xDEAD, 0xBEEF]  # Common bad checksums
            
            return {
                "actual_checksum": f"0x{actual_checksum:04X}",
                "expected_checksum": f"0x{expected_checksum:04X}",
                "checksum_valid": is_valid,
                "checksum_intentionally_bad": is_intentionally_bad,
                "checksum_invalid": not is_valid and not is_intentionally_bad
            }
            
        except Exception as e:
            return {"checksum_analysis_error": str(e)}
    
    def _has_intentionally_bad_checksum(self, pkt) -> bool:
        """Check if packet has intentionally bad checksum"""
        checksum_analysis = self._analyze_tcp_checksum(pkt)
        return checksum_analysis.get("checksum_intentionally_bad", False)
    
    def _calculate_tcp_checksum(self, ip_bytes: bytes, tcp_start: int, tcp_hl: int) -> int:
        """Calculate TCP checksum"""
        try:
            # Extract IP header info
            src = ip_bytes[12:16]
            dst = ip_bytes[16:20]
            proto = ip_bytes[9]
            
            # Extract TCP header and payload
            tcp_end = tcp_start + tcp_hl
            tcp_hdr = bytearray(ip_bytes[tcp_start:tcp_end])
            payload = ip_bytes[tcp_end:]
            
            # Zero out checksum field
            tcp_hdr[16:18] = b"\x00\x00"
            
            # Create pseudo header
            tcp_len = len(tcp_hdr) + len(payload)
            pseudo = src + dst + bytes([0, proto]) + struct.pack("!H", tcp_len)
            
            # Calculate checksum
            data = pseudo + bytes(tcp_hdr) + payload
            return self._ones_complement_checksum(data)
            
        except Exception:
            return 0
    
    def _ones_complement_checksum(self, data: bytes) -> int:
        """Calculate ones complement checksum"""
        if len(data) % 2:
            data += b"\x00"
        
        s = 0
        for i in range(0, len(data), 2):
            s += (data[i] << 8) + data[i+1]
            s = (s & 0xFFFF) + (s >> 16)
        
        return (~s) & 0xFFFF
    
    def _extract_tcp_options(self, tcp) -> List[str]:
        """Extract TCP options"""
        options = []
        try:
            for opt in tcp.options:
                if isinstance(opt, tuple) and len(opt) >= 1:
                    options.append(str(opt[0]))
                else:
                    options.append(str(opt))
        except Exception:
            pass
        return options
    
    def _is_tls_packet(self, payload: bytes) -> bool:
        """Check if payload is TLS"""
        return len(payload) > 5 and payload[0] == 0x16
    
    def _is_tls_client_hello(self, payload: bytes) -> bool:
        """Check if payload is TLS ClientHello"""
        return (len(payload) > 6 and 
                payload[0] == 0x16 and  # TLS Handshake
                payload[5] == 0x01)     # ClientHello
    
    def _analyze_sni(self, payload: bytes) -> Dict[str, Any]:
        """Analyze SNI in TLS ClientHello"""
        try:
            sni = self._extract_sni(payload)
            return {
                "sni": sni,
                "sni_extraction_failed": sni is None,
                "sni_length": len(sni) if sni else 0
            }
        except Exception as e:
            return {
                "sni": None,
                "sni_extraction_failed": True,
                "sni_error": str(e)
            }
    
    def _extract_sni(self, payload: bytes) -> Optional[str]:
        """Extract SNI from TLS ClientHello"""
        try:
            if not self._is_tls_client_hello(payload):
                return None
            
            # Navigate to extensions
            pos = 9 + 2 + 32  # Skip handshake header, version, random
            
            # Session ID
            if pos + 1 > len(payload):
                return None
            sid_len = payload[pos]
            pos += 1 + sid_len
            
            # Cipher Suites
            if pos + 2 > len(payload):
                return None
            cs_len = struct.unpack("!H", payload[pos:pos+2])[0]
            pos += 2 + cs_len
            
            # Compression Methods
            if pos + 1 > len(payload):
                return None
            comp_len = payload[pos]
            pos += 1 + comp_len
            
            # Extensions
            if pos + 2 > len(payload):
                return None
            ext_len = struct.unpack("!H", payload[pos:pos+2])[0]
            pos += 2
            
            # Find SNI extension
            ext_end = pos + ext_len
            while pos + 4 <= ext_end:
                ext_type = struct.unpack("!H", payload[pos:pos+2])[0]
                ext_len_field = struct.unpack("!H", payload[pos+2:pos+4])[0]
                
                if ext_type == 0:  # SNI extension
                    # Extract SNI
                    sni_pos = pos + 4 + 2  # Skip extension header and list length
                    if sni_pos + 3 <= len(payload):
                        name_type = payload[sni_pos]
                        name_len = struct.unpack("!H", payload[sni_pos+1:sni_pos+3])[0]
                        if name_type == 0 and sni_pos + 3 + name_len <= len(payload):
                            return payload[sni_pos+3:sni_pos+3+name_len].decode('utf-8')
                
                pos += 4 + ext_len_field
            
            return None
            
        except Exception:
            return None
    
    def _analyze_sequence_patterns(self, flow_analysis: Dict[str, Any]):
        """Analyze sequence number patterns in flow"""
        fake_packets = flow_analysis["fake_packets"]
        real_packets = flow_analysis["real_packets"]
        
        if not fake_packets or not real_packets:
            return
        
        # Check for proper sequence number relationships
        for fake in fake_packets:
            for real in real_packets:
                if abs(fake["time"] - real["time"]) < 0.1:  # Within 100ms
                    seq_delta = (real["seq"] - fake["seq"]) & 0xFFFFFFFF
                    if seq_delta > (1 << 31):  # Handle wrap-around
                        seq_delta = seq_delta - (1 << 32)
                    
                    if abs(seq_delta) > 1500:  # Suspicious sequence gap
                        flow_analysis["sequence_issues"].append({
                            "issue": "Large sequence number gap",
                            "fake_seq": fake["seq"],
                            "real_seq": real["seq"],
                            "delta": seq_delta
                        })
    
    def _analyze_fake_real_relationships(self, flow_analysis: Dict[str, Any]):
        """Analyze relationships between fake and real packets"""
        fake_packets = flow_analysis["fake_packets"]
        real_packets = flow_analysis["real_packets"]
        
        # Check timing relationships
        for fake in fake_packets:
            closest_real = None
            min_time_diff = float('inf')
            
            for real in real_packets:
                time_diff = abs(real["time"] - fake["time"])
                if time_diff < min_time_diff:
                    min_time_diff = time_diff
                    closest_real = real
            
            if closest_real and min_time_diff > 0.05:  # >50ms gap
                flow_analysis["construction_issues"].append({
                    "issue": "Large timing gap between fake and real packets",
                    "fake_time": fake["time"],
                    "real_time": closest_real["time"],
                    "gap_ms": min_time_diff * 1000
                })
    
    def generate_report(self, analysis: Dict[str, Any]) -> str:
        """Generate comprehensive analysis report"""
        report = []
        report.append("# PCAP Analysis Report")
        report.append(f"## Summary")
        report.append(f"- Total packets: {analysis['total_packets']}")
        report.append(f"- Total flows: {analysis['total_flows']}")
        report.append(f"- Construction issues: {len(analysis['construction_issues'])}")
        report.append(f"- Checksum issues: {len(analysis['checksum_issues'])}")
        report.append(f"- SNI issues: {len(analysis['sni_issues'])}")
        report.append(f"- Sequence issues: {len(analysis['sequence_issues'])}")
        report.append("")
        
        # Detailed issues
        if analysis['checksum_issues']:
            report.append("## Checksum Issues")
            for issue in analysis['checksum_issues'][:10]:  # Limit to first 10
                report.append(f"- {issue['issue']}")
                if 'details' in issue:
                    details = issue['details']
                    report.append(f"  - Actual: {details.get('actual_checksum', 'N/A')}")
                    report.append(f"  - Expected: {details.get('expected_checksum', 'N/A')}")
            report.append("")
        
        if analysis['sni_issues']:
            report.append("## SNI Issues")
            for issue in analysis['sni_issues'][:10]:
                report.append(f"- {issue['issue']}")
            report.append("")
        
        if analysis['construction_issues']:
            report.append("## Construction Issues")
            for issue in analysis['construction_issues'][:10]:
                report.append(f"- {issue['issue']}")
            report.append("")
        
        # Recommendations
        report.append("## Recommendations")
        
        if analysis['checksum_issues']:
            report.append("1. **Fix Checksum Corruption**: Ensure bad checksums are properly applied to fake packets")
        
        if analysis['sni_issues']:
            report.append("2. **Fix SNI Replacement**: Improve SNI replacement logic in TLS ClientHello")
        
        if analysis['construction_issues']:
            report.append("3. **Fix Packet Timing**: Reduce timing gaps between fake and real packets")
        
        if analysis['sequence_issues']:
            report.append("4. **Fix Sequence Numbers**: Align sequence number calculation with zapret")
        
        return "\n".join(report)

def main():
    """Main analysis function"""
    pcap_path = sys.argv[1] if len(sys.argv) > 1 else "out2.pcap"
    
    analyzer = PCAPAnalyzer(pcap_path)
    
    if not analyzer.load_pcap():
        logger.error("Failed to load PCAP file")
        return
    
    # Perform analysis
    analysis = analyzer.analyze_packet_construction()
    
    # Generate report
    report = analyzer.generate_report(analysis)
    
    # Save report
    report_path = "pcap_analysis_report.md"
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report)
    
    # Save detailed analysis
    analysis_path = "pcap_analysis_detailed.json"
    with open(analysis_path, 'w', encoding='utf-8') as f:
        json.dump(analysis, f, indent=2, default=str)
    
    logger.info(f"Analysis complete. Report saved to {report_path}")
    logger.info(f"Detailed analysis saved to {analysis_path}")
    
    # Print summary
    print("\n" + "="*50)
    print("PCAP ANALYSIS SUMMARY")
    print("="*50)
    print(f"Total packets: {analysis['total_packets']}")
    print(f"Total flows: {analysis['total_flows']}")
    print(f"Construction issues: {len(analysis['construction_issues'])}")
    print(f"Checksum issues: {len(analysis['checksum_issues'])}")
    print(f"SNI issues: {len(analysis['sni_issues'])}")
    print(f"Sequence issues: {len(analysis['sequence_issues'])}")
    
    if analysis['checksum_issues']:
        print(f"\n⚠️  CRITICAL: {len(analysis['checksum_issues'])} checksum issues found")
        print("   This likely means fake packets have valid checksums instead of bad ones")
    
    if analysis['sni_issues']:
        print(f"\n⚠️  CRITICAL: {len(analysis['sni_issues'])} SNI issues found")
        print("   This likely means SNI replacement is failing")
    
    if analysis['construction_issues']:
        print(f"\n⚠️  WARNING: {len(analysis['construction_issues'])} construction issues found")
        print("   This likely means timing or packet structure problems")

if __name__ == "__main__":
    main()