#!/usr/bin/env python3
"""
Hex-level PCAP Analyzer
Побайтовый анализ PCAP файлов без зависимости от Scapy

This tool performs raw binary analysis of PCAP files for detailed comparison.
"""

import struct
import sys
import os
from typing import List, Dict, Tuple, Optional
import json
from datetime import datetime

class PcapHeader:
    """PCAP file header structure"""
    def __init__(self, data: bytes):
        # PCAP Global Header: 24 bytes
        fields = struct.unpack('<LHHLLLL', data[:24])
        self.magic_number = fields[0]
        self.version_major = fields[1]
        self.version_minor = fields[2]
        self.thiszone = fields[3]
        self.sigfigs = fields[4]
        self.snaplen = fields[5]
        self.network = fields[6]

class PcapPacketHeader:
    """PCAP packet header structure"""
    def __init__(self, data: bytes):
        # Packet Header: 16 bytes
        fields = struct.unpack('<LLLL', data[:16])
        self.ts_sec = fields[0]
        self.ts_usec = fields[1]
        self.incl_len = fields[2]
        self.orig_len = fields[3]

class EthernetHeader:
    """Ethernet header structure"""
    def __init__(self, data: bytes):
        # Ethernet Header: 14 bytes
        self.dst_mac = data[0:6]
        self.src_mac = data[6:12]
        self.ethertype = struct.unpack('>H', data[12:14])[0]

class IPHeader:
    """IP header structure"""
    def __init__(self, data: bytes):
        # IP Header: minimum 20 bytes
        fields = struct.unpack('>BBHHHBBH4s4s', data[:20])
        self.version_ihl = fields[0]
        self.version = (fields[0] >> 4) & 0xF
        self.ihl = fields[0] & 0xF
        self.tos = fields[1]
        self.total_length = fields[2]
        self.identification = fields[3]
        self.flags_fragment = fields[4]
        self.flags = (fields[4] >> 13) & 0x7
        self.fragment_offset = fields[4] & 0x1FFF
        self.ttl = fields[5]
        self.protocol = fields[6]
        self.checksum = fields[7]
        self.src_ip = fields[8]
        self.dst_ip = fields[9]
        
        # Parse options if present
        self.header_length = self.ihl * 4
        if self.header_length > 20:
            self.options = data[20:self.header_length]
        else:
            self.options = b''

class TCPHeader:
    """TCP header structure"""
    def __init__(self, data: bytes):
        # TCP Header: minimum 20 bytes
        fields = struct.unpack('>HHLLBBHHH', data[:20])
        self.src_port = fields[0]
        self.dst_port = fields[1]
        self.seq_number = fields[2]
        self.ack_number = fields[3]
        self.data_offset_reserved = fields[4]
        self.data_offset = (fields[4] >> 4) & 0xF
        self.flags = fields[5]
        self.window_size = fields[6]
        self.checksum = fields[7]
        self.urgent_pointer = fields[8]
        
        # Parse options if present
        self.header_length = self.data_offset * 4
        if self.header_length > 20:
            self.options = data[20:self.header_length]
        else:
            self.options = b''

class HexPcapAnalyzer:
    """Raw binary PCAP analyzer"""
    
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
    
    def read_pcap_file(self, filename: str) -> List[Dict]:
        """Read PCAP file and parse packets"""
        packets = []
        
        try:
            with open(filename, 'rb') as f:
                # Read PCAP header
                pcap_header_data = f.read(24)
                if len(pcap_header_data) < 24:
                    print(f"Error: Invalid PCAP file {filename}")
                    return packets
                
                pcap_header = PcapHeader(pcap_header_data)
                
                packet_index = 0
                while True:
                    # Read packet header
                    packet_header_data = f.read(16)
                    if len(packet_header_data) < 16:
                        break  # End of file
                    
                    packet_header = PcapPacketHeader(packet_header_data)
                    
                    # Read packet data
                    packet_data = f.read(packet_header.incl_len)
                    if len(packet_data) < packet_header.incl_len:
                        break  # Incomplete packet
                    
                    # Parse packet
                    packet_info = self.parse_packet(packet_data, packet_header, packet_index)
                    if packet_info:
                        packets.append(packet_info)
                    
                    packet_index += 1
                
        except Exception as e:
            print(f"Error reading {filename}: {e}")
        
        return packets
    
    def parse_packet(self, data: bytes, header: PcapPacketHeader, index: int) -> Optional[Dict]:
        """Parse individual packet"""
        try:
            packet_info = {
                "index": index,
                "timestamp": header.ts_sec + header.ts_usec / 1000000.0,
                "length": header.incl_len,
                "raw_data": data.hex(),
                "parsed": {}
            }
            
            offset = 0
            
            # Parse Ethernet header
            if len(data) >= 14:
                eth_header = EthernetHeader(data[offset:])
                packet_info["parsed"]["ethernet"] = {
                    "dst_mac": eth_header.dst_mac.hex(),
                    "src_mac": eth_header.src_mac.hex(),
                    "ethertype": f"0x{eth_header.ethertype:04x}"
                }
                offset += 14
                
                # Check if it's IP packet
                if eth_header.ethertype == 0x0800:  # IPv4
                    if len(data) >= offset + 20:
                        ip_header = IPHeader(data[offset:])
                        packet_info["parsed"]["ip"] = {
                            "version": ip_header.version,
                            "ihl": ip_header.ihl,
                            "tos": ip_header.tos,
                            "total_length": ip_header.total_length,
                            "identification": ip_header.identification,
                            "flags": ip_header.flags,
                            "fragment_offset": ip_header.fragment_offset,
                            "ttl": ip_header.ttl,
                            "protocol": ip_header.protocol,
                            "checksum": f"0x{ip_header.checksum:04x}",
                            "src_ip": self.ip_to_string(ip_header.src_ip),
                            "dst_ip": self.ip_to_string(ip_header.dst_ip),
                            "header_length": ip_header.header_length,
                            "options": ip_header.options.hex() if ip_header.options else ""
                        }
                        offset += ip_header.header_length
                        
                        # Check if it's TCP packet
                        if ip_header.protocol == 6:  # TCP
                            if len(data) >= offset + 20:
                                tcp_header = TCPHeader(data[offset:])
                                packet_info["parsed"]["tcp"] = {
                                    "src_port": tcp_header.src_port,
                                    "dst_port": tcp_header.dst_port,
                                    "seq_number": tcp_header.seq_number,
                                    "ack_number": tcp_header.ack_number,
                                    "data_offset": tcp_header.data_offset,
                                    "flags": f"0x{tcp_header.flags:02x}",
                                    "window_size": tcp_header.window_size,
                                    "checksum": f"0x{tcp_header.checksum:04x}",
                                    "urgent_pointer": tcp_header.urgent_pointer,
                                    "header_length": tcp_header.header_length,
                                    "options": tcp_header.options.hex() if tcp_header.options else ""
                                }
            
            return packet_info
            
        except Exception as e:
            print(f"Error parsing packet {index}: {e}")
            return None
    
    def ip_to_string(self, ip_bytes: bytes) -> str:
        """Convert IP bytes to string"""
        return ".".join(str(b) for b in ip_bytes)
    
    def find_matching_packets(self, zapret_packets: List[Dict], recon_packets: List[Dict]) -> List[Tuple[Dict, Dict]]:
        """Find matching packets between zapret and recon"""
        matches = []
        
        # Simple matching by destination IP and port
        for zapret_pkt in zapret_packets[:10]:  # Analyze first 10 packets
            if "ip" in zapret_pkt["parsed"] and "tcp" in zapret_pkt["parsed"]:
                zapret_dst = zapret_pkt["parsed"]["ip"]["dst_ip"]
                zapret_dport = zapret_pkt["parsed"]["tcp"]["dst_port"]
                
                for recon_pkt in recon_packets:
                    if "ip" in recon_pkt["parsed"] and "tcp" in recon_pkt["parsed"]:
                        recon_dst = recon_pkt["parsed"]["ip"]["dst_ip"]
                        recon_dport = recon_pkt["parsed"]["tcp"]["dst_port"]
                        
                        if zapret_dst == recon_dst and zapret_dport == recon_dport:
                            matches.append((zapret_pkt, recon_pkt))
                            break
        
        return matches
    
    def compare_packet_headers(self, zapret_pkt: Dict, recon_pkt: Dict) -> Dict:
        """Compare packet headers byte by byte"""
        comparison = {
            "packet_indices": {
                "zapret": zapret_pkt["index"],
                "recon": recon_pkt["index"]
            },
            "ip_differences": [],
            "tcp_differences": [],
            "raw_hex_comparison": {}
        }
        
        # Compare IP headers
        if "ip" in zapret_pkt["parsed"] and "ip" in recon_pkt["parsed"]:
            zapret_ip = zapret_pkt["parsed"]["ip"]
            recon_ip = recon_pkt["parsed"]["ip"]
            
            ip_fields = ["version", "ihl", "tos", "total_length", "identification", 
                        "flags", "fragment_offset", "ttl", "protocol", "checksum"]
            
            for field in ip_fields:
                if zapret_ip.get(field) != recon_ip.get(field):
                    comparison["ip_differences"].append({
                        "field": field,
                        "zapret": zapret_ip.get(field),
                        "recon": recon_ip.get(field)
                    })
        
        # Compare TCP headers
        if "tcp" in zapret_pkt["parsed"] and "tcp" in recon_pkt["parsed"]:
            zapret_tcp = zapret_pkt["parsed"]["tcp"]
            recon_tcp = recon_pkt["parsed"]["tcp"]
            
            tcp_fields = ["src_port", "dst_port", "seq_number", "ack_number", 
                         "data_offset", "flags", "window_size", "checksum", "urgent_pointer"]
            
            for field in tcp_fields:
                if zapret_tcp.get(field) != recon_tcp.get(field):
                    comparison["tcp_differences"].append({
                        "field": field,
                        "zapret": zapret_tcp.get(field),
                        "recon": recon_tcp.get(field)
                    })
        
        # Raw hex comparison (first 100 bytes)
        zapret_hex = zapret_pkt["raw_data"][:200]  # First 100 bytes in hex
        recon_hex = recon_pkt["raw_data"][:200]
        
        comparison["raw_hex_comparison"] = {
            "zapret": zapret_hex,
            "recon": recon_hex,
            "identical": zapret_hex == recon_hex
        }
        
        return comparison
    
    def analyze_tcp_options_detailed(self, zapret_pkt: Dict, recon_pkt: Dict) -> Dict:
        """Detailed TCP options analysis"""
        analysis = {
            "zapret_options": "",
            "recon_options": "",
            "options_identical": False,
            "parsed_options": {
                "zapret": [],
                "recon": []
            }
        }
        
        if "tcp" in zapret_pkt["parsed"]:
            analysis["zapret_options"] = zapret_pkt["parsed"]["tcp"].get("options", "")
        
        if "tcp" in recon_pkt["parsed"]:
            analysis["recon_options"] = recon_pkt["parsed"]["tcp"].get("options", "")
        
        analysis["options_identical"] = analysis["zapret_options"] == analysis["recon_options"]
        
        # Parse TCP options
        for pkt_type, options_hex in [("zapret", analysis["zapret_options"]), 
                                     ("recon", analysis["recon_options"])]:
            if options_hex:
                try:
                    options_bytes = bytes.fromhex(options_hex)
                    parsed = self.parse_tcp_options(options_bytes)
                    analysis["parsed_options"][pkt_type] = parsed
                except Exception as e:
                    analysis["parsed_options"][pkt_type] = [f"Parse error: {e}"]
        
        return analysis
    
    def parse_tcp_options(self, options_data: bytes) -> List[Dict]:
        """Parse TCP options from raw bytes"""
        options = []
        offset = 0
        
        while offset < len(options_data):
            if offset >= len(options_data):
                break
            
            option_type = options_data[offset]
            
            if option_type == 0:  # End of options
                options.append({"type": 0, "name": "End of Options"})
                break
            elif option_type == 1:  # NOP
                options.append({"type": 1, "name": "NOP"})
                offset += 1
            else:
                if offset + 1 >= len(options_data):
                    break
                
                option_length = options_data[offset + 1]
                if option_length < 2 or offset + option_length > len(options_data):
                    break
                
                option_data = options_data[offset + 2:offset + option_length]
                
                option_info = {
                    "type": option_type,
                    "length": option_length,
                    "data": option_data.hex()
                }
                
                # Decode common options
                if option_type == 2:  # MSS
                    option_info["name"] = "Maximum Segment Size"
                    if len(option_data) >= 2:
                        option_info["mss"] = struct.unpack('>H', option_data[:2])[0]
                elif option_type == 3:  # Window Scale
                    option_info["name"] = "Window Scale"
                    if len(option_data) >= 1:
                        option_info["scale"] = option_data[0]
                elif option_type == 4:  # SACK Permitted
                    option_info["name"] = "SACK Permitted"
                elif option_type == 8:  # Timestamps
                    option_info["name"] = "Timestamps"
                    if len(option_data) >= 8:
                        ts_val, ts_ecr = struct.unpack('>LL', option_data[:8])
                        option_info["timestamp_value"] = ts_val
                        option_info["timestamp_echo_reply"] = ts_ecr
                else:
                    option_info["name"] = f"Unknown Option {option_type}"
                
                options.append(option_info)
                offset += option_length
        
        return options
    
    def perform_analysis(self) -> Dict:
        """Perform comprehensive hex-level analysis"""
        print("=== Hex-level PCAP Analysis ===")
        
        if not os.path.exists(self.zapret_pcap):
            print(f"Error: {self.zapret_pcap} not found")
            return self.analysis_results
        
        if not os.path.exists(self.recon_pcap):
            print(f"Error: {self.recon_pcap} not found")
            return self.analysis_results
        
        # Read PCAP files
        print(f"Reading {self.zapret_pcap}...")
        zapret_packets = self.read_pcap_file(self.zapret_pcap)
        print(f"Loaded {len(zapret_packets)} packets from zapret.pcap")
        
        print(f"Reading {self.recon_pcap}...")
        recon_packets = self.read_pcap_file(self.recon_pcap)
        print(f"Loaded {len(recon_packets)} packets from out2.pcap")
        
        if not zapret_packets or not recon_packets:
            print("Error: Could not load packets from one or both files")
            return self.analysis_results
        
        # Find matching packets
        print("Finding matching packets...")
        matches = self.find_matching_packets(zapret_packets, recon_packets)
        print(f"Found {len(matches)} matching packet pairs")
        
        if not matches:
            print("No matching packets found!")
            return self.analysis_results
        
        # Analyze first few matches
        analysis_results = []
        for i, (zapret_pkt, recon_pkt) in enumerate(matches[:4]):  # First 4 matches
            print(f"Analyzing packet pair {i+1}...")
            
            # Header comparison
            header_comparison = self.compare_packet_headers(zapret_pkt, recon_pkt)
            
            # TCP options analysis
            options_analysis = self.analyze_tcp_options_detailed(zapret_pkt, recon_pkt)
            
            packet_analysis = {
                "pair_index": i + 1,
                "header_comparison": header_comparison,
                "tcp_options_analysis": options_analysis
            }
            
            analysis_results.append(packet_analysis)
            
            # Export raw packet data for manual hex inspection
            with open(f"zapret_packet_{i+1}_raw.hex", 'w') as f:
                f.write(zapret_pkt["raw_data"])
            
            with open(f"recon_packet_{i+1}_raw.hex", 'w') as f:
                f.write(recon_pkt["raw_data"])
        
        self.analysis_results["analysis"]["packet_comparisons"] = analysis_results
        self.analysis_results["analysis"]["total_matches"] = len(matches)
        
        return self.analysis_results
    
    def generate_report(self) -> str:
        """Generate detailed hex analysis report"""
        report = []
        report.append("=" * 80)
        report.append("HEX-LEVEL PCAP ANALYSIS REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {self.analysis_results['timestamp']}")
        report.append(f"Zapret PCAP: {self.analysis_results['files']['zapret']}")
        report.append(f"Recon PCAP: {self.analysis_results['files']['recon']}")
        report.append("")
        
        if "packet_comparisons" not in self.analysis_results["analysis"]:
            report.append("ERROR: No packet analysis available")
            return "\n".join(report)
        
        comparisons = self.analysis_results["analysis"]["packet_comparisons"]
        total_matches = self.analysis_results["analysis"]["total_matches"]
        
        report.append(f"Total matching packets found: {total_matches}")
        report.append(f"Analyzed packet pairs: {len(comparisons)}")
        report.append("")
        
        # Analyze each packet pair
        for comparison in comparisons:
            pair_idx = comparison["pair_index"]
            header_comp = comparison["header_comparison"]
            options_comp = comparison["tcp_options_analysis"]
            
            report.append(f"PACKET PAIR {pair_idx}:")
            report.append("-" * 40)
            report.append(f"Zapret packet index: {header_comp['packet_indices']['zapret']}")
            report.append(f"Recon packet index: {header_comp['packet_indices']['recon']}")
            report.append("")
            
            # IP header differences
            if header_comp["ip_differences"]:
                report.append("IP Header Differences:")
                for diff in header_comp["ip_differences"]:
                    report.append(f"  {diff['field']}: zapret={diff['zapret']}, recon={diff['recon']}")
            else:
                report.append("IP Headers: IDENTICAL")
            report.append("")
            
            # TCP header differences
            if header_comp["tcp_differences"]:
                report.append("TCP Header Differences:")
                for diff in header_comp["tcp_differences"]:
                    report.append(f"  {diff['field']}: zapret={diff['zapret']}, recon={diff['recon']}")
            else:
                report.append("TCP Headers: IDENTICAL")
            report.append("")
            
            # TCP options
            if options_comp["options_identical"]:
                report.append("TCP Options: IDENTICAL")
            else:
                report.append("TCP Options: DIFFERENT")
                report.append(f"  Zapret options: {options_comp['zapret_options']}")
                report.append(f"  Recon options: {options_comp['recon_options']}")
            report.append("")
            
            # Raw hex comparison
            if header_comp["raw_hex_comparison"]["identical"]:
                report.append("Raw packet data: IDENTICAL")
            else:
                report.append("Raw packet data: DIFFERENT")
                report.append("  (See exported .hex files for detailed comparison)")
            report.append("")
        
        # Summary
        report.append("SUMMARY:")
        report.append("-" * 40)
        
        total_ip_diffs = sum(len(comp["header_comparison"]["ip_differences"]) for comp in comparisons)
        total_tcp_diffs = sum(len(comp["header_comparison"]["tcp_differences"]) for comp in comparisons)
        options_identical_count = sum(1 for comp in comparisons if comp["tcp_options_analysis"]["options_identical"])
        
        report.append(f"Total IP header differences: {total_ip_diffs}")
        report.append(f"Total TCP header differences: {total_tcp_diffs}")
        report.append(f"Packets with identical TCP options: {options_identical_count}/{len(comparisons)}")
        
        if total_ip_diffs == 0 and total_tcp_diffs == 0:
            report.append("✓ All analyzed packets have identical headers")
        else:
            report.append("✗ Header differences detected")
        
        return "\n".join(report)

def main():
    """Main function"""
    analyzer = HexPcapAnalyzer()
    
    # Perform analysis
    results = analyzer.perform_analysis()
    
    # Generate report
    report = analyzer.generate_report()
    print("\n" + report)
    
    # Save results
    with open("hex_pcap_analysis_results.json", 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    with open("hex_pcap_analysis_report.txt", 'w', encoding='utf-8') as f:
        f.write(report)
    
    print("\nResults saved to hex_pcap_analysis_results.json")
    print("Report saved to hex_pcap_analysis_report.txt")

if __name__ == "__main__":
    main()