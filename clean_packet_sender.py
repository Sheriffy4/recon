#!/usr/bin/env python3
"""
Clean Packet Sender
Эксперимент с "чистой" отправкой пакетов

This tool extracts a packet from zapret.pcap and sends it exactly as-is
to test if our raw socket mechanism works correctly.
"""

import sys
import os
import socket
import struct
import time
from typing import Optional, Dict, Any
import json
from datetime import datetime

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP
    from scapy.utils import rdpcap
    SCAPY_AVAILABLE = True
except ImportError:
    print("Warning: Scapy not available. Limited functionality.")
    SCAPY_AVAILABLE = False

try:
    import windivert
    WINDIVERT_AVAILABLE = True
except ImportError:
    print("Warning: WinDivert not available. Will try raw sockets.")
    WINDIVERT_AVAILABLE = False

class CleanPacketSender:
    """Tool for sending exact packet copies from PCAP files"""
    
    def __init__(self, pcap_file: str = "zapret.pcap"):
        self.pcap_file = pcap_file
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "pcap_file": pcap_file,
            "experiments": []
        }
    
    def extract_first_fake_packet(self) -> Optional[bytes]:
        """Extract the first fake packet from zapret.pcap"""
        if not SCAPY_AVAILABLE:
            print("Scapy not available - cannot extract packets")
            return None
        
        try:
            print(f"Loading {self.pcap_file}...")
            packets = rdpcap(self.pcap_file)
            print(f"Loaded {len(packets)} packets")
            
            # Look for the first outgoing packet with low TTL (likely fake)
            for i, pkt in enumerate(packets):
                if IP in pkt and TCP in pkt:
                    # Check if this looks like a fake packet (low TTL)
                    if pkt[IP].ttl <= 10:  # Fake packets usually have low TTL
                        print(f"Found potential fake packet at index {i}:")
                        print(f"  TTL: {pkt[IP].ttl}")
                        print(f"  Src: {pkt[IP].src}:{pkt[TCP].sport}")
                        print(f"  Dst: {pkt[IP].dst}:{pkt[TCP].dport}")
                        print(f"  Seq: {pkt[TCP].seq}")
                        print(f"  Flags: {pkt[TCP].flags}")
                        print(f"  Length: {len(pkt)}")
                        
                        # Return raw packet bytes
                        return bytes(pkt)
            
            # If no low TTL packet found, return first TCP packet
            for i, pkt in enumerate(packets):
                if IP in pkt and TCP in pkt:
                    print(f"Using first TCP packet at index {i} (no low TTL found)")
                    print(f"  TTL: {pkt[IP].ttl}")
                    print(f"  Src: {pkt[IP].src}:{pkt[TCP].sport}")
                    print(f"  Dst: {pkt[IP].dst}:{pkt[TCP].dport}")
                    return bytes(pkt)
            
            print("No suitable packets found")
            return None
            
        except Exception as e:
            print(f"Error extracting packet: {e}")
            return None
    
    def analyze_packet_structure(self, packet_bytes: bytes) -> Dict:
        """Analyze the structure of the packet"""
        analysis = {
            "total_length": len(packet_bytes),
            "hex_dump": packet_bytes.hex(),
            "layers": []
        }
        
        if not SCAPY_AVAILABLE:
            return analysis
        
        try:
            # Parse with Scapy
            pkt = Ether(packet_bytes)
            
            # Analyze each layer
            layer = pkt
            while layer:
                layer_info = {
                    "name": layer.__class__.__name__,
                    "fields": {}
                }
                
                # Extract key fields
                if hasattr(layer, 'fields_desc'):
                    for field_desc in layer.fields_desc:
                        field_name = field_desc.name
                        if hasattr(layer, field_name):
                            field_value = getattr(layer, field_name)
                            layer_info["fields"][field_name] = str(field_value)
                
                analysis["layers"].append(layer_info)
                layer = layer.payload if hasattr(layer, 'payload') else None
            
        except Exception as e:
            analysis["parse_error"] = str(e)
        
        return analysis
    
    def send_packet_raw_socket(self, packet_bytes: bytes, target_ip: str) -> Dict:
        """Send packet using raw socket"""
        result = {
            "method": "raw_socket",
            "success": False,
            "error": None,
            "bytes_sent": 0
        }
        
        try:
            # Create raw socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            # Extract IP layer (skip Ethernet header if present)
            ip_packet = packet_bytes
            if len(packet_bytes) > 20:
                # Check if this starts with Ethernet header
                if packet_bytes[12:14] == b'\x08\x00':  # IPv4 EtherType
                    ip_packet = packet_bytes[14:]  # Skip Ethernet header
            
            # Send packet
            bytes_sent = sock.sendto(ip_packet, (target_ip, 0))
            sock.close()
            
            result["success"] = True
            result["bytes_sent"] = bytes_sent
            print(f"Successfully sent {bytes_sent} bytes via raw socket")
            
        except Exception as e:
            result["error"] = str(e)
            print(f"Raw socket send failed: {e}")
        
        return result
    
    def send_packet_windivert(self, packet_bytes: bytes) -> Dict:
        """Send packet using WinDivert"""
        result = {
            "method": "windivert",
            "success": False,
            "error": None,
            "bytes_sent": 0
        }
        
        if not WINDIVERT_AVAILABLE:
            result["error"] = "WinDivert not available"
            return result
        
        try:
            # Open WinDivert handle
            handle = windivert.WinDivert("false")  # Don't capture anything, just inject
            
            # Extract IP layer
            ip_packet = packet_bytes
            if len(packet_bytes) > 20 and packet_bytes[12:14] == b'\x08\x00':
                ip_packet = packet_bytes[14:]  # Skip Ethernet header
            
            # Send packet
            handle.send(ip_packet)
            handle.close()
            
            result["success"] = True
            result["bytes_sent"] = len(ip_packet)
            print(f"Successfully sent {len(ip_packet)} bytes via WinDivert")
            
        except Exception as e:
            result["error"] = str(e)
            print(f"WinDivert send failed: {e}")
        
        return result
    
    def monitor_responses(self, target_ip: str, duration: float = 5.0) -> Dict:
        """Monitor for responses after sending packet"""
        responses = {
            "duration": duration,
            "packets_captured": 0,
            "rst_packets": 0,
            "other_packets": 0,
            "details": []
        }
        
        if not SCAPY_AVAILABLE:
            responses["error"] = "Scapy not available for monitoring"
            return responses
        
        try:
            print(f"Monitoring responses from {target_ip} for {duration} seconds...")
            
            # Capture packets
            filter_str = f"host {target_ip}"
            packets = sniff(filter=filter_str, timeout=duration, count=10)
            
            responses["packets_captured"] = len(packets)
            
            for pkt in packets:
                pkt_info = {
                    "timestamp": float(pkt.time),
                    "summary": str(pkt.summary())
                }
                
                if TCP in pkt:
                    pkt_info["tcp_flags"] = pkt[TCP].flags
                    if pkt[TCP].flags & 0x04:  # RST flag
                        responses["rst_packets"] += 1
                        pkt_info["type"] = "RST"
                    else:
                        responses["other_packets"] += 1
                        pkt_info["type"] = "OTHER"
                
                responses["details"].append(pkt_info)
            
            print(f"Captured {responses['packets_captured']} packets")
            print(f"RST packets: {responses['rst_packets']}")
            print(f"Other packets: {responses['other_packets']}")
            
        except Exception as e:
            responses["error"] = str(e)
            print(f"Monitoring failed: {e}")
        
        return responses
    
    def perform_clean_send_experiment(self) -> Dict:
        """Perform the clean packet sending experiment"""
        print("=== Clean Packet Sending Experiment ===")
        
        if not os.path.exists(self.pcap_file):
            print(f"Error: {self.pcap_file} not found")
            return {"error": f"PCAP file {self.pcap_file} not found"}
        
        # Extract packet
        print("Extracting packet from PCAP...")
        packet_bytes = self.extract_first_fake_packet()
        if not packet_bytes:
            return {"error": "Could not extract packet from PCAP"}
        
        # Analyze packet structure
        print("Analyzing packet structure...")
        packet_analysis = self.analyze_packet_structure(packet_bytes)
        
        # Extract target IP
        target_ip = None
        if SCAPY_AVAILABLE:
            try:
                pkt = Ether(packet_bytes)
                if IP in pkt:
                    target_ip = pkt[IP].dst
                    print(f"Target IP: {target_ip}")
            except:
                pass
        
        if not target_ip:
            print("Could not determine target IP")
            return {"error": "Could not determine target IP"}
        
        experiment_result = {
            "packet_analysis": packet_analysis,
            "target_ip": target_ip,
            "send_attempts": []
        }
        
        # Try different sending methods
        print("\n--- Attempting Raw Socket Send ---")
        raw_result = self.send_packet_raw_socket(packet_bytes, target_ip)
        experiment_result["send_attempts"].append(raw_result)
        
        if WINDIVERT_AVAILABLE:
            print("\n--- Attempting WinDivert Send ---")
            windivert_result = self.send_packet_windivert(packet_bytes)
            experiment_result["send_attempts"].append(windivert_result)
        
        # Monitor for responses if any send was successful
        successful_sends = [r for r in experiment_result["send_attempts"] if r["success"]]
        if successful_sends:
            print("\n--- Monitoring for Responses ---")
            responses = self.monitor_responses(target_ip)
            experiment_result["responses"] = responses
        else:
            print("No successful sends - skipping response monitoring")
        
        return experiment_result
    
    def save_packet_to_file(self, packet_bytes: bytes, filename: str = "extracted_packet.bin"):
        """Save extracted packet to binary file"""
        try:
            with open(filename, 'wb') as f:
                f.write(packet_bytes)
            print(f"Packet saved to {filename}")
        except Exception as e:
            print(f"Error saving packet: {e}")
    
    def generate_report(self, experiment_result: Dict) -> str:
        """Generate experiment report"""
        report = []
        report.append("=" * 80)
        report.append("CLEAN PACKET SENDING EXPERIMENT REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {self.results['timestamp']}")
        report.append(f"PCAP File: {self.pcap_file}")
        report.append("")
        
        if "error" in experiment_result:
            report.append(f"EXPERIMENT FAILED: {experiment_result['error']}")
            return "\n".join(report)
        
        # Packet analysis
        packet_analysis = experiment_result["packet_analysis"]
        report.append("EXTRACTED PACKET ANALYSIS:")
        report.append("-" * 40)
        report.append(f"Total length: {packet_analysis['total_length']} bytes")
        report.append(f"Target IP: {experiment_result['target_ip']}")
        
        if "layers" in packet_analysis:
            report.append("Packet layers:")
            for layer in packet_analysis["layers"]:
                report.append(f"  - {layer['name']}")
        report.append("")
        
        # Send attempts
        report.append("SEND ATTEMPTS:")
        report.append("-" * 40)
        for attempt in experiment_result["send_attempts"]:
            method = attempt["method"]
            success = "SUCCESS" if attempt["success"] else "FAILED"
            report.append(f"{method}: {success}")
            if attempt["success"]:
                report.append(f"  Bytes sent: {attempt['bytes_sent']}")
            else:
                report.append(f"  Error: {attempt['error']}")
        report.append("")
        
        # Response monitoring
        if "responses" in experiment_result:
            responses = experiment_result["responses"]
            report.append("RESPONSE MONITORING:")
            report.append("-" * 40)
            report.append(f"Duration: {responses['duration']} seconds")
            report.append(f"Packets captured: {responses['packets_captured']}")
            report.append(f"RST packets: {responses['rst_packets']}")
            report.append(f"Other packets: {responses['other_packets']}")
            
            if responses["rst_packets"] > 0:
                report.append("⚠ RST packets detected - server rejected the packet")
            elif responses["packets_captured"] > 0:
                report.append("✓ Server responded (no RST)")
            else:
                report.append("? No response detected")
            report.append("")
        
        # Conclusions
        report.append("CONCLUSIONS:")
        report.append("-" * 40)
        
        successful_methods = [a["method"] for a in experiment_result["send_attempts"] if a["success"]]
        if successful_methods:
            report.append(f"✓ Packet sending works via: {', '.join(successful_methods)}")
        else:
            report.append("✗ All packet sending methods failed")
        
        if "responses" in experiment_result:
            if experiment_result["responses"]["rst_packets"] > 0:
                report.append("✗ Server rejected the packet (RST response)")
            elif experiment_result["responses"]["packets_captured"] > 0:
                report.append("✓ Server accepted the packet (no RST)")
            else:
                report.append("? No server response (packet may have been dropped)")
        
        return "\n".join(report)

def main():
    """Main function"""
    pcap_file = "zapret.pcap"
    if len(sys.argv) > 1:
        pcap_file = sys.argv[1]
    
    sender = CleanPacketSender(pcap_file)
    
    # Perform experiment
    result = sender.perform_clean_send_experiment()
    
    # Save extracted packet
    if "packet_analysis" in result:
        packet_bytes = bytes.fromhex(result["packet_analysis"]["hex_dump"])
        sender.save_packet_to_file(packet_bytes)
    
    # Generate report
    report = sender.generate_report(result)
    print("\n" + report)
    
    # Save results
    sender.results["experiments"].append(result)
    
    with open("clean_packet_experiment_results.json", 'w', encoding='utf-8') as f:
        json.dump(sender.results, f, indent=2, ensure_ascii=False)
    
    with open("clean_packet_experiment_report.txt", 'w', encoding='utf-8') as f:
        f.write(report)
    
    print("\nResults saved to clean_packet_experiment_results.json")
    print("Report saved to clean_packet_experiment_report.txt")

if __name__ == "__main__":
    main()