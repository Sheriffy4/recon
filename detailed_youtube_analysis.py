#!/usr/bin/env python3
"""
Detailed YouTube Connection Analysis

Analyzes every packet in the YouTube flow to understand why connection fails.
"""

import sys
from pathlib import Path

try:
    from scapy.all import rdpcap, TCP, IP, IPv6, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def analyze_packet_details(pcap_file: str):
    """Detailed packet-by-packet analysis."""
    
    if not SCAPY_AVAILABLE:
        print("❌ Error: Scapy required")
        return
    
    print("=" * 80)
    print("Detailed YouTube Connection Analysis")
    print("=" * 80)
    print()
    
    packets = rdpcap(pcap_file)
    
    # Find YouTube flow
    youtube_ip = "142.250.74.54"
    youtube_packets = []
    
    for i, pkt in enumerate(packets):
        if not pkt.haslayer(TCP):
            continue
        
        ip = pkt[IP] if IP in pkt else (pkt[IPv6] if IPv6 in pkt else None)
        if not ip:
            continue
        
        if ip.dst == youtube_ip or ip.src == youtube_ip:
            youtube_packets.append((i, pkt))
    
    print(f"📦 Found {len(youtube_packets)} packets to/from {youtube_ip}")
    print()
    
    if not youtube_packets:
        print("❌ No YouTube packets found!")
        return
    
    print("📊 Packet-by-Packet Analysis:")
    print()
    
    for idx, (pkt_num, pkt) in enumerate(youtube_packets[:50]):  # First 50 packets
        ip = pkt[IP] if IP in pkt else pkt[IPv6]
        tcp = pkt[TCP]
        
        # Direction
        direction = "→" if ip.dst == youtube_ip else "←"
        
        # Flags
        flags = []
        if tcp.flags & 0x01: flags.append("FIN")
        if tcp.flags & 0x02: flags.append("SYN")
        if tcp.flags & 0x04: flags.append("RST")
        if tcp.flags & 0x08: flags.append("PSH")
        if tcp.flags & 0x10: flags.append("ACK")
        if tcp.flags & 0x20: flags.append("URG")
        flags_str = "|".join(flags) if flags else "NONE"
        
        # Payload
        payload_len = len(pkt[Raw]) if pkt.haslayer(Raw) else 0
        
        # Sequence and ACK
        seq = tcp.seq
        ack = tcp.ack
        
        print(f"Packet {pkt_num:3d} {direction} "
              f"Flags: {flags_str:15s} "
              f"Seq: 0x{seq:08X} "
              f"Ack: 0x{ack:08X} "
              f"Len: {payload_len:4d}")
        
        # Special analysis for first few packets
        if idx < 10:
            if "SYN" in flags and "ACK" not in flags:
                print(f"         ⚠️  SYN packet (initiating connection)")
            elif "SYN" in flags and "ACK" in flags:
                print(f"         ✅ SYN-ACK packet (server accepting connection)")
            elif "ACK" in flags and payload_len == 0 and idx < 5:
                print(f"         ✅ ACK packet (completing handshake)")
            elif payload_len > 0:
                # Check if TLS ClientHello
                if pkt.haslayer(Raw):
                    payload = bytes(pkt[Raw])
                    if len(payload) > 5 and payload[0] == 0x16 and payload[1] == 0x03:
                        print(f"         📜 TLS ClientHello detected!")
                    else:
                        print(f"         📦 Data packet")
    
    print()
    print("=" * 80)
    print("🔍 Analysis Summary:")
    print("=" * 80)
    print()
    
    # Count packet types
    syn_out = 0
    syn_ack_in = 0
    ack_out = 0
    data_out = 0
    data_in = 0
    rst_any = 0
    
    for _, pkt in youtube_packets:
        ip = pkt[IP] if IP in pkt else pkt[IPv6]
        tcp = pkt[TCP]
        
        is_outbound = (ip.dst == youtube_ip)
        
        if tcp.flags & 0x02 and not (tcp.flags & 0x10):  # SYN without ACK
            if is_outbound:
                syn_out += 1
        elif tcp.flags == 0x12:  # SYN-ACK
            if not is_outbound:
                syn_ack_in += 1
        elif tcp.flags & 0x04:  # RST
            rst_any += 1
        elif tcp.flags & 0x10:  # ACK
            if is_outbound:
                ack_out += 1
        
        if pkt.haslayer(Raw) and len(pkt[Raw]) > 0:
            if is_outbound:
                data_out += 1
            else:
                data_in += 1
    
    print(f"Outbound SYN: {syn_out}")
    print(f"Inbound SYN-ACK: {syn_ack_in}")
    print(f"Outbound ACK: {ack_out}")
    print(f"Outbound data packets: {data_out}")
    print(f"Inbound data packets: {data_in}")
    print(f"RST packets: {rst_any}")
    print()
    
    # Diagnosis
    if syn_out > 0 and syn_ack_in == 0:
        print("❌ CRITICAL ISSUE: SYN sent but no SYN-ACK received")
        print()
        print("This means:")
        print("  1. Server never received the SYN packet, OR")
        print("  2. Server sent SYN-ACK but it was blocked/lost, OR")
        print("  3. Bypass engine is blocking SYN packets")
        print()
        print("Most likely cause:")
        print("  → Bypass engine is intercepting and blocking SYN packets")
        print("  → SYN packets should NOT be processed by bypass!")
        print("  → Bypass should ONLY process TLS ClientHello packets")
        print()
        print("Solution:")
        print("  1. Check WinDivert filter - should only capture packets with payload")
        print("  2. Check _is_tls_clienthello() - should reject SYN packets")
        print("  3. Add explicit check: if packet.payload is None or len(packet.payload) == 0: w.send(packet)")
    elif syn_ack_in > 0 and data_out == 0:
        print("⚠️  ISSUE: Handshake completed but no data sent")
        print("  → Connection established but TLS handshake not initiated")
    elif data_out > 0 and data_in == 0:
        print("⚠️  ISSUE: Data sent but no response")
        print("  → Server not responding to ClientHello")
    else:
        print("✅ Connection appears normal")


def main():
    if len(sys.argv) < 2:
        print("Usage: python detailed_youtube_analysis.py <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    if not Path(pcap_file).exists():
        print(f"❌ Error: File not found: {pcap_file}")
        sys.exit(1)
    
    analyze_packet_details(pcap_file)


if __name__ == "__main__":
    main()
