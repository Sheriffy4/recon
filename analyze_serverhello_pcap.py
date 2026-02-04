#!/usr/bin/env python3
"""Analyze PCAP to understand why ServerHello detector doesn't see packets."""

import sys

try:
    from scapy.all import rdpcap, IP, TCP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

if not SCAPY_AVAILABLE:
    print("❌ Scapy not available, trying pyshark...")
    try:
        import pyshark
        PYSHARK_AVAILABLE = True
    except ImportError:
        print("❌ Neither scapy nor pyshark available")
        sys.exit(1)
else:
    PYSHARK_AVAILABLE = False


def analyze_with_scapy(pcap_file):
    """Analyze PCAP with scapy."""
    print(f"📂 Reading {pcap_file} with scapy...")
    pkts = rdpcap(pcap_file)
    print(f"✅ Loaded {len(pkts)} packets\n")
    
    # Find ServerHello packets
    server_ip = "142.250.74.132"
    serverhello_packets = []
    
    for i, pkt in enumerate(pkts):
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            continue
            
        if pkt[IP].src == server_ip:
            payload_len = len(pkt[TCP].payload) if pkt.haslayer(Raw) else 0
            
            # Check if it looks like TLS ServerHello
            is_serverhello = False
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
                # TLS Handshake (0x16) + version (0x03 0x??) + ServerHello (0x02)
                if len(payload) >= 6:
                    if payload[0] == 0x16 and payload[1] == 0x03 and payload[5] == 0x02:
                        is_serverhello = True
            
            info = {
                'index': i,
                'src': f"{pkt[IP].src}:{pkt[TCP].sport}",
                'dst': f"{pkt[IP].dst}:{pkt[TCP].dport}",
                'payload_len': payload_len,
                'is_serverhello': is_serverhello,
                'flags': pkt[TCP].flags,
                'seq': pkt[TCP].seq,
                'ack': pkt[TCP].ack
            }
            
            if is_serverhello:
                serverhello_packets.append(info)
                print(f"🎯 SERVERHELLO FOUND:")
                print(f"   Packet #{i}")
                print(f"   {info['src']} -> {info['dst']}")
                print(f"   Payload: {payload_len} bytes")
                print(f"   Flags: {info['flags']}")
                print(f"   Seq: {info['seq']}, Ack: {info['ack']}")
                print()
    
    print(f"\n📊 Summary:")
    print(f"   Total packets: {len(pkts)}")
    print(f"   ServerHello packets found: {len(serverhello_packets)}")
    
    if serverhello_packets:
        print(f"\n🔍 ServerHello Details:")
        for sh in serverhello_packets:
            print(f"   Packet #{sh['index']}: {sh['src']} -> {sh['dst']}, {sh['payload_len']} bytes")
    
    return serverhello_packets


def main():
    pcap_file = "serv.pcap"
    
    if SCAPY_AVAILABLE:
        analyze_with_scapy(pcap_file)
    else:
        print("❌ No packet analysis library available")
        sys.exit(1)


if __name__ == "__main__":
    main()
