#!/usr/bin/env python3
"""
Simple PCAP Verification Tool
Упрощенная верификация PCAP для быстрого анализа
"""

import sys

try:
    from scapy.all import rdpcap, wrpcap, Ether, Raw
    from scapy.layers.inet import IP, TCP
    from scapy.utils import rdpcap

    SCAPY_AVAILABLE = True
except ImportError:
    print("Error: Scapy not available")
    sys.exit(1)


def analyze_pcap_basic(filename):
    """Basic PCAP analysis"""
    print(f"\n=== Analyzing {filename} ===")

    try:
        packets = rdpcap(filename)
        print(f"Total packets: {len(packets)}")

        tcp_packets = [pkt for pkt in packets if TCP in pkt]
        print(f"TCP packets: {len(tcp_packets)}")

        # Analyze first few TCP packets
        print("\nFirst 5 TCP packets:")
        for i, pkt in enumerate(tcp_packets[:5]):
            if IP in pkt:
                print(
                    f"  Packet {i+1}: {pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport}"
                )
                print(
                    f"    TTL: {pkt[IP].ttl}, Seq: {pkt[TCP].seq}, Flags: {pkt[TCP].flags}"
                )
                if hasattr(pkt[TCP], "options") and pkt[TCP].options:
                    print(f"    TCP Options: {pkt[TCP].options}")

        return tcp_packets

    except Exception as e:
        print(f"Error analyzing {filename}: {e}")
        return []


def compare_packets(zapret_pkt, recon_pkt, pair_num):
    """Compare two packets"""
    print(f"\n--- Comparing Packet Pair {pair_num} ---")

    if IP not in zapret_pkt or IP not in recon_pkt:
        print("Missing IP layer in one packet")
        return

    if TCP not in zapret_pkt or TCP not in recon_pkt:
        print("Missing TCP layer in one packet")
        return

    # IP comparison
    zapret_ip = zapret_pkt[IP]
    recon_ip = recon_pkt[IP]

    print("IP Header Comparison:")
    ip_fields = ["ttl", "id", "flags", "tos"]
    for field in ip_fields:
        z_val = getattr(zapret_ip, field)
        r_val = getattr(recon_ip, field)
        match = "✓" if z_val == r_val else "✗"
        print(f"  {field}: zapret={z_val}, recon={r_val} {match}")

    # TCP comparison
    zapret_tcp = zapret_pkt[TCP]
    recon_tcp = recon_pkt[TCP]

    print("TCP Header Comparison:")
    tcp_fields = ["seq", "ack", "flags", "window", "urgptr"]
    for field in tcp_fields:
        z_val = getattr(zapret_tcp, field)
        r_val = getattr(recon_tcp, field)
        match = "✓" if z_val == r_val else "✗"
        print(f"  {field}: zapret={z_val}, recon={r_val} {match}")

    # TCP Options comparison
    z_opts = getattr(zapret_tcp, "options", [])
    r_opts = getattr(recon_tcp, "options", [])
    opts_match = "✓" if z_opts == r_opts else "✗"
    print(f"TCP Options: zapret={z_opts}, recon={r_opts} {opts_match}")

    # Check for retransmissions (same seq number)
    if zapret_tcp.seq == recon_tcp.seq:
        print("⚠ Same sequence number - potential retransmission")

    # Export raw bytes for hex comparison
    with open(f"zapret_pkt_{pair_num}.hex", "w") as f:
        f.write(bytes(zapret_pkt).hex())
    with open(f"recon_pkt_{pair_num}.hex", "w") as f:
        f.write(bytes(recon_pkt).hex())

    print(
        f"Raw packet data exported to zapret_pkt_{pair_num}.hex and recon_pkt_{pair_num}.hex"
    )


def find_similar_flows(zapret_packets, recon_packets):
    """Find flows with similar destinations"""
    print("\n=== Finding Similar Flows ===")

    # Group by destination
    zapret_dests = {}
    recon_dests = {}

    for pkt in zapret_packets:
        if IP in pkt and TCP in pkt:
            dest = f"{pkt[IP].dst}:{pkt[TCP].dport}"
            if dest not in zapret_dests:
                zapret_dests[dest] = []
            zapret_dests[dest].append(pkt)

    for pkt in recon_packets:
        if IP in pkt and TCP in pkt:
            dest = f"{pkt[IP].dst}:{pkt[TCP].dport}"
            if dest not in recon_dests:
                recon_dests[dest] = []
            recon_dests[dest].append(pkt)

    print(f"Zapret destinations: {len(zapret_dests)}")
    print(f"Recon destinations: {len(recon_dests)}")

    # Find common destinations
    common_dests = set(zapret_dests.keys()) & set(recon_dests.keys())
    print(f"Common destinations: {len(common_dests)}")

    if common_dests:
        # Analyze first common destination
        first_dest = list(common_dests)[0]
        print(f"\nAnalyzing flows to {first_dest}")

        zapret_flow = zapret_dests[first_dest][:4]  # First 4 packets
        recon_flow = recon_dests[first_dest][:4]

        print(f"Zapret flow: {len(zapret_flow)} packets")
        print(f"Recon flow: {len(recon_flow)} packets")

        # Compare packet by packet
        max_compare = min(len(zapret_flow), len(recon_flow))
        for i in range(max_compare):
            compare_packets(zapret_flow[i], recon_flow[i], i + 1)

    return common_dests


def check_retransmissions(packets, label):
    """Check for TCP retransmissions"""
    print(f"\n=== Checking Retransmissions in {label} ===")

    seq_numbers = {}
    retransmissions = []

    for i, pkt in enumerate(packets):
        if TCP in pkt and IP in pkt:
            seq = pkt[TCP].seq
            ttl = pkt[IP].ttl

            if seq in seq_numbers:
                # Potential retransmission
                prev_info = seq_numbers[seq]
                retrans_info = {
                    "seq": seq,
                    "first_pkt": prev_info,
                    "retrans_pkt": {"index": i, "ttl": ttl},
                }
                retransmissions.append(retrans_info)

                if ttl == 128:  # Windows default TTL
                    print(
                        f"⚠ OS Retransmission detected: seq={seq}, TTL={ttl} at packet {i}"
                    )
            else:
                seq_numbers[seq] = {"index": i, "ttl": ttl}

    print(f"Total retransmissions found: {len(retransmissions)}")
    os_retrans = [r for r in retransmissions if r["retrans_pkt"]["ttl"] == 128]
    print(f"OS retransmissions (TTL=128): {len(os_retrans)}")

    return retransmissions


def check_rst_packets(packets, label):
    """Check for RST packets"""
    print(f"\n=== Checking RST Packets in {label} ===")

    rst_packets = []
    for i, pkt in enumerate(packets):
        if TCP in pkt and pkt[TCP].flags & 0x04:  # RST flag
            rst_info = {
                "index": i,
                "src": pkt[IP].src if IP in pkt else "unknown",
                "dst": pkt[IP].dst if IP in pkt else "unknown",
                "seq": pkt[TCP].seq,
                "ack": pkt[TCP].ack,
            }
            rst_packets.append(rst_info)
            print(f"RST packet {i}: {rst_info['src']} -> {rst_info['dst']}")

    print(f"Total RST packets: {len(rst_packets)}")
    return rst_packets


def main():
    """Main function"""
    print("SIMPLE PCAP VERIFICATION")
    print("=" * 50)

    # Analyze both files
    zapret_packets = analyze_pcap_basic("zapret.pcap")
    recon_packets = analyze_pcap_basic("out2.pcap")

    if not zapret_packets or not recon_packets:
        print("Error: Could not load packets from one or both files")
        return

    # Find and compare similar flows
    common_dests = find_similar_flows(zapret_packets, recon_packets)

    # Check for retransmissions
    zapret_retrans = check_retransmissions(zapret_packets, "Zapret")
    recon_retrans = check_retransmissions(recon_packets, "Recon")

    # Check for RST packets
    zapret_rst = check_rst_packets(zapret_packets, "Zapret")
    recon_rst = check_rst_packets(recon_packets, "Recon")

    # Summary
    print("\n" + "=" * 50)
    print("VERIFICATION SUMMARY")
    print("=" * 50)
    print(f"Zapret packets: {len(zapret_packets)} TCP")
    print(f"Recon packets: {len(recon_packets)} TCP")
    print(f"Common destinations: {len(common_dests) if common_dests else 0}")
    print(f"Zapret retransmissions: {len(zapret_retrans)}")
    print(f"Recon retransmissions: {len(recon_retrans)}")
    print(f"Zapret RST packets: {len(zapret_rst)}")
    print(f"Recon RST packets: {len(recon_rst)}")

    # Key findings
    print("\nKEY FINDINGS:")
    if recon_retrans:
        os_retrans = [r for r in recon_retrans if r["retrans_pkt"]["ttl"] == 128]
        if os_retrans:
            print("✗ OS retransmissions detected in recon - timing issue likely!")
        else:
            print("⚠ Retransmissions detected in recon")
    else:
        print("✓ No retransmissions in recon")

    if len(recon_rst) > len(zapret_rst):
        print("✗ More RST packets in recon than zapret - connection issues")
    elif len(recon_rst) == len(zapret_rst):
        print("✓ Similar RST packet count")
    else:
        print("? Fewer RST packets in recon than zapret")


if __name__ == "__main__":
    main()
