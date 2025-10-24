#!/usr/bin/env python3
"""
Analyzer for out.pcap file to identify why domains are not opening successfully.
"""

import json
from collections import defaultdict, Counter
from scapy.all import rdpcap, IP, TCP, UDP, DNS
from scapy.layers.http import HTTPRequest, HTTPResponse

try:
    from scapy.layers.tls.all import TLS
except ImportError:
    TLS = None


def analyze_pcap(pcap_file):
    """Analyze the pcap file and identify issues."""
    try:
        packets = rdpcap(pcap_file)
        print(f"Total packets in {pcap_file}: {len(packets)}")
    except Exception as e:
        print(f"Error reading pcap file: {e}")
        return

    # Initialize counters
    stats = {
        "total_packets": len(packets),
        "ip_packets": 0,
        "tcp_packets": 0,
        "udp_packets": 0,
        "dns_packets": 0,
        "http_packets": 0,
        "tls_packets": 0,
        "connections": defaultdict(list),
        "failed_connections": [],
        "timeouts": [],
        "rst_packets": [],
        "blocked_domains": set(),
        "protocol_distribution": Counter(),
        "destination_ips": Counter(),
        "tcp_flags": Counter(),
        "connection_attempts": defaultdict(int),
        "handshake_failures": [],
    }

    # Analyze packets
    for i, packet in enumerate(packets):
        if IP in packet:
            stats["ip_packets"] += 1
            dst_ip = packet[IP].dst
            stats["destination_ips"][dst_ip] += 1

            if TCP in packet:
                stats["tcp_packets"] += 1
                tcp_layer = packet[TCP]

                # Track TCP flags
                flags = []
                if tcp_layer.flags.F:
                    flags.append("FIN")
                if tcp_layer.flags.S:
                    flags.append("SYN")
                if tcp_layer.flags.R:
                    flags.append("RST")
                if tcp_layer.flags.P:
                    flags.append("PSH")
                if tcp_layer.flags.A:
                    flags.append("ACK")
                if tcp_layer.flags.U:
                    flags.append("URG")

                flag_combo = "+".join(flags) if flags else "NONE"
                stats["tcp_flags"][flag_combo] += 1

                # Track connection attempts
                src = f"{packet[IP].src}:{tcp_layer.sport}"
                dst = f"{packet[IP].dst}:{tcp_layer.dport}"
                connection = f"{src} -> {dst}"

                if tcp_layer.flags.S and not tcp_layer.flags.A:  # SYN packet
                    stats["connection_attempts"][dst] += 1

                # Track RST packets (connection failures)
                if tcp_layer.flags.R:
                    stats["rst_packets"].append(
                        {
                            "src": packet[IP].src,
                            "dst": packet[IP].dst,
                            "sport": tcp_layer.sport,
                            "dport": tcp_layer.dport,
                            "seq": tcp_layer.seq,
                            "time": packet.time if hasattr(packet, "time") else i,
                        }
                    )

                # Check for TLS/SSL
                if hasattr(packet, "load") and packet.load:
                    # Simple heuristic for TLS detection
                    if len(packet.load) > 5 and packet.load[0] in [
                        0x16,
                        0x14,
                        0x15,
                        0x17,
                    ]:
                        stats["tls_packets"] += 1
                        stats["protocol_distribution"]["TLS"] += 1

                        # Check for TLS alerts (connection failures)
                        if packet.load[0] == 0x15:  # Alert
                            stats["handshake_failures"].append(
                                {
                                    "src": packet[IP].src,
                                    "dst": packet[IP].dst,
                                    "dport": tcp_layer.dport,
                                    "alert_level": (
                                        packet.load[1] if len(packet.load) > 1 else 0
                                    ),
                                    "alert_description": (
                                        packet.load[2] if len(packet.load) > 2 else 0
                                    ),
                                }
                            )

            elif UDP in packet:
                stats["udp_packets"] += 1
                stats["protocol_distribution"]["UDP"] += 1

                # Check for DNS
                if DNS in packet:
                    stats["dns_packets"] += 1
                    stats["protocol_distribution"]["DNS"] += 1

                    dns_layer = packet[DNS]
                    if dns_layer.qr == 0:  # Query
                        if dns_layer.qd:
                            domain = dns_layer.qd.qname.decode().rstrip(".")
                            if any(
                                blocked in domain
                                for blocked in [
                                    "x.com",
                                    "instagram.com",
                                    "youtube.com",
                                    "facebook.com",
                                ]
                            ):
                                stats["blocked_domains"].add(domain)

        # Check for HTTP
        if HTTPRequest in packet:
            stats["http_packets"] += 1
            stats["protocol_distribution"]["HTTP"] += 1
        elif HTTPResponse in packet:
            stats["protocol_distribution"]["HTTP_Response"] += 1

    return stats


def generate_report(stats):
    """Generate a detailed analysis report."""
    print("\n" + "=" * 60)
    print("PCAP ANALYSIS REPORT")
    print("=" * 60)

    print("\nPACKET OVERVIEW:")
    print(f"  Total packets: {stats['total_packets']}")
    print(f"  IP packets: {stats['ip_packets']}")
    print(f"  TCP packets: {stats['tcp_packets']}")
    print(f"  UDP packets: {stats['udp_packets']}")
    print(f"  DNS packets: {stats['dns_packets']}")
    print(f"  TLS packets: {stats['tls_packets']}")
    print(f"  HTTP packets: {stats['http_packets']}")

    print("\nPROTOCOL DISTRIBUTION:")
    for protocol, count in stats["protocol_distribution"].most_common():
        print(f"  {protocol}: {count}")

    print("\nTCP FLAGS ANALYSIS:")
    for flags, count in stats["tcp_flags"].most_common(10):
        print(f"  {flags}: {count}")

    print("\nCONNECTION FAILURES:")
    print(f"  RST packets: {len(stats['rst_packets'])}")
    print(f"  TLS handshake failures: {len(stats['handshake_failures'])}")

    if stats["rst_packets"]:
        print("\nRST PACKET DETAILS (first 10):")
        for rst in stats["rst_packets"][:10]:
            print(
                f"  {rst['src']}:{rst['sport']} -> {rst['dst']}:{rst['dport']} (seq: {rst['seq']})"
            )

    if stats["handshake_failures"]:
        print("\nTLS HANDSHAKE FAILURES (first 10):")
        for failure in stats["handshake_failures"][:10]:
            print(
                f"  {failure['src']} -> {failure['dst']}:{failure['dport']} Alert: {failure['alert_level']}.{failure['alert_description']}"
            )

    print("\nTOP DESTINATION IPs:")
    for ip, count in stats["destination_ips"].most_common(15):
        print(f"  {ip}: {count} packets")

    print("\nCONNECTION ATTEMPTS BY DESTINATION:")
    for dest, attempts in sorted(
        stats["connection_attempts"].items(), key=lambda x: x[1], reverse=True
    )[:15]:
        print(f"  {dest}: {attempts} attempts")

    if stats["blocked_domains"]:
        print("\nBLOCKED DOMAINS DETECTED:")
        for domain in sorted(stats["blocked_domains"]):
            print(f"  {domain}")

    # Generate summary insights
    print("\n" + "=" * 60)
    print("KEY INSIGHTS:")
    print("=" * 60)

    if len(stats["rst_packets"]) > 0:
        print(
            f"⚠️  High number of RST packets ({len(stats['rst_packets'])}) indicates connection resets"
        )

    if len(stats["handshake_failures"]) > 0:
        print(f"⚠️  TLS handshake failures detected ({len(stats['handshake_failures'])}")

    if stats["tcp_packets"] > 0 and stats["tls_packets"] > 0:
        tls_ratio = stats["tls_packets"] / stats["tcp_packets"]
        print(f"📊 TLS traffic ratio: {tls_ratio:.2%}")

    if stats["dns_packets"] == 0:
        print(
            "⚠️  No DNS packets detected - may indicate DNS blocking or alternative resolution"
        )

    # Connection success estimation
    syn_count = stats["tcp_flags"].get("SYN", 0)
    syn_ack_count = stats["tcp_flags"].get("SYN+ACK", 0)
    if syn_count > 0:
        success_ratio = syn_ack_count / syn_count
        print(
            f"📊 Connection success ratio: {success_ratio:.2%} ({syn_ack_count}/{syn_count})"
        )
        if success_ratio < 0.5:
            print("⚠️  Low connection success rate indicates blocking")


def main():
    pcap_file = "out.pcap"

    print(f"Analyzing {pcap_file}...")
    stats = analyze_pcap(pcap_file)

    if stats:
        generate_report(stats)

        # Save detailed results
        with open("out_pcap_analysis.json", "w") as f:
            # Convert sets to lists for JSON serialization
            json_stats = stats.copy()
            json_stats["blocked_domains"] = list(json_stats["blocked_domains"])
            json_stats["protocol_distribution"] = dict(
                json_stats["protocol_distribution"]
            )
            json_stats["destination_ips"] = dict(json_stats["destination_ips"])
            json_stats["tcp_flags"] = dict(json_stats["tcp_flags"])
            json_stats["connection_attempts"] = dict(json_stats["connection_attempts"])

            json.dump(json_stats, f, indent=2, default=str)
            print("\n📄 Detailed analysis saved to out_pcap_analysis.json")


if __name__ == "__main__":
    main()
