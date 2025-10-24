# file pcap_to_json_analyzer.py
import argparse
import json
import sys
import os
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import PcapReader, TCP, IP, IPv6, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def _recalculate_tcp_checksum(pkt):
    """
    Recalculate TCP checksum and compare with the original value.

    Returns:
        (original_checksum, is_valid)
        original_checksum: int | None
        is_valid: bool
    """
    if TCP not in pkt:
        return None, False

    # Work on a copy so we don't mutate the original packet
    pkt_copy = pkt.copy()

    # Remove checksum to force Scapy to recalculate on serialization
    try:
        del pkt_copy[TCP].chksum
    except Exception:
        # If field is missing or cannot be deleted, continue
        pass

    # Important: reparse from the IP/IPv6 layer bytes (not from the whole frame),
    # otherwise Ether bytes could be misinterpreted as IP if present.
    if IP in pkt_copy:
        ip_bytes = bytes(pkt_copy[IP])
        recalculated_csum = IP(ip_bytes)[TCP].chksum
    elif IPv6 in pkt_copy:
        ipv6_bytes = bytes(pkt_copy[IPv6])
        recalculated_csum = IPv6(ipv6_bytes)[TCP].chksum
    else:
        return None, False

    original_csum = pkt[TCP].chksum
    # If original checksum is None (rare), just say it's invalid
    if original_csum is None:
        return None, False

    return original_csum, (original_csum == recalculated_csum)


def packet_to_dict(pkt, pkt_num):
    """
    Convert a Scapy packet to a JSON-serializable dictionary with TCP details.
    Returns None if the packet is not IPv4/IPv6 TCP.
    """
    if not (IP in pkt or IPv6 in pkt):
        return None
    if TCP not in pkt:
        return None

    info = {
        "num": pkt_num,
        "timestamp": float(pkt.time),
        "len": len(pkt),
    }

    if IP in pkt:
        info.update({
            "src_ip": pkt[IP].src,
            "dst_ip": pkt[IP].dst,
            "ttl": pkt[IP].ttl,
            "ip_len": pkt[IP].len,
            "ip_id": pkt[IP].id,
        })
    elif IPv6 in pkt:
        info.update({
            "src_ip": pkt[IPv6].src,
            "dst_ip": pkt[IPv6].dst,
            "ttl": pkt[IPv6].hlim,
        })

    tcp_layer = pkt[TCP]
    original_csum, is_valid = _recalculate_tcp_checksum(pkt)

    payload_len = len(bytes(tcp_layer.payload)) if tcp_layer.payload is not None else 0

    info.update({
        "src_port": tcp_layer.sport,
        "dst_port": tcp_layer.dport,
        "seq": tcp_layer.seq,
        "ack": tcp_layer.ack,
        "flags": str(tcp_layer.flags),
        "window": tcp_layer.window,
        "payload_len": payload_len,
        "tcp_checksum": original_csum,
        "tcp_checksum_valid": is_valid,
    })

    if Raw in tcp_layer:
        try:
            info["payload_hex"] = tcp_layer[Raw].load.hex()
        except Exception:
            # Fallback in case of unusual payload type
            info["payload_hex"] = bytes(tcp_layer[Raw].load or b"").hex()

    return info


def analyze_pcap(pcap_file):
    """
    Analyze a PCAP file and group TCP packets by bidirectional flows.
    Returns a JSON-serializable dict.
    """
    flows = defaultdict(list)
    reader = PcapReader(pcap_file)

    try:
        for i, pkt in enumerate(reader, start=1):
            pkt_dict = packet_to_dict(pkt, i)
            if not pkt_dict:
                continue

            # Direction-independent flow key (ip:port pairs sorted)
            flow_key_part1 = f"{pkt_dict['src_ip']}:{pkt_dict['src_port']}"
            flow_key_part2 = f"{pkt_dict['dst_ip']}:{pkt_dict['dst_port']}"
            flow_key = tuple(sorted((flow_key_part1, flow_key_part2)))

            flows[flow_key].append(pkt_dict)
    finally:
        try:
            reader.close()
        except Exception:
            pass

    # Convert defaultdict to a regular dict for JSON output
    output_flows = {}
    for (end_a, end_b), packets in flows.items():
        output_flows[f"{end_a} <-> {end_b}"] = packets

    return {
        "pcap_file": os.path.basename(pcap_file),
        "analysis_timestamp": datetime.now().astimezone().isoformat(),
        "total_flows": len(output_flows),
        "flows": output_flows,
    }


def main():
    if not SCAPY_AVAILABLE:
        print("Error: Scapy is not installed. Please run 'pip install scapy'.", file=sys.stderr)
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Analyze a PCAP file and convert TCP flows to a detailed JSON format."
    )
    parser.add_argument("pcap_file", help="Path to the input PCAP file.")
    parser.add_argument(
        "-o", "--output",
        help="Path to the output JSON file. If not provided, prints to stdout."
    )

    args = parser.parse_args()

    if not os.path.exists(args.pcap_file):
        print(f"Error: File not found at '{args.pcap_file}'", file=sys.stderr)
        sys.exit(1)

    try:
        analysis_result = analyze_pcap(args.pcap_file)
        json_output = json.dumps(analysis_result, indent=2)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(json_output)
            print(f"Analysis complete. Results saved to '{args.output}'")
        else:
            print(json_output)

    except Exception as e:
        print(f"An error occurred during analysis: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()