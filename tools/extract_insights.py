#!/usr/bin/env python3
import json
import argparse
from collections import Counter

try:
    from scapy.all import PcapReader, TCP, Raw, IP

    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


def analyze_pcap(pcap_path: str) -> dict:
    if not SCAPY_AVAILABLE:
        return {"error": "scapy not available"}
    stats = {
        "total": 0,
        "tcp_443": 0,
        "tls_clienthello": 0,
        "tls_serverhello": 0,
        "tcp_rst": 0,
        "ttl_histogram": Counter(),
        "top_dst_ips": Counter(),
    }
    try:
        with PcapReader(pcap_path) as r:
            for pkt in r:
                stats["total"] += 1
                try:
                    if IP in pkt:
                        stats["ttl_histogram"][pkt[IP].ttl] += 1
                        if TCP in pkt:
                            if pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
                                stats["tcp_443"] += 1
                                stats["top_dst_ips"][pkt[IP].dst] += 1
                                if pkt[TCP].flags & 0x04:
                                    stats["tcp_rst"] += 1
                                if Raw in pkt:
                                    payload = bytes(pkt[Raw])
                                    if len(payload) > 6 and payload[0] == 0x16:
                                        if payload[5] == 0x01:
                                            stats["tls_clienthello"] += 1
                                        elif payload[5] == 0x02:
                                            stats["tls_serverhello"] += 1
                except Exception:
                    continue
        # pack results
        out = dict(stats)
        out["ttl_histogram"] = dict(stats["ttl_histogram"].most_common(20))
        out["top_dst_ips"] = stats["top_dst_ips"].most_common(10)
        return out
    except Exception as e:
        return {"error": str(e)}


def analyze_report(report_path: str) -> dict:
    try:
        with open(report_path, "r", encoding="utf-8") as f:
            rep = json.load(f)
        out = {
            "timestamp": rep.get("timestamp"),
            "target": rep.get("target"),
            "port": rep.get("port"),
            "total_strategies": rep.get("total_strategies_tested"),
            "working": rep.get("working_strategies_found"),
            "success_rate": rep.get("success_rate"),
        }
        # top strategies
        top = []
        for item in rep.get("all_results", []):
            top.append(
                {
                    "strategy": item.get("strategy"),
                    "success_rate": item.get("success_rate"),
                    "avg_latency_ms": item.get("avg_latency_ms"),
                }
            )
        top.sort(
            key=lambda x: (x["success_rate"], -(x["avg_latency_ms"] or 0)), reverse=True
        )
        out["top_strategies"] = top[:10]
        return out
    except Exception as e:
        return {"error": str(e)}


def main():
    ap = argparse.ArgumentParser(
        description="Extract insights from PCAP and JSON report"
    )
    ap.add_argument("--pcap", type=str, help="PCAP file path")
    ap.add_argument("--report", type=str, help="Recon JSON report path")
    args = ap.parse_args()

    res = {}
    if args.pcap:
        res["pcap_metrics"] = analyze_pcap(args.pcap)
    if args.report:
        res["report_metrics"] = analyze_report(args.report)
    print(json.dumps(res, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
