#!/usr/bin/env python3
import json
import sys
import os
import argparse
from collections import Counter, defaultdict
from datetime import datetime

try:
    from scapy.all import rdpcap, TCP, Raw
    SCAPY = True
except Exception:
    SCAPY = False

def analyze_pcap(pcap_path: str) -> dict:
    out = {
        "total_packets": 0,
        "tcp_443": 0,
        "tls_clienthello": 0,
        "tls_serverhello": 0,
        "tcp_rst": 0,
        "ttl_histogram": {},
        "top_dst_ips": [],
        "syn_packets": 0
    }
    if not SCAPY or not os.path.exists(pcap_path):
        return out
    try:
        pkts = rdpcap(pcap_path)
    except Exception as e:
        print(f"[WARN] could not read pcap: {e}")
        return out

    ttl_counter = Counter()
    dst_counter = Counter()
    ch = sh = rst = syn = tcp443 = 0
    total = 0
    for p in pkts:
        total += 1
        try:
            ttl = int(p.ttl) if hasattr(p, 'ttl') else None
            if ttl is not None:
                ttl_counter[ttl] += 1
        except Exception:
            pass
        try:
            daddr = getattr(p, 'dst', None)
            dport = int(getattr(p, 'dport', 0))
            sport = int(getattr(p, 'sport', 0))
            if daddr:
                dst_counter[daddr] += 1
            if TCP in p and dport == 443:
                tcp443 += 1
            if TCP in p and p[TCP].flags & 0x02:  # SYN
                syn += 1
            if TCP in p and p[TCP].flags & 0x04:  # RST
                rst += 1
            if Raw in p:
                pl = bytes(p[Raw])
                if len(pl) > 6 and pl[0] == 0x16:  # TLS
                    if pl[5] == 0x01:
                        ch += 1
                    elif pl[5] == 0x02:
                        sh += 1
        except Exception:
            continue

    out["total_packets"] = total
    out["tcp_443"] = tcp443
    out["tls_clienthello"] = ch
    out["tls_serverhello"] = sh
    out["tcp_rst"] = rst
    out["syn_packets"] = syn
    out["ttl_histogram"] = dict(ttl_counter.most_common(30))
    out["top_dst_ips"] = dst_counter.most_common(10)
    return out

def analyze_report(report_path: str) -> dict:
    if not os.path.exists(report_path):
        return {}
    with open(report_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    out = {
        "timestamp": data.get("timestamp"),
        "target": data.get("target"),
        "port": data.get("port"),
        "total_strategies": data.get("total_strategies_tested"),
        "working_strategies": data.get("working_strategies_found"),
        "success_rate": data.get("success_rate"),
        "best_strategy": data.get("best_strategy"),
        "top_strategies": [],
    }
    # Соберем top стратегий из all_results
    results = data.get("all_results", [])
    results_sorted = sorted(results, key=lambda r: (r.get("success_rate", 0), -r.get("avg_latency_ms", 0)), reverse=True)
    out["top_strategies"] = [{
        "strategy": r.get("strategy"),
        "success_rate": r.get("success_rate"),
        "avg_latency_ms": r.get("avg_latency_ms"),
        "status": r.get("result_status")
    } for r in results_sorted[:10]]
    return out

def main():
    ap = argparse.ArgumentParser("extract_run_insights")
    ap.add_argument("--pcap", type=str, help="Path to pcap file")
    ap.add_argument("--report", type=str, help="Path to recon report json")
    ap.add_argument("--save", type=str, default="", help="Save merged insights to json")
    args = ap.parse_args()

    merged = {"generated_at": datetime.utcnow().isoformat() + "Z"}
    if args.pcap:
        merged["pcap_metrics"] = analyze_pcap(args.pcap)
    if args.report:
        merged["report_metrics"] = analyze_report(args.report)

    # Compact print
    print(json.dumps(merged, indent=2, ensure_ascii=False))

    if args.save:
        with open(args.save, "w", encoding="utf-8") as f:
            json.dump(merged, f, indent=2, ensure_ascii=False)
        print(f"[OK] saved to {args.save}")

if __name__ == "__main__":
    main()
