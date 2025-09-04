#!/usr/bin/env python3
import argparse
import json
from collections import Counter, defaultdict
from typing import Dict, Any
from datetime import datetime

try:
    from scapy.all import rdpcap, TCP, Raw, IP
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

def analyze_pcap(pcap_path: str) -> Dict[str, Any]:
    if not SCAPY_AVAILABLE:
        return {"error": "scapy not available"}
    pkts = rdpcap(pcap_path)
    stats = {
        "total_packets": len(pkts),
        "tcp_443": 0,
        "tls_clienthello": 0,
        "tls_serverhello": 0,
        "tcp_rst": 0,
        "ttl_histogram": Counter(),
        "top_dst_ips": Counter(),
        "syn_packets": 0,
    }
    for p in pkts:
        try:
            if not p.haslayer(TCP): continue
            tcp = p[TCP]
            ip = p[IP] if p.haslayer(IP) else None
            dst_ip = ip.dst if ip else None
            if dst_ip: stats["top_dst_ips"][dst_ip] += 1
            if ip and hasattr(ip, "ttl"): stats["ttl_histogram"][ip.ttl] += 1
            if tcp.flags & 0x02 and not (tcp.flags & 0x10):  # SYN w/o ACK
                stats["syn_packets"] += 1
            if tcp.dport == 443 or tcp.sport == 443:
                stats["tcp_443"] += 1
                if p.haslayer(Raw):
                    payload = bytes(p[Raw])
                    if len(payload) > 6 and payload[0] == 0x16:  # TLS record
                        hs_type = payload[5]
                        if hs_type == 0x01:
                            stats["tls_clienthello"] += 1
                        elif hs_type == 0x02:
                            stats["tls_serverhello"] += 1
            if tcp.flags & 0x04:
                stats["tcp_rst"] += 1
        except Exception:
            continue
    stats["top_dst_ips"] = stats["top_dst_ips"].most_common(10)
    stats["ttl_histogram"] = dict(stats["ttl_histogram"].most_common())
    return stats

def analyze_json(report_path: str) -> Dict[str, Any]:
    try:
        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        return {"error": str(e)}
    out = {}
    out["timestamp"] = data.get("timestamp")
    out["target"] = data.get("target")
    out["port"] = data.get("port")
    out["total_strategies"] = data.get("total_strategies_tested")
    out["working_strategies"] = data.get("working_strategies_found")
    out["success_rate"] = data.get("success_rate")
    out["best_strategy"] = data.get("best_strategy", {})
    out["domains"] = data.get("domains", {})
    # Extract top strategies by success
    all_results = data.get("all_results", [])
    top = sorted(all_results, key=lambda x: (x.get("success_rate", 0), -x.get("avg_latency_ms", 0)), reverse=True)[:10]
    out["top_strategies"] = [
        {
            "strategy": r.get("strategy"),
            "success_rate": r.get("success_rate"),
            "avg_latency_ms": r.get("avg_latency_ms")
        } for r in top
    ]
    # Basic fingerprint summary if present
    fps = data.get("fingerprints", {})
    fp_summary = {}
    for dom, fp in fps.items():
        try:
            dtype = fp.get("dpi_type") or getattr(fp.get("dpi_type", {}), "value", None)
        except Exception:
            dtype = None
        fp_summary[dom] = {
            "dpi_type": dtype,
            "confidence": fp.get("confidence"),
            "reliability": fp.get("reliability_score"),
            "rst_injection": fp.get("rst_injection_detected"),
            "dns_hijacking": fp.get("dns_hijacking_detected"),
        }
    out["fingerprints"] = fp_summary
    return out

def main():
    ap = argparse.ArgumentParser(description="Extract key insights from PCAP and recon JSON report")
    ap.add_argument("--pcap", required=False, help="Path to PCAP file")
    ap.add_argument("--report", required=True, help="Path to recon JSON report")
    ap.add_argument("--out", required=False, help="Save insights JSON to file")
    args = ap.parse_args()

    insights = {"generated_at": datetime.utcnow().isoformat() + "Z"}
    if args.pcap:
        insights["pcap_metrics"] = analyze_pcap(args.pcap)
    insights["report_metrics"] = analyze_json(args.report)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(insights, f, indent=2, ensure_ascii=False)
        print(f"Insights saved to {args.out}")
    else:
        print(json.dumps(insights, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
