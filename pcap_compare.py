# pcap_compare.py
import json
from pcap_inspect import inspect_pcap

def to_key(entry):
    # пытаемся матчить по SNI, иначе по dst IP
    sni = entry.get("sni")
    return ("sni", sni) if sni else ("dst", entry.get("dst"))

def compare(a_report: dict, b_report: dict):
    a_map, b_map = {}, {}
    for e in a_report.get("flows", []):
        a_map[to_key(e)] = e
    for e in b_report.get("flows", []):
        b_map[to_key(e)] = e

    keys = set(a_map.keys()) & set(b_map.keys())
    diffs = []
    for k in keys:
        A = a_map[k]["metrics"]; B = b_map[k]["metrics"]
        diffs.append({
            "key": k,
            "our_fake_first": A["fake_first"], "zapret_fake_first": B["fake_first"],
            "our_ttl_order_ok": A["ttl_order_ok"], "zapret_ttl_order_ok": B["ttl_order_ok"],
            "our_csum_fake_bad": A["csum_fake_bad"], "zapret_csum_fake_bad": B["csum_fake_bad"],
            "our_flags_real_psh": A["flags_real_psh"], "zapret_flags_real_psh": B["flags_real_psh"],
            "our_flags_fake_no_psh": A["flags_fake_no_psh"], "zapret_flags_fake_no_psh": B["flags_fake_no_psh"],
            "our_pair_dt_ms": round(A["pair_dt_ms"], 2), "zapret_pair_dt_ms": round(B["pair_dt_ms"], 2),
            "our_fake": A["fake"], "zapret_fake": B["fake"],
            "our_real": A["real"], "zapret_real": B["real"]
        })
    return diffs

if __name__ == "__main__":
    import argparse, json
    ap = argparse.ArgumentParser()
    ap.add_argument("ours", help="out2.pcap from our engine")
    ap.add_argument("zapret", help="zapret.pcap baseline")
    ap.add_argument("-o", "--out", default="pcap_diff.json")
    args = ap.parse_args()
    rep_ours = inspect_pcap(args.ours)
    rep_zapret = inspect_pcap(args.zapret)
    diffs = compare(rep_ours, rep_zapret)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump({"ours": rep_ours["pcap"], "zapret": rep_zapret["pcap"], "diffs": diffs}, f, ensure_ascii=False, indent=2)
    print(f"Compared {len(diffs)} matched flows. Saved to {args.out}")