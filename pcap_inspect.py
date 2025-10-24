# pcap_inspect.py
import json
import struct
import logging
from collections import defaultdict
from typing import Dict, List, Tuple, Optional, Any
from scapy.all import IP, Raw, TCP, rdpcap


def is_tls_clienthello(payload: bytes) -> bool:
    try:
        return (
            payload and len(payload) > 6 and payload[0] == 0x16 and payload[5] == 0x01
        )
    except Exception:
        return False


def parse_sni(payload: bytes) -> Optional[str]:
    try:
        if not is_tls_clienthello(payload):
            return None
        pos = 9
        pos += 2 + 32
        if pos + 1 > len(payload):
            return None
        sid_len = payload[pos]
        pos += 1 + sid_len
        if pos + 2 > len(payload):
            return None
        cs_len = int.from_bytes(payload[pos : pos + 2], "big")
        pos += 2 + cs_len
        if pos + 1 > len(payload):
            return None
        comp_len = payload[pos]
        pos += 1 + comp_len
        if pos + 2 > len(payload):
            return None
        ext_len = int.from_bytes(payload[pos : pos + 2], "big")
        ext_start = pos + 2
        ext_end = min(len(payload), ext_start + ext_len)
        s = ext_start
        while s + 4 <= ext_end:
            etype = int.from_bytes(payload[s : s + 2], "big")
            elen = int.from_bytes(payload[s + 2 : s + 4], "big")
            epos = s + 4
            if epos + elen > ext_end:
                break
            if etype == 0 and elen >= 5:
                list_len = int.from_bytes(payload[epos : epos + 2], "big")
                npos = epos + 2
                if npos + list_len <= epos + elen and npos + 3 <= len(payload):
                    ntype = payload[npos]
                    nlen = int.from_bytes(payload[npos + 1 : npos + 3], "big")
                    nstart = npos + 3
                    if ntype == 0 and nstart + nlen <= len(payload):
                        return payload[nstart : nstart + nlen].decode(
                            "idna", errors="strict"
                        )
            s = epos + elen
        return None
    except Exception:
        return None


def ones_complement_sum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
        s = (s & 0xFFFF) + (s >> 16)
    return s


def tcp_checksum(ip_hdr: bytes, tcp_hdr: bytes, payload: bytes) -> int:
    src = ip_hdr[12:16]
    dst = ip_hdr[16:20]
    proto = ip_hdr[9]
    tcp_len = len(tcp_hdr) + len(payload)
    pseudo = src + dst + bytes([0, proto]) + struct.pack("!H", tcp_len)
    tcp_wo = bytearray(tcp_hdr)
    tcp_wo[16:18] = b"\x00\x00"
    s = ones_complement_sum(pseudo + bytes(tcp_wo) + payload)
    return (~s) & 0xFFFF


def tcp_checksum_ok(ip_pkt_bytes: bytes) -> bool:
    try:
        ip_hl = (ip_pkt_bytes[0] & 0x0F) * 4
        tcp_start = ip_hl
        if len(ip_pkt_bytes) < ip_hl + 20:
            return False
        tcp_hl = ((ip_pkt_bytes[tcp_start + 12] >> 4) & 0x0F) * 4
        if tcp_hl < 20:
            tcp_hl = 20
        tcp_end = tcp_start + tcp_hl
        hdr_csum = struct.unpack("!H", ip_pkt_bytes[tcp_start + 16 : tcp_start + 18])[0]
        calc = tcp_checksum(
            ip_pkt_bytes[:ip_hl],
            ip_pkt_bytes[tcp_start:tcp_end],
            ip_pkt_bytes[tcp_end:],
        )
        return hdr_csum == calc
    except Exception:
        return False


def extract_pktinfo(pkt):
    ip = pkt[IP]
    tcp = pkt[TCP]
    rawb = bytes(ip)
    payload = bytes(pkt[Raw].load) if Raw in pkt else b""
    return {
        "time": float(pkt.time),
        "src": ip.src,
        "dst": ip.dst,
        "sport": int(tcp.sport),
        "dport": int(tcp.dport),
        "seq": int(tcp.seq),
        "ack": int(tcp.ack),
        "ttl": int(ip.ttl),
        "flags": int(tcp.flags),
        "len": len(payload),
        "raw": rawb,
        "payload": payload,
        "is_ch": is_tls_clienthello(payload),
        "sni": parse_sni(payload) if is_tls_clienthello(payload) else None,
        "csum_ok": tcp_checksum_ok(rawb),
    }


def load_flows(pcap_path: str):
    packets = rdpcap(pcap_path)
    flows = defaultdict(list)
    for pkt in packets:
        if IP in pkt and TCP in pkt and pkt[TCP].dport == 443:
            info = extract_pktinfo(pkt)
            # предполагаем исходящие: клиентские ephemeral порты > 1024
            if info["sport"] > 1024:
                key = (info["src"], info["sport"], info["dst"], info["dport"])
                flows[key].append(info)
    # сортировка по времени
    for k in flows:
        flows[k].sort(key=lambda x: x["time"])
    return flows


def detect_injection_pair(flow_packets: List[Dict]) -> Optional[Tuple[Dict, Dict]]:
    """
    Ищем две подряд идущие посылки с CH-полезной нагрузкой/продолжением (Raw),
    в пределах 50 мс, где один кандидат имеет низкий TTL (<=8) или bad checksum.
    """
    cand = []
    for p in flow_packets[:20]:
        if p["len"] > 0:  # есть payload
            cand.append(p)
    best = None
    for i in range(len(cand) - 1):
        p1, p2 = cand[i], cand[i + 1]
        if (p2["time"] - p1["time"]) > 0.05:  # 50 мс окно
            continue
        # один «фейковый» признак: TTL низкий или checksum испорчен
        p1_fake_score = (p1["ttl"] <= 8) + (not p1["csum_ok"])
        p2_fake_score = (p2["ttl"] <= 8) + (not p2["csum_ok"])
        if p1_fake_score == p2_fake_score == 0:
            continue
        best = (p1, p2)
        break
    return best


def analyze_flow_pair(p1: Dict, p2: Dict) -> Dict:
    # кто fake/real
    def is_fake(p):
        return (p["ttl"] <= 8) or (not p["csum_ok"])

    fake, real = (p1, p2) if is_fake(p1) else (p2, p1)
    order_ok = fake["time"] <= real["time"]
    ttl_ok = fake["ttl"] <= 8 and real["ttl"] >= 32
    csum_fake_bad = not fake["csum_ok"]
    flags_real_psh = bool(real["flags"] & 0x08)
    flags_fake_no_psh = not bool(fake["flags"] & 0x08)
    # SEQ
    seq_delta = (real["seq"] - fake["seq"]) & 0xFFFFFFFF
    # простая метрика: fake.seq <= real.seq (с учётом wrap мы считаем нормальным небольшую разницу)
    seq_order_ok = ((real["seq"] - fake["seq"]) >= 0) or (seq_delta < 1 << 20)
    return {
        "fake_first": order_ok,
        "ttl_order_ok": ttl_ok,
        "csum_fake_bad": csum_fake_bad,
        "flags_real_psh": flags_real_psh,
        "flags_fake_no_psh": flags_fake_no_psh,
        "seq_order_ok": seq_order_ok,
        "fake": {
            "ttl": fake["ttl"],
            "flags": fake["flags"],
            "csum_ok": fake["csum_ok"],
            "seq": fake["seq"],
            "len": fake["len"],
        },
        "real": {
            "ttl": real["ttl"],
            "flags": real["flags"],
            "csum_ok": real["csum_ok"],
            "seq": real["seq"],
            "len": real["len"],
        },
        "pair_dt_ms": (real["time"] - fake["time"]) * 1000.0,
        "sni": p1.get("sni") or p2.get("sni"),
    }


def inspect_pcap(pcap_path: str) -> Dict:
    flows = load_flows(pcap_path)
    report = {"pcap": pcap_path, "flows": []}
    for key, pkts in flows.items():
        pair = detect_injection_pair(pkts)
        if not pair:
            continue
        p1, p2 = pair
        analysis = analyze_flow_pair(p1, p2)
        report["flows"].append(
            {
                "flow": f"{key[0]}:{key[1]} -> {key[2]}:{key[3]}",
                "dst": key[2],
                "sni": analysis["sni"],
                "metrics": analysis,
            }
        )
    return report


class AttackValidator:
    """
    Валидирует инциденты, обнаруженные в pcap_inspect,
    проверяя корректность применения техник атаки (fake/real).
    """

    def __init__(self, pcap_inspect_report: Dict[str, Any]):
        self.report = pcap_inspect_report or {}
        # Для быстрого доступа индексируем потоки по их ключу
        self.flows_by_key = {
            flow.get("flow_key"): flow
            for flow in self.report.get("flows", [])
            if flow.get("flow_key")
        }
        self.logger = logging.getLogger("AttackValidator")

    def _normalize_stream_key(self, stream_label: str) -> Optional[str]:
        """Приводит ключ потока к формату 'ip:port-ip:port' для поиска."""
        try:
            # Ожидаемый формат: "192.168.18.188:54709-162.159.140.229:443"
            parts = stream_label.replace(" -> ", "-").split("-")
            src = parts[0]
            dst = parts[1]

            # pcap_inspect использует формат "src:port -> dst:port"
            return f"{src} -> {dst}"
        except Exception:
            return None

    def validate_incident(self, incident: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Валидирует один инцидент, проверяя пакеты в соответствующем потоке.
        """
        stream_label = incident.get("stream")
        if not stream_label:
            return None

        flow_key = self._normalize_stream_key(stream_label)
        flow_data = self.flows_by_key.get(flow_key)

        if not flow_data:
            return {
                "detected": False,
                "confidence": 0.1,
                "issues": ["Flow not found in pcap_inspect report."],
            }

        packets = flow_data.get("packets", [])
        if not packets:
            return {
                "detected": False,
                "confidence": 0.1,
                "issues": ["No packets found for this flow."],
            }

        # --- Основная логика валидации ---
        issues = []
        fixes = []

        # 1. Проверяем, был ли первый пакет фейковым, как и ожидалось
        first_pkt = packets[0]
        if not first_pkt.get("is_fake_candidate"):
            issues.append("No fake packet detected for fakeddisorder-style attack.")
            fixes.append(
                "Ensure fake packet is sent first with low TTL or bad checksum."
            )

        # 2. Проверяем, что "реальные" пакеты не помечены как фейковые
        real_packets_with_bad_checksum = []
        for i, pkt in enumerate(
            packets[1:]
        ):  # Пропускаем первый (предположительно фейковый)
            if not pkt.get("tcp_checksum_valid"):
                real_packets_with_bad_checksum.append(i + 1)

        if real_packets_with_bad_checksum:
            issues.append(
                f"Real segments have invalid TCP checksums (packets: {real_packets_with_bad_checksum})."
            )
            fixes.append("Ensure TCP checksum is valid for all real segments.")

        if not issues:
            return {"detected": True, "confidence": 0.95, "issues": [], "fixes": []}
        else:
            return {
                "detected": False,
                "confidence": 0.8,
                "issues": issues,
                "fixes": fixes,
            }


# --- START OF FIX: Restored functions from the old version ---


def _has_md5sig(pkt):
    """Checks for the TCP MD5 Signature option (kind=19)."""
    try:
        if TCP in pkt:
            # Scapy's options are a list of tuples (kind, value)
            for opt_kind, _ in pkt[TCP].options:
                if opt_kind == 19:
                    return True
            # Fallback for raw byte parsing if Scapy fails
            b = bytes(pkt[TCP])
            hdr_len = pkt[TCP].dataofs * 4
            opts = b[20:hdr_len] if hdr_len > 20 else b""
            return b"\x13\x12" in opts  # kind=19, len=18
    except Exception:
        return False
    return False


def _classify_window(segments):
    """
    Restored classification logic from the old, working version.
    This logic is more flexible and correctly identifies complex attack patterns.
    """
    segs = sorted(segments, key=lambda x: x["idx"])
    fake = [
        s
        for s in segs
        if (s["ttl"] is not None and s["ttl"] <= 4) or (not s["tcp_ok"]) or s["md5"]
    ]

    rels = [s["rel_seq"] for s in segs]
    ttls = [s["ttl"] for s in segs]
    has_md5 = any(s["md5"] for s in segs)
    count = len(segs)

    # fakeddisorder (fake + part2 + part1)
    if fake and len(segs) >= 3 and segs[0] in fake:
        rel_after = [s["rel_seq"] for s in segs[1:]]
        if 0 in rel_after and any(r > 0 for r in rel_after):
            split_pos = max([r for r in rel_after if r > 0] or [0])
            label = f"fakeddisorder_badsum={'y' if not segs[0]['tcp_ok'] else 'n'}_ttl{segs[0]['ttl']}_split{split_pos}{'_md5' if has_md5 else ''}"
            return label, {"type": "fakeddisorder", "split_pos": split_pos}

    # fake race (fake + real)
    if fake and count >= 2 and segs[0] in fake:
        if segs[1]["rel_seq"] == 0:
            label = f"fake_race_badsum={'y' if not segs[0]['tcp_ok'] else 'n'}_ttl{segs[0]['ttl']}{'_md5' if has_md5 else ''}"
            return label, {"type": "fake_race"}

    # multisplit/split (no fake packets)
    if not fake and count >= 2:
        splits = sorted(set([s["rel_seq"] for s in segs]))
        if len(splits) >= 2 and splits[0] == 0:
            positions = splits[1:]
            if len(positions) == 1:
                label = f"split_{positions[0]}"
                return label, {"type": "split", "split_pos": positions[0]}
            else:
                label = f"multisplit_{','.join(str(x) for x in positions)}"
                return label, {"type": "multisplit", "positions": positions}

    # seqovl heuristic
    if count >= 2 and segs[1]["rel_seq"] > 0 and segs[1]["rel_seq"] < segs[0]["paylen"]:
        overlap = segs[0]["paylen"] - segs[1]["rel_seq"]
        label = f"seqovl_ovl{overlap}"
        return label, {"type": "seqovl", "overlap": overlap}

    return "unknown", {"type": "unknown"}


# --- END OF FIX ---

if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("pcap", help="Path to pcap to inspect")
    ap.add_argument("-o", "--out", default="pcap_report.json")
    args = ap.parse_args()
    rep = inspect_pcap(args.pcap)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(rep, f, ensure_ascii=False, indent=2)
    print(f"Saved report to {args.out}, flows analyzed: {len(rep.get('flows', []))}")
