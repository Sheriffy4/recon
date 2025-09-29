import argparse
import sys
import os
import json
import asyncio
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple, Set
import logging

# Добавляем корень проекта в путь
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

from core.pcap.rst_analyzer import RSTTriggerAnalyzer

# Для второго прогона
try:
    from core.hybrid_engine import HybridEngine
    from core.doh_resolver import DoHResolver
    HYBRID_AVAILABLE = True
except ImportError as e:
    print(f"[WARNING] HybridEngine/DoHResolver недоступны: {e}")
    HYBRID_AVAILABLE = False

# Попытка импортировать scapy для доступа к payload/переассемблированию
try:
    from scapy.all import PcapReader, TCP, IP, IPv6
    SCAPY_AVAILABLE = True
except ImportError as e:
    print(f"[WARNING] Scapy недоступен: {e}")
    SCAPY_AVAILABLE = False

# ====== TLS helpers ======
TLS_VER_MAP = {0x0301: "TLS1.0", 0x0302: "TLS1.1", 0x0303: "TLS1.2", 0x0304: "TLS1.3"}
TLS_EXT_NAMES = {
    0x0000: "server_name",
    0x0005: "status_request",
    0x000a: "supported_groups",
    0x000b: "ec_point_formats",
    0x000d: "signature_algorithms",
    0x0010: "alpn",
    0x0017: "sct",
    0x0023: "extended_master_secret",
    0x002b: "supported_versions",
    0x002d: "psk_key_exchange_modes",
    0x0031: "pre_shared_key",
    0x0033: "key_share",
    0xff01: "renegotiation_info",
}
TLS_CIPHER_NAMES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
}

# ====== Enhanced TLS Parser ======
def parse_client_hello(payload: bytes) -> Optional[Dict[str, Any]]:
    """Улучшенный парсер TLS ClientHello из сырого TCP payload."""
    try:
        pos = 0
        while pos + 5 <= len(payload):
            ct = payload[pos]
            ver = int.from_bytes(payload[pos+1:pos+3], "big")
            rec_len = int.from_bytes(payload[pos+3:pos+5], "big")
            pos += 5

            if pos + rec_len > len(payload):
                break

            rec = payload[pos:pos+rec_len]
            pos += rec_len

            # TLS handshake record
            if ct != 0x16 or len(rec) < 4:
                continue

            hs_type = rec[0]
            hs_len = int.from_bytes(rec[1:4], "big")
            
            # ClientHello handshake type
            if hs_type != 0x01:
                continue

            body = rec[4:4+hs_len] if 4+hs_len <= len(rec) else rec[4:]
            off = 0

            if len(body) < 2+32+1:
                return None

            # Client Version
            client_version = int.from_bytes(body[off:off+2], "big"); off += 2
            # Random (32 bytes)
            off += 32
            # Session ID
            sid_len = body[off]; off += 1
            off += sid_len

            if off + 2 > len(body):
                return None

            # Cipher Suites
            cs_len = int.from_bytes(body[off:off+2], "big"); off += 2
            cs_bytes = body[off:off+cs_len]; off += cs_len
            cipher_suites_raw = []
            for i in range(0, len(cs_bytes), 2):
                if i+1 < len(cs_bytes):
                    cipher_suites_raw.append((cs_bytes[i] << 8) | cs_bytes[i+1])

            # Compression Methods
            if off >= len(body):
                return None
            comp_len = body[off]; off += 1
            off += comp_len

            # Extensions
            sni_list, exts, alpn_list, sup_ver, sig_algs, groups, points = [], [], [], [], [], [], []
            if off + 2 <= len(body):
                ext_total = int.from_bytes(body[off:off+2], "big"); off += 2
                ext_end = off + ext_total

                while off + 4 <= len(body) and off < ext_end:
                    et = int.from_bytes(body[off:off+2], "big")
                    el = int.from_bytes(body[off+2:off+4], "big")
                    off += 4
                    ed = body[off:off+el]; off += el

                    ext_name = TLS_EXT_NAMES.get(et, f"ext_{et:04x}")
                    exts.append(ext_name)

                    if et == 0x0000 and len(ed) >= 2: # SNI
                        try:
                            lst_len = int.from_bytes(ed[0:2], "big"); p = 2
                            endp = min(len(ed), 2+lst_len)
                            while p + 3 <= endp:
                                nt = ed[p]; p += 1
                                nl = int.from_bytes(ed[p:p+2], "big"); p += 2
                                host = ed[p:p+nl].decode("utf-8","ignore"); p += nl
                                if nt == 0 and host:
                                    sni_list.append(host)
                        except Exception:
                            pass
                    elif et == 0x0010 and len(ed) >= 2: # ALPN
                        try:
                            lst_len = int.from_bytes(ed[0:2], "big"); p = 2
                            endp = min(len(ed), 2+lst_len)
                            while p + 1 <= endp:
                                nlen = ed[p]; p += 1
                                proto = ed[p:p+nlen].decode("ascii","ignore"); p += nlen
                                if proto:
                                    alpn_list.append(proto)
                        except Exception:
                            pass
                    elif et == 0x002b and len(ed) >= 1: # Supported Versions
                        try:
                            vlen = ed[0]; p = 1
                            for i in range(0, vlen, 2):
                                if p+i+1 < len(ed):
                                    vc = int.from_bytes(ed[p+i:p+i+2], "big")
                                    sup_ver.append(TLS_VER_MAP.get(vc, f"0x{vc:04x}"))
                        except Exception:
                            pass
                    elif et == 0x000d and len(ed) >= 2: # Signature Algorithms
                        try:
                            alg_len = int.from_bytes(ed[0:2], "big"); p = 2
                            for i in range(0, alg_len, 2):
                                if p+i+1 < len(ed):
                                    alg = int.from_bytes(ed[p+i:p+i+2], "big")
                                    sig_algs.append(f"0x{alg:04x}")
                        except Exception:
                            pass
                    elif et == 0x000a and len(ed) >= 2: # Supported Groups
                        try:
                            g_len = int.from_bytes(ed[0:2], "big"); p = 2
                            for i in range(0, g_len, 2):
                                if p+i+1 < len(ed):
                                    g = int.from_bytes(ed[p+i:p+i+2], "big")
                                    groups.append(f"0x{g:04x}")
                        except Exception:
                            pass
                    elif et == 0x000b and len(ed) >= 1: # EC Point Formats
                        try:
                            pf_len = ed[0]; p = 1
                            for i in range(pf_len):
                                if p+i < len(ed):
                                    pf = ed[p+i]
                                    points.append(f"0x{pf:02x}")
                        except Exception:
                            pass

            # Human-readable cipher names
            cipher_suites = [TLS_CIPHER_NAMES.get(c, f"0x{c:04x}") for c in cipher_suites_raw]

            return {
                "is_client_hello": True,
                "record_version": TLS_VER_MAP.get(ver, f"0x{ver:04x}"),
                "client_version": TLS_VER_MAP.get(client_version, f"0x{client_version:04x}"),
                "sni": sni_list,
                "cipher_suites": cipher_suites,
                "cipher_suites_raw": cipher_suites_raw,
                "extensions": exts,
                "alpn": alpn_list,
                "supported_versions": sup_ver,
                "signature_algorithms": sig_algs,
                "supported_groups": groups,
                "ec_point_formats": points,
                "ch_length": hs_len,
            }
    except Exception as e:
        # logging.debug(f"Error parsing ClientHello: {e}") # Может быть шумно
        return None
    return None

# ====== robust field access ======
def get_first(d: Dict[str, Any], keys: List[str], default=None):
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return default

def detect_trigger_index(t: Dict[str, Any]) -> Optional[int]:
    tp = t.get("trigger_packet") or t.get("trigger") or {}
    if isinstance(tp, dict):
        n = get_first(tp, ["num","index","idx","packet_no","packet_num"])
        if isinstance(n, int):
            return n
    candidates = [
        "trigger_pkt_no","trigger_index","trigger_packet_no","trigger_pkt_idx",
        "suspected_trigger_index","suspected_trigger_no","trigger_num"
    ]
    n = get_first(t, candidates)
    if isinstance(n, int):
        return n
    for k, v in t.items():
        kl = str(k).lower()
        if "trigger" in kl and any(x in kl for x in ("num","index","idx","no")) and isinstance(v, int):
            return v
    return None

def detect_rst_index(t: Dict[str, Any]) -> Optional[int]:
    n = get_first(t, ["rst_packet_num","rst_packet_no","rst_index","rst_pkt_no","rst_num"])
    if isinstance(n, int):
        return n
    for k, v in t.items():
        kl = str(k).lower()
        if "rst" in kl and any(x in kl for x in ("num","index","idx","no")) and isinstance(v, int):
            return v
    return None

def format_stream_label_from_pkt(pkt) -> Optional[str]:
    try:
        if IP in pkt and TCP in pkt:
            return f"{pkt[IP].src}:{pkt[TCP].sport}-{pkt[IP].dst}:{pkt[TCP].dport}"
        if IPv6 in pkt and TCP in pkt:
            return f"[{pkt[IPv6].src}]:{pkt[TCP].sport}-[{pkt[IPv6].dst}]:{pkt[TCP].dport}"
    except Exception:
        pass
    return None

def get_stream_label(trigger: Dict[str, Any], pcap_file: str, idx_hint: Optional[int]) -> str:
    s = get_first(trigger, ["stream_id","stream","flow","flow_id","five_tuple","label"])
    if isinstance(s, str):
        return s
    if not SCAPY_AVAILABLE or not isinstance(idx_hint, int):
        return "<unknown>"
    
    i = 0
    with PcapReader(pcap_file) as pr:
        for pkt in pr:
            i += 1
            if i == idx_hint:
                lbl = format_stream_label_from_pkt(pkt)
                return lbl or "<unknown>"
    return "<unknown>"

def read_payload_by_index(pcap_file: str, idx: int) -> bytes:
    if not SCAPY_AVAILABLE:
        return b""
    i = 0
    with PcapReader(pcap_file) as pr:
        for pkt in pr:
            i += 1
            if i == idx:
                try:
                    if TCP in pkt:
                        return bytes(pkt[TCP].payload) if pkt[TCP].payload else b""
                except Exception:
                    return b""
                return b""
    return b""

def reassemble_clienthello(pcap_file: str, idx: int, max_back: int = 10) -> Tuple[bytes, Optional[str]]:
    """Собираем несколько предыдущих payload’ов того же 4‑tuple и того же направления."""
    if not SCAPY_AVAILABLE:
        return b"", None

    trigger_pkt = None
    i = 0
    with PcapReader(pcap_file) as pr:
        for pkt in pr:
            i += 1
            if i == idx:
                trigger_pkt = pkt
                break

    if trigger_pkt is None or TCP not in trigger_pkt:
        return b"", None

    lbl = format_stream_label_from_pkt(trigger_pkt)

    def key_tuple(pkt):
        if IP in pkt and TCP in pkt:
            return (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
        if IPv6 in pkt and TCP in pkt:
            return (pkt[IPv6].src, pkt[TCP].sport, pkt[IPv6].dst, pkt[TCP].dport)
        return None

    k_target = key_tuple(trigger_pkt)
    if not k_target:
        return b"", lbl

    window: List[bytes] = []
    j = 0
    with PcapReader(pcap_file) as pr:
        for pkt in pr:
            j += 1
            if j > idx:
                break
            try:
                if TCP in pkt and key_tuple(pkt) == k_target:
                    raw = bytes(pkt[TCP].payload) if pkt[TCP].payload else b""
                    if raw:
                        window.append(raw)
                        if len(window) > max_back:
                            window.pop(0) # FIFO
            except Exception:
                pass # Пропускаем пакеты, которые не удается обработать

    assembled = b"".join(window)
    return assembled, lbl

def print_tls_summary(idx: int, payload: bytes):
    details = parse_client_hello(payload)
    print(f"\n  [TLS анализ триггерного пакета #{idx}]")
    if not payload:
        print("   • Нет TCP payload (пусто)")
        return
    if not details or not details.get("is_client_hello"):
        print("   • ClientHello не обнаружен (возможна фрагментация или другой тип данных)")
        if len(payload) >= 5:
            ct = payload[0]; ver = int.from_bytes(payload[1:3], "big")
            print(f"   • Первый TLS record: type=0x{ct:02x}, ver={TLS_VER_MAP.get(ver, f'0x{ver:04x}')}, len={int.from_bytes(payload[3:5],'big')}")
        return

    sni = details.get("sni", [])
    ciphers = details.get("cipher_suites", [])
    exts = details.get("extensions", [])
    alpn = details.get("alpn", [])
    vers = details.get("supported_versions", [])
    rec_ver = details.get("record_version")
    cli_ver = details.get("client_version")
    ch_len = details.get("ch_length", 0)
    sig_algs = details.get("signature_algorithms", [])
    groups = details.get("supported_groups", [])
    points = details.get("ec_point_formats", [])

    print(f"   • TLS Record Version: {rec_ver}, Client Version (hello): {cli_ver}, CH length: {ch_len}")
    print(f"   • SNI: {', '.join(sni) if sni else '<не указано>'}")
    if vers: print(f"   • Supported Versions: {', '.join(vers)}")
    if alpn: print(f"   • ALPN: {', '.join(alpn)}")
    if sig_algs: print(f"   • Signature Algs (first 5): {', '.join(sig_algs[:5])}{'...' if len(sig_algs) > 5 else ''}")
    if groups: print(f"   • Supported Groups (first 5): {', '.join(groups[:5])}{'...' if len(groups) > 5 else ''}")
    if points: print(f"   • EC Point Formats: {', '.join(points)}")
    if exts:
        ext_show = ", ".join(exts[:10]) + (", …" if len(exts) > 10 else "")
        print(f"   • Extensions ({len(exts)}): {ext_show}")
    if ciphers:
        cshow = ", ".join(ciphers[:12]) + (", …" if len(ciphers) > 12 else "")
        print(f"   • Cipher Suites ({len(ciphers)}): {cshow}")

# ====== Improved Strategy Recommendations ======
def generate_strategy_recs(tls: Dict[str, Any], trigger: Dict[str, Any]) -> List[Dict[str, Any]]:
    recs: List[Dict[str, Any]] = []
    reasons: List[str] = []

    def add(cmd: str, base: float, reason: str):
        recs.append({"cmd": cmd, "score": round(base, 3), "reason": reason})

    inj = bool(get_first(trigger, ["is_injected","dpi_injection","injection"], False))
    ttl_diff = get_first(trigger, ["ttl_difference","ttl_diff"], 0) or 0
    sni_list = tls.get("sni") or []
    sni_present = bool(sni_list)
    exts = tls.get("extensions") or []
    exts_count = len(exts)
    ch_len = int(tls.get("ch_length") or tls.get("clienthello_length") or 0)
    sv = [str(x) for x in (tls.get("supported_versions") or [])]
    alpn = [str(x) for x in (tls.get("alpn") or [])]
    cipher_count = len(tls.get("cipher_suites", []))
    sig_algs = tls.get("signature_algorithms", [])
    groups = tls.get("supported_groups", [])
    points = tls.get("ec_point_formats", [])

    has_tls13 = any("1.3" in v for v in sv)
    has_h2 = any(v == "h2" for v in alpn)
    has_tls12 = any("1.2" in v for v in sv)
    has_h3 = any(v == "h3" for v in alpn)

    # --- Приоритетные признаки ---
    # 1. Инъекция RST
    if inj or ttl_diff >= 4:
        reasons.append("RST инъекция")
        add("--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-fooling=badsum",
            0.85, "RST инъекция — fake с badsum, низкий TTL")
        add("--dpi-desync=fake --dpi-desync-ttl=2 --dpi-desync-fooling=badsum,badseq",
            0.80, "RST инъекция — fake с badsum и badseq")
        add("--dpi-desync=fake,disorder --dpi-desync-ttl=2 --dpi-desync-fooling=badsum",
            0.78, "RST инъекция — fake+disorder с fooling")

    # 2. Чувствительность к SNI
    if sni_present:
        reasons.append("SNI")
        sni_host = sni_list[0]
        add(f"--dpi-desync=split --dpi-desync-split-pos=midsld --dpi-desync-ttl=2 --dpi-desync-sni={sni_host}",
            0.75, f"SNI={sni_host} — split по SLD")
        add(f"--dpi-desync=fake,split --dpi-desync-split-pos=prefix --dpi-desync-ttl=1 --dpi-desync-fooling=badsum",
            0.72, f"SNI={sni_host} — fake+split до SNI")
        add(f"--dpi-desync=split --dpi-desync-split-pos=10 --dpi-desync-ttl=3",
            0.70, f"SNI={sni_host} — split по фикс. позиции")

    # 3. TLS 1.3
    if has_tls13:
        reasons.append("TLS 1.3")
        add("--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-ttl=2 --dpi-desync-fooling=badseq",
            0.70, "TLS 1.3 — сдвиг первых байт с badseq")
        add("--dpi-desync=split --dpi-desync-split-pos=10 --dpi-desync-ttl=3",
            0.65, "TLS 1.3 — фрагментация раннего CH")
        add("--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-split-seqovl=10 --dpi-desync-ttl=4",
            0.60, "TLS 1.3 — мульти-фрагментация")

    # 4. ALPN h2/h3
    if has_h2 or has_h3:
        reasons.append("HTTP/2 или HTTP/3")
        alpn_str = "h2" if has_h2 else "h3"
        add(f"--dpi-desync=multisplit --dpi-desync-split-count=4 --dpi-desync-split-seqovl=15 --dpi-desync-ttl=4 --dpi-desync-repeats=2 --dpi-desync-alpn={alpn_str}",
            0.75, f"ALPN {alpn_str} — мульти-фрагментация + повторы")
        add(f"--dpi-desync=split --dpi-desync-split-pos=prefix --dpi-desync-ttl=3 --dpi-desync-alpn={alpn_str}",
            0.68, f"ALPN {alpn_str} — split до ALPN")

    # 5. Крупный ClientHello
    if ch_len >= 350 or exts_count >= 14 or cipher_count >= 20:
        reasons.append("Крупный CH")
        add("--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=20 --dpi-desync-ttl=4",
            0.72, f"Крупный CH ({ch_len}b/{exts_count}ext/{cipher_count}ciphers) — мульти-фрагментация")
        add("--dpi-desync=multidisorder --dpi-desync-split-count=5 --dpi-desync-ttl=8",
            0.65, "Крупный CH — мульти-перестановка")

    # 6. TLS 1.2
    if has_tls12 and not has_tls13:
        reasons.append("TLS 1.2")
        add("--dpi-desync=fake --dpi-desync-ttl=2 --dpi-desync-fooling=badsum",
            0.65, "TLS 1.2 — fake с fooling")
        add("--dpi-desync=split --dpi-desync-split-pos=3 --dpi-desync-ttl=2",
            0.60, "TLS 1.2 — split начальных байт")

    # --- Дополнительные признаки ---
    # Много сигнатур
    if len(sig_algs) > 10:
        reasons.append("Много сигнатур")
        add("--dpi-desync=disorder --dpi-desync-ttl=3",
            0.58, f"Много сигнатур ({len(sig_algs)}) — перестановка")

    # Много групп
    if len(groups) > 10:
        reasons.append("Много групп")
        add("--dpi-desync=split --dpi-desync-split-pos=25 --dpi-desync-ttl=3",
            0.55, f"Много групп ({len(groups)}) — split внутри")

    # --- Универсальные ---
    if not reasons:
        reasons.append("Универсальный")
        add("--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-ttl=2 --dpi-desync-fooling=badsum",
            0.50, "Универсальная комбинация")
        add("--dpi-desync=multisplit --dpi-desync-split-count=4 --dpi-desync-split-seqovl=10 --dpi-desync-ttl=4",
            0.45, "Универсальная мульти-фрагментация")

    # --- Дедупликация и сортировка ---
    seen, uniq = set(), []
    for r in recs:
        if r["cmd"] in seen:
            continue
        seen.add(r["cmd"])
        uniq.append(r)

    uniq.sort(key=lambda x: x["score"], reverse=True)
    # print(f"DEBUG: Generated {len(uniq)} unique strategies based on: {', '.join(reasons)}") # Отладка
    return uniq[:6]

def build_json_report(pcap_file: str, triggers: List[Dict[str, Any]], no_reassemble: bool) -> Dict[str, Any]:
    report = {
        "pcap_file": pcap_file,
        "analysis_timestamp": datetime.now().isoformat(),
        "incident_count": len(triggers),
        "incidents": []
    }

    for t in triggers:
        trig_idx = detect_trigger_index(t)
        rst_idx = detect_rst_index(t)
        tp = t.get("trigger_packet") or {}
        raw = tp.get("raw_data") or tp.get("payload") if isinstance(tp, dict) else None
        if raw is None and isinstance(trig_idx, int):
            raw = read_payload_by_index(pcap_file, trig_idx)

        assembled = None
        if not no_reassemble and isinstance(trig_idx, int):
            assembled, _ = reassemble_clienthello(pcap_file, trig_idx, max_back=10)

        stream_label = get_stream_label(t, pcap_file, trig_idx or rst_idx)

        payload_for_parse = (assembled or b"") if assembled else (raw or b"")
        tls = parse_client_hello(payload_for_parse) or {}
        recs = generate_strategy_recs(tls, t)

        incident = {
            "stream": stream_label,
            "rst_index": rst_idx,
            "trigger_index": trig_idx,
            "injected": bool(get_first(t, ["is_injected","dpi_injection","injection"], False)),
            "ttl_rst": get_first(t, ["rst_ttl","ttl_rst","rst_ttl_value"]),
            "expected_ttl": get_first(t, ["expected_ttl","server_ttl"]),
            "ttl_difference": get_first(t, ["ttl_difference","ttl_diff"]),
            "time_delta": get_first(t, ["time_delta","dt"]),
            "tls": {
                "is_client_hello": tls.get("is_client_hello", False),
                "record_version": tls.get("record_version"),
                "client_version": tls.get("client_version"),
                "sni": tls.get("sni") or [],
                "cipher_suites": tls.get("cipher_suites") or [],
                "cipher_suites_raw": tls.get("cipher_suites_raw") or [],
                "extensions": tls.get("extensions") or [],
                "alpn": tls.get("alpn") or [],
                "supported_versions": tls.get("supported_versions") or [],
                "signature_algorithms": tls.get("signature_algorithms") or [],
                "supported_groups": tls.get("supported_groups") or [],
                "ec_point_formats": tls.get("ec_point_formats") or [],
                "ch_length": tls.get("ch_length"),
            },
            "payload_preview_hex": (payload_for_parse[:64].hex() if payload_for_parse else ""),
            "recommended_strategies": recs
        }
        report["incidents"].append(incident)

    return report

# ====== Second Pass (Enhanced) ======
async def run_second_pass_from_report(report: Dict[str, Any], limit: int, port: int, engine_override: Optional[str]):
    if not HYBRID_AVAILABLE:
        print("[INFO] HybridEngine/DoHResolver недоступны — второй прогон пропущен.")
        return

    # Сгруппируем рекомендации по доменам (SNI), fallback на dst IP из stream
    host_to_strats: Dict[str, List[str]] = {}
    for inc in report.get("incidents", []):
        tls = inc.get("tls", {}) or {}
        sni_list = tls.get("sni") or []
        recs = inc.get("recommended_strategies") or []
        if recs:
            # целевой host
            if sni_list:
                host = sni_list[0]
            else:
                # stream "a:b-c:d"
                stream = inc.get("stream") or ""
                try:
                    dst_part = stream.split("-")[1]
                    host = dst_part.split(":")[0].strip("[]") # Убираем квадратные скобки IPv6
                except Exception:
                    host = None
            if not host:
                continue
            cmds = [r["cmd"] for r in recs[:max(1, limit)]]
            host_to_strats.setdefault(host, [])
            for c in cmds:
                if c not in host_to_strats[host]:
                    host_to_strats[host].append(c)

    if not host_to_strats:
        print("[INFO] Нет стратегий для второго прогона (реков не найдено).")
        return

    resolver = DoHResolver()
    engine = HybridEngine(debug=False, enable_enhanced_tracking=False, enable_online_optimization=False)
    all_results: Dict[str, Any] = {}

    for host, strategies in host_to_strats.items():
        try:
            ip = await resolver.resolve(host)
        except Exception:
            ip = None
        if not ip:
            # попробуем использовать host как IP
            ip = host if host and (host.replace(".", "").isdigit() or ':' in host) else None
        dns_cache = {host: ip} if ip else {}
        test_site = f"https://{host}"
        ips = {ip} if ip else set()
        print(f"\n[2nd pass] {host}: {len(strategies)} стратегий, ip={ip or 'N/A'}")

        # прогон через HybridEngine
        try:
            results = await engine.test_strategies_hybrid(
                strategies=strategies,
                test_sites=[test_site],
                ips=ips,
                dns_cache=dns_cache,
                port=port,
                domain=host,
                fast_filter=True,
                initial_ttl=None,
                enable_fingerprinting=False,
                engine_override=engine_override,
                telemetry_full=False,
                capturer=None,
                fingerprint=None
            )
            all_results[host] = results
            # быстрая сводка
            best = [r for r in results if r.get("success_rate", 0) > 0]
            if best:
                b0 = best[0]
                print(f"   ✓ best: {b0['strategy']} (rate={b0['success_rate']:.0%}, {b0['avg_latency_ms']:.1f}ms)")
            else:
                print("   ✗ нет успехов на втором прогоне")
        except Exception as e:
            print(f"   [WARN] second pass failed for {host}: {e}")

    # сохраним репорт
    out_name = f"pcap_second_pass_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        with open(out_name, "w", encoding="utf-8") as f:
            json.dump(all_results, f, ensure_ascii=False, indent=2)
        print(f"\n[OK] second-pass results saved → {out_name}")
    except Exception as e:
        print(f"[WARN] cannot save second-pass file: {e}")

def main():
    parser = argparse.ArgumentParser(description="Находит RST‑триггеры в PCAP, вытаскивает TLS ClientHello и генерит рекомендации стратегий. Может запустить второй прогон через HybridEngine.")
    parser.add_argument("pcap_file", help="Путь к PCAP‑файлу")
    parser.add_argument("--no-reassemble", action="store_true", help="Не пытаться собирать фрагментированный ClientHello")
    parser.add_argument("--json", action="store_true", help="Вывести результат в JSON (stdout)")
    parser.add_argument("--json-file", type=str, help="Сохранить результат в JSON‑файл")
    parser.add_argument("--second-pass", action="store_true", help="Запустить второй прогон стратегий (pcap‑driven) через HybridEngine")
    parser.add_argument("--second-pass-limit", type=int, default=6, help="Сколько стратегий на домен во втором прогоне (default: 6)")
    parser.add_argument("--second-pass-port", type=int, default=443, help="Порт второго прогона (default: 443)")
    parser.add_argument("--engine-override", choices=["native","external"], default=None, help="Принудительный движок для второго прогона")

    args = parser.parse_args()

    if not os.path.exists(args.pcap_file):
        print(f"[ERROR] Файл не найден: {args.pcap_file}", file=sys.stderr)
        sys.exit(1)

    analyzer = RSTTriggerAnalyzer(args.pcap_file)
    triggers = analyzer.analyze()

    # JSON/текстовый отчёт + TLS + рекомендации
    if not SCAPY_AVAILABLE:
        report = {"pcap_file": args.pcap_file, "incident_count": len(triggers), "incidents": triggers}
    else:
        report = build_json_report(args.pcap_file, triggers, args.no_reassemble)

    if args.json or args.json_file:
        if args.json_file:
            try:
                with open(args.json_file, "w", encoding="utf-8") as f:
                    json.dump(report, f, ensure_ascii=False, indent=2)
                print(f"[OK] JSON сохранён в {args.json_file}")
            except Exception as e:
                print(f"[ERROR] Не удалось сохранить JSON: {e}", file=sys.stderr)
                sys.exit(2)
        else:
            print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        # Человекочитаемый вывод
        analyzer.print_report(triggers)
        if SCAPY_AVAILABLE and report.get("incidents"):
            print("\n[PCAP → TLS] Детали ClientHello и рекомендации")
            for inc in report["incidents"]:
                trig_idx = inc.get("trigger_index")
                rst_idx = inc.get("rst_index")
                print("\n============================================================")
                print(f"Поток: {inc.get('stream', '<unknown>')}")
                if isinstance(rst_idx, int): print(f"RST получен в пакете: {rst_idx}")
                if isinstance(trig_idx, int): print(f"Вероятный триггер: пакет #{trig_idx}")

                tls = inc.get("tls", {}) or {}
                if tls.get("is_client_hello"):
                    print(f"  • SNI: {', '.join(tls.get('sni') or []) or '<не указано>'}")
                    print(f"  • ALPN: {', '.join(tls.get('alpn') or []) or '<не указано>'}")
                    print(f"  • TLS Versions: {', '.join(tls.get('supported_versions') or []) or '<не указано>'}")
                    print(f"  • CH length: {tls.get('ch_length')}")
                    print(f"  • Extensions count: {len(tls.get('extensions', []))}")
                    print(f"  • Cipher suites count: {len(tls.get('cipher_suites', []))}")

                # рекомендации
                recs = inc.get("recommended_strategies") or []
                if recs:
                    print("\n  РЕКОМЕНДАЦИИ ПО СТРАТЕГИЯМ:")
                    for r in recs[:3]:
                        print(f"   • {r['cmd']}   [{r['score']:.2f}] — {r['reason']}")
                else:
                    print("\n  РЕКОМЕНДАЦИИ ПО СТРАТЕГИЯМ: (не найдено)")

    # Второй прогон (опционально)
    if args.second_pass:
        asyncio.run(run_second_pass_from_report(report, limit=args.second_pass_limit, port=args.second_pass_port, engine_override=args.engine_override))

if __name__ == "__main__":
    main()