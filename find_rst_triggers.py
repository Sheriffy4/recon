# --- START OF FILE find_rst_triggers.py (UPGRADED WITH FLOW FAILURE ANALYSIS) ---

import argparse
import sys
import os
import json
import asyncio
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple, Set, Iterable
import logging
import socket
import time
import struct
from collections import Counter, defaultdict, namedtuple
import math
import ipaddress
# EXPERT 2: New imports for enhanced analysis
from enum import Enum
from dataclasses import dataclass, field
from typing import NamedTuple


# Подавляем излишне "шумные" предупреждения от Scapy TLS
logging.getLogger("scapy.layers.ssl_tls").setLevel(logging.ERROR)
LOG = logging.getLogger("find_rst_triggers")
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

# Добавляем корень проекта в путь
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from core.pcap.rst_analyzer import RSTTriggerAnalyzer

try:
    # pcap_inspect.py из вашего проекта
    from pcap_inspect import inspect_pcap, AttackValidator
    PCAP_INSPECT_AVAILABLE = True
except Exception as e:
    print(f"[WARNING] pcap_inspect unavailable: {e}")
    PCAP_INSPECT_AVAILABLE = False


# Попытка импортировать scapy для доступа к payload/переассемблированию
try:
    from scapy.all import PcapReader, TCP, IP, IPv6, Raw, rdpcap, wrpcap, Scapy_Exception
    SCAPY_AVAILABLE = True
except ImportError as e:
    print(f"[WARNING] Scapy недоступен: {e}")
    SCAPY_AVAILABLE = False

# NEW: optional integrations
try:
    from core.reporting.advanced_reporting_integration import (
        get_reporting_integration,
        initialize_advanced_reporting,
    )
    ADV_REPORTING_AVAILABLE = True
except Exception as e:
    print(f"[WARNING] AdvancedReportingIntegration unavailable: {e}")
    ADV_REPORTING_AVAILABLE = False

# Зависимости для расширенного анализа
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    print("[WARNING] NumPy не найден. Расширенный статистический анализ будет ограничен.")
    NUMPY_AVAILABLE = False

# Константа для синтетического SNI
FAKE_SNI_FALLBACK = "a.invalid"

# ====== TLS helpers ======
TLS_VER_MAP = {0x0301: "TLS1.0", 0x0302: "TLS1.1", 0x0303: "TLS1.2", 0x0304: "TLS1.3"}
TLS_EXT_NAMES = {
    0x0000: "server_name", 0x0005: "status_request", 0x000a: "supported_groups",
    0x000b: "ec_point_formats", 0x000d: "signature_algorithms", 0x0010: "alpn",
    0x0017: "sct", 0x0023: "extended_master_secret", 0x002b: "supported_versions",
    0x002d: "psk_key_exchange_modes", 0x0031: "pre_shared_key", 0x0033: "key_share",
    0xff01: "renegotiation_info",
    0xfe0d: "encrypted_client_hello", 0x0029: "pre_shared_key", 0x0015: "padding",
    0x0018: "token_binding", 0x754f: "channel_id",
}
TLS_CIPHER_NAMES = {
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256", 0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256", 0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", 0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384", 0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA", 0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
}

def is_grease(v: int) -> bool:
    try:
        return (v & 0x0F0F) == 0x0A0A
    except Exception:
        return False

def strip_grease_from_list(int_list: List[int]) -> List[int]:
    return [x for x in int_list if not is_grease(int(x))]

def find_clienthello_offset(payload: bytes) -> Optional[int]:
    if not payload or len(payload) < 6: return None
    limit = len(payload) - 6
    for i in range(limit):
        try:
            if payload[i] == 0x16 and payload[i+1] == 0x03 and payload[i+2] in (0x00, 0x01, 0x02, 0x03, 0x04):
                if payload[i+5] == 0x01:
                    return i
        except Exception:
            continue
    return None

def extract_sni_loose(payload: bytes) -> List[str]:
    snis: Set[str] = set()
    n = len(payload)
    i = 0
    while i + 9 <= n:
        if payload[i] == 0x00 and payload[i+1] == 0x00:
            try:
                ext_len = int.from_bytes(payload[i+2:i+4], "big")
                end_ext = i + 4 + ext_len
                if end_ext <= n and i + 6 <= end_ext:
                    list_len = int.from_bytes(payload[i+4:i+6], "big")
                    p = i + 6
                    if p + 3 <= end_ext:
                        name_type = payload[p]
                        name_len = int.from_bytes(payload[p+1:p+3], "big")
                        p += 3
                        if name_type == 0 and p + name_len <= end_ext and name_len > 0:
                            host = payload[p:p+name_len].decode("utf-8", "ignore").strip().lower()
                            if host and "." in host:
                                try:
                                    ipaddress.ip_address(host)
                                except ValueError:
                                    snis.add(host)
            except Exception:
                pass
        i += 1
    return sorted(snis)

def _iter_tls_record_starts(payload: bytes) -> Iterable[Tuple[int, int, int]]:
    i = 0
    while i + 5 <= len(payload):
        content_type = payload[i]
        if content_type in {20, 21, 22, 23}:
            version = int.from_bytes(payload[i+1:i+3], "big")
            if 0x0300 <= version <= 0x0304:
                length = int.from_bytes(payload[i+3:i+5], "big")
                if length > 0:
                    yield i, content_type, length
        i += 1

def parse_ech_extension(data: bytes) -> Dict[str, Any]:
    try:
        if len(data) < 4: return {}
        ech_version = int.from_bytes(data[0:2], 'big')
        config_id = data[2]
        return {'ech_supported': True, 'ech_version': ech_version, 'config_id': config_id, 'raw_length': len(data)}
    except Exception:
        return {}

def parse_key_share_extension(data: bytes) -> List[Dict[str, Any]]:
    shares = []
    try:
        if len(data) < 2: return shares
        total_len = int.from_bytes(data[0:2], 'big')
        pos = 2
        while pos + 4 <= len(data) and pos < total_len + 2:
            group = int.from_bytes(data[pos:pos+2], 'big')
            key_len = int.from_bytes(data[pos+2:pos+4], 'big')
            key_exchange = data[pos+4:pos+4+key_len] if key_len > 0 else b""
            shares.append({'group': f"0x{group:04x}", 'key_length': key_len, 'key_exchange_preview': key_exchange[:16].hex() if key_exchange else ""})
            pos += 4 + key_len
    except Exception:
        pass
    return shares

def parse_client_hello(payload: bytes) -> Optional[Dict[str, Any]]:
    try:
        start = find_clienthello_offset(payload)
        if start is None: return None
        pos = start
        if pos + 5 > len(payload): return None
        ct = payload[pos]
        rec_ver = int.from_bytes(payload[pos+1:pos+3], "big")
        rec_len = int.from_bytes(payload[pos+3:pos+5], "big")
        pos += 5
        rec_end = pos + rec_len
        rec = payload[pos:rec_end] if rec_end <= len(payload) else payload[pos:]
        if ct != 0x16 or len(rec) < 4: return None
        hs_type = rec[0]
        hs_len = int.from_bytes(rec[1:4], "big")
        if hs_type != 0x01: return None
        body = rec[4:4+hs_len] if 4+hs_len <= len(rec) else rec[4:]
        off = 0
        if len(body) < 2+32+1: return None
        client_version = int.from_bytes(body[off:off+2], "big"); off += 2
        off += 32
        sid_len = body[off]; off += 1
        off += sid_len
        if off + 2 > len(body): return None
        cs_len = int.from_bytes(body[off:off+2], "big"); off += 2
        cs_bytes = body[off:off+cs_len]; off += cs_len
        cipher_suites_raw = [(cs_bytes[i] << 8) | cs_bytes[i+1] for i in range(0, len(cs_bytes), 2) if i+1 < len(cs_bytes)]
        cipher_suites_raw = [c for c in cipher_suites_raw if isinstance(c, int)]
        cipher_suites_no_grease = strip_grease_from_list(cipher_suites_raw)
        if off >= len(body): return None
        comp_len = body[off]; off += 1
        off += comp_len
        tls_data = {}
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
                if et == 0x0000 and len(ed) >= 2:
                    try:
                        lst_len = int.from_bytes(ed[0:2], "big"); p = 2
                        endp = min(len(ed), 2+lst_len)
                        while p + 3 <= endp:
                            nt = ed[p]; p += 1
                            nl = int.from_bytes(ed[p:p+2], "big"); p += 2
                            host = ed[p:p+nl].decode("utf-8","ignore").strip().lower(); p += nl
                            if nt == 0 and host:
                                try:
                                    ipaddress.ip_address(host)
                                except ValueError:
                                    sni_list.append(host)
                    except Exception: pass
                elif et == 0x0010 and len(ed) >= 2:
                    try:
                        lst_len = int.from_bytes(ed[0:2], "big"); p = 2
                        endp = min(len(ed), 2+lst_len)
                        while p + 1 <= endp:
                            nlen = ed[p]; p += 1
                            proto = ed[p:p+nlen].decode("ascii","ignore"); p += nlen
                            if proto: alpn_list.append(proto)
                    except Exception: pass
                elif et == 0x002b and len(ed) >= 1:
                    try:
                        vlen = ed[0]; p = 1
                        tmp = []
                        for i in range(0, vlen, 2):
                            if p+i+1 < len(ed):
                                vc = int.from_bytes(ed[p+i:p+i+2], "big")
                                if not is_grease(vc):
                                    tmp.append(TLS_VER_MAP.get(vc, f"0x{vc:04x}"))
                        sup_ver = tmp
                    except Exception: pass
                elif et == 0x000d and len(ed) >= 2:
                    try:
                        alg_len = int.from_bytes(ed[0:2], "big"); p = 2
                        for i in range(0, alg_len, 2):
                            if p+i+1 < len(ed):
                                alg = int.from_bytes(ed[p+i:p+i+2], "big")
                                sig_algs.append(f"0x{alg:04x}")
                    except Exception: pass
                elif et == 0x000a and len(ed) >= 2:
                    try:
                        g_len = int.from_bytes(ed[0:2], "big"); p = 2
                        for i in range(0, g_len, 2):
                            if p+i+1 < len(ed):
                                g = int.from_bytes(ed[p+i:p+i+2], "big")
                                groups.append(f"0x{g:04x}")
                    except Exception: pass
                elif et == 0x000b and len(ed) >= 1:
                    try:
                        pf_len = ed[0]; p = 1
                        for i in range(pf_len):
                            if p+i < len(ed):
                                pf = ed[p+i]
                                points.append(f"0x{pf:02x}")
                    except Exception: pass
                elif et == 0x0033:
                    key_shares = parse_key_share_extension(ed)
                    if key_shares: tls_data["key_share"] = key_shares
                elif et == 0xfe0d:
                    ech_info = parse_ech_extension(ed)
                    if ech_info: tls_data["encrypted_client_hello"] = ech_info
                elif et == 0x0015:
                    tls_data["padding_length"] = el
                    tls_data["has_padding"] = True
        result = {
            "is_client_hello": True, "record_version": TLS_VER_MAP.get(rec_ver, f"0x{rec_ver:04x}"),
            "client_version": TLS_VER_MAP.get(client_version, f"0x{client_version:04x}"), "sni": sni_list,
            "cipher_suites": [TLS_CIPHER_NAMES.get(c, f"0x{c:04x}") for c in cipher_suites_no_grease],
            "cipher_suites_raw": cipher_suites_raw, "extensions": list(dict.fromkeys(exts)), "alpn": alpn_list,
            "supported_versions": sup_ver, "signature_algorithms": sig_algs, "supported_groups": groups,
            "ec_point_formats": points, "ch_length": len(body),
        }
        result.update(tls_data)
        return result
    except Exception:
        return None

class TCPStreamReassembler:
    """Правильная реассемблировка с учетом retransmissions, out-of-order, overlap"""
    def __init__(self):
        self.streams = {}
    
    def _detect_overlaps(self, sorted_segments: List[Tuple[int, bytes]]) -> List[Dict[str, int]]:
        """Обнаруживает перекрывающиеся сегменты."""
        overlaps = []
        if len(sorted_segments) < 2:
            return []

        last_seq, last_data = sorted_segments[0]
        last_end = last_seq + len(last_data)

        for seq, data in sorted_segments[1:]:
            if seq < last_end:
                overlap_amount = last_end - seq
                overlaps.append({"seq": seq, "overlap_bytes": overlap_amount})
            last_end = max(last_end, seq + len(data))
        return overlaps

    def _calculate_confidence(self, state: Dict) -> float:
        """Вычисляет оценку уверенности для сборки."""
        if not state.get('segments'):
            return 0.0

        confidence = 1.0
        # Штраф за повторные передачи
        if state.get('retrans_count', 0) > 0:
            confidence -= 0.1 * min(state['retrans_count'], 5)  # Макс. штраф 0.5

        # Штраф за пакеты не по порядку
        if state.get('out_of_order_count', 0) > 0:
            confidence -= 0.05 * min(state['out_of_order_count'], 4)  # Макс. штраф 0.2
        
        # Проверка на пропуски (gaps)
        sorted_keys = sorted(state['segments'].keys())
        gaps = 0
        if len(sorted_keys) > 1:
            last_end = sorted_keys[0] + len(state['segments'][sorted_keys[0]])
            for seq in sorted_keys[1:]:
                if seq > last_end:
                    gaps += 1
                last_end = max(last_end, seq + len(state['segments'][seq]))
        
        confidence -= 0.2 * min(gaps, 3)  # Макс. штраф 0.6 за пропуски

        return max(0.0, confidence)

    def _get_stream_key(self, pkt):
        try:
            if TCP in pkt:
                if IP in pkt:
                    return tuple(sorted(((pkt[IP].src, pkt[TCP].sport), (pkt[IP].dst, pkt[TCP].dport))))
                if IPv6 in pkt:
                    return tuple(sorted(((pkt[IPv6].src, pkt[TCP].sport), (pkt[IPv6].dst, pkt[TCP].dport))))
        except Exception:
            pass
        return None

    def _get_dir_key(self, pkt):
        if TCP in pkt:
            if IP in pkt:
                return (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
            if IPv6 in pkt:
                return (pkt[IPv6].src, pkt[TCP].sport, pkt[IPv6].dst, pkt[TCP].dport)
        return None

    def reassemble_stream(self, pcap_file: str, target_index: int) -> Tuple[bytes, Dict]:
        target_pkt = None
        with PcapReader(pcap_file) as pr:
            for idx, pkt in enumerate(pr, 1):
                if idx == target_index:
                    target_pkt = pkt
                    break
        if not target_pkt or TCP not in target_pkt: return b"", {}
        target_stream_key = self._get_stream_key(target_pkt)
        target_direction_key = self._get_dir_key(target_pkt)
        state = {'segments': {}, 'base_seq': None, 'retrans_count': 0, 'out_of_order_count': 0, 'max_seq_seen': 0}
        with PcapReader(pcap_file) as pr:
            for idx, pkt in enumerate(pr, 1):
                if idx > target_index: break
                if TCP not in pkt or self._get_stream_key(pkt) != target_stream_key: continue
                if self._get_dir_key(pkt) != target_direction_key: continue
                seq = int(pkt[TCP].seq)
                payload = bytes(pkt[TCP].payload) if pkt[TCP].payload else b""
                if not payload: continue
                if state['base_seq'] is None: state['base_seq'] = seq
                if seq < state['max_seq_seen']: state['out_of_order_count'] += 1
                if seq in state['segments']:
                    state['retrans_count'] += 1
                    if len(payload) > len(state['segments'][seq]): state['segments'][seq] = payload
                else:
                    state['segments'][seq] = payload
                state['max_seq_seen'] = max(state['max_seq_seen'], seq + len(payload))
        sorted_segments = sorted(state['segments'].items())
        assembled = b""
        if sorted_segments:
            assembled = sorted_segments[0][1]
            last_seq = sorted_segments[0][0]
            last_end = last_seq + len(assembled)
            for seq, data in sorted_segments[1:]:
                if seq < last_end:
                    overlap = last_end - seq
                    if overlap < len(data): assembled += data[overlap:]
                else:
                    assembled += data
                last_end = max(last_end, seq + len(data))
        ch_off = find_clienthello_offset(assembled)
        metadata = {
            'retransmissions': state['retrans_count'], 'out_of_order': state['out_of_order_count'],
            'overlaps': len(self._detect_overlaps([(s[0], s[1]) for s in sorted_segments])),
            'total_segments': len(state['segments']), 'reassembly_confidence': self._calculate_confidence(state),
            'clienthello_found': ch_off is not None, 'clienthello_offset': ch_off if ch_off is not None else -1,
        }
        return assembled, metadata

# Энтропийный анализ
def _detect_repetitive_patterns(payload: bytes, min_len=4) -> List[Tuple[bytes, int]]:
    """Находит повторяющиеся последовательности (признак padding/fingerprint)"""
    if not payload: return []
    patterns = {}
    for i in range(len(payload) - min_len):
        pattern = payload[i:i+min_len]
        patterns[pattern] = patterns.get(pattern, 0) + 1
    
    threshold = max(5, len(payload) / (256 ** min_len) * 3)
    return [(p, c) for p, c in patterns.items() if c > threshold]

def analyze_payload_entropy(payload: bytes) -> Dict[str, Any]:
    """Выявляет аномалии в энтропии для детекции DPI-фильтрации"""
    if not payload or len(payload) < 10:
        return {'entropy': 0, 'anomaly_score': 0}
    
    byte_counts = Counter(payload)
    entropy = -sum((count/len(payload)) * math.log2(count/len(payload)) for count in byte_counts.values())
    
    local_entropies = []
    if NUMPY_AVAILABLE:
        window_size = 16
        for i in range(0, len(payload) - window_size, window_size):
            window = payload[i:i+window_size]
            wc = Counter(window)
            we = -sum((c/window_size) * math.log2(c/window_size) for c in wc.values())
            local_entropies.append(we)
        entropy_variance = np.var(local_entropies) if local_entropies else 0.0
    else:
        entropy_variance = 0.0

    expected_freq = len(payload) / 256
    chi_square = sum((count - expected_freq)**2 / expected_freq for count in byte_counts.values()) if expected_freq > 0 else 0
    
    return {
        'global_entropy': entropy, 'local_entropy_variance': entropy_variance,
        'chi_square': chi_square, 'anomaly_score': entropy_variance * chi_square / 1000,
        'suspicious_patterns': _detect_repetitive_patterns(payload)
    }

class AdvancedSignatureAnalyzer:
    """Обнаруживает специфичные сигнатуры DPI по аномалиям в ClientHello"""
    
    def __init__(self):
        self.known_dpi_patterns = {
            'sni_length_trigger': lambda tls: self._check_sni_length(tls),
            'cipher_order_trigger': lambda tls: self._check_cipher_order(tls),
            'extension_order_trigger': lambda tls: self._check_extension_order(tls),
            'rare_extension_trigger': lambda tls: self._check_rare_extensions(tls),
            'padding_trigger': lambda tls: self._check_padding_pattern(tls),
            'ech_detection_trigger': lambda tls: self._check_ech_presence(tls),
        }
    
    def analyze_tls_fingerprint(self, tls_data: Dict) -> Dict[str, Any]:
        """Анализирует TLS отпечаток на предмет DPI-триггеров"""
        results = {}
        
        for pattern_name, checker in self.known_dpi_patterns.items():
            score, reason = checker(tls_data)
            if score > 0.3:
                results[pattern_name] = {
                    'score': score,
                    'reason': reason,
                    'mitigation': self._suggest_mitigation(pattern_name, tls_data)
                }
        
        return {
            'risk_score': sum(r['score'] for r in results.values()),
            'triggers': results,
            'recommended_evasions': self._generate_evasion_strategies(results)
        }
    
    def _check_sni_length(self, tls: Dict) -> Tuple[float, str]:
        sni_list = tls.get('sni', [])
        if not sni_list: return 0.0, ""
        sni = sni_list[0]
        if len(sni) > 64: return 0.8, f"Длинное SNI ({len(sni)} chars) может триггерить DPI"
        elif len(sni) < 4: return 0.6, f"Короткое SNI ({len(sni)} chars) подозрительно"
        return 0.0, ""
    
    def _check_cipher_order(self, tls: Dict) -> Tuple[float, str]:
        ciphers = tls.get('cipher_suites', [])
        if not ciphers: return 0.0, ""
        if ciphers and any("TLS_AES" in c for c in ciphers[:2]):
            return 0.0, "Нормальный порядок (TLS 1.3 сначала)"
        else:
            return 0.7, "Подозрительный порядок шифров (TLS 1.3 не в начале)"
    
    def _check_extension_order(self, tls: Dict) -> Tuple[float, str]:
        # Placeholder for more complex logic
        return 0.0, ""

    def _check_rare_extensions(self, tls: Dict) -> Tuple[float, str]:
        extensions = tls.get('extensions', [])
        rare_exts = {'token_binding', 'channel_id'}
        found_rare = rare_exts.intersection(extensions)
        if found_rare: return 0.9, f"Редкие расширения: {', '.join(found_rare)}"
        return 0.0, ""
    
    def _check_padding_pattern(self, tls: Dict) -> Tuple[float, str]:
        # Placeholder for more complex logic
        return 0.0, ""

    def _check_ech_presence(self, tls: Dict) -> Tuple[float, str]:
        if tls.get('encrypted_client_hello'):
            return 0.95, "Обнаружено Encrypted ClientHello (блокируется некоторыми DPI)"
        return 0.0, ""
    
    def _suggest_mitigation(self, pattern_name: str, tls_data: Dict) -> str:
        # Placeholder for mitigation logic
        return "No specific mitigation suggested."

    def _generate_evasion_strategies(self, triggers: Dict) -> List[str]:
        strategies = []
        if 'ech_detection_trigger' in triggers:
            strategies.append("--remove-extension=encrypted_client_hello")
        if 'rare_extension_trigger' in triggers:
            strategies.append("--strip-rare-extensions")
        if 'cipher_order_trigger' in triggers:
            strategies.append("--reorder-ciphers --tls13-first")
        if 'sni_length_trigger' in triggers:
            strategies.append("--randomize-sni-length --sni-padding")
        return strategies

# Статистический анализ паттернов
class BlockingPatternAnalyzer:
    """Выявляет статистические паттерны блокировок на основе множества инцидентов"""
    def __init__(self):
        self.patterns = {'sni_triggers': Counter(), 'cipher_correlations': Counter(), 'extension_patterns': Counter(), 'size_thresholds': [], 'timing_patterns': []}
    
    def _extract_domain_pattern(self, sni: str) -> str:
        parts = sni.split('.')
        return f"*.{'.'.join(parts[-2:])}" if len(parts) > 2 else sni

    def analyze_incidents(self, incidents: List[Dict]) -> Dict[str, Any]:
        """Кросс-анализ множества инцидентов"""
        if not incidents: return {}
        for inc in incidents:
            tls_data = inc.get('tls', {})
            if not tls_data: continue
            for sni in tls_data.get('sni', []): self.patterns['sni_triggers'][self._extract_domain_pattern(sni)] += 1
            ciphers = tuple(sorted(tls_data.get('cipher_suites_raw', [])))
            if ciphers: self.patterns['cipher_correlations'][ciphers] += 1
            exts = tuple(sorted(tls_data.get('extensions', [])))
            if exts: self.patterns['extension_patterns'][exts] += 1
            sz = tls_data.get('ch_length', None)
            try:
                if sz is not None and int(sz) > 0: self.patterns['size_thresholds'].append(int(sz))
            except Exception: pass
            self.patterns['timing_patterns'].append(inc.get('time_delta', 0) or 0)
        return {
            'sni_patterns': self.patterns['sni_triggers'].most_common(5),
            'cipher_triggers': self.patterns['cipher_correlations'].most_common(3),
            'extension_patterns': self.patterns['extension_patterns'].most_common(3),
            'size_boundaries': self._detect_size_clusters(self.patterns['size_thresholds']),
            'ttl_signature': self._analyze_ttl_distribution([i.get('ttl_difference',0) for i in incidents if i.get('ttl_difference')]),
        }

    def _detect_size_clusters(self, sizes: List[int]) -> Dict:
        if not sizes or not NUMPY_AVAILABLE: return {}
        clean = [int(s) for s in sizes if s is not None and int(s) > 0]
        if not clean: return {}
        arr = np.array(clean, dtype=int)
        return {'min': int(arr.min()), 'max': int(arr.max()), 'mean': float(arr.mean()), 'std': float(arr.std()), 'p25': int(np.percentile(arr, 25)), 'p75': int(np.percentile(arr, 75))}

    def _analyze_ttl_distribution(self, ttls: List[int]) -> Dict:
        if not ttls or not NUMPY_AVAILABLE: return {}
        clean = [int(t) for t in ttls if t is not None]
        if not clean: return {}
        arr = np.array(clean, dtype=int)
        return {'mean': float(arr.mean()), 'std': float(arr.std()), 'min': int(arr.min()), 'max': int(arr.max())}

# ====== robust field access ======
def get_first(d: Dict[str, Any], keys: List[str], default=None):
    for k in keys:
        if k in d and d[k] is not None: return d[k]
    return default

def detect_trigger_index(t: Dict[str, Any]) -> Optional[int]:
    tp = t.get("trigger_packet") or t.get("trigger") or {}
    if isinstance(tp, dict):
        n = get_first(tp, ["num","index","idx","packet_no","packet_num", "trigger_packet_index"])
        if isinstance(n, int): return n
    n = get_first(t, ["trigger_pkt_no","trigger_index","trigger_packet_no","trigger_pkt_idx","suspected_trigger_index","suspected_trigger_no","trigger_num", "trigger_packet_index"])
    if isinstance(n, int): return n
    for k, v in t.items():
        if "trigger" in str(k).lower() and any(x in str(k).lower() for x in ("num","index","idx","no")) and isinstance(v, int): return v
    return None

def detect_rst_index(t: Dict[str, Any]) -> Optional[int]:
    n = get_first(t, ["rst_packet_num","rst_packet_no","rst_index","rst_pkt_no","rst_num", "rst_packet_index"])
    if isinstance(n, int): return n
    for k, v in t.items():
        if "rst" in str(k).lower() and any(x in str(k).lower() for x in ("num","index","idx","no")) and isinstance(v, int): return v
    return None

def format_stream_label_from_pkt(pkt) -> Optional[str]:
    try:
        if IP in pkt and TCP in pkt: return f"{pkt[IP].src}:{pkt[TCP].sport}-{pkt[IP].dst}:{pkt[TCP].dport}"
        if IPv6 in pkt and TCP in pkt: return f"[{pkt[IPv6].src}]:{pkt[TCP].sport}-[{pkt[IPv6].dst}]:{pkt[TCP].dport}"
    except Exception: pass
    return None

def get_stream_label(trigger: Dict[str, Any], pcap_file: str, idx_hint: Optional[int]) -> str:
    s = get_first(trigger, ["stream_id","stream","flow","flow_id","five_tuple","label"])
    if isinstance(s, str): return s
    if not SCAPY_AVAILABLE or not isinstance(idx_hint, int): return "<unknown>"
    with PcapReader(pcap_file) as pr:
        for i, pkt in enumerate(pr, 1):
            if i == idx_hint: return format_stream_label_from_pkt(pkt) or "<unknown>"
    return "<unknown>"

def _crop_to_client_hello(data: bytes) -> bytes:
    # Находим первую TLS-запись с ClientHello и возвращаем с неё
    for start, ct, rec_len in _iter_tls_record_starts(data):
        rec = data[start+5:start+5+rec_len] if start+5+rec_len <= len(data) else data[start+5:]
        if ct == 0x16 and rec and rec[0] == 0x01:
            return data[start:]
    return data  # если не нашли — пусть парсер сам решает

def reassemble_clienthello(pcap_file: str, idx: int) -> Tuple[bytes, Optional[str], Dict]:
    if not SCAPY_AVAILABLE:
        return b"", None, {}
    reassembler = TCPStreamReassembler()
    assembled_payload, metadata = reassembler.reassemble_stream(pcap_file, idx)
    assembled_payload = _crop_to_client_hello(assembled_payload)

    lbl = None
    with PcapReader(pcap_file) as pr:
        for i, pkt in enumerate(pr, 1):
            if i == idx:
                lbl = format_stream_label_from_pkt(pkt)
                break
    return assembled_payload, lbl, metadata

def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False

def _synthesize_sni(tls: Dict[str, Any], trigger: Dict[str, Any], stream_label: Optional[str]) -> Optional[str]:
    sni_list = (tls.get("sni") or [])
    if sni_list:
        return sni_list[0]
    host = get_first(trigger, ["host","domain","target_host","server_name"])
    if isinstance(host, str) and "." in host and not _is_ip(host):
        return host.lower()
    if isinstance(stream_label, str) and "-" in stream_label:
        try:
            dst_part = stream_label.split("-")[1]
            h = dst_part.split(":")[0].strip("[]").lower()
            # --- НОВАЯ ПРОВЕРКА ---
            # Проверяем, что хост состоит из допустимых символов
            if all(c in "abcdefghijklmnopqrstuvwxyz0123456789.-" for c in h):
                if _is_ip(h):
                    return FAKE_SNI_FALLBACK
                if "." in h:
                    return h
            # --- КОНЕЦ ПРОВЕРКИ ---
        except Exception:
            pass
    return None

def generate_advanced_strategies(tls: Dict, triggers: Dict, entropy_data: Dict, 
                               signature_analysis: Dict) -> List[Dict[str, Any]]:
    strategies = []
    base_score = 0.5
    risk_score = signature_analysis.get('risk_score', 0)

    # ### START OF FIX ###
    # Translate abstract recommendations into concrete zapret-style commands.

    if tls.get('supported_versions'):
        if 'TLS1.3' in tls['supported_versions']:
            base_score += 0.2
            # This is a conceptual strategy; we map it to a robust fakeddisorder.
            strategies.append({'cmd': '--dpi-desync=fake,disorder --dpi-desync-split-pos=sni --dpi-desync-fooling=badsum,badseq', 'score': base_score, 'reason': 'Forcing TLS 1.3 behavior with a robust disorder attack', 'dpi_type': 'signature_based'})

    if tls.get('encrypted_client_hello'):
        # ECH is hard to bypass; suggest a strong fragmentation strategy.
        strategies.append({'cmd': '--dpi-desync=multisplit --dpi-desync-split-count=7 --dpi-desync-split-seqovl=10', 'score': 0.85, 'reason': 'Using multisplit fragmentation to bypass ECH inspection', 'dpi_type': 'sni_based'})
    else:
        # Map --fake-sni-random to a fake race attack.
        strategies.append({'cmd': '--dpi-desync=fake --dpi-desync-ttl=2 --dpi-desync-fooling=badsum', 'score': 0.75, 'reason': 'Using a fake packet race to hide real SNI', 'dpi_type': 'sni_based'})

    entropy_score = entropy_data.get('anomaly_score', 0)
    if entropy_score > 0.5:
        # Map --fragment-tls to a multisplit strategy.
        strategies.append({'cmd': '--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=15', 'score': 0.8, 'reason': f'High entropy ({entropy_score:.2f}) suggests fragmentation (multisplit)', 'dpi_type': 'entropy_based'})

    if tls.get('key_share'):
        key_share_groups = [ks.get('group', '') for ks in tls.get('key_share', [])]
        if len(key_share_groups) > 2:
            # Map --optimize-keyshare to a simple split at a safe position.
            strategies.append({'cmd': '--dpi-desync=split --dpi-desync-split-pos=128', 'score': 0.7, 'reason': f'Complex KeyShare groups; trying a simple split after headers', 'dpi_type': 'signature_based'})

    if triggers.get('injected') or triggers.get('ttl_difference', 0) > 4:
        # These are already good zapret-style commands.
        strategies.extend([
            {'cmd': '--dpi-desync=fake,disorder --dpi-desync-ttl=2 --dpi-desync-fooling=badsum,badseq --dpi-desync-split-pos=sni', 'score': 0.9, 'reason': 'Stateful DPI detected - full desynchronization', 'dpi_type': 'stateful'},
            {'cmd': '--dpi-desync=multisplit --dpi-desync-split-count=4 --dpi-desync-split-seqovl=10', 'score': 0.85, 'reason': 'Adaptive multi-fragmentation against stateful DPI', 'dpi_type': 'stateful'}
        ])
    
    # ### END OF FIX ###
    
    strategies.sort(key=lambda x: x['score'], reverse=True)
    return strategies[:8]



def locate_clienthello_start(pcap_file: str, idx_hint: int) -> Optional[int]:
    if not SCAPY_AVAILABLE or not isinstance(idx_hint, int) or idx_hint <= 0: return None
    target_pkt = None
    with PcapReader(pcap_file) as pr:
        for i, pkt in enumerate(pr, 1):
            if i == idx_hint:
                target_pkt = pkt
                break
    if not target_pkt or TCP not in target_pkt: return None
    def dir_key(pkt):
        if TCP in pkt:
            if IP in pkt: return (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
            if IPv6 in pkt: return (pkt[IPv6].src, pkt[TCP].sport, pkt[IPv6].dst, pkt[TCP].dport)
        return None
    stream_key = None
    if TCP in target_pkt:
        if IP in target_pkt: stream_key = tuple(sorted(((target_pkt[IP].src, target_pkt[TCP].sport), (target_pkt[IP].dst, target_pkt[TCP].dport))))
        elif IPv6 in target_pkt: stream_key = tuple(sorted(((target_pkt[IPv6].src, target_pkt[TCP].sport), (target_pkt[IPv6].dst, target_pkt[TCP].dport))))
    if not stream_key: return None
    tdir = dir_key(target_pkt)
    found_idx = None
    with PcapReader(pcap_file) as pr:
        for i, pkt in enumerate(pr, 1):
            if i > idx_hint: break
            if TCP in pkt:
                if IP in pkt: sk = tuple(sorted(((pkt[IP].src, pkt[TCP].sport), (pkt[IP].dst, pkt[TCP].dport))))
                elif IPv6 in pkt: sk = tuple(sorted(((pkt[IPv6].src, pkt[TCP].sport), (pkt[IPv6].dst, pkt[TCP].dport))))
                else: continue
                if sk != stream_key or dir_key(pkt) != tdir: continue
                raw = bytes(pkt[TCP].payload) if pkt[TCP].payload else b""
                if not raw: continue
                off = find_clienthello_offset(raw)
                if off is not None:
                    if found_idx is None: found_idx = i
    return found_idx

class AttackType(Enum):
    FAKEDDISORDER = "fakeddisorder"
    SPLIT = "split"
    MULTISPLIT = "multisplit"
    SEQOVL = "seqovl"
    FAKE_RACE = "fake_race"
    UNKNOWN = "unknown"

@dataclass
class PacketAnalysis:
    index: int
    ttl: int
    tcp_checksum: int
    tcp_checksum_valid: bool
    is_fake: bool
    fake_indicators: List[str] = field(default_factory=list)
    payload_len: int = 0
    seq: int = 0
    rel_seq: int = 0
    flags: str = ""
    has_md5sig: bool = False
    timestamp: float = 0.0

@dataclass 
class AttackDiagnosis:
    attack_type: AttackType
    confidence: float
    issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    packet_sequence: List[PacketAnalysis] = field(default_factory=list)

class FlowFailureAnalyzer:
    def __init__(self, pcap_file: str, local_ip: str, flow_port: int = 443, window_ms: float = 800.0):
        if not SCAPY_AVAILABLE: raise RuntimeError("Scapy не установлен, анализ невозможен.")
        self.pcap_file = pcap_file
        self.local_ip = local_ip
        self.flow_port = flow_port
        self.window_ms = window_ms
        self.flows = defaultdict(list)
        self.analysis_verdicts = Counter()

    def analyze(self):
        print("\n" + "="*80)
        print("🚀 ЗАПУСК РАСШИРЕННОЙ ДИАГНОСТИКИ СБОЕВ TCP-ПОТОКОВ (POST-BYPASS)")
        print("="*80)
        try:
            packets = rdpcap(self.pcap_file)
        except Scapy_Exception as e:
            LOG.error(f"Не удалось прочитать PCAP файл: {e}")
            return
        if not self.local_ip:
            self.local_ip = self._autodetect_local_ip(packets)
            if not self.local_ip:
                LOG.error("Не удалось определить локальный IP. Укажите его через --local-ip. Анализ остановлен.")
                return
        has_inbound_traffic = False
        for i, pkt in enumerate(packets):
            if TCP in pkt and IP in pkt:
                is_outbound = pkt[IP].src == self.local_ip
                if not is_outbound: has_inbound_traffic = True
                if is_outbound and int(pkt[TCP].dport) != self.flow_port: continue
                pkt.packet_num = i + 1
                flow_key = self._get_flow_key(pkt)
                if flow_key: self.flows[flow_key].append(pkt)
        if not has_inbound_traffic:
            print("\n" + "!"*80)
            print("! КРИТИЧЕСКОЕ ПРЕДУПРЕЖДЕНИЕ: В PCAP-ФАЙЛЕ ПОЛНОСТЬЮ ОТСУТСТВУЕТ ВХОДЯЩИЙ ТРАФИК!")
            print("! Анализ ответа сервера (ServerHello/RST) НЕВОЗМОЖЕН.")
            print("! ПРИЧИНА: Ваш фильтр захвата трафика (pydivert/WinPCAP) настроен НЕПРАВИЛЬНО.")
            print("! РЕШЕНИЕ: Убедитесь, что фильтр захватывает ОБА направления (inbound и outbound).")
            print("!"*80 + "\n")
        LOG.info(f"Найдено {len(self.flows)} TCP-потоков к порту {self.flow_port}.")
        failed_flows_count = 0
        for flow_key, stream_pkts in self.flows.items():
            if flow_key[0] != self.local_ip: continue
            analysis_result = self._analyze_stream(stream_pkts)
            if analysis_result["is_failed_bypass_attempt"]:
                failed_flows_count += 1
                self.analysis_verdicts[analysis_result["verdict"]] += 1
                self._print_stream_report(flow_key, analysis_result)
        self._print_summary_report(failed_flows_count)

    def _print_summary_report(self, failed_count: int):
        print("\n" + "="*80)
        print("🏁 АНАЛИЗ ЗАВЕРШЕН")
        print("="*80)
        if failed_count == 0:
            print("✅ Не найдено потоков с явными признаками неудачного обхода.")
            return
        print(f"Найдено {failed_count} подозрительных потоков. Статистика по вердиктам:")
        for verdict, count in self.analysis_verdicts.most_common():
            print(f"  - {verdict}: {count} раз")
        if self.analysis_verdicts:
            top_verdict = self.analysis_verdicts.most_common(1)[0][0]
            print("\n--- ОСНОВНАЯ РЕКОМЕНДАЦИЯ ---")
            if top_verdict == "ОШИБКА ЗАХВАТА ТРАФИКА":
                print("❗️ Ваша главная проблема - неправильная настройка захвата трафика. Вы не видите ответы сервера.")
                print("   Решение: Настройте pydivert/Wireshark для захвата и 'inbound', и 'outbound' трафика.")
            elif top_verdict == "РЕТРАНСМИССИЯ ОТ ОС":
                print("❗️ Ваша главная проблема - операционная система мешает вашей инъекции, отправляя свои пакеты.")
                print("   Решение: Ваш движок обхода ДОЛЖЕН блокировать оригинальный ClientHello от ОС.")
            elif top_verdict == "КРИТИЧЕСКАЯ ОШИБКА SEQ":
                 print("❗️ Ваша главная проблема - неверный расчёт TCP Sequence Number в реальных сегментах.")
                 print("   Решение: Перепроверьте логику: `new_seq = base_seq + rel_seq`. Ошибка в коде вашего движка.")
            elif top_verdict == "REAL ПАКЕТЫ С BAD CHECKSUM":
                 print("❗️ Ваша главная проблема - реальные (не фейковые) пакеты отправляются с неверной TCP checksum.")
                 print("   Решение: Убедитесь, что ваш PacketSender/Builder ПЕРЕСЧИТЫВАЕТ checksum для всех реальных пакетов.")
        print("="*80)

    def _analyze_stream(self, packets: List[Any]) -> Dict:
        report = {
            "is_failed_bypass_attempt": False,
            "checks": {},
            "verdict": "НЕИЗВЕСТНАЯ ОШИБКА",
            "recommendation": "Проверьте PCAP вручную."
        }
        outbound_pkts = [p for p in packets if p[IP].src == self.local_ip]
        inbound_pkts = [p for p in packets if p[IP].dst == self.local_ip]
        outbound_payload_pkts = [p for p in outbound_pkts if p[TCP].payload]
        if not outbound_payload_pkts or len(outbound_payload_pkts) < 2: return report
        out_win, in_win = self._select_attack_window(outbound_payload_pkts, inbound_pkts)
        if not out_win: return report
        
        report["checks"]["checksums"] = self._analyze_packet_checksums(out_win)
        report["checks"]["fake_packet"] = self._check_fake_packet(out_win)
        report["checks"]["reassembly"] = self._check_reassembly_smart(out_win)
        report["checks"]["server_response"] = self._check_server_response(in_win, out_win)

        reasm_check = report["checks"]["reassembly"]
        resp_check = report["checks"]["server_response"]
        checksum_check = report["checks"]["checksums"]

        if resp_check["pattern"] == "NO_INBOUND_CAPTURE":
            report["is_failed_bypass_attempt"] = True
            report["verdict"] = "ОШИБКА ЗАХВАТА ТРАФИКА"
            report["recommendation"] = "Настройте pydivert/Wireshark для захвата 'inbound' и 'outbound' трафика."
        elif checksum_check["status"] == "FAIL":
            report["is_failed_bypass_attempt"] = True
            report["verdict"] = "REAL ПАКЕТЫ С BAD CHECKSUM"
            report["recommendation"] = "КРИТИЧНО: Real пакеты имеют невалидную checksum! Проверьте, что corrupt_tcp_checksum применяется ТОЛЬКО к fake пакетам."
        elif reasm_check["status"] == "FAIL":
            report["is_failed_bypass_attempt"] = True
            report["verdict"] = "КРИТИЧЕСКАЯ ОШИБКА SEQ"
            report["recommendation"] = f"Неверный расчёт TCP SEQ. {reasm_check['details'][0]}"
        elif reasm_check["pattern"] == "DUPLICATES_FOUND":
            report["is_failed_bypass_attempt"] = True
            report["verdict"] = "РЕТРАНСМИССИЯ ОТ ОС"
            report["recommendation"] = "Ваш движок должен блокировать оригинальный пакет от ОС после инъекции."
        elif resp_check["pattern"] == "SH_RECEIVED":
            report["is_failed_bypass_attempt"] = False
            report["verdict"] = "УСПЕШНЫЙ ОБХОД"
            report["recommendation"] = "Стратегия сработала, ServerHello получен."
        elif resp_check["pattern"] in ("NO_RESPONSE_TIMEOUT", "NO_SERVER_HELLO_IN_BUFFER"):
            report["is_failed_bypass_attempt"] = True
            report["verdict"] = "СЕРВЕР НЕ ОТВЕЧАЕТ"
            report["recommendation"] = "Вероятно, реальные пакеты повреждены (bad checksum?) или сервер не может собрать ClientHello."
        
        return report

    def _analyze_packet_checksums(self, packets: List[Any]) -> Dict[str, Any]:
        results = {"status": "PASS", "details": [], "fake_packets": [], "real_packets": [], "checksum_issues": []}
        for i, pkt in enumerate(packets):
            is_fake = self._is_fake_pkt(pkt)
            try:
                if TCP in pkt:
                    tcp_original = pkt[TCP].chksum
                    pkt_copy = pkt.copy()
                    del pkt_copy[TCP].chksum
                    pkt_copy = IP(bytes(pkt_copy))
                    tcp_recalculated = pkt_copy[TCP].chksum
                    tcp_valid = (tcp_original == tcp_recalculated)
                    if not is_fake and not tcp_valid:
                        results["checksum_issues"].append(f"❌ КРИТИЧЕСКАЯ ОШИБКА: Real пакет #{i+1} имеет НЕВАЛИДНУЮ checksum (0x{tcp_original:04X} вместо 0x{tcp_recalculated:04X}).")
            except Exception as e:
                results["checksum_issues"].append(f"⚠️ Не удалось проверить пакет #{i+1}: {e}")
        if results["checksum_issues"]:
            results["status"] = "FAIL"
            results["details"] = results["checksum_issues"]
        else:
            results["details"] = ["✅ Все checksums корректны"]
        return results

    def _check_reassembly_smart(self, out_win: List[Any]) -> Dict:
        reals = [p for p in out_win if not self._is_fake_pkt(p)]
        if len(reals) < 2: return {"status": "SKIP", "pattern": "NOT_ENOUGH_REALS", "details": [f"Недостаточно real-сегментов ({len(reals)}) для анализа."]}
        segs = [(int(p[TCP].seq), len(bytes(p[TCP].payload) if p[TCP].payload else b""), p.packet_num) for p in reals]
        seq_counts = Counter(s[0] for s in segs)
        if any(c > 1 for c in seq_counts.values()):
            return {"status": "PASS", "pattern": "DUPLICATES_FOUND", "details": ["Обнаружены дубликаты/ретрансмиты real-пакетов (одинаковые SEQ). Это может быть помеха от ОС."]}
        segs.sort(key=lambda x: x[0])
        gaps = []
        for i in range(len(segs) - 1):
            s1, l1, num1 = segs[i]
            s2, _, num2 = segs[i+1]
            expected_s2 = (s1 + l1) & 0xFFFFFFFF
            if s2 != expected_s2:
                gaps.append(f"Разрыв между п.#{num1} и п.#{num2}: ожидался seq={expected_s2}, получен={s2}")
        if not gaps:
            return {"status": "PASS", "pattern": "CONTINUOUS_STREAM", "details": ["Real-сегменты образуют логически непрерывную последовательность."]}
        return {"status": "FAIL", "pattern": "STREAM_HAS_GAPS", "details": gaps}

    def _check_fake_packet(self, out_win: List[Any]) -> Dict:
        first_pkt = out_win[0]
        res = {"status": "PASS", "details": []}
        is_fake = False
        ttl = first_pkt[IP].ttl if IP in first_pkt else None
        if ttl and ttl <= 4:
            res["details"].append(f"✅ Низкий TTL ({ttl}).")
            is_fake = True
        try:
            tcp_pkt = first_pkt.copy()
            original_tcp_chksum = tcp_pkt[TCP].chksum
            del tcp_pkt[TCP].chksum
            recalculated_tcp_chksum = IP(bytes(tcp_pkt))[TCP].chksum
            if original_tcp_chksum != recalculated_tcp_chksum:
                 res["details"].append(f"✅ Неверная TCP Checksum (0x{original_tcp_chksum:04X}).")
                 is_fake = True
        except Exception: pass
        if not is_fake: return {"status": "SKIP", "details": ["Недостаточно признаков, чтобы считать первый пакет fake."]}
        return res

    def _check_server_response(self, inbound_packets: List[Any], outbound_packets: List[Any]) -> Dict:
        if not inbound_packets: return {"status": "FAIL", "pattern": "NO_INBOUND_CAPTURE", "details": ["В PCAP нет входящих пакетов."]}
        last_real_pkt = self._last_real_pkt(outbound_packets)
        if not last_real_pkt: return {"status": "UNKNOWN", "pattern": "NO_REALS_SENT", "details": ["Не найден 'real' пакет для отсчёта."]}
        t0 = last_real_pkt.time
        server_ip = outbound_packets[0][IP].dst
        buf = bytearray()
        for pkt in inbound_packets:
            if pkt[IP].src != server_ip or pkt.time < t0: continue
            if (pkt.time - t0) * 1000.0 > self.window_ms: break
            if TCP in pkt and pkt[TCP].payload:
                buf.extend(bytes(pkt[TCP].payload))
        if self._find_server_hello_in_buffer(bytes(buf)):
            return {"status": "PASS", "pattern": "SH_RECEIVED", "details": ["Обнаружен ServerHello в ответном трафике."]}
        elif buf:
            return {"status": "FAIL", "pattern": "NO_SERVER_HELLO_IN_BUFFER", "details": ["Ответ от сервера получен, но ServerHello в нем не найден."]}
        else:
            return {"status": "FAIL", "pattern": "NO_RESPONSE_TIMEOUT", "details": [f"В течение {self.window_ms}мс после инъекции нет ответа от сервера."]}
    
    def _print_stream_report(self, flow_key: Tuple, report: Dict):
        print("\n" + "-"*70)
        print(f"🔍 Анализ потока: {flow_key[0]}:{flow_key[1]} -> {flow_key[2]}:{flow_key[3]}")
        print("-"*70)
        status_map = {"PASS": "✅", "FAIL": "❌", "SKIP": "🟡", "UNKNOWN": "❓"}
        for check_name, check_data in report["checks"].items():
            status = check_data.get("status", "UNKNOWN")
            symbol = status_map.get(status, "❓")
            print(f"  {symbol} {check_name.replace('_', ' ').capitalize()}: [{status}]")
            for detail in check_data.get("details", []):
                print(f"      - {detail}")
        print("\n  --- ДИАГНОЗ ---")
        print(f"  Вердикт: {report['verdict']}")
        print(f"  Рекомендация: {report['recommendation']}")
        print("-"*70)

    def _get_flow_key(self, pkt: Any) -> Optional[Tuple[str, int, str, int]]:
        try:
            if IP in pkt and TCP in pkt:
                if pkt[IP].src == self.local_ip:
                    return (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
                else:
                    return (pkt[IP].dst, pkt[TCP].dport, pkt[IP].src, pkt[TCP].sport)
        except Exception: pass
        return None

    def _select_attack_window(self, outbound_payload_pkts: List[Any], inbound_pkts: List[Any]) -> Tuple[List[Any], List[Any]]:
        if not outbound_payload_pkts: return [], []
        t0 = outbound_payload_pkts[0].time
        out_win = [p for p in outbound_payload_pkts if (p.time - t0)*1000.0 <= self.window_ms]
        in_win = [p for p in inbound_pkts if p.time >= t0 and (p.time - t0)*1000.0 <= self.window_ms]
        return out_win, in_win

    def _find_server_hello_in_buffer(self, buf: bytes) -> bool:
        try:
            n = len(buf)
            for i in range(0, max(0, n-6)):
                if buf[i] == 0x16 and buf[i+1] == 0x03 and buf[i+2] in (0x00,1,2,3,4):
                    if buf[i+5] == 0x02: return True
        except Exception: pass
        return False

    def _last_real_pkt(self, out_win: List[Any]) -> Optional[Any]:
        reals = [p for p in out_win if not self._is_fake_pkt(p)]
        return reals[-1] if reals else None

    def _autodetect_local_ip(self, packets: List[Any]) -> Optional[str]:
        src_ips = Counter()
        for i, pkt in enumerate(packets):
            if i > 200: break
            if IP in pkt and pkt[IP].src:
                try:
                    if ipaddress.ip_address(pkt[IP].src).is_private:
                        src_ips[pkt[IP].src] += 1
                except ValueError: continue
        return src_ips.most_common(1)[0][0] if src_ips else None

    def _is_fake_pkt(self, pkt: Any) -> bool:
        try:
            if IP in pkt and pkt[IP].ttl <= 4: return True
            tcp_pkt = pkt.copy()
            original_tcp_chksum = tcp_pkt[TCP].chksum
            del tcp_pkt[TCP].chksum
            recalculated_tcp_chksum = IP(bytes(tcp_pkt))[TCP].chksum
            if original_tcp_chksum != recalculated_tcp_chksum: return True
        except Exception: pass
        return False

class StrategyOptimizer:
    def __init__(self, history_file: str = "strategy_history.json"):
        self.history_file = history_file
        self.success_rates = self._load_history()
    
    def _load_history(self) -> Dict[str, float]:
        try:
            with open(self.history_file, 'r') as f: return json.load(f)
        except: return {}
    
    def record_success(self, strategy: str, success: bool, target: str = ""):
        key = f"{strategy}|{target}" if target else strategy
        if key not in self.success_rates: self.success_rates[key] = {'success': 0, 'total': 0}
        self.success_rates[key]['total'] += 1
        if success: self.success_rates[key]['success'] += 1
        self._save_history()
    
    def optimize_strategies(self, strategies: List[Dict], target: str = "") -> List[Dict]:
        optimized = []
        for strategy in strategies:
            cmd = strategy['cmd']
            key = f"{cmd}|{target}" if target else cmd
            base_score = strategy['score']
            if key in self.success_rates:
                history = self.success_rates[key]
                success_rate = history['success'] / history['total']
                adjusted_score = base_score * (0.3 + 0.7 * success_rate)
                strategy['score'] = min(adjusted_score, 1.0)
                strategy['success_rate'] = success_rate
                strategy['trials'] = history['total']
            optimized.append(strategy)
        return sorted(optimized, key=lambda x: x['score'], reverse=True)
    
    def _save_history(self):
        try:
            with open(self.history_file, 'w') as f: json.dump(self.success_rates, f, indent=2)
        except Exception as e: print(f"Warning: Cannot save strategy history: {e}")

def enhanced_build_json_report(pcap_file: str, triggers: List[Dict], no_reassemble: bool, validate: bool, strategy_optimizer: StrategyOptimizer) -> Dict[str, Any]:
    report = {"pcap_file": pcap_file, "analysis_timestamp": datetime.now().isoformat(), "incident_count": len(triggers), "incidents": [], "enhanced_analysis": True}
    signature_analyzer = AdvancedSignatureAnalyzer()
    for t in triggers:
        trig_idx = detect_trigger_index(t)
        rst_idx = detect_rst_index(t)
        assembled_payload, stream_label, reassembly_meta = b"", None, {}
        if not no_reassemble and isinstance(trig_idx, int):
            ch_idx = locate_clienthello_start(pcap_file, trig_idx)
            real_idx = ch_idx or trig_idx
            assembled_payload, stream_label, reassembly_meta = reassemble_clienthello(pcap_file, real_idx)
        if not stream_label: stream_label = get_stream_label(t, pcap_file, trig_idx or rst_idx)
        tls = parse_client_hello(assembled_payload) or {}
        entropy_analysis = analyze_payload_entropy(assembled_payload)
        signature_analysis = signature_analyzer.analyze_tls_fingerprint(tls)
        enhanced_strategies = generate_advanced_strategies(tls, t, entropy_analysis, signature_analysis)
        target_host = (tls.get('sni', [''])[0] if tls.get('sni') else "")
        optimized_strategies = strategy_optimizer.optimize_strategies(enhanced_strategies, target_host)
        incident = {
            "stream": stream_label, "rst_index": rst_idx, "trigger_index": trig_idx,
            "injected": bool(get_first(t, ["is_injected","dpi_injection"], False)),
            "ttl_difference": get_first(t, ["ttl_difference","ttl_diff"]),
            "reassembly_metadata": reassembly_meta, "tls": tls, "signature_analysis": signature_analysis,
            "entropy_analysis": entropy_analysis, "recommended_strategies": optimized_strategies,
            "advanced_metadata": {
                "ech_detected": bool(tls.get('encrypted_client_hello')),
                "key_share_groups": [ks.get('group') for ks in tls.get('key_share', [])],
                "padding_used": tls.get('has_padding', False),
                "tls13_support": 'TLS1.3' in (tls.get('supported_versions') or [])
            }
        }
        report["incidents"].append(incident)
    return report

def build_json_report(pcap_file: str, triggers: List[Dict[str, Any]], no_reassemble: bool, validate: bool) -> Dict[str, Any]:
    report = {"pcap_file": pcap_file, "analysis_timestamp": datetime.now().isoformat(), "incident_count": len(triggers), "incidents": []}
    pcap_inspect_report = None
    validator = None
    if validate and PCAP_INSPECT_AVAILABLE:
        try:
            pcap_inspect_report = inspect_pcap(pcap_file)
            validator = AttackValidator(pcap_inspect_report)
        except Exception as e: print(f"[WARNING] pcap_inspect failed: {e}")
    for t in triggers:
        trig_idx = detect_trigger_index(t)
        rst_idx = detect_rst_index(t)
        assembled_payload, stream_label, reassembly_meta = b"", None, {}
        if not no_reassemble and isinstance(trig_idx, int):
            ch_idx = locate_clienthello_start(pcap_file, trig_idx)
            real_idx = ch_idx or trig_idx
            assembled_payload, stream_label, reassembly_meta = reassemble_clienthello(pcap_file, real_idx)
        if not stream_label: stream_label = get_stream_label(t, pcap_file, trig_idx or rst_idx)
        tls = parse_client_hello(assembled_payload) or {}
        if not tls.get("sni"):
            loose = extract_sni_loose(assembled_payload)
            if loose:
                tls.setdefault("is_client_hello", True)
                tls["sni"] = loose
        entropy_analysis = analyze_payload_entropy(assembled_payload)
        signature_analyzer = AdvancedSignatureAnalyzer()
        signature_analysis = signature_analyzer.analyze_tls_fingerprint(tls)
        recs = generate_advanced_strategies(tls, t, entropy_analysis, signature_analysis)
        validation = {}
        if validator and stream_label:
            try:
                fake_real_eval = validator.validate_incident({"stream": stream_label})
                validation = fake_real_eval or {}
            except Exception as e: validation = {"error": f"validation_failed: {e}"}
        incident = {
            "stream": stream_label, "rst_index": rst_idx, "trigger_index": trig_idx,
            "injected": bool(get_first(t, ["is_injected","dpi_injection","injection", "dpi_injection_suspected"], False)),
            "ttl_rst": get_first(t, ["rst_ttl","ttl_rst","rst_ttl_value", "rst_packet_ttl"]),
            "expected_ttl": get_first(t, ["expected_ttl","server_ttl", "server_base_ttl"]),
            "ttl_difference": get_first(t, ["ttl_difference","ttl_diff"]),
            "time_delta": get_first(t, ["time_delta","dt"]),
            "reassembly_metadata": reassembly_meta, "entropy_analysis": entropy_analysis, "tls": tls,
            "payload_preview_hex": (assembled_payload[:64].hex() if assembled_payload else ""),
            "recommended_strategies": recs, "attack_validation": validation, "signature_analysis": signature_analysis,
            "advanced_metadata": {
                "ech_detected": bool(tls.get('encrypted_client_hello')),
                "key_share_groups": [ks.get('group') for ks in tls.get('key_share', [])],
                "padding_used": tls.get('has_padding', False),
                "tls13_support": 'TLS1.3' in (tls.get('supported_versions') or [])
            }
        }
        report["incidents"].append(incident)
    if report["incidents"]:
        pattern_analyzer = BlockingPatternAnalyzer()
        report["statistical_analysis"] = pattern_analyzer.analyze_incidents(report["incidents"])
    if pcap_inspect_report:
        report["pcap_inspect_summary"] = {"flows_count": len(pcap_inspect_report.get("flows", []))}
    return report

async def run_second_pass_from_report(report: Dict[str, Any], limit: int, port: int, engine_override: Optional[str], use_advanced_reporting: bool=False, save_adv_file: Optional[str]=None):
    try:
        from core.unified_bypass_engine import UnifiedBypassEngine
        from core.doh_resolver import DoHResolver
    except ImportError as e:
        print(f"[INFO] UnifiedBypassEngine/DoHResolver недоступны — второй прогон пропущен: {e}")
        return
    host_to_strats: Dict[str, List[str]] = {}
    host_to_dpi: Dict[str, str] = {}
    for inc in report.get("incidents", []):
        recs = inc.get("recommended_strategies") or []
        if recs:
            sni_list = (inc.get("tls", {}) or {}).get("sni") or []
            host = sni_list[0] if sni_list else None
            if not host:
                stream = inc.get("stream") or ""
                try:
                    dst_part = stream.split("-")[1]
                    host = dst_part.split(":")[0].strip("[]")
                except Exception: continue
            if not host: continue
            cmds = [r["cmd"] for r in recs[:max(1, limit)]]
            host_to_strats.setdefault(host, [])
            for c in cmds:
                if c not in host_to_strats[host]: host_to_strats[host].append(c)
            dpi_type = "unknown"
            if inc.get("injected", False) or (inc.get("ttl_difference") or 0) > 4: dpi_type = "stateful"
            elif ((inc.get("tls") or {}).get("is_client_hello")): dpi_type = "signature_based"
            host_to_dpi[host] = host_to_dpi.get(host) or dpi_type
    if not host_to_strats:
        print("[INFO] Нет стратегий для второго прогона (реков не найдено).")
        return
    integration = None
    if use_advanced_reporting and ADV_REPORTING_AVAILABLE:
        ok = await initialize_advanced_reporting()
        if ok:
            integration = get_reporting_integration()
            print("[INFO] AdvancedReportingIntegration initialized")
    from core.unified_bypass_engine import UnifiedEngineConfig
    resolver = DoHResolver()
    engine_config = UnifiedEngineConfig(debug=False)
    engine = UnifiedBypassEngine(config=engine_config)
    all_results: Dict[str, Any] = {}
    adv_reports: Dict[str, List[Dict[str, Any]]] = {}
    for host, strategies in host_to_strats.items():
        try: ip = await resolver.resolve(host)
        except Exception: ip = None
        if not ip: ip = host if host and (host.replace(".", "").isdigit() or ':' in host) else None
        dns_cache, ips = ({host: ip} if ip else {}), ({ip} if ip else set())
        test_site = f"https://{host}"
        dpi_type = host_to_dpi.get(host, "unknown")
        print(f"\n[2nd pass] {host}: {len(strategies)} стратегий, ip={ip or 'N/A'}")
        try:
            results = await engine.test_strategies_hybrid(
                strategies=strategies, test_sites=[test_site], ips=ips, dns_cache=dns_cache,
                port=port, domain=host, fast_filter=True, initial_ttl=None, enable_fingerprinting=False,
                engine_override=engine_override, telemetry_full=False, capturer=None, fingerprint=None
            )
            all_results[host] = results
            best = [r for r in results if r.get("success_rate", 0) > 0]
            if best: print(f"   ✓ best: {best[0]['strategy']} (rate={best[0]['success_rate']:.0%}, {best[0].get('avg_latency_ms', 0):.1f}ms)")
            else: print("   ✗ нет успехов на втором прогоне")
            if integration:
                adv_reports.setdefault(host, [])
                for r in results:
                    attack_name = r.get("strategy") or "unknown_strategy"
                    exec_ms = float(r.get("avg_latency_ms", 0.0))
                    success = float(r.get("success_rate", 0.0)) > 0.0
                    eff = float(r.get("success_rate", 0.0))
                    execution_result = {"dpi_type": dpi_type, "execution_time_ms": exec_ms, "success": success, "effectiveness_score": eff, "ml_prediction": r.get("ml_prediction") or {}}
                    adv = await integration.generate_attack_report(attack_name=attack_name, target_domain=host, execution_result=execution_result)
                    if adv:
                        adv_reports[host].append({"attack_name": adv.attack_name, "target_domain": adv.target_domain, "dpi_type": adv.dpi_type, "success": adv.success, "effectiveness_score": adv.effectiveness_score, "execution_time_ms": adv.execution_time_ms, "timestamp": adv.timestamp.isoformat(), "recommendations": adv.recommendations})
        except Exception as e: print(f"   [WARN] second pass failed for {host}: {e}")
    out_name = f"pcap_second_pass_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        with open(out_name, "w", encoding="utf-8") as f: json.dump(all_results, f, ensure_ascii=False, indent=2)
        print(f"\n[OK] second-pass results saved → {out_name}")
    except Exception as e: print(f"[WARN] cannot save second-pass file: {e}")
    if integration and save_adv_file:
        try:
            comp = await integration.export_comprehensive_report(format_type="json", include_raw_data=True)
            with open(save_adv_file, "w", encoding="utf-8") as f: json.dump(comp, f, ensure_ascii=False, indent=2, default=str)
            print(f"[OK] advanced comprehensive report saved → {save_adv_file}")
        except Exception as e: print(f"[WARN] cannot save advanced report: {e}")

def _autodetect_local_ip_from_pcap(pcap_file: str) -> str:
    priv = defaultdict(int)
    def _is_priv(ip):
        try:
            a = ip.split('.')
            o1, o2 = int(a[0]), int(a[1])
            return (o1==10) or (o1==172 and 16<=o2<=31) or (o1==192 and o2==168)
        except: return False
    with PcapReader(pcap_file) as pr:
        for i, pkt in enumerate(pr, 1):
            if i>200: break
            try:
                if IP in pkt and _is_priv(pkt[IP].src):
                    priv[pkt[IP].src]+=1
            except: pass
    if priv:
        return max(priv.items(), key=lambda x:x[1])[0]
    return None

def _get_tuple(pkt):
    if IP in pkt and TCP in pkt:
        return (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport, int(pkt.time))
    if IPv6 in pkt and TCP in pkt:
        return (pkt[IPv6].src, pkt[TCP].sport, pkt[IPv6].dst, pkt[TCP].dport, int(pkt.time))
    return None

def _pkt_ttl(pkt):
    if IP in pkt: return int(pkt[IP].ttl)
    if IPv6 in pkt: return int(pkt[IPv6].hlim)
    return None

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

def _recalc_checksums(pkt):
    # Быстрый детектор badsum: сравним записанную TCP checksum с пересчитанной
    try:
        if TCP not in pkt: return False, False
        # Извлекаем байты IP/TCP
        if IP in pkt:
            ip = pkt[IP]
            ip_bytes = bytes(ip)
            tcp_bytes = bytes(ip.payload)
            # Пересчитаем IP чексум
            def _sum16(data):
                if len(data)%2: data+=b"\x00"
                s=0
                for i in range(0,len(data),2):
                    s += (data[i]<<8)+data[i+1]
                    s = (s & 0xFFFF) + (s>>16)
                return (~s) & 0xFFFF
            ip_hdr = bytearray(ip_bytes[:ip.ihl*4])
            ip_hdr[10:12]=b"\x00\x00"
            ip_ok = (struct.unpack("!H", ip_bytes[10:12])[0] == _sum16(bytes(ip_hdr)))
            # Пересчитаем TCP чексум с псевдозаголовком
            src = ip_bytes[12:16]; dst = ip_bytes[16:20]
            proto = ip_bytes[9]
            tcp_len = len(tcp_bytes)
            pseudo = src+dst+bytes([0, proto])+struct.pack("!H", tcp_len)
            tb = bytearray(tcp_bytes); tb[16:18]=b"\x00\x00"
            tcp_ok = (struct.unpack("!H", tcp_bytes[16:18])[0] == _sum16(pseudo+bytes(tb)))
            return ip_ok, tcp_ok
        # IPv6: пересчитаем только TCP (IP6 без checksum)
        if IPv6 in pkt:
            v6 = pkt[IPv6]; tcp = pkt[TCP]
            src = socket.inet_pton(socket.AF_INET6, v6.src)
            dst = socket.inet_pton(socket.AF_INET6, v6.dst)
            tcp_bytes = bytes(tcp)
            tcp_len = len(tcp_bytes)
            pseudo = src+dst+struct.pack("!I3xB", tcp_len, 6)
            def _sum16(data):
                if len(data)%2: data+=b"\x00"
                s=0
                for i in range(0,len(data),2):
                    s += (data[i]<<8)+data[i+1]
                    s = (s & 0xFFFF) + (s>>16)
                return (~s) & 0xFFFF
            tb = bytearray(tcp_bytes); tb[16:18]=b"\x00\x00"
            tcp_ok = (struct.unpack("!H", tcp_bytes[16:18])[0] == _sum16(pseudo+bytes(tb)))
            return True, tcp_ok
    except:
        pass
    return False, False

def _classify_window(segments):
    """
    Restored classification logic from the old, working version.
    This logic is more flexible and correctly identifies complex attack patterns.
    """
    segs = sorted(segments, key=lambda x: x["idx"])
    fake = [s for s in segs if (s["ttl"] is not None and s["ttl"] <= 4) or (not s["tcp_ok"]) or s["md5"]]
    
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
        overlap = segs[0]['paylen'] - segs[1]['rel_seq']
        label = f"seqovl_ovl{overlap}"
        return label, {"type": "seqovl", "overlap": overlap}

    return "unknown", {"type": "unknown"}

def export_strategy_samples(pcap_file: str, out_dir: str, window_ms: float = 200.0, max_samples: int = 1):
    """
    Экспортирует по одному эталонному примеру пакетов на каждую распознанную стратегию.
    - pcap_file: входной PCAP (например, out2.pcap)
    - out_dir: каталог для сохранения (pcap+json на каждую стратегию)
    """
    os.makedirs(out_dir, exist_ok=True)
    index = {}  # label -> info
    local_ip = _autodetect_local_ip_from_pcap(pcap_file)

    # 1) Собираем все TCP с payload и индексируем по flow
    FlowKey = namedtuple("FlowKey", "src sp dst dp")
    flows = defaultdict(list)  # flow -> list of (idx, time, pkt)

    with PcapReader(pcap_file) as pr:
        for i, pkt in enumerate(pr, 1):
            try:
                if TCP in pkt and (pkt[TCP].payload):
                    if IP in pkt:
                        fk = FlowKey(pkt[IP].src, int(pkt[TCP].sport), pkt[IP].dst, int(pkt[TCP].dport))
                    elif IPv6 in pkt:
                        fk = FlowKey(pkt[IPv6].src, int(pkt[TCP].sport), pkt[IPv6].dst, int(pkt[TCP].dport))
                    else:
                        continue
                    flows[fk].append((i, float(pkt.time), pkt))
            except Exception:
                continue

    # 2) Для каждого flow находим окна вокруг ClientHello
    samples_written = 0
    labels_taken = set()
    for fk, items in flows.items():
        # сортируем по времени/индексу
        items.sort(key=lambda x: x[1])
        # найдём потенциальные CH-секции: первый пакет, где в payload есть 0x16 .. 0x01 (ClientHello)
        candidate_idx = []
        for idx, ts, pkt in items:
            raw = bytes(pkt[TCP].payload) if pkt[TCP].payload else b""
            off = find_clienthello_offset(raw)
            if off is not None:
                candidate_idx.append((idx, ts))
        if not candidate_idx:
            continue
        for idx0, ts0 in candidate_idx:
            # окно 0..window_ms
            window = []
            for idx, ts, pkt in items:
                if ts < ts0: continue
                if (ts - ts0)*1000.0 > window_ms: break
                window.append((idx, ts, pkt))
            if not window:
                continue
            # превратим окно в фичи
            base_seq = int(window[0][2][TCP].seq)
            segs = []
            for idx, ts, pkt in window:
                pay = bytes(pkt[TCP].payload) if pkt[TCP].payload else b""
                ttl = _pkt_ttl(pkt)
                ip_ok, tcp_ok = _recalc_checksums(pkt)
                md5 = _has_md5sig(pkt)
                flags = int(pkt[TCP].flags)
                rel = (int(pkt[TCP].seq) - base_seq) & 0xFFFFFFFF
                # нормализуем rel в 0.. если переполнения нет — будет ок
                if rel > (1<<31):  # редкий случай wrap-around
                    rel = 0
                segs.append({
                    "idx": idx,
                    "ttl": ttl,
                    "tcp_ok": tcp_ok,
                    "ip_ok": ip_ok,
                    "md5": md5,
                    "flags": flags,
                    "paylen": len(pay),
                    "seq": int(pkt[TCP].seq),
                    "rel_seq": rel,
                })
            label, meta = _classify_window(segs)
            # сохраняем только по одному примеру на стратегию
            if label not in labels_taken and label != "unknown":
                labels_taken.add(label)
                # write pcap sample with сегменты из окна
                out_pcap = os.path.join(out_dir, f"strategy_{label}.pcap")
                wrpcap(out_pcap, [p for _,_,p in window])
                # write json meta
                info = {
                    "flow": f"{fk.src}:{fk.sp} -> {fk.dst}:{fk.dp}",
                   
                    "label": label,
                    "meta": meta,
                    "base_packet_index": window[0][0],
                    "packet_indices": [idx for idx,_,_ in window],
                    "segments": segs
                }
                with open(os.path.join(out_dir, f"strategy_{label}.json"), "w", encoding="utf-8") as f:
                    json.dump(info, f, ensure_ascii=False, indent=2)
                index[label] = info
                samples_written += 1
            if samples_written >= 64:  # safety cap
                break

    # итоговый индекс
    with open(os.path.join(out_dir, "index.json"), "w", encoding="utf-8") as f:
        json.dump(index, f, ensure_ascii=False, indent=2)
    print(f"[OK] Strategy samples exported: {len(index)} (→ {out_dir})")



def export_strategy_samples_json(
    pcap_file: str,
    out_json: str,
    *,
    local_ip: str = None,
    flow_port: int = 443,
    window_ms: float = 800.0,
    cap_per_label: int = 1,
    include_inbound: bool = True
) -> dict:
    if not SCAPY_AVAILABLE:
        raise RuntimeError("Scapy не установлен")
    res = {
        "pcap_file": os.path.abspath(pcap_file),
        "local_ip": None,
        "flow_port": int(flow_port),
        "window_ms": float(window_ms),
        "samples": [],
        "counts_by_label": {}
    }

    def _autodetect():
        try:
            return _autodetect_local_ip_from_pcap(pcap_file)
        except Exception:
            return None

    lip = local_ip or _autodetect()
    res["local_ip"] = lip

    FlowKey = namedtuple("FlowKey", "src sp dst dp")
    flows_out = defaultdict(list)
    flows_in  = defaultdict(list)

    with PcapReader(pcap_file) as pr:
        for i, pkt in enumerate(pr, 1):
            try:
                if TCP in pkt:
                    dport = int(pkt[TCP].dport)
                    if dport != flow_port:
                        continue
                    if IP in pkt:
                        fk = FlowKey(pkt[IP].src, int(pkt[TCP].sport), pkt[IP].dst, dport)
                        is_out = (lip is None) or (pkt[IP].src == lip)
                    elif IPv6 in pkt:
                        fk = FlowKey(pkt[IPv6].src, int(pkt[TCP].sport), pkt[IPv6].dst, dport)
                        is_out = (lip is None) or (pkt[IPv6].src == lip)
                    else:
                        continue
                    pkt.packet_num = i
                    if is_out:
                        flows_out[fk].append(pkt)
                    else:
                        flows_in[fk].append(pkt)
            except Exception:
                continue

    # Хелперы
    def _pkt_ttl(pkt):
        try:
            if IP in pkt: return int(pkt[IP].ttl)
            if IPv6 in pkt: return int(pkt[IPv6].hlim)
        except Exception:
            pass
        return None

    def _read_tcp_csum(pkt):
        try:
            b = bytes(pkt[TCP])
            return struct.unpack("!H", b[16:18])[0]
        except Exception:
            return None

    def _is_fake(pkt):
        ttl = _pkt_ttl(pkt)
        ip_ok, tcp_ok = _recalc_checksums(pkt)
        md5 = _has_md5sig(pkt)
        csum = _read_tcp_csum(pkt)
        return (ttl is not None and ttl <= 4) or (not tcp_ok) or md5 or (csum in (0xDEAD, 0xBEEF))

    def _classify_and_build_segments(out_win):
        if not out_win:
            return None, None, None
        base_seq = int(out_win[0][TCP].seq)
        segs = []
        for pkt in out_win:
            pay = bytes(pkt[TCP].payload) if pkt[TCP].payload else b""
            ttl = _pkt_ttl(pkt)
            ip_ok, tcp_ok = _recalc_checksums(pkt)
            md5 = _has_md5sig(pkt)
            flags = int(pkt[TCP].flags)
            cur_seq = int(pkt[TCP].seq)
            rel = (cur_seq - base_seq) & 0xFFFFFFFF
            if rel > (1<<31): rel = 0
            csum = _read_tcp_csum(pkt)
            segs.append({
                "idx": int(getattr(pkt, "packet_num", 0)),
                "ttl": ttl,
                "tcp_ok": bool(tcp_ok),
                "ip_ok": bool(ip_ok),
                "md5": bool(md5),
                "flags": flags,
                "paylen": len(pay),
                "seq": cur_seq,
                "rel_seq": rel,
                "badsum_val": ("0x%04X" % csum) if isinstance(csum, int) else None
            })
        label, meta = _classify_window(segs)
        return segs, label, meta

    def _select_window(out_pkts, in_pkts, include_inbound):
        out_payload = [p for p in out_pkts if TCP in p and p[TCP].payload]
        if not out_payload:
            return [], [], None
        t0 = None
        for p in out_payload:
            raw = bytes(p[TCP].payload) if p[TCP].payload else b""
            if find_clienthello_offset(raw) is not None:
                t0 = float(p.time); break
        if t0 is None:
            t0 = float(out_payload[0].time)
        out_win = [p for p in out_payload if float(p.time) >= t0 and (float(p.time)-t0)*1000.0 <= window_ms]
        in_win = [p for p in in_pkts     if float(p.time) >= t0 and (float(p.time)-t0)*1000.0 <= window_ms] if include_inbound else []
        base_idx = int(out_win[0].packet_num) if out_win else None
        return out_win, in_win, base_idx

    samples = []
    label_caps = defaultdict(int)

    for fk, out_pkts in flows_out.items():
        out_pkts.sort(key=lambda p: float(getattr(p, "time", 0.0)))
        in_pkts = flows_in.get(FlowKey(fk.dst, fk.dp, fk.src, fk.sp), [])
        in_pkts.sort(key=lambda p: float(getattr(p, "time", 0.0)))

        out_win, in_win, base_idx = _select_window(out_pkts, in_pkts, include_inbound)
        if not out_win:
            continue
        segs, label, meta = _classify_and_build_segments(out_win)
        if not segs or not label or label == "unknown":
            continue
        if label_caps[label] >= cap_per_label:
            continue
        label_caps[label] += 1

        pkt_indices = [int(getattr(p, "packet_num", 0)) for p in out_win]
        sample = {
            "flow": f"{fk.src}:{fk.sp} -> {fk.dst}:{fk.dp}",
            "label": label,
            "meta": meta or {},
            "base_packet_index": base_idx,
            "packet_indices": pkt_indices,
            "segments": segs
        }

        if include_inbound:
            rst_ttls, rst_cnt = [], 0
            for p in in_win:
                try:
                    if TCP in p and (int(p[TCP].flags) & 0x04):
                        rst_cnt += 1
                        rst_ttls.append(_pkt_ttl(p))
                except Exception:
                    pass
            sample["inbound_summary"] = {"rst_count": rst_cnt, "rst_ttls": rst_ttls}

        samples.append(sample)

    res["samples"] = samples
    res["counts_by_label"] = dict(sorted((label_caps.items()), key=lambda x: x[0]))
    try:
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(res, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[WARN] cannot save {out_json}: {e}")
    return res


def main():
    parser = argparse.ArgumentParser(description="Находит RST‑триггеры в PCAP, вытаскивает TLS ClientHello и генерит рекомендации стратегий.")
    parser.add_argument("pcap_file", help="Путь к PCAP‑файлу")
    parser.add_argument("--no-reassemble", action="store_true", help="Не пытаться собирать фрагментированный ClientHello")
    parser.add_argument("--json", action="store_true", help="Вывести результат в JSON (stdout)")
    parser.add_argument("--json-file", type=str, help="Сохранить результат в JSON‑файл")
    parser.add_argument("--second-pass", action="store_true", help="Запустить второй прогон стратегий (pcap‑driven) через HybridEngine")
    parser.add_argument("--second-pass-limit", type=int, default=6, help="Сколько стратегий на домен во втором прогоне (default: 6)")
    parser.add_argument("--second-pass-port", type=int, default=443, help="Порт второго прогона (default: 443)")
    parser.add_argument("--engine-override", choices=["native","external"], default=None, help="Принудительный движок для второго прогона")
    parser.add_argument("--validate", action="store_true", help="Валидировать «фейк/реал» через pcap_inspect и авто-рефайн стратегий")
    parser.add_argument("--save-inspect-json", type=str, default=None, help="Сохранить сырой отчёт pcap_inspect в файл")
    parser.add_argument("--advanced-report", action="store_true", help="Сгенерировать AdvancedReportingIntegration артефакты")
    parser.add_argument("--advanced-report-file", type=str, default="advanced_report.json", help="Куда сохранить сводный advanced-отчёт")
    parser.add_argument("--export-strategy-samples", type=str, help="Каталог для выгрузки пер-стратегийных PCAP/JSON самплов")
    parser.add_argument("--export-strategy-samples-json", type=str, help="Сохранить все сэмплы стратегий в единый JSON файл")
    parser.add_argument("--flow-port", type=int, default=443, help="Анализировать только потоки на этот порт (default: 443)")
    parser.add_argument("--flow-window-ms", type=float, default=800.0, help="Ширина окна анализа после CH/первого payload, мс (default: 800)")
    parser.add_argument("--analyze-flow-failures", action="store_true", help="Запустить детальный анализ неудачных TCP-потоков для диагностики проблем сборки.")
    parser.add_argument("--local-ip", help="IP-адрес локальной машины для анализа потоков (если автоопределение неверно).")
    parser.add_argument("--enable-ech-analysis", action="store_true", help="Анализ Encrypted ClientHello")
    parser.add_argument("--strategy-history", type=str, default="strategy_history.json", help="Файл истории успешности стратегий")
    parser.add_argument("--adaptive-optimization", action="store_true", help="Адаптивная оптимизация стратегий на основе истории")
    parser.add_argument("--risk-threshold", type=float, default=0.7, help="Порог риска для агрессивных стратегий (0.0-1.0)")
    parser.add_argument("--export-fingerprints", type=str, help="Экспорт TLS отпечатков в JSON файл")

    args = parser.parse_args()

    if not os.path.exists(args.pcap_file):
        print(f"[ERROR] Файл не найден: {args.pcap_file}", file=sys.stderr)
        sys.exit(1)

    if args.analyze_flow_failures:
        analyzer = FlowFailureAnalyzer(
            args.pcap_file,
            local_ip=args.local_ip,
            flow_port=args.flow_port,
            window_ms=args.flow_window_ms,
        )
        analyzer.analyze()
        sys.exit(0)

    analyzer = RSTTriggerAnalyzer(args.pcap_file)
    triggers = analyzer.analyze()
    
    strategy_optimizer = StrategyOptimizer(args.strategy_history)
    
    report = enhanced_build_json_report(args.pcap_file, triggers, args.no_reassemble, args.validate, strategy_optimizer)

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
        analyzer.print_report(triggers)
        if SCAPY_AVAILABLE and report.get("incidents"):
            print("\n[PCAP → TLS] Детали ClientHello, рекомендации и валидация")
            for inc in report["incidents"]:
                print("\n============================================================")
                print(f"Поток: {inc.get('stream', '<unknown>')}")
                
                tls = inc.get("tls", {}) or {}
                if tls.get("is_client_hello"):
                    print(f"  • SNI: {', '.join(tls.get('sni') or []) or '<не указано>'}")
                    print(f"  • ALPN: {', '.join(tls.get('alpn') or []) or '<не указано>'}")
                    if inc.get('advanced_metadata', {}).get('ech_detected'):
                        print("  • ECH: [bold yellow]Detected[/bold yellow]")
                
                sig_analysis = inc.get("signature_analysis", {})
                if sig_analysis.get('triggers'):
                    print("\n  DPI СИГНАТУРЫ:")
                    for name, data in sig_analysis['triggers'].items():
                        print(f"   • {name}: {data['reason']} (score: {data['score']:.2f})")

                recs = inc.get("recommended_strategies") or []
                if recs:
                    print("\n  РЕКОМЕНДАЦИИ ПО СТРАТЕГИЯМ:")
                    for r in recs[:3]:
                        print(f"   • {r['cmd']}   [{r['score']:.2f}] — {r['reason']}")

    async def _async_tail():
        reporting = None
        if args.advanced_report:
            if not ADV_REPORTING_AVAILABLE:
                print("[WARN] AdvancedReportingIntegration недоступен — отчеты не будут собираться.")
            else:
                ok = await initialize_advanced_reporting()
                if not ok:
                    print("[WARN] Не удалось инициализировать Advanced Reporting Integration.")
                else:
                    reporting = get_reporting_integration()

        if args.second_pass:
            await run_second_pass_from_report(
                report,
                limit=args.second_pass_limit,
                port=args.second_pass_port,
                engine_override=args.engine_override,
                use_advanced_reporting=args.advanced_report,
                save_adv_file=(args.advanced_report_file if args.advanced_report else None)
            )

        if args.advanced_report_file and reporting and not args.second_pass:
            try:
                comprehensive = await reporting.export_comprehensive_report(
                    format_type="json",
                    include_raw_data=True
                )
                with open(args.advanced_report_file, "w", encoding="utf-8") as f:
                    json.dump(comprehensive, f, ensure_ascii=False, indent=2, default=str)
                print(f"[OK] Advanced report exported → {args.advanced_report_file}")
            except Exception as e:
                print(f"[WARN] Не удалось экспортировать advanced-отчет: {e}")

    if args.second_pass or (args.advanced_report and ADV_REPORTING_AVAILABLE):
        asyncio.run(_async_tail())

    if args.export_strategy_samples_json and SCAPY_AVAILABLE:
        export_strategy_samples_json(
            pcap_file=args.pcap_file,
            out_json=args.export_strategy_samples_json,
            local_ip=None,
            flow_port=args.flow_port,
            window_ms=args.flow_window_ms,
            cap_per_label=1,
            include_inbound=True
        )
        print(f"[OK] Strategy samples JSON saved → {args.export_strategy_samples_json}")

if __name__ == "__main__":
    if not SCAPY_AVAILABLE:
        print("[ERROR] Scapy не установлен. Пожалуйста, установите его: pip install scapy")
        if any(arg in sys.argv for arg in ["--analyze-flow-failures", "--validate", "--export-strategy-samples"]):
             print("[ERROR] Выбранный режим требует Scapy. Установка прервана.")
             sys.exit(1)
    
    main()
