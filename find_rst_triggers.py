# --- START OF FILE find_rst_triggers.py (UPGRADED) ---

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

# Подавляем излишне "шумные" предупреждения от Scapy TLS
logging.getLogger("scapy.layers.ssl_tls").setLevel(logging.ERROR)
LOG = logging.getLogger("find_rst_triggers")
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

# Добавляем корень проекта в путь
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from core.pcap.rst_analyzer import RSTTriggerAnalyzer

# Для второго прогона
# ✅ FIX: Lazy import to avoid circular dependency
# Import HybridEngine only when needed, not at module level
# try:
#     from core.hybrid_engine import HybridEngine
#     from core.doh_resolver import DoHResolver
#     HYBRID_AVAILABLE = True
# except ImportError as e:
#     print(f"[WARNING] HybridEngine/DoHResolver недоступны: {e}")
#     HYBRID_AVAILABLE = False

# Lazy import - will be imported inside functions that need it
HYBRID_AVAILABLE = True  # Assume available, will check when needed

# Попытка импортировать scapy для доступа к payload/переассемблированию
try:
    from scapy.all import PcapReader, TCP, IP, IPv6, Raw, rdpcap, wrpcap
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

try:
    # pcap_inspect.py из вашего проекта
    from pcap_inspect import inspect_pcap
    PCAP_INSPECT_AVAILABLE = True
except Exception as e:
    print(f"[WARNING] pcap_inspect unavailable: {e}")
    PCAP_INSPECT_AVAILABLE = False


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
}
# Расширенный словарь шифров для устранения предупреждений
TLS_CIPHER_NAMES = {
    # TLS 1.3
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    # TLS 1.2
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
}

# GREASE helper
def is_grease(v: int) -> bool:
    try:
        return (v & 0x0F0F) == 0x0A0A
    except Exception:
        return False

def strip_grease_from_list(int_list: List[int]) -> List[int]:
    return [x for x in int_list if not is_grease(int(x))]

def find_clienthello_offset(payload: bytes) -> Optional[int]:
    """Находит смещение первой TLS-записи Handshake с типом ClientHello (0x16 ... 0x01 ...)."""
    if not payload or len(payload) < 6:
        return None
    limit = len(payload) - 6
    for i in range(limit):
        # TLS record header: ContentType(0x16), Version(0x03, 0x00..0x04)
        try:
            if payload[i] == 0x16 and payload[i+1] == 0x03 and payload[i+2] in (0x00, 0x01, 0x02, 0x03, 0x04):
                # handshake type should be at i+5
                if payload[i+5] == 0x01:  # ClientHello
                    return i
        except Exception:
            continue
    return None

def extract_sni_loose(payload: bytes) -> List[str]:
    """
    Грубый поиск SNI по структуре расширения 0x0000:
      00 00 [ext_len(2)] [list_len(2)] [name_type=0(1)] [name_len(2)] [host bytes]
    Используем как fallback, когда структурный парсер не сработал.
    """
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
                            # Простая валидация: доменное имя, не IP
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
    """Итерируется по потенциальным начальным позициям TLS-записей в потоке байтов."""
    i = 0
    while i + 5 <= len(payload):
        content_type = payload[i]
        # Проверка на валидные типы контента (handshake, alert, application_data, и т.д.)
        if content_type in {20, 21, 22, 23}:
            version = int.from_bytes(payload[i+1:i+3], "big")
            # Проверка на валидные версии TLS (e.g., 0x0301 to 0x0304)
            if 0x0300 <= version <= 0x0304:
                length = int.from_bytes(payload[i+3:i+5], "big")
                if length > 0:  # упрощенная проверка
                    yield i, content_type, length
        i += 1

# ====== Enhanced TLS Parser ======
def parse_client_hello(payload: bytes) -> Optional[Dict[str, Any]]:
    """Улучшенный парсер TLS ClientHello: умеет находить CH внутри потока, даже если до него есть байты."""
    try:
        start = find_clienthello_offset(payload)
        if start is None:
            return None

        pos = start
        # читаем первую TLS-запись
        if pos + 5 > len(payload):
            return None
        ct = payload[pos]
        rec_ver = int.from_bytes(payload[pos+1:pos+3], "big")
        rec_len = int.from_bytes(payload[pos+3:pos+5], "big")
        pos += 5

        rec_end = pos + rec_len
        rec = payload[pos:rec_end] if rec_end <= len(payload) else payload[pos:]
        if ct != 0x16 or len(rec) < 4:
            return None

        hs_type = rec[0]
        hs_len = int.from_bytes(rec[1:4], "big")
        if hs_type != 0x01:
            return None

        body = rec[4:4+hs_len] if 4+hs_len <= len(rec) else rec[4:]
        off = 0
        if len(body) < 2+32+1:
            return None

        client_version = int.from_bytes(body[off:off+2], "big"); off += 2
        off += 32  # random
        sid_len = body[off]; off += 1
        off += sid_len

        if off + 2 > len(body):
            return None
        cs_len = int.from_bytes(body[off:off+2], "big"); off += 2
        cs_bytes = body[off:off+cs_len]; off += cs_len
        cipher_suites_raw = [(cs_bytes[i] << 8) | cs_bytes[i+1] for i in range(0, len(cs_bytes), 2) if i+1 < len(cs_bytes)]
        cipher_suites_raw = [c for c in cipher_suites_raw if isinstance(c, int)]
        cipher_suites_no_grease = strip_grease_from_list(cipher_suites_raw)

        if off >= len(body):
            return None
        comp_len = body[off]; off += 1
        off += comp_len

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
                                # Исключим IP, оставим домены
                                try:
                                    ipaddress.ip_address(host)
                                except ValueError:
                                    sni_list.append(host)
                    except Exception:
                        pass
                elif et == 0x0010 and len(ed) >= 2:  # ALPN
                    try:
                        lst_len = int.from_bytes(ed[0:2], "big"); p = 2
                        endp = min(len(ed), 2+lst_len)
                        while p + 1 <= endp:
                            nlen = ed[p]; p += 1
                            proto = ed[p:p+nlen].decode("ascii","ignore"); p += nlen
                            if proto: alpn_list.append(proto)
                    except Exception:
                        pass
                elif et == 0x002b and len(ed) >= 1:  # supported_versions
                    try:
                        vlen = ed[0]; p = 1
                        tmp = []
                        for i in range(0, vlen, 2):
                            if p+i+1 < len(ed):
                                vc = int.from_bytes(ed[p+i:p+i+2], "big")
                                if not is_grease(vc):
                                    tmp.append(TLS_VER_MAP.get(vc, f"0x{vc:04x}"))
                        sup_ver = tmp
                    except Exception:
                        pass
                elif et == 0x000d and len(ed) >= 2:  # signature_algorithms
                    try:
                        alg_len = int.from_bytes(ed[0:2], "big"); p = 2
                        for i in range(0, alg_len, 2):
                            if p+i+1 < len(ed):
                                alg = int.from_bytes(ed[p+i:p+i+2], "big")
                                sig_algs.append(f"0x{alg:04x}")
                    except Exception:
                        pass
                elif et == 0x000a and len(ed) >= 2:  # groups
                    try:
                        g_len = int.from_bytes(ed[0:2], "big"); p = 2
                        for i in range(0, g_len, 2):
                            if p+i+1 < len(ed):
                                g = int.from_bytes(ed[p+i:p+i+2], "big")
                                groups.append(f"0x{g:04x}")
                    except Exception:
                        pass
                elif et == 0x000b and len(ed) >= 1:  # ec_point_formats
                    try:
                        pf_len = ed[0]; p = 1
                        for i in range(pf_len):
                            if p+i < len(ed):
                                pf = ed[p+i]
                                points.append(f"0x{pf:02x}")
                    except Exception:
                        pass

        return {
            "is_client_hello": True,
            "record_version": TLS_VER_MAP.get(rec_ver, f"0x{rec_ver:04x}"),
            "client_version": TLS_VER_MAP.get(client_version, f"0x{client_version:04x}"),
            "sni": sni_list,
            "cipher_suites": [TLS_CIPHER_NAMES.get(c, f"0x{c:04x}") for c in cipher_suites_no_grease],
            "cipher_suites_raw": cipher_suites_raw,
            "extensions": list(dict.fromkeys(exts)),  # дедуп
            "alpn": alpn_list,
            "supported_versions": sup_ver,
            "signature_algorithms": sig_algs,
            "supported_groups": groups,
            "ec_point_formats": points,
            "ch_length": len(body),
        }
    except Exception:
        return None

# Умная реассемблировка с TCP state machine
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

        if not target_pkt or TCP not in target_pkt:
            return b"", {}

        target_stream_key = self._get_stream_key(target_pkt)
        target_direction_key = self._get_dir_key(target_pkt)

        state = {
            'segments': {}, 'base_seq': None, 'retrans_count': 0, 'out_of_order_count': 0, 'max_seq_seen': 0
        }

        with PcapReader(pcap_file) as pr:
            for idx, pkt in enumerate(pr, 1):
                if idx > target_index:
                    break
                if TCP not in pkt or self._get_stream_key(pkt) != target_stream_key:
                    continue
                if self._get_dir_key(pkt) != target_direction_key:
                    continue

                seq = int(pkt[TCP].seq)
                payload = bytes(pkt[TCP].payload) if pkt[TCP].payload else b""
                if not payload:
                    continue

                if state['base_seq'] is None:
                    state['base_seq'] = seq

                if seq < state['max_seq_seen']:
                    state['out_of_order_count'] += 1

                if seq in state['segments']:
                    state['retrans_count'] += 1
                    if len(payload) > len(state['segments'][seq]):
                        state['segments'][seq] = payload
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
                    if overlap < len(data):
                        assembled += data[overlap:]
                else:
                    # разрыв — просто склеиваем (далее parse_client_hello сам найдёт валидную точку старта)
                    assembled += data
                last_end = max(last_end, seq + len(data))

        ch_off = find_clienthello_offset(assembled)
        metadata = {
            'retransmissions': state['retrans_count'],
            'out_of_order': state['out_of_order_count'],
            'overlaps': len(self._detect_overlaps([(s[0], s[1]) for s in sorted_segments])),
            'total_segments': len(state['segments']),
            'reassembly_confidence': self._calculate_confidence(state),
            'clienthello_found': ch_off is not None,
            'clienthello_offset': ch_off if ch_off is not None else -1,
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
            # если это IP — используем fallback, иначе вернем как есть
            if _is_ip(h):
                return FAKE_SNI_FALLBACK
            if "." in h:
                return h
        except Exception:
            pass
    return None

def generate_ml_enhanced_strategies(tls: Dict[str, Any], trigger: Dict[str, Any], raw_payload: bytes) -> List[Dict[str, Any]]:
    recs: List[Dict[str, Any]] = []

    def add(cmd: str, base: float, reason: str, dpi_type: str):
        recs.append({"cmd": cmd, "score": round(base, 3), "reason": reason, "dpi_type": dpi_type})

    dpi_type = "unknown"
    if trigger.get('injected', False) or trigger.get('ttl_difference', 0) > 4:
        dpi_type = "stateful"
    elif tls.get('ch_length', 0) or tls.get("is_client_hello"):
        dpi_type = "signature_based"

    # Получим stream_label, если есть, чтобы синтезировать SNI при необходимости
    stream_label = trigger.get("stream") or trigger.get("stream_id") or None
    sni = _synthesize_sni(tls, trigger, stream_label)
    has_real_sni = bool(tls.get("sni"))

    if tls.get("is_client_hello"):
        if dpi_type == 'signature_based':
            if has_real_sni:
                add('--dpi-desync=split --dpi-desync-split-pos=sni', 0.88, 'Signature evasion: SNI boundary split', dpi_type)
                add(f'--dpi-desync=fake --dpi-desync-fake-sni={tls["sni"][0][::-1]} --dpi-desync-ttl=1', 0.85, 'Signature evasion: Fake reversed SNI', dpi_type)
            if len(tls.get('cipher_suites_raw', [])) > 15:
                add('--dpi-desync=split --dpi-desync-split-pos=cipher', 0.82, 'Signature evasion: Split at cipher suites', dpi_type)

        elif dpi_type == 'stateful':
            # Для fake всегда указываем fake-sni (реальный или fallback)
            fsni = sni or FAKE_SNI_FALLBACK
            add(f"--dpi-desync=fake --dpi-desync-fake-sni={fsni} --dpi-desync-ttl=1 --dpi-desync-fooling=badsum", 0.85, "State confusion: fake with badsum, low TTL", dpi_type)
            add(f"--dpi-desync=fake,disorder --dpi-desync-fake-sni={fsni} --dpi-desync-ttl=2 --dpi-desync-fooling=badsum", 0.80, "State confusion: fake+disorder with fooling", dpi_type)
            add("--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-split-seqovl=10 --dpi-desync-ttl=4", 0.78, "State confusion: multi-fragmentation with overlap", dpi_type)

    if not recs:
        # Фоллбэки, не требующие SNI
        if b'\x16\x03' in raw_payload or b'\x00\x00\x00' in raw_payload:
            add("--dpi-desync=split --dpi-desync-split-pos=cipher --dpi-desync-ttl=2", 0.75, "TLS-like pattern found — split near ciphers", "unknown")
        if len(raw_payload) > 350:
            add("--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=20 --dpi-desync-ttl=4", 0.72, "Large payload — multi-fragmentation", "unknown")
        if sni:
            add(f"--dpi-desync=fake --dpi-desync-fake-sni={sni} --dpi-desync-ttl=1 --dpi-desync-fooling=badsum", 0.7, "Fallback fake with synthesized SNI", "unknown")

        if not recs:
            add("--dpi-desync=fake,disorder --dpi-desync-fake-sni=a.invalid --dpi-desync-fooling=badsum --dpi-desync-split-pos=76 --dpi-desync-ttl=3", 0.64, "Desperation fallback with safe fake-sni", "unknown")

    # Дедуп и сортировка
    seen, uniq = set(), []
    for r in recs:
        if r["cmd"] not in seen:
            seen.add(r["cmd"])
            uniq.append(r)
    uniq.sort(key=lambda x: x["score"], reverse=True)
    return uniq[:6]

def locate_clienthello_start(pcap_file: str, idx_hint: int) -> Optional[int]:
    """Находит индекс пакета, где начинается ClientHello, в том же потоке и направлении, что и idx_hint."""
    if not SCAPY_AVAILABLE or not isinstance(idx_hint, int) or idx_hint <= 0:
        return None

    target_pkt = None
    with PcapReader(pcap_file) as pr:
        for i, pkt in enumerate(pr, 1):
            if i == idx_hint:
                target_pkt = pkt
                break
    if not target_pkt or TCP not in target_pkt:
        return None

    # Определяем поток/направление
    def dir_key(pkt):
        if TCP in pkt:
            if IP in pkt: return (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
            if IPv6 in pkt: return (pkt[IPv6].src, pkt[TCP].sport, pkt[IPv6].dst, pkt[TCP].dport)
        return None

    stream_key = None
    if TCP in target_pkt:
        if IP in target_pkt:
            stream_key = tuple(sorted(((target_pkt[IP].src, target_pkt[TCP].sport),
                                       (target_pkt[IP].dst, target_pkt[TCP].dport))))
        elif IPv6 in target_pkt:
            stream_key = tuple(sorted(((target_pkt[IPv6].src, target_pkt[TCP].sport),
                                       (target_pkt[IPv6].dst, target_pkt[TCP].dport))))
    if not stream_key:
        return None

    tdir = dir_key(target_pkt)
    found_idx = None

    with PcapReader(pcap_file) as pr:
        for i, pkt in enumerate(pr, 1):
            if i > idx_hint:
                break
            if TCP in pkt:
                # тот же поток и направление
                if IP in pkt:
                    sk = tuple(sorted(((pkt[IP].src, pkt[TCP].sport), (pkt[IP].dst, pkt[TCP].dport))))
                elif IPv6 in pkt:
                    sk = tuple(sorted(((pkt[IPv6].src, pkt[TCP].sport), (pkt[IPv6].dst, pkt[TCP].dport))))
                else:
                    continue
                if sk != stream_key or dir_key(pkt) != tdir:
                    continue
                raw = bytes(pkt[TCP].payload) if pkt[TCP].payload else b""
                if not raw:
                    continue
                # ищем сигнатуру начала CH прямо в этом TCP-сегменте
                off = find_clienthello_offset(raw)
                if off is not None:
                    # Нашли пакет с началом CH. Берем самый первый из найденных до нашего триггера.
                    if found_idx is None:
                        found_idx = i
    return found_idx

# NEW: helpers to map stream labels between modules
def _normalize_stream_to_arrow(stream_label: Optional[str]) -> Optional[str]:
    # find_rst_triggers: "src:sp-dst:dp" -> "src:sp -> dst:dp"
    if not stream_label or "-" not in stream_label:
        return None
    try:
        left, right = stream_label.split("-", 1)
        return f"{left.strip()} -> {right.strip()}"
    except Exception:
        return None

def _parse_arrow_flow(flow_str: str) -> Optional[Tuple[str,int,str,int]]:
    # "a.b.c.d:12345 -> e.f.g.h:443"
    try:
        left, right = flow_str.split("->")
        lhost, lport = left.strip().rsplit(":", 1)
        rhost, rport = right.strip().rsplit(":", 1)
        return (lhost.strip("[] "), int(lport), rhost.strip("[] "), int(rport))
    except Exception:
        return None

# NEW: AttackValidator over pcap_inspect metrics
class AttackValidator:
    """
    Сопоставляет инциденты из find_rst_triggers с flow-метриками pcap_inspect
    и оценивает корректность реализации «фейк/реал».
    """
    @staticmethod
    def _score_pair(m: Dict[str, Any]) -> Tuple[float, List[str], List[str]]:
        # Возвращает (confidence 0..1, issues, fixes)
        issues, fixes = [], []
        score = 0.0

        if m.get("fake_first", False):
            score += 0.25
        else:
            issues.append("fake_first=false: фейк идёт не первым")
            fixes.append("Добавьте 'disorder' в --dpi-desync=..., чтобы фейк шёл первым")

        if m.get("csum_fake_bad", False):
            score += 0.20
        else:
            issues.append("csum_fake_bad=false: чек-сумма фейка не испорчена")
            fixes.append("Добавьте '--dpi-desync-fooling=badsum' (или badseq)")

        if m.get("seq_order_ok", False):
            score += 0.20
        else:
            issues.append("seq_order_ok=false: подозрительный порядок SEQ")
            fixes.append("Попробуйте '--dpi-desync-split-seqovl=10' или 'multisplit'")

        # TTL и время
        ttl_ok = m.get("ttl_order_ok", False)
        pair_dt = float(m.get("pair_dt_ms", 1000.0))
        if ttl_ok:
            score += 0.20
        else:
            # Мягкая альтернатива TTL: если окно времени маленькое — часть очков
            if pair_dt <= 50.0:
                score += 0.10
            issues.append("ttl_order_ok=false: порядок TTL не подтверждает fake->real")
            fixes.append("Уменьшите '--dpi-desync-ttl' до 1-2, чтобы фейк умер ближе")

        # Флаги
        if m.get("flags_real_psh", False) and m.get("flags_fake_no_psh", True):
            score += 0.05
        else:
            issues.append("PSH-флаги: real должен иметь PSH, fake — не обязан")
            fixes.append("Увеличьте фрагментацию или переиграйте split-позицию")

        # Временное окно
        if pair_dt <= 10.0:
            score += 0.10
        elif pair_dt <= 50.0:
            score += 0.05
        else:
            issues.append(f"pair_dt_ms={pair_dt:.1f}ms слишком велико")
            fixes.append("Увеличьте 'disorder' и уменьшите TTL на фейке")

        return min(1.0, score), issues, fixes

    def __init__(self, pcap_report: Dict[str, Any]):
        self._flows = {}
        for item in (pcap_report or {}).get("flows", []):
            flow = item.get("flow")
            if flow:
                self._flows[flow] = item

    def validate_incident(self, inc: Dict[str, Any]) -> Dict[str, Any]:
        stream = inc.get("stream")
        flow_arrow = _normalize_stream_to_arrow(stream)
        result = {
            "matched_flow": flow_arrow,
            "confidence": 0.0,
            "detected": False,
            "issues": [],
            "fixes": [],
            "metrics": None,
        }
        if not flow_arrow or flow_arrow not in self._flows:
            result["issues"].append("Не найден соотв. flow в pcap_inspect")
            return result

        metrics = (self._flows[flow_arrow] or {}).get("metrics")
        if not metrics:
            result["issues"].append("pcap_inspect не дал метрики по этому flow")
            return result

        conf, issues, fixes = self._score_pair(metrics)
        result.update({
            "detected": True,
            "confidence": conf,
            "issues": issues,
            "fixes": fixes,
            "metrics": metrics
        })
        return result

# NEW: refine strategies using validation findings
def _has_token(cmd: str, token: str) -> bool:
    return token in cmd.replace(",", " ")

def refine_strategies_with_validation(recs: List[Dict[str, Any]], validation: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not validation or not validation.get("detected"):
        return recs

    issues = set(validation.get("issues") or [])
    fixes = []

    def apply_fix(cmd: str) -> str:
        new_cmd = cmd
        # Если нет badsum — добавим
        if any("csum_fake_bad=false" in i for i in issues) and not _has_token(new_cmd, "badsum"):
            if "--dpi-desync-fooling=" in new_cmd:
                new_cmd = new_cmd.replace("--dpi-desync-fooling=", "--dpi-desync-fooling=badsum,")
            else:
                new_cmd += " --dpi-desync-fooling=badsum"
            fixes.append("Добавлен badsum")

        # Если fake_first=false -> disorder
        if any("fake_first=false" in i for i in issues) and "disorder" not in new_cmd:
            if "--dpi-desync=" in new_cmd:
                new_cmd = new_cmd.replace("--dpi-desync=", "--dpi-desync=disorder,")
            else:
                new_cmd += " --dpi-desync=disorder"
            fixes.append("Добавлен disorder")

        # Если ttl_order_ok=false -> ttl=1..2
        if any("ttl_order_ok=false" in i for i in issues) and "--dpi-desync-ttl=" not in new_cmd:
            new_cmd += " --dpi-desync-ttl=2"
            fixes.append("Добавлен ttl=2")

        # Если seq_order_ok=false — добавить seqovl
        if any("seq_order_ok=false" in i for i in issues) and "--dpi-desync-split-seqovl=" not in new_cmd:
            new_cmd += " --dpi-desync-split-seqovl=10"
            fixes.append("Добавлен split-seqovl=10")

        # Если окно времени слишком велико — повысим фрагментацию
        if any(i.startswith("pair_dt_ms=") for i in issues) and "multisplit" not in new_cmd:
            if "--dpi-desync=" in new_cmd:
                new_cmd = new_cmd.replace("--dpi-desync=", "--dpi-desync=multisplit,")
            else:
                new_cmd += " --dpi-desync=multisplit --dpi-desync-split-count=3"
            if "--dpi-desync-split-count=" not in new_cmd:
                new_cmd += " --dpi-desync-split-count=3"
            fixes.append("Добавлен multisplit")

        return new_cmd

    refined = []
    for r in recs:
        new_cmd = apply_fix(r["cmd"])
        if new_cmd != r["cmd"]:
            refined.append({
                **r,
                "cmd": new_cmd,
                "reason": r["reason"] + " | refined by pcap validation",
                "refined_from": r["cmd"],
                "refine_notes": list(set(fixes)),
                "validation_confidence": validation.get("confidence", 0.0),
            })
        else:
            refined.append(r)
    # Дедуп
    seen, uniq = set(), []
    for r in refined:
        if r["cmd"] in seen:
            continue
        seen.add(r["cmd"])
        uniq.append(r)
    return uniq


def build_json_report(pcap_file: str, triggers: List[Dict[str, Any]], no_reassemble: bool, validate: bool) -> Dict[str, Any]:
    report = {
        "pcap_file": pcap_file,
        "analysis_timestamp": datetime.now().isoformat(),
        "incident_count": len(triggers),
        "incidents": []
    }

    # NEW: единоразовый запуск pcap_inspect
    pcap_inspect_report = None
    validator = None
    if validate and PCAP_INSPECT_AVAILABLE:
        try:
            pcap_inspect_report = inspect_pcap(pcap_file)
            validator = AttackValidator(pcap_inspect_report)
        except Exception as e:
            print(f"[WARNING] pcap_inspect failed: {e}")

    for t in triggers:
        trig_idx = detect_trigger_index(t)
        rst_idx = detect_rst_index(t)
        
        assembled_payload, stream_label, reassembly_meta = b"", None, {}
        if not no_reassemble and isinstance(trig_idx, int):
            ch_idx = locate_clienthello_start(pcap_file, trig_idx)
            real_idx = ch_idx or trig_idx
            assembled_payload, stream_label, reassembly_meta = reassemble_clienthello(pcap_file, real_idx)
        
        if not stream_label:
            stream_label = get_stream_label(t, pcap_file, trig_idx or rst_idx)

        tls = parse_client_hello(assembled_payload) or {}
        if not tls.get("sni"):
            loose = extract_sni_loose(assembled_payload)
            if loose:
                tls.setdefault("is_client_hello", True)
                tls["sni"] = loose
        entropy_analysis = analyze_payload_entropy(assembled_payload)
        
        # базовые рекомендации
        recs = generate_ml_enhanced_strategies(tls, t, assembled_payload)

        # NEW: валидация по pcap_inspect и рефайн стратегий
        validation = {}
        if validator and stream_label:
            try:
                # у inc мы храним stream как в find_rst_triggers
                # validator сам нормализует до "src:sp -> dst:dp"
                fake_real_eval = validator.validate_incident({"stream": stream_label})
                validation = fake_real_eval or {}
                # рефайн рекомендаций
                recs = refine_strategies_with_validation(recs, validation)
            except Exception as e:
                validation = {"error": f"validation_failed: {e}"}

        incident = {
            "stream": stream_label,
            "rst_index": rst_idx,
            "trigger_index": trig_idx,
            "injected": bool(get_first(t, ["is_injected","dpi_injection","injection", "dpi_injection_suspected"], False)),
            "ttl_rst": get_first(t, ["rst_ttl","ttl_rst","rst_ttl_value", "rst_packet_ttl"]),
            "expected_ttl": get_first(t, ["expected_ttl","server_ttl", "server_base_ttl"]),
            "ttl_difference": get_first(t, ["ttl_difference","ttl_diff"]),
            "time_delta": get_first(t, ["time_delta","dt"]),
            "reassembly_metadata": reassembly_meta,
            "entropy_analysis": entropy_analysis,
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
            "payload_preview_hex": (assembled_payload[:64].hex() if assembled_payload else ""),
            "recommended_strategies": recs,
            # NEW: pcap_inspect validation footprint
            "attack_validation": validation
        }
        report["incidents"].append(incident)

    if report["incidents"]:
        pattern_analyzer = BlockingPatternAnalyzer()
        report["statistical_analysis"] = pattern_analyzer.analyze_incidents(report["incidents"])

    # NEW: прикрепим сырой отчёт pcap_inspect (коротко), чтобы не потерять контекст
    if pcap_inspect_report:
        report["pcap_inspect_summary"] = {
            "flows_count": len(pcap_inspect_report.get("flows", []))
        }

    return report


async def run_second_pass_from_report(
    report: Dict[str, Any],
    limit: int,
    port: int,
    engine_override: Optional[str],
    use_advanced_reporting: bool=False,
    save_adv_file: Optional[str]=None
):
    # ✅ FIX: Lazy import UnifiedBypassEngine here
    try:
        # Используем новый унифицированный движок
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
                except Exception:
                    continue
            if not host:
                continue
            cmds = [r["cmd"] for r in recs[:max(1, limit)]]
            host_to_strats.setdefault(host, [])
            for c in cmds:
                if c not in host_to_strats[host]:
                    host_to_strats[host].append(c)
            # derive dpi_type
            dpi_type = "unknown"
            if inc.get("injected", False) or (inc.get("ttl_difference") or 0) > 4:
                dpi_type = "stateful"
            elif ((inc.get("tls") or {}).get("is_client_hello")):
                dpi_type = "signature_based"
            host_to_dpi[host] = host_to_dpi.get(host) or dpi_type

    if not host_to_strats:
        print("[INFO] Нет стратегий для второго прогона (реков не найдено).")
        return

    # Advanced reporting integration
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
        try:
            ip = await resolver.resolve(host)
        except Exception:
            ip = None
        if not ip:
            ip = host if host and (host.replace(".", "").isdigit() or ':' in host) else None
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
            if best:
                print(f"   ✓ best: {best[0]['strategy']} (rate={best[0]['success_rate']:.0%}, {best[0].get('avg_latency_ms', 0):.1f}ms)")
            else:
                print("   ✗ нет успехов на втором прогоне")

            # Advanced reporting per strategy
            if integration:
                adv_reports.setdefault(host, [])
                for r in results:
                    attack_name = r.get("strategy") or "unknown_strategy"
                    exec_ms = float(r.get("avg_latency_ms", 0.0))
                    success = float(r.get("success_rate", 0.0)) > 0.0
                    eff = float(r.get("success_rate", 0.0))  # трактуем как 0..1
                    execution_result = {
                        "dpi_type": dpi_type,
                        "execution_time_ms": exec_ms,
                        "success": success,
                        "effectiveness_score": eff,
                        "ml_prediction": r.get("ml_prediction") or {},
                    }
                    adv = await integration.generate_attack_report(
                        attack_name=attack_name, target_domain=host, execution_result=execution_result
                    )
                    if adv:
                        # dataclass -> dict может быть сериализован в export_comprehensive_report
                        adv_reports[host].append({
                            "attack_name": adv.attack_name,
                            "target_domain": adv.target_domain,
                            "dpi_type": adv.dpi_type,
                            "success": adv.success,
                            "effectiveness_score": adv.effectiveness_score,
                            "execution_time_ms": adv.execution_time_ms,
                            "timestamp": adv.timestamp.isoformat(),
                            "recommendations": adv.recommendations,
                        })

        except Exception as e:
            print(f"   [WARN] second pass failed for {host}: {e}")

    out_name = f"pcap_second_pass_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    try:
        with open(out_name, "w", encoding="utf-8") as f:
            json.dump(all_results, f, ensure_ascii=False, indent=2)
        print(f"\n[OK] second-pass results saved → {out_name}")
    except Exception as e:
        print(f"[WARN] cannot save second-pass file: {e}")

    # Итоговый advanced comprehensive report (опционально)
    if integration and save_adv_file:
        try:
            comp = await integration.export_comprehensive_report(format_type="json", include_raw_data=True)
            with open(save_adv_file, "w", encoding="utf-8") as f:
                json.dump(comp, f, ensure_ascii=False, indent=2, default=str)
            print(f"[OK] advanced comprehensive report saved → {save_adv_file}")
        except Exception as e:
            print(f"[WARN] cannot save advanced report: {e}")

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
    # TCP options kind=19,len=18
    try:
        if TCP in pkt:
            # быстрый парсер опций из байтов TCP-заголовка
            # data offset
            if IP in pkt:
                ip_hl = pkt[IP].ihl*4
                tcp_ofs = ip_hl+20
                dataofs = pkt[TCP].dataofs*4
                opt_bytes = bytes(pkt.payload)[(dataofs-20):] if dataofs>20 else b""
            elif IPv6 in pkt:
                # у Scapy для TCP в IPv6 dataofs тоже валиден
                dataofs = pkt[TCP].dataofs*4
                opt_bytes = bytes(pkt[TCP])[:dataofs][20:] if dataofs>20 else b""
            else:
                return False
            b = bytes(pkt[TCP])
            hdr_len = pkt[TCP].dataofs*4
            opts = b[20:hdr_len] if hdr_len>20 else b""
            # простая проверка наличия \x13\x12
            return (b"\x13\x12" in opts)
    except:
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
    segments: list of dicts with keys:
      idx, flow, ttl, tcp_ok, ip_ok, md5, flags, paylen, seq, rel_seq
    returns: (label:str, meta:dict)
    """
    # sort by time/idx
    segs = sorted(segments, key=lambda x: x["idx"])
    fake = [s for s in segs if s["ttl"] is not None and s["ttl"] <= 4 or (not s["tcp_ok"]) or s["md5"]]
    # estimate pattern
    rels = [s["rel_seq"] for s in segs]
    ttls = [s["ttl"] for s in segs]
    has_md5 = any(s["md5"] for s in segs)
    count = len(segs)
    # try fakeddisorder (fake + part2 + part1)
    if fake and len(segs)>=3 and segs[0] in fake:
        # две «реальные» после фейка
        rel_after = [s["rel_seq"] for s in segs[1:]]
        # паттерн: [split_pos, 0] или [0, split_pos]
        if 0 in rel_after and any(r>0 for r in rel_after):
            split_pos = max([r for r in rel_after if r>0] or [0])
            label = f"fakeddisorder_badsum={'y' if not segs[0]['tcp_ok'] else 'n'}_ttl{segs[0]['ttl']}_split{split_pos}{'_md5' if has_md5 else ''}"
            return label, {"type":"fakeddisorder","split_pos":split_pos}
    # fake race (fake + real)
    if fake and count>=2 and segs[0] in fake:
        if segs[1]["rel_seq"]==0:
            label = f"fake_race_badsum={'y' if not segs[0]['tcp_ok'] else 'n'}_ttl{segs[0]['ttl']}{'_md5' if has_md5 else ''}"
            return label, {"type":"fake_race"}
    # multisplit/split: без фейка, несколько real с различными rel_seq
    if not fake and count>=2:
        splits = sorted(set([s["rel_seq"] for s in segs]))
        if len(splits)>=2:
            if len(splits)==2:
                label = f"split_{splits[1]}"
                return label, {"type":"split","split_pos":splits[1]}
            else:
                label = f"multisplit_{','.join(str(x) for x in splits[1:])}"
                return label, {"type":"multisplit","positions":splits[1:]}
    # seqovl эвристика: второй сегмент начинается раньше длины первого
    if count>=2 and segs[1]["rel_seq"]>0 and segs[1]["rel_seq"] < segs[0]["paylen"]:
        label = f"seqovl_ovl{segs[0]['paylen']-segs[1]['rel_seq']}"
        return label, {"type":"seqovl","overlap":segs[0]['paylen']-segs[1]['rel_seq']}
    # fallback
    return "unknown", {"type":"unknown"}

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


# ==============================================================================
# НОВЫЙ КЛАСС ДЛЯ АНАЛИЗА СБОЕВ ПОТОКОВ (ДИАГНОСТИКА ВТОРИЧНОЙ ПРОБЛЕМЫ)
# ==============================================================================

class FlowFailureAnalyzer:
    """
    Анализирует PCAP на предмет неудачных TCP-потоков ПОСЛЕ обхода DPI.
    Диагностирует проблемы с TCP Sequence Numbers и ответы сервера.
    """
    def __init__(self, pcap_file: str, local_ip: Optional[str] = None):
        self.pcap_file = pcap_file
        self.local_ip = local_ip
        self.flows = defaultdict(list)
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy не найден. Анализ потоков невозможен.")

    def analyze(self):
        """Основной метод для запуска анализа."""
        print("\n" + "="*80)
        print("🚀 ЗАПУСК АНАЛИЗА СБОЕВ TCP-ПОТОКОВ (POST-BYPASS)")
        print("="*80)

        packets = rdpcap(self.pcap_file)
        if not self.local_ip:
            self.local_ip = self._autodetect_local_ip(packets)
            if not self.local_ip:
                LOG.error("Не удалось определить локальный IP. Анализ остановлен.")
                return

        # 1. Группировка пакетов по потокам
        for pkt in packets:
            if TCP in pkt and IP in pkt:
                flow_key = self._get_flow_key(pkt)
                self.flows[flow_key].append(pkt)

        LOG.info(f"Найдено {len(self.flows)} TCP-потоков.")

        # 2. Анализ каждого потока
        failed_flows_count = 0
        for flow_key, packets in self.flows.items():
            # Нас интересуют только исходящие потоки от нашей машины
            if flow_key[0] != self.local_ip:
                continue

            analysis_result = self._analyze_stream(packets)
            if analysis_result["is_failed_bypass_attempt"]:
                failed_flows_count += 1
                self._print_stream_report(flow_key, analysis_result)

        if failed_flows_count == 0:
            print("\n✅ Не найдено потоков с признаками неудачного обхода (Server Hello -> RST).")
        else:
            print(f"\n🏁 Анализ завершен. Найдено {failed_flows_count} подозрительных потоков.")
        print("="*80)


    def _analyze_stream(self, packets: List[Any]) -> Dict:
        """Анализирует один TCP-поток на предмет ошибок сборки."""
        report = {
            "is_failed_bypass_attempt": False,
            "checks": {},
            "conclusion": "Причина сбоя не установлена.",
            "recommendation": "Проверьте PCAP вручную."
        }

        outbound_payload_pkts = [p for p in packets if p[IP].src == self.local_ip and TCP in p and p[TCP].payload]
        inbound_pkts = [p for p in packets if p[IP].dst == self.local_ip]

        # Эвристика для поиска fakeddisorder: 3 исходящих пакета с данными в начале
        if len(outbound_payload_pkts) < 3:
            return report

        # Предполагаем, что первые 3 пакета - это наша атака
        fake_pkt, part2_pkt, part1_pkt = outbound_payload_pkts[0], outbound_payload_pkts[1], outbound_payload_pkts[2]

        # Проверка 1: Анализ фейкового пакета
        report["checks"]["fake_packet"] = self._check_fake_packet(fake_pkt)

        # Проверка 2: Анализ сборки реальных сегментов
        report["checks"]["reassembly"] = self._check_reassembly(part1_pkt, part2_pkt)

        # Проверка 3: Анализ ответа сервера
        report["checks"]["server_response"] = self._check_server_response(inbound_pkts, part1_pkt[IP].dst)

        # Итоговое заключение
        if (report["checks"]["server_response"].get("pattern") == "SH_THEN_RST_FROM_SERVER"):
            report["is_failed_bypass_attempt"] = True
            if report["checks"]["reassembly"]["status"] == "FAIL":
                report["conclusion"] = "Наиболее вероятная причина - ошибка в TCP Sequence Number реальных сегментов."
                report["recommendation"] = "Проверьте логику вычисления `seq_offset` в `base_engine.py` и `segment_packet_builder.py`. Убедитесь, что `seq(part2) == seq(part1) + len(part1)`."
            elif report["checks"]["fake_packet"]["status"] == "FAIL":
                 report["conclusion"] = "Обнаружены проблемы в фейковом пакете. Хотя ответ от сервера есть, это может влиять на сессию."
                 report["recommendation"] = "Убедитесь, что у фейкового пакета всегда неверная контрольная сумма и низкий TTL."
            else:
                report["conclusion"] = "Обход DPI, вероятно, успешен, но сервер разрывает соединение из-за невалидного Client Hello."
                report["recommendation"] = "Проверьте, что содержимое `part1` и `part2` при сборке дает корректный Client Hello. Возможно, проблема в `split_pos`."

        return report

    def _check_fake_packet(self, pkt: Any) -> Dict:
        """Проверяет TTL и контрольную сумму фейкового пакета."""
        res = {"status": "PASS", "details": []}

        # Проверка TTL
        if pkt[IP].ttl > 10:
            res["status"] = "FAIL"
            res["details"].append(f"❌ TTL слишком высокий ({pkt[IP].ttl}), ожидался низкий (1-4).")
        else:
            res["details"].append(f"✅ TTL низкий ({pkt[IP].ttl}).")

        # Проверка контрольной суммы
        is_valid, _ = self._recalculate_checksums(pkt)
        if is_valid:
            res["status"] = "FAIL"
            res["details"].append("❌ TCP Checksum ВЕРНАЯ, хотя ожидалась неверная (badsum).")
        else:
            res["details"].append("✅ TCP Checksum неверная, как и ожидалось.")

        return res

    def _check_reassembly(self, part1_pkt: Any, part2_pkt: Any) -> Dict:
        """Проверяет корректность TCP Sequence Numbers для сборки."""
        res = {"status": "PASS", "details": []}

        seq1 = part1_pkt[TCP].seq
        len1 = len(part1_pkt[TCP].payload)
        seq2 = part2_pkt[TCP].seq

        expected_seq2 = (seq1 + len1) & 0xFFFFFFFF # Учитываем переполнение

        res["details"].append(f"  - Part1: seq={seq1}, len={len1}")
        res["details"].append(f"  - Part2: seq={seq2}")
        res["details"].append(f"  - Ожидаемый seq для Part2: {expected_seq2}")

        if seq2 != expected_seq2:
            res["status"] = "FAIL"
            res["details"].append(f"❌ ОШИБКА: Sequence number для Part2 некорректен! Разница: {seq2 - expected_seq2}")
        else:
            res["details"].append("✅ Sequence numbers корректны для сборки.")

        return res

    def _check_server_response(self, inbound_packets: List[Any], server_ip: str) -> Dict:
        """Ищет Server Hello и последующий RST от сервера."""
        res = {"status": "UNKNOWN", "pattern": "NO_RESPONSE", "details": []}

        server_hello_pkt = None
        rst_pkt = None

        for i, pkt in enumerate(inbound_packets):
            if pkt[IP].src != server_ip: continue

            # Ищем Server Hello (SYN+ACK - начало сессии, или PSH+ACK с TLS Server Hello)
            if TCP in pkt and (pkt[TCP].flags.SA or (pkt[TCP].flags.PA and pkt[TCP].payload and bytes(pkt[TCP].payload)[0] == 0x16)):
                if self._is_tls_server_hello(bytes(pkt[TCP].payload)):
                    server_hello_pkt = pkt
                    res["details"].append(f"✅ Найден Server Hello в пакете #{pkt.packet_num if hasattr(pkt, 'packet_num') else 'N/A'}.")

                    # Ищем RST сразу после Server Hello
                    if i + 1 < len(inbound_packets):
                        next_pkt = inbound_packets[i+1]
                        if next_pkt[IP].src == server_ip and TCP in next_pkt and next_pkt[TCP].flags.R:
                            rst_pkt = next_pkt
                            res["details"].append(f"✅ Найден RST от сервера сразу после Server Hello в пакете #{rst_pkt.packet_num if hasattr(rst_pkt, 'packet_num') else 'N/A'}.")
                    break

        if server_hello_pkt and rst_pkt:
            res["status"] = "FAIL"
            res["pattern"] = "SH_THEN_RST_FROM_SERVER"
        elif server_hello_pkt and not rst_pkt:
            res["status"] = "PASS"
            res["pattern"] = "SH_ONLY"
            res["details"].append("✅ Получен Server Hello, но RST от сервера не найден. Проблема может быть дальше в потоке.")
        else:
            res["details"].append("❌ Server Hello от целевого сервера не найден.")

        return res

    def _print_stream_report(self, flow_key: Tuple, report: Dict):
        """Выводит отформатированный отчет по одному потоку."""
        print("\n" + "-"*70)
        print(f"🔍 Анализ потока: {flow_key[0]}:{flow_key[1]} -> {flow_key[2]}:{flow_key[3]}")
        print("-"*70)

        # Отчет по фейковому пакету
        fake_check = report["checks"]["fake_packet"]
        print(f"  [1] Анализ фейкового пакета: [{fake_check['status']}]")
        for detail in fake_check["details"]:
            print(f"      {detail}")

        # Отчет по сборке
        reasm_check = report["checks"]["reassembly"]
        print(f"  [2] Проверка сборки реальных сегментов: [{reasm_check['status']}]")
        for detail in reasm_check["details"]:
            print(f"      {detail}")

        # Отчет по ответу сервера
        resp_check = report["checks"]["server_response"]
        print(f"  [3] Анализ ответа сервера: [{resp_check['status']}]")
        for detail in resp_check["details"]:
            print(f"      {detail}")

        print("\n  --- Заключение ---")
        print(f"  Вывод: {report['conclusion']}")
        print(f"  Рекомендация: {report['recommendation']}")
        print("-"*70)

    def _get_flow_key(self, pkt: Any) -> Tuple:
        return (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)

    def _autodetect_local_ip(self, packets: List[Any]) -> Optional[str]:
        # ... (эта функция уже есть в pcap_checksum_validator, можно скопировать)
        src_ips = Counter()
        for i, pkt in enumerate(packets):
            if i > 200: break
            if IP in pkt and pkt[IP].src:
                try:
                    if ipaddress.ip_address(pkt[IP].src).is_private:
                        src_ips[pkt[IP].src] += 1
                except ValueError:
                    continue
        if src_ips:
            return src_ips.most_common(1)[0][0]
        return None

    def _recalculate_checksums(self, pkt: Any) -> Tuple[bool, bool]:
        # ... (эта функция тоже есть, можно адаптировать)
        try:
            # TCP Checksum
            tcp_pkt = pkt.copy()
            original_tcp_chksum = tcp_pkt[TCP].chksum
            del tcp_pkt[TCP].chksum
            recalculated_tcp_chksum = IP(bytes(tcp_pkt))[TCP].chksum
            tcp_valid = original_tcp_chksum == recalculated_tcp_chksum

            # IP Checksum
            ip_pkt = pkt[IP].copy()
            original_ip_chksum = ip_pkt.chksum
            del ip_pkt.chksum
            recalculated_ip_chksum = IP(bytes(ip_pkt)).chksum
            ip_valid = original_ip_chksum == recalculated_ip_chksum

            return tcp_valid, ip_valid
        except Exception:
            return False, False

    def _is_tls_server_hello(self, payload: bytes) -> bool:
        # Простая проверка на Server Hello (Handshake Type 2)
        return payload and len(payload) > 5 and payload[0] == 0x16 and payload[5] == 0x02

# ==============================================================================
# ИНТЕГРАЦИЯ В `main()`
# ==============================================================================

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
    # NEW:
    parser.add_argument("--validate", action="store_true", help="Валидировать «фейк/реал» через pcap_inspect и авто-рефайн стратегий")
    parser.add_argument("--save-inspect-json", type=str, default=None, help="Сохранить сырой отчёт pcap_inspect в файл")
    parser.add_argument("--advanced-report", action="store_true", help="Сгенерировать AdvancedReportingIntegration артефакты")
    parser.add_argument("--advanced-report-file", type=str, default="advanced_report.json", help="Куда сохранить сводный advanced-отчёт")
    parser.add_argument("--export-strategy-samples", type=str, help="Каталог для выгрузки пер-стратегийных PCAP/JSON самплов")

    # <<< НОВЫЙ АРГУМЕНТ >>>
    parser.add_argument("--analyze-flow-failures", action="store_true", help="Запустить детальный анализ неудачных TCP-потоков для диагностики проблем сборки.")
    parser.add_argument("--local-ip", help="IP-адрес локальной машины для анализа потоков (если автоопределение неверно).")


    args = parser.parse_args()

    if not os.path.exists(args.pcap_file):
        print(f"[ERROR] Файл не найден: {args.pcap_file}", file=sys.stderr)
        sys.exit(1)

    # <<< НОВЫЙ РЕЖИМ РАБОТЫ >>>
    if args.analyze_flow_failures:
        analyzer = FlowFailureAnalyzer(args.pcap_file, local_ip=args.local_ip)
        analyzer.analyze()
        sys.exit(0)

    # Анализ RST
    analyzer = RSTTriggerAnalyzer(args.pcap_file)
    triggers = analyzer.analyze()

    # Собираем основной отчёт, внутри него уже прикрепится pcap_inspect validation (при наличии)
    report = build_json_report(args.pcap_file, triggers, args.no_reassemble, args.validate)

    # Дополнительно — сохранить сырой отчёт pcap_inspect, если просили
    if args.save_inspect_json and PCAP_INSPECT_AVAILABLE:
        try:
            raw_inspect = inspect_pcap(args.pcap_file)
            with open(args.save_inspect_json, "w", encoding="utf-8") as f:
                json.dump(raw_inspect, f, ensure_ascii=False, indent=2)
            print(f"[OK] pcap_inspect report saved → {args.save_inspect_json}")
        except Exception as e:
            print(f"[WARN] cannot save pcap_inspect report: {e}")

    # Вывод/сохранение JSON
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
                elif inc.get("payload_preview_hex"):
                    print(f"  • ClientHello не разобран. Начало payload (hex): {inc['payload_preview_hex']}")

                # Рекомендации (уже со встроенным рефайном)
                recs = inc.get("recommended_strategies") or []
                if recs:
                    print("\n  РЕКОМЕНДАЦИИ ПО СТРАТЕГИЯМ:")
                    for r in recs[:3]:
                        marker = " (refined)" if r.get("refined_from") else ""
                        print(f"   • {r['cmd']}{marker}   [{r['score']:.2f}] — {r['reason']}")
                        if r.get("refine_notes"):
                            print(f"       ↳ fixes: {', '.join(r['refine_notes'])}")
                else:
                    print("\n  РЕКОМЕНДАЦИИ ПО СТРАТЕГИЯМ: (не найдено)")

                # Валидация
                val = inc.get("attack_validation") or {}
                if val:
                    conf = val.get("confidence", 0.0)
                    print(f"  • Валидация fake/real: detected={val.get('detected', False)}, confidence={conf:.2f}")
                    if val.get("issues"):
                        print(f"    issues: {', '.join(val['issues'])}")
                    if val.get("fixes"):
                        print(f"    fixes: {', '.join(val['fixes'])}")

        stats = report.get("statistical_analysis")
        if stats:
            print("\n[СТАТИСТИЧЕСКИЙ АНАЛИЗ ПАТТЕРНОВ БЛОКИРОВОК]")
            print("============================================================")
            if stats.get('sni_patterns'):
                print("  • Частые SNI-триггеры:")
                for pattern, count in stats['sni_patterns']: print(f"    - {pattern}: {count} раз")
            if stats.get('size_boundaries'):
                sz = stats['size_boundaries']
                if 'mean' in sz: print(f"  • Размеры ClientHello: min={sz['min']}, max={sz['max']}, mean={sz['mean']:.1f}")
            if stats.get('ttl_signature'):
                ttl = stats['ttl_signature']
                if 'mean' in ttl: print(f"  • TTL инъекций: mean={ttl['mean']:.1f}, std={ttl['std']:.1f}")

    # Асинхронная часть: второй прогон + advanced reporting/export (если требуется)
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

        # Второй прогон
        if args.second_pass:
            await run_second_pass_from_report(
                report,
                limit=args.second_pass_limit,
                port=args.second_pass_port,
                engine_override=args.engine_override,
                use_advanced_reporting=args.advanced_report,
                save_adv_file=(args.advanced_report_file if args.advanced_report else None)
            )

        # Экспорт advanced-отчета (если просили)
        if args.advanced_report_file and reporting and not args.second_pass:
            try:
                # NB: export_comprehensive_report реализован в интеграции; формат управляется флагами
                comprehensive = await reporting.export_comprehensive_report(
                    format_type="json",
                    include_raw_data=True
                )
                with open(args.advanced_report_file, "w", encoding="utf-8") as f:
                    json.dump(comprehensive, f, ensure_ascii=False, indent=2, default=str)
                print(f"[OK] Advanced report exported → {args.advanced_report_file}")
            except Exception as e:
                print(f"[WARN] Не удалось экспортировать advanced-отчет: {e}")

    # Запуск асинхронного хвоста, если есть, что делать
    if args.second_pass or (args.advanced_report and ADV_REPORTING_AVAILABLE):
        asyncio.run(_async_tail())

    if args.export_strategy_samples and SCAPY_AVAILABLE:
        export_strategy_samples(args.pcap_file, args.export_strategy_samples)

if __name__ == "__main__":
    main()