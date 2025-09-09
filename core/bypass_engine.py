import platform
import time
import threading
import logging
import struct
import random
import re
import copy
from collections import defaultdict
from typing import List, Dict, Optional, Tuple, Set, Any
from core.bypass.attacks.base import AttackResult, AttackStatus
try:
    from core.quic_handler import QuicHandler
except Exception:
    from quic_handler import QuicHandler

# Calibrator and alias map integration
from core.bypass.attacks.alias_map import normalize_attack_name
from core.calibration.calibrator import Calibrator, CalibCandidate
try:
    from core.strategy_manager import StrategyManager
except (ImportError, ModuleNotFoundError):
    try:
        # Fallback to root strategy_manager if available
        from strategy_manager import StrategyManager
    except (ImportError, ModuleNotFoundError):
        StrategyManager = None
        logging.getLogger("BypassEngine").warning("StrategyManager could not be imported.")


if platform.system() == "Windows":
    import pydivert


class BypassTechniques:
    """Библиотека продвинутых техник обхода DPI."""

    @staticmethod
    def apply_fakeddisorder(
        payload: bytes, split_pos: int = 76, overlap_size: int = 336
    ) -> List[Tuple[bytes, int]]:
        """
        Apply fakeddisorder technique with zapret-compatible sequence overlap.
        
        CRITICAL FIX: Implements zapret's exact sequence overlap algorithm.
        
        Zapret Algorithm:
        1. Split payload at split_pos (default 76, not 3)
        2. Send part2 first with sequence number = original_seq + split_pos
        3. Send part1 with sequence number = original_seq - overlap_size
        4. This creates overlap that confuses DPI but reassembles correctly
        
        Args:
            payload: Original payload to split
            split_pos: Position to split the payload (default 76 from zapret)
            overlap_size: Size of overlap between segments (default 336 from zapret)
            
        Returns:
            List of (segment, seq_offset) tuples for disordered transmission
        """
        if split_pos >= len(payload):
            return [(payload, 0)]

        part1, part2 = (payload[:split_pos], payload[split_pos:])

        # ВАЖНО: zapret не ограничивает overlap длиной part1/part2/split_pos — допускается NEGATIVE seq-offset,
        # когда второй фрагмент (part1) уходит "назад" относительно base_seq.
        # Поэтому НЕ режем overlap до split_pos, оставляем как есть (но защитимся от безумных значений).
        ov = int(overlap_size) if isinstance(overlap_size, int) else 336
        if ov <= 0:
            return [(part2, split_pos), (part1, 0)]
        if ov > 4096:
            ov = 4096

        offset_part2 = split_pos                           # seq = base + split_pos
        offset_part1 = split_pos - ov                      # seq = base + split_pos - overlap (может быть < base)

        return [(part2, offset_part2), (part1, offset_part1)]

    @staticmethod
    def apply_multisplit(
        payload: bytes, positions: List[int]
    ) -> List[Tuple[bytes, int]]:
        if not positions:
            return [(payload, 0)]
        segments, last_pos = ([], 0)
        for pos in sorted(positions):
            if pos > last_pos and pos < len(payload):
                segments.append((payload[last_pos:pos], last_pos))
                last_pos = pos
        if last_pos < len(payload):
            segments.append((payload[last_pos:], last_pos))
        return segments

    @staticmethod
    def apply_multidisorder(
        payload: bytes, positions: List[int]
    ) -> List[Tuple[bytes, int]]:
        segments = BypassTechniques.apply_multisplit(payload, positions)
        return segments[::-1] if len(segments) > 1 else segments

    @staticmethod
    def apply_seqovl(
        payload: bytes, split_pos: int = 3, overlap_size: int = 10
    ) -> List[Tuple[bytes, int]]:
        if split_pos >= len(payload):
            return [(payload, 0)]
        part1, part2 = (payload[:split_pos], payload[split_pos:])
        overlap_data = b"\x00" * overlap_size
        part1_with_overlap = overlap_data + part1
        return [(part2, split_pos), (part1_with_overlap, -overlap_size)]

    @staticmethod
    def apply_tlsrec_split(payload: bytes, split_pos: int = 5) -> bytes:
        """
        Безопасный split одного TLS record (ClientHello) на два записи.
        Поддерживает TLS 1.0–1.3 (версия 0x0301..0x0303). Сохраняет хвост после record.
        """
        try:
            if not payload or len(payload) < 5:
                return payload
            # TLS record header: ContentType(1)=0x16, Version(2)=0x03 xx, Length(2)
            if payload[0] != 0x16 or payload[1] != 0x03 or payload[2] not in (0x00, 0x01, 0x02, 0x03):
                return payload
            rec_len = int.from_bytes(payload[3:5], "big")
            content = payload[5:5 + rec_len] if 5 + rec_len <= len(payload) else payload[5:]
            tail = payload[5 + rec_len:] if 5 + rec_len <= len(payload) else b""
            if split_pos < 1 or split_pos >= len(content):
                return payload
            part1, part2 = content[:split_pos], content[split_pos:]
            ver = payload[1:3]
            rec1 = bytes([0x16]) + ver + len(part1).to_bytes(2, "big") + part1
            rec2 = bytes([0x16]) + ver + len(part2).to_bytes(2, "big") + part2
            return rec1 + rec2 + tail
        except Exception:
            return payload

    @staticmethod
    def apply_wssize_limit(
        payload: bytes, window_size: int = 1
    ) -> List[Tuple[bytes, int]]:
        segments, pos = ([], 0)
        while pos < len(payload):
            chunk_size = min(window_size, len(payload) - pos)
            chunk = payload[pos : pos + chunk_size]
            segments.append((chunk, pos))
            pos += chunk_size
        return segments

    @staticmethod
    def apply_badsum_fooling(packet_data: bytearray) -> bytearray:
        ip_header_len = (packet_data[0] & 15) * 4
        tcp_checksum_pos = ip_header_len + 16
        if len(packet_data) > tcp_checksum_pos + 1:
            packet_data[tcp_checksum_pos : tcp_checksum_pos + 2] = struct.pack(
                "!H", 57005
            )
        return packet_data

    @staticmethod
    def apply_md5sig_fooling(packet_data: bytearray) -> bytearray:
        ip_header_len = (packet_data[0] & 15) * 4
        tcp_checksum_pos = ip_header_len + 16
        if len(packet_data) > tcp_checksum_pos + 1:
            packet_data[tcp_checksum_pos : tcp_checksum_pos + 2] = struct.pack(
                "!H", 48879
            )
        return packet_data


if platform.system() == "Windows":

    class BypassEngine:

        def __init__(self, debug=True):
            self.debug = debug
            self.running = False
            self.techniques = BypassTechniques()
            self.logger = logging.getLogger("BypassEngine")
            self.logger.info(f"BypassEngine from {self.__class__.__module__}")
            if debug:
                if self.logger.level == logging.NOTSET:
                    self.logger.setLevel(logging.DEBUG)
                if not any(
                    (isinstance(h, logging.StreamHandler) for h in self.logger.handlers)
                ):
                    logging.basicConfig(
                        level=logging.DEBUG,
                        format="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
                    )
            self.stats = {
                "packets_captured": 0,
                "tls_packets_bypassed": 0,
                "quic_packets_bypassed": 0,
                "fragments_sent": 0,
                "fake_packets_sent": 0,
            }
            self.cloudflare_prefixes = (
                "104.",
                "172.64.",
                "172.67.",
                "162.158.",
                "162.159.",
            )
            self.current_params = {}
            self.quic_handler = QuicHandler(debug=debug)
            self._telemetry_max_targets = 1000
            
            # Adaptive strategy controller and flow tracking
            # Маркер для собственных инжекций (чтобы не перехватывать их повторно)
            self._INJECT_MARK = 0xC0DE

            self.controller = None
            self.flow_table = {}
            self._lock = threading.Lock()
            self._inbound_thread = None
            # Guard: чтобы не инжектить один и тот же поток многократно
            self._active_flows: Set[Tuple[str,int,str,int]] = set()
            self._flow_ttl_sec = 3.0
            # For calibrator early stopping
            self._inbound_events: Dict[Tuple[str, int, str, int], threading.Event] = {}
            self._inbound_results: Dict[Tuple[str, int, str, int], str] = {}
            # Ограничение параллельных инъекций и jitter
            self._max_injections = 12
            self._inject_sema = threading.Semaphore(self._max_injections)
            # Профили по CDN: md5sig_allowed/badsum_allowed + лучшие параметры
            self.cdn_profiles: Dict[str, Dict[str, Any]] = {}
            # --- Телеметрия инжектов/исходов ---
            self._tlock = threading.Lock()
            self._telemetry = self._init_telemetry()

        def attach_controller(self, base_rules, zapret_parser, task_translator,
                              store_path="learned_strategies.json", epsilon=0.1):
            """
            Подключает онлайн-контроллер стратегий (ε-greedy).
            base_rules: dict {domain|*.domain|default: zapret_string}
            zapret_parser: экземпляр ZapretStrategyParser
            task_translator: функция parsed_params -> engine_task dict
            """
            try:
                from core.optimizer.adaptive_controller import AdaptiveStrategyController
            except Exception as e:
                self.logger.error(f"Adaptive controller not available: {e}")
                return False
            self.controller = AdaptiveStrategyController(
                base_rules=base_rules,
                zapret_parser=zapret_parser,
                task_translator=task_translator,
                store_path=store_path,
                epsilon=epsilon
            )
            self.logger.info("✅ AdaptiveStrategyController attached")
            return True

        def start(self, target_ips: Set[str], strategy_map: Dict[str, Dict], reset_telemetry: bool = False):
            """Запускает движок обхода в отдельном потоке."""
            if reset_telemetry:
                with self._tlock:
                    self._telemetry = self._init_telemetry()
            self.running = True
            self.logger.info("🚀 Запуск универсального движка обхода DPI...")
            thread = threading.Thread(
                target=self._run_bypass_loop,
                args=(target_ips, strategy_map),
                daemon=True,
            )
            thread.start()
            # Всегда запускаем inbound-обсервер (нужен для ранней остановки калибратора)
            if not self._inbound_thread:
                self._inbound_thread = self._start_inbound_observer()
            return thread

        def start_with_config(self, config: dict):
            """Запускает движок обхода с упрощенной конфигурацией для службы."""
            strategy_task = self._config_to_strategy_task(config)
            target_ips = set()
            strategy_map = {"default": strategy_task}
            self.logger.info(f"🚀 Starting service mode with strategy: {strategy_task}")
            return self.start(target_ips, strategy_map)

        def _config_to_strategy_task(self, config: dict) -> dict:
            """
            ИСПРАВЛЕНИЕ: Конвертация конфигурации в стратегию.
            Теперь стратегии применяются точно как указано в конфигурации.
            """
            desync_method = config.get("desync_method", "fake")
            fooling = config.get("fooling", "none")
            ttl = config.get("ttl", 3)
            split_pos = config.get("split_pos", 3)
            if desync_method == "multisplit":
                positions = []
                split_count = config.get("split_count", 3)
                overlap = config.get("overlap_size", 20)
                if split_count > 0:
                    if split_count <= 3:
                        positions = [6, 12, 18][:split_count]
                    else:
                        positions = []
                        base_offset = 6
                        gaps = [8, 12, 16, 20, 24]
                        last_pos = base_offset
                        for i in range(split_count):
                            positions.append(last_pos)
                            gap = gaps[i] if i < len(gaps) else gaps[-1]
                            last_pos += gap
                return {
                    "type": "multisplit",
                    "params": {
                        "ttl": ttl,
                        "split_pos": split_pos,
                        "positions": positions,
                        "overlap_size": overlap,
                        "fooling": fooling,
                        "window_div": 2,
                        "tcp_flags": {"psh": True, "ack": True},
                        "ipid_step": 2048,
                        "delay_ms": 5,
                    },
                }
            elif desync_method in ("fake", "fakeddisorder", "seqovl"):
                base_params = {
                    "ttl": ttl,
                    "split_pos": split_pos,
                    "window_div": 8,
                    "tcp_flags": {"psh": True, "ack": True},
                    "ipid_step": 2048,
                }
                if fooling == "badsum":
                    task_type = "badsum_race"
                    base_params["extra_ttl"] = ttl + 1
                    base_params["delay_ms"] = 5
                elif fooling == "md5sig":
                    task_type = "md5sig_race"
                    base_params["extra_ttl"] = ttl + 2
                    base_params["delay_ms"] = 7
                elif desync_method == "seqovl":
                    task_type = "seqovl"
                    base_params["overlap_size"] = config.get("overlap_size", 20)
                else:
                    task_type = "fakedisorder"
                return {"type": task_type, "params": base_params}
            return {
                "type": "fakedisorder",
                "params": {
                    "ttl": ttl,
                    "split_pos": split_pos,
                    "window_div": 8,
                    "tcp_flags": {"psh": True, "ack": True},
                    "ipid_step": 2048,
                },
            }

        def stop(self):
            """Останавливает движок обхода."""
            self.running = False
            self.logger.info("🛑 Остановка движка обхода DPI...")

        def _strategy_key(self, strategy_task: Dict[str, Any]) -> str:
            try:
                t = (strategy_task or {}).get("type", "unknown")
                p = (strategy_task or {}).get("params", {})
                parts = []
                for k, v in p.items():
                    parts.append(f"{k}={v}")
                return f"{t}({', '.join(parts)})"
            except Exception:
                return str(strategy_task)

        def _init_telemetry(self) -> Dict[str, Any]:
            return {
                "start_ts": time.time(),
                "strategy_key": None,
                "aggregate": {
                    "segments_sent": 0,
                    "fake_packets_sent": 0,
                    "modified_packets_sent": 0,
                    "quic_segments_sent": 0
                },
                "ttls": {"fake": defaultdict(int), "real": defaultdict(int)},
                "seq_offsets": defaultdict(int),
                "overlaps": defaultdict(int),
                "clienthellos": 0,
                "serverhellos": 0,
                "rst_count": 0,
                "per_target": defaultdict(lambda: {
                    "segments_sent": 0, "fake_packets_sent": 0,
                    "seq_offsets": defaultdict(int), "ttls_fake": defaultdict(int),
                    "ttls_real": defaultdict(int), "overlaps": defaultdict(int),
                    "last_outcome": None, "last_outcome_ts": None
                })
            }

        def _cleanup_old_telemetry(self):
            """Clean up old telemetry entries to prevent memory leak."""
            with self._tlock:
                if len(self._telemetry["per_target"]) > self._telemetry_max_targets:
                    sorted_targets = sorted(
                        self._telemetry["per_target"].items(),
                        key=lambda x: x[1].get("last_outcome_ts", 0) or 0,
                        reverse=True
                    )
                    self._telemetry["per_target"] = dict(sorted_targets[:self._telemetry_max_targets])
            # Clean up old flow entries under lock
            try:
                with self._lock:
                    current_time = time.time()
                    old_flows = [k for k, v in self.flow_table.items()
                                 if current_time - v.get("start_ts", 0) > 30]
                    for flow in old_flows:
                        self.flow_table.pop(flow, None)
            except Exception:
                pass

        def _is_target_ip(self, ip_str: str, target_ips: Set[str]) -> bool:
            """
            ИСПРАВЛЕНИЕ: Улучшенная логика определения целевых IP.
            Теперь учитывает больше CDN и правильно обрабатывает режим службы.
            """
            if not target_ips:
                return True
            if ip_str in target_ips:
                return True
            cdn_prefixes = {
                "104.",
                "172.64.",
                "172.67.",
                "162.158.",
                "162.159.",
                "104.16.",
                "104.17.",
                "104.18.",
                "104.19.",
                "104.20.",
                "104.21.",
                "104.22.",
                "104.23.",
                "104.24.",
                "104.25.",
                "104.26.",
                "104.27.",
                "104.28.",
                "104.29.",
                "104.30.",
                "151.101.",
                "199.232.",
                "23.",
                "104.",
                "184.",
                "2.16.",
                "95.100.",
                "185.199.",
                "87.240.",
                "93.186.",
                "54.192.",
                "54.230.",
                "54.239.",
                "54.182.",
                "216.58.",
                "172.217.",
                "142.250.",
                "172.253.",
                "13.107.",
                "40.96.",
                "40.97.",
                "40.98.",
                "40.99.",
                "77.88.",
                "5.255.",
                "128.140.",
                "217.20.",
                "51.89.",
                "51.91.",
                "104.131.",
                "104.236.",
                "91.108.",
                "149.154.",
            }
            for prefix in cdn_prefixes:
                if ip_str.startswith(prefix):
                    self.logger.debug(
                        f"IP {ip_str} соответствует CDN префиксу {prefix}"
                    )
                    return True
            return False

        def _resolve_midsld_pos(self, payload: bytes) -> Optional[int]:
            """Находит позицию середины домена второго уровня в SNI."""
            try:
                pos = payload.find(b"\x00\x00")
                while pos != -1:
                    if pos + 9 < len(payload):
                        ext_len = int.from_bytes(payload[pos + 2 : pos + 4], "big")
                        list_len = int.from_bytes(payload[pos + 4 : pos + 6], "big")
                        name_type = payload[pos + 6]
                        if (
                            name_type == 0
                            and ext_len == list_len + 2
                            and (list_len > 0)
                        ):
                            name_len = int.from_bytes(payload[pos + 7 : pos + 9], "big")
                            name_start = pos + 9
                            if name_start + name_len <= len(payload):
                                domain_bytes = payload[
                                    name_start : name_start + name_len
                                ]
                                domain_str = domain_bytes.decode(
                                    "idna", errors="strict"
                                )
                                parts = domain_str.split(".")
                                if len(parts) >= 2:
                                    sld_start_in_domain = domain_str.rfind(parts[-2])
                                    sld_mid_pos = (
                                        sld_start_in_domain + len(parts[-2]) // 2
                                    )
                                    return name_start + sld_mid_pos
                    pos = payload.find(b"\x00\x00", pos + 1)
            except Exception as e:
                self.logger.debug(f"Error resolving midsld: {e}")
            return None

        def _classify_cdn(self, ip_str: str) -> str:
            """Грубая классификация CDN по префиксам."""
            mapping = {
                "104.": "cloudflare",
                "172.64.": "cloudflare", "172.67.": "cloudflare",
                "162.158.": "cloudflare", "162.159.": "cloudflare",
                "151.101.": "fastly",
                "199.232.": "fastly",
                "23.": "akamai",
                "2.16.": "akamai", "95.100.": "akamai",
                "54.192.": "cloudfront", "54.230.": "cloudfront", "54.239.": "cloudfront", "54.182.": "cloudfront",
                "216.58.": "google", "172.217.": "google", "142.250.": "google", "172.253.": "google",
                "157.240.": "meta", "69.171.": "meta", "31.13.": "meta",
                "77.88.": "yandex", "5.255.": "yandex",
                "104.244.": "twitter", "199.59.": "twitter",
                "91.108.": "telegram", "149.154.": "telegram",
                "13.107.": "microsoft", "40.96.": "microsoft", "40.97.": "microsoft", "40.98.": "microsoft", "40.99.": "microsoft",
                "104.131.": "digitalocean", "104.236.": "digitalocean",
            }
            for pref, name in mapping.items():
                if ip_str.startswith(pref):
                    return name
            return "generic"

        def _get_cdn_profile(self, cdn: str) -> Dict[str, Any]:
            prof = self.cdn_profiles.get(cdn)
            if not prof:
                prof = {"md5sig_allowed": None, "badsum_allowed": None, "best_fakeddisorder": None}
                self.cdn_profiles[cdn] = prof
            return prof

        def _estimate_split_pos_from_ch(self, payload: bytes) -> Optional[int]:
            """Оценивает разумный split_pos из структуры TLS ClientHello."""
            try:
                if not self._is_tls_clienthello(payload):
                    return None
                # TLS record (5), HandshakeType=1 @ [5], len[6:9]
                if len(payload) < 43:
                    return None
                # Handshake header
                if payload[5] != 0x01:
                    return None
                pos = 9  # after hs header(4)
                # legacy_version(2) + random(32)
                pos += 2 + 32
                if pos + 1 >= len(payload):
                    return None
                # session_id
                sid_len = payload[pos]
                pos += 1 + sid_len
                if pos + 2 > len(payload):
                    return None
                # cipher_suites
                cs_len = int.from_bytes(payload[pos:pos+2], "big")
                pos += 2 + cs_len
                if pos + 1 > len(payload):
                    return None
                # compression
                comp_len = payload[pos]
                pos += 1 + comp_len
                if pos + 2 > len(payload):
                    return None
                # extensions
                ext_len = int.from_bytes(payload[pos:pos+2], "big")
                ext_start = pos + 2
                if ext_start + ext_len > len(payload):
                    ext_len = max(0, len(payload) - ext_start)
                # Попробуем найти SNI внутри extensions
                s = ext_start
                sni_mid_abs = None
                while s + 4 <= ext_start + ext_len:
                    etype = int.from_bytes(payload[s:s+2], "big")
                    elen = int.from_bytes(payload[s+2:s+4], "big")
                    epos = s + 4
                    if epos + elen > len(payload):
                        break
                    if etype == 0 and elen >= 5:
                        # server_name
                        try:
                            list_len = int.from_bytes(payload[epos:epos+2], "big")
                            npos = epos + 2
                            if npos + list_len <= epos + elen:
                                if npos + 3 <= len(payload):
                                    ntype = payload[npos]
                                    nlen = int.from_bytes(payload[npos+1:npos+3], "big")
                                    nstart = npos + 3
                                    if ntype == 0 and nstart + nlen <= len(payload):
                                        # середина SLD
                                        try:
                                            name = payload[nstart:nstart+nlen].decode("idna")
                                            parts = name.split(".")
                                            if len(parts) >= 2:
                                                sld = parts[-2]
                                                sld_start_dom = name.rfind(sld)
                                                sld_mid = sld_start_dom + len(sld)//2
                                                sni_mid_abs = nstart + sld_mid
                                        except Exception:
                                            pass
                        except Exception:
                            pass
                        break
                    s = epos + elen
                # Выбор split_pos:
                if sni_mid_abs:
                    sp = max(32, min(sni_mid_abs, len(payload)-1))
                else:
                    # немного внутрь extensions
                    sp = max(48, min(ext_start + min(32, ext_len//8), len(payload)-1))
                return sp
            except Exception:
                return None

        def _estimate_overlap(self, part1_len: int, part2_len: int, split_pos: int) -> int:
            """Оценивает overlap с приоритетом 336, затем 160, затем безопасный минимум."""
            cap = min(part1_len, part2_len, split_pos)
            for cand in (336, 160, 96, 64, 32):
                if cap >= cand:
                    return cand
            return max(8, min(cap, 24))

        def _get_inbound_event_for_flow(self, packet: "pydivert.Packet") -> threading.Event:
            rev_key = (packet.dst_addr, packet.dst_port, packet.src_addr, packet.src_port)
            with self._lock:
                ev = self._inbound_events.get(rev_key)
                if not ev:
                    ev = threading.Event()
                    self._inbound_events[rev_key] = ev
                return ev

        def _start_inbound_observer(self):
            def run():
                try:
                    with pydivert.WinDivert("inbound and tcp.SrcPort == 443", priority=900) as wi:
                        self.logger.info("👂 Inbound observer started")
                        while self.running:
                            pkt = wi.recv()
                            if not pkt:
                                continue
                            outcome = None
                            try:
                                payload = bytes(pkt.payload) if pkt.payload else b""
                                if len(payload) > 6 and payload[0] == 0x16 and payload[5] == 0x02:
                                    outcome = "ok"   # TLS ServerHello
                                elif pkt.tcp and pkt.tcp.rst:
                                    outcome = "rst"
                            except Exception:
                                pass
                            # Телеметрия inbound
                            if outcome:
                                try:
                                    with self._tlock:
                                        if outcome == "ok":
                                            self._telemetry["serverhellos"] += 1
                                        elif outcome == "rst":
                                            self._telemetry["rst_count"] += 1
                                except Exception:
                                    pass
                            # Сигнал исхода + привязка к стратегии/цели
                            if outcome:
                                rev_key = (pkt.dst_addr, pkt.dst_port, pkt.src_addr, pkt.src_port)
                                # Signal early stopping event for calibrator
                                try:
                                    with self._lock:
                                        ev = self._inbound_events.get(rev_key)
                                    if ev:
                                        self._inbound_results[rev_key] = outcome
                                        ev.set()
                                except Exception:
                                    pass
                                # Record outcome for adaptive controller
                                if self.controller:
                                    with self._lock:
                                        info = self.flow_table.pop(rev_key, None)
                                    if info:
                                        rtt_ms = int((time.time() - info["start_ts"]) * 1000)
                                        self.controller.record_outcome(info["key"], info["strategy"], outcome, rtt_ms)
                                # Запишем last_outcome в телеметрии на цель
                                try:
                                    tgt = pkt.src_addr  # inbound: src is server
                                    with self._tlock:
                                        per = self._telemetry["per_target"][tgt]
                                        per["last_outcome"] = outcome
                                        per["last_outcome_ts"] = time.time()
                                except Exception:
                                    pass
                            wi.send(pkt)
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Inbound observer error: {e}", exc_info=self.debug)
            t = threading.Thread(target=run, daemon=True)
            t.start()
            return t

        def _run_bypass_loop(self, target_ips: Set[str], strategy_map: Dict[str, Dict]):
            """Основной цикл перехвата и обработки пакетов."""
            filter_str = "outbound and (tcp.DstPort == 443 or udp.DstPort == 443 or tcp.DstPort == 80)"
            self.logger.info(f"🔍 Фильтр pydivert: {filter_str}")
            try:
                with pydivert.WinDivert(filter_str, priority=1000) as w:
                    # Увеличим очереди WinDivert для снижения вероятности таймаутов 258
                    try:
                        from pydivert.windivert import WinDivertParam
                        w.set_param(WinDivertParam.QueueLen, 8192)
                        w.set_param(WinDivertParam.QueueTime, 2048)       # usec
                        w.set_param(WinDivertParam.QueueSize, 64 * 1024)  # KB
                        self.logger.debug("WinDivert queue params set: Len=8192, Time=2048, Size=64KB")
                    except Exception as e:
                        self.logger.debug(f"WinDivert set_param failed: {e}")

                    self.logger.info("✅ WinDivert запущен успешно.")
                    last_cleanup = time.time()
                    while self.running:
                        packet = w.recv()
                        if packet is None:
                            continue
                        # Periodic cleanup (each ~5s)
                        if time.time() - last_cleanup >= 5.0:
                            last_cleanup = time.time()
                            self._cleanup_old_telemetry()
                        # Не обрабатываем собственные инжектированные пакеты (по mark)
                        try:
                            pkt_mark = getattr(packet, "mark", 0)
                        except Exception:
                            pkt_mark = 0
                        if pkt_mark == self._INJECT_MARK:
                            # Просто пропускаем дальше в стек
                            w.send(packet)
                            continue
                        self.stats["packets_captured"] += 1
                        if (
                            self._is_target_ip(packet.dst_addr, target_ips)
                            and packet.payload
                        ):
                            # Телеметрия: CH на исходящих ClientHello
                            try:
                                if self._is_tls_clienthello(packet.payload):
                                    with self._tlock:
                                        self._telemetry["clienthellos"] += 1
                                        # откроем пер-цель запись
                                        _ = self._telemetry["per_target"][packet.dst_addr]
                            except Exception:
                                pass
                            # Сначала пытаемся применить контроллер (SNI->wildcard->IP->default)
                            if self.controller and self._is_tls_clienthello(packet.payload):
                                sni = self._extract_sni(packet.payload)
                                strategy_task, why = self.controller.choose(sni, packet.dst_addr)
                                self.logger.info(f"🎯 Strategy pick ({why}): {strategy_task} for SNI={sni} IP={packet.dst_addr}")
                                # Привязываем попытку к потоку для последующего исхода (ServerHello/RST)
                                flow_id = (packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)
                                with self._lock:
                                    self.flow_table[flow_id] = {
                                        "start_ts": time.time(),
                                        "key": sni or packet.dst_addr,
                                        "strategy": strategy_task
                                    }
                                # Применяем стратегию сразу (не используем _choose_strategy)
                                # Телеметрия: текущее ключ-имя стратегии
                                try:
                                    with self._tlock:
                                        self._telemetry["strategy_key"] = self._strategy_key(strategy_task)
                                except Exception: pass
                                if self._is_udp(packet) and packet.dst_port == 443:
                                    if strategy_task and self.quic_handler.is_quic_initial(packet.payload):
                                        self.stats["quic_packets_bypassed"] += 1
                                        self.logger.info(f"Обнаружен QUIC Initial к {packet.dst_addr}. Применяем bypass...")
                                        self.apply_bypass(packet, w, strategy_task)
                                    else:
                                        w.send(packet)
                                elif strategy_task and self._is_tls_clienthello(packet.payload):
                                    self.stats["tls_packets_bypassed"] += 1
                                    self.logger.info(f"Обнаружен TLS ClientHello к {packet.dst_addr}. Применяем bypass...")
                                    self.apply_bypass(packet, w, strategy_task)
                                else:
                                    w.send(packet)
                                continue

                            # Fallback: старая логика по таблице strategy_map (SNI/IP/default)
                            strategy_task = strategy_map.get(
                                packet.dst_addr
                            ) or strategy_map.get("default")
                            # Привязка потока к стратегии для inbound-учёта + телеметрия ключа
                            if strategy_task and self._is_tls_clienthello(packet.payload):
                                try:
                                    flow_id = (packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)
                                    with self._lock:
                                        self.flow_table[flow_id] = {
                                            "start_ts": time.time(),
                                            "key": packet.dst_addr,
                                            "strategy": strategy_task
                                        }
                                    with self._tlock:
                                        self._telemetry["strategy_key"] = self._strategy_key(strategy_task)
                                except Exception: pass
                            if self._is_udp(packet) and packet.dst_port == 443:
                                if strategy_task and self.quic_handler.is_quic_initial(
                                    packet.payload
                                ):
                                    self.stats["quic_packets_bypassed"] += 1
                                    self.logger.info(
                                        f"Обнаружен QUIC Initial к {packet.dst_addr}. Применяем bypass..."
                                    )
                                    self.apply_bypass(packet, w, strategy_task)
                                else:
                                    w.send(packet)
                            elif strategy_task and self._is_tls_clienthello(
                                packet.payload
                            ):
                                self.stats["tls_packets_bypassed"] += 1
                                self.logger.info(
                                    f"Обнаружен TLS ClientHello к {packet.dst_addr}. Применяем bypass..."
                                )
                                self.apply_bypass(packet, w, strategy_task)
                            else:
                                w.send(packet)
                        else:
                            w.send(packet)
            except Exception as e:
                if self.running:
                    self.logger.error(
                        f"❌ Критическая ошибка в цикле WinDivert: {e}",
                        exc_info=self.debug,
                    )
                self.running = False

        def _is_tls_clienthello(self, payload: Optional[bytes]) -> bool:
            """Проверяет, является ли payload сообщением TLS ClientHello."""
            return (
                payload
                and len(payload) > 6
                and (payload[0] == 22)
                and (payload[5] == 1)
            )

        def _is_udp(self, packet: pydivert.Packet) -> bool:
            """Проверяет, является ли пакет UDP пакетом."""
            return packet.protocol == 17

        def _is_tcp(self, packet: pydivert.Packet) -> bool:
            """Проверяет, является ли пакет TCP пакетом."""
            return packet.protocol == 6

        def apply_bypass(
            self, packet: pydivert.Packet, w: pydivert.WinDivert, strategy_task: Dict
        ):
            """
            Применяет стратегию обхода к пакету, используя калибратор, раннюю остановку
            и централизованную логику.
            """
            try:
                # Лимит параллельных инъекций
                acquired = self._inject_sema.acquire(timeout=0.5)
                if not acquired:
                    self.logger.debug("Injection semaphore limit reached, forwarding original")
                    w.send(packet)
                    return
                params = strategy_task.get("params", {}).copy()
                # Нормализуем ключи из интерпретатора: fooling_methods -> fooling
                if "fooling" not in params and "fooling_methods" in params:
                    params["fooling"] = params.get("fooling_methods", [])
                self.current_params = params
                task_type = normalize_attack_name(strategy_task.get("type"))

                # --- Улучшенная логика TTL ---
                fake_ttl_source = params.get("autottl") or params.get("ttl")
                if fake_ttl_source is not None:
                    try:
                        fake_ttl = int(fake_ttl_source)
                        if not (1 <= fake_ttl <= 255):
                            self.logger.warning(f"Invalid fake TTL {fake_ttl}, using default 1 for fakes.")
                            fake_ttl = 1
                    except (ValueError, TypeError):
                        self.logger.warning(f"Invalid fake TTL format '{fake_ttl_source}', using default 1.")
                        fake_ttl = 1
                else:
                    fake_ttl = 1 if task_type == "fakeddisorder" else 3
                self.current_params["fake_ttl"] = fake_ttl
                self.logger.info(f"Base TTL for FAKE packets set to: {fake_ttl}")

                orig_ttl = bytearray(packet.raw)[8]
                real_ttl = orig_ttl if 1 <= orig_ttl <= 255 else 64
                self.current_params["real_ttl"] = real_ttl
                self.logger.info(f"TTL for REAL segments set to: {real_ttl} (from original packet)")
                # --- Конец логики TTL ---

                self.logger.info(f"🎯 Applying bypass for {packet.dst_addr} -> Type: {task_type}, Params: {params}")
                
                payload = bytes(packet.payload)
                success = False
                # Телеметрия: ensure per-target bucket
                try:
                    with self._tlock:
                        _ = self._telemetry["per_target"][packet.dst_addr]
                except Exception:
                    pass

                # UDP/QUIC путь: используем реальную атаку quic_fragmentation и отправляем UDP-дейтаграммы
                if self._is_udp(packet) and packet.dst_port == 443:
                    try:
                        from core.bypass.attacks.tunneling.quic_fragmentation import QUICFragmentationAttack
                        from core.bypass.attacks.base import AttackContext
                        sni = self._extract_sni(payload)
                        attack = QUICFragmentationAttack()
                        # Настроим параметры атаки из strategy_task (если есть)
                        ap = strategy_task.get("params", {}) if isinstance(strategy_task, dict) else {}
                        # Зададим дефолты, если не передано
                        ap.setdefault("fragment_size", 120)  # мелкая фрагментация QUIC Initial
                        ap.setdefault("split_by_frames", True)
                        ap.setdefault("coalesce_count", 0)
                        ap.setdefault("padding_ratio", 0.0)
                        ctx = AttackContext(
                            dst_ip=packet.dst_addr,
                            dst_port=packet.dst_port,
                            src_ip=packet.src_addr,
                            src_port=packet.src_port,
                            domain=sni or getattr(packet, "domain", None),
                            payload=None,     # для синтетического Initial
                            protocol="udp",
                            params=ap,
                            timeout=1.0,
                            debug=self.debug
                        )
                        ares = attack.execute(ctx)
                        udp_segments = []
                        if ares and ares.status.name == "SUCCESS":
                            segs = (ares.metadata or {}).get("segments", [])
                            for s in segs:
                                if isinstance(s, tuple) and len(s) >= 1:
                                    b = s[0]
                                    d = s[1] if len(s) >= 2 else 0
                                    if isinstance(b, (bytes, bytearray)):
                                        udp_segments.append((bytes(b), int(d)))
                        # Если атака не предоставила сегменты — fallback к позиционному split
                        if not udp_segments:
                            positions = ap.get("positions") or [10, 25, 40, 80, 160]
                            split_segs = self.quic_handler.split_quic_initial(payload, positions)
                            # split_quic_initial возвращает [(data, rel_off)] — нам нужны UDP payload без заголовка
                            # Для совместимости возьмём только сырой payload к отправке и нулевые задержки
                            udp_segments = []
                            for seg, _ in split_segs:
                                udp_segments.append((seg, 0))
                        ok = self._send_udp_segments(packet, w, udp_segments)
                        if ok:
                            with self._tlock:
                                self._telemetry["aggregate"]["quic_segments_sent"] += len(udp_segments or [])
                        if not ok:
                            self.logger.error("UDP/QUIC send failed; forwarding original")
                            w.send(packet)
                        return
                    except Exception as e:
                        self.logger.debug(f"QUIC fragmentation path failed: {e}")
                        # Последний fallback: отправим оригинал
                        w.send(packet)
                        return

                if params.get("split_pos") == "midsld":
                    params["split_pos"] = self._resolve_midsld_pos(payload) or 3

                if task_type == "fakeddisorder":
                    # --- Логика с калибратором и ранней остановкой ---
                    flow_id = (packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)
                    if flow_id in self._active_flows:
                        self.logger.debug("Flow already processed, forwarding original")
                        w.send(packet)
                        return
                    self._active_flows.add(flow_id)
                    threading.Timer(self._flow_ttl_sec, lambda: self._active_flows.discard(flow_id)).start()

                    inbound_ev = self._get_inbound_event_for_flow(packet)
                    rev_key = (packet.dst_addr, packet.dst_port, packet.src_addr, packet.src_port)
                    if inbound_ev.is_set(): inbound_ev.clear()
                    self._inbound_results.pop(rev_key, None)

                    is_tls_ch = self._is_tls_clienthello(payload)
                    # Оценка split_pos по структуре CH
                    sp_guess = self._estimate_split_pos_from_ch(payload) if is_tls_ch else None
                    init_sp = params.get("split_pos") or sp_guess or (76 if is_tls_ch else max(16, len(payload)//2))

                    # Seed из StrategyManager
                    seed = None
                    if StrategyManager:
                        try:
                            sm = StrategyManager()
                            sni = self._extract_sni(payload)
                            key_domain = getattr(packet, "domain", None) or sni or packet.dst_addr
                            ds = sm.get_strategy(key_domain)
                            if ds and ds.split_pos and ds.overlap_size:
                                seed = CalibCandidate(split_pos=int(ds.split_pos), overlap_size=int(ds.overlap_size))
                                self.logger.info(f"Calibrator seed from StrategyManager: sp={seed.split_pos}, ov={seed.overlap_size}")
                        except Exception as e:
                            self.logger.debug(f"Seed fetch failed: {e}")

                    # Подготовка кандидатов
                    cand_list = Calibrator.prepare_candidates(payload, initial_split_pos=init_sp)
                    if seed:
                        cand_list = [seed] + [c for c in cand_list if (c.split_pos, c.overlap_size) != (seed.split_pos, seed.overlap_size)]
                    elif "split_pos" in params and "overlap_size" in params:
                        # Fallback to params from the strategy string if no seed from learning
                        head = CalibCandidate(split_pos=int(params["split_pos"]), overlap_size=int(params["overlap_size"]))
                        cand_list = [head] + [c for c in cand_list if (c.split_pos, c.overlap_size) != (head.split_pos, head.overlap_size)]

                    # Предпробинг fooling по CDN
                    cdn = self._classify_cdn(packet.dst_addr)
                    prof = self._get_cdn_profile(cdn)
                    fooling_list = params.get("fooling", []) or []
                    if isinstance(fooling_list, str):
                        fooling_list = [f.strip() for f in fooling_list.split(",") if f.strip()]
                    # Если не задано явно — пробуем автоматом оценить совместимость md5sig/badsum
                    try:
                        inbound_ev = self._get_inbound_event_for_flow(packet)
                        if inbound_ev.is_set(): inbound_ev.clear()
                        rev_key = (packet.dst_addr, packet.dst_port, packet.src_addr, packet.src_port)
                        self._inbound_results.pop(rev_key, None)
                        # md5sig
                        if prof["md5sig_allowed"] is None:
                            self._send_aligned_fake_segment(packet, w, init_sp, b"", max(1, self.current_params["fake_ttl"]), ["md5sig"])
                            got = inbound_ev.wait(timeout=0.2)
                            outcome = self._inbound_results.pop(rev_key, None) if got else None
                            prof["md5sig_allowed"] = (outcome != "rst")
                        # badsum
                        if prof["badsum_allowed"] is None:
                            inbound_ev.clear()
                            self._send_aligned_fake_segment(packet, w, init_sp, b"", max(1, self.current_params["fake_ttl"]), ["badsum"])
                            got = inbound_ev.wait(timeout=0.2)
                            outcome = self._inbound_results.pop(rev_key, None) if got else None
                            prof["badsum_allowed"] = (outcome != "rst")
                    except Exception:
                        pass
                    # Фильтруем запрещённые режимы
                    if "md5sig" in fooling_list and prof["md5sig_allowed"] is False:
                        fooling_list = [f for f in fooling_list if f != "md5sig"]
                    if "badsum" in fooling_list and prof["badsum_allowed"] is False:
                        fooling_list = [f for f in fooling_list if f != "badsum"]
                    autottl = params.get("autottl")
                    ttl_list = list(range(1, min(int(autottl), 8) + 1)) if autottl else [self.current_params["fake_ttl"]]

                    # Sweep с тайм-бюджетом (350мс)
                    def _send_try(cand: CalibCandidate, ttl: int, d_ms: int):
                        self._send_aligned_fake_segment(packet, w, cand.split_pos, payload[cand.split_pos:cand.split_pos + 100], ttl, fooling_list)
                        time.sleep((d_ms * random.uniform(0.85, 1.35)) / 1000.0)
                        self.current_params["delay_ms"] = d_ms
                        segments = self.techniques.apply_fakeddisorder(payload, cand.split_pos, cand.overlap_size)
                        # Телеметрия: отметим использованный overlap
                        with self._tlock:
                            self._telemetry["overlaps"][int(cand.overlap_size)] += 1
                            for _, rel_off in segments:
                                self._telemetry["seq_offsets"][int(rel_off)] += 1
                        self._send_segments(packet, w, segments)
                    def _wait_outcome(timeout: float=0.25) -> Optional[str]:
                        got = inbound_ev.wait(timeout=timeout)
                        if not got: return None
                        return self._inbound_results.get(rev_key)
                    best_cand = Calibrator.sweep(
                        payload=payload,
                        candidates=cand_list,
                        ttl_list=ttl_list,
                        delays=[1,2,3],
                        send_func=_send_try,
                        wait_func=_wait_outcome,
                        time_budget_ms=350
                    )
                    got_inbound = best_cand is not None
                    if got_inbound:
                        with self._lock:
                            self._inbound_events.pop(rev_key, None)
                            self._inbound_results.pop(rev_key, None)
                        self.logger.info(f"✅ Calibrator: success with sp={best_cand.split_pos}, ov={best_cand.overlap_size}, delay={self.current_params.get('delay_ms',2)}ms")

                    if best_cand and StrategyManager:
                        try:
                            sm = StrategyManager()
                            sni = self._extract_sni(payload)
                            key_domain = getattr(packet, "domain", sni or packet.dst_addr)
                            strategy_str = f"fakeddisorder(overlap_size={best_cand.overlap_size}, split_pos={best_cand.split_pos})"
                            sm.add_strategy(
                                key_domain,
                                strategy_str,
                                1.0,
                                200.0,  # success_rate, avg_latency_ms
                                # Pass micro-parameters to be stored
                                split_pos=best_cand.split_pos,
                                overlap_size=best_cand.overlap_size,
                                fooling_modes=fooling_list,
                                fake_ttl_source=autottl or self.current_params.get("fake_ttl"),
                                delay_ms=self.current_params.get("delay_ms", 2)
                            )
                            sm.save_strategies()
                            self.logger.info(f"Saved best params for {key_domain} via StrategyManager.")
                        except Exception as e:
                            self.logger.debug(f"StrategyManager immediate update failed: {e}")

                    # Для fakeddisorder гарантируем минимальную задержку 2мс между p2→p1
                    try:
                        if best_cand:
                            self.current_params["delay_ms"] = max(2, int(self.current_params.get("delay_ms", 2)))
                    except Exception:
                        pass

                    success = (best_cand is not None)
                    if not success:
                        # Фоллбэк: пробуем seqovl, затем multisplit
                        self.logger.warning("Calibrator failed. Trying fallbacks (seqovl -> multisplit)...")
                        try:
                            sp_fb = init_sp
                            ov_fb = params.get("overlap_size", 20)
                            segments = self.techniques.apply_seqovl(payload, sp_fb, ov_fb)
                            if self._send_segments(packet, w, segments):
                                # чуть подождём входящий
                                _ev = self._get_inbound_event_for_flow(packet)
                                if _ev.wait(timeout=0.25) and self._inbound_results.get(rev_key) == "ok":
                                    success = True
                            if not success:
                                positions = [max(6, sp_fb//4), max(12, sp_fb//2), max(18, (3*sp_fb)//4)]
                                segments = self.techniques.apply_multisplit(payload, positions)
                                if self._send_segments(packet, w, segments):
                                    _ev = self._get_inbound_event_for_flow(packet)
                                    if _ev.wait(timeout=0.25) and self._inbound_results.get(rev_key) == "ok":
                                        success = True
                        except Exception:
                            pass

                # --- Остальные типы атак (логика сохранена для совместимости) ---
                elif task_type == "multisplit":
                    # Если передан preinject_fake или есть fooling — сначала отправим fake‑пакет
                    try:
                        pre = params.get("preinject_fake", False)
                        fool = params.get("fooling", []) or []
                        if pre or fool:
                            ttl_fake = self.current_params.get("fake_ttl")
                            if "badsum" in fool:
                                self._send_fake_packet_with_badsum(packet, w, ttl=ttl_fake)
                            elif "md5sig" in fool:
                                self._send_fake_packet_with_md5sig(packet, w, ttl=ttl_fake)
                            elif "badseq" in fool:
                                self._send_fake_packet_with_badseq(packet, w, ttl=ttl_fake)
                            else:
                                self._send_fake_packet(packet, w, ttl=ttl_fake)
                            time.sleep(0.003)
                    except Exception:
                        pass
                    ttl = self.current_params.get("fake_ttl")
                    is_meta_ip = any(
                        (packet.dst_addr.startswith(prefix) for prefix in ["157.240.", "69.171.", "31.13."])
                    )
                    is_twitter_ip = packet.dst_addr.startswith("104.244.") or packet.dst_addr.startswith("199.59.")
                    if is_meta_ip or is_twitter_ip:
                        for fake_ttl in [ttl - 1, ttl, ttl + 1]:
                            self._send_fake_packet_with_badsum(packet, w, ttl=fake_ttl)
                            with self._tlock:
                                self._telemetry["ttls"]["fake"][int(fake_ttl)] += 1
                                self._telemetry["aggregate"]["fake_packets_sent"] += 1
                            time.sleep(0.002)
                        segments = self.techniques.apply_multisplit(payload, params.get("positions", [6, 14, 26, 42, 64]))
                        success = self._send_segments(packet, w, segments)
                        time.sleep(0.002)
                        self._send_fake_packet_with_badsum(packet, w, ttl=ttl + 2)
                    else:
                        if params.get("fooling") == "badsum":
                            self._send_fake_packet_with_badsum(packet, w, ttl=ttl)
                            time.sleep(0.005)
                        segments = self.techniques.apply_multisplit(payload, params.get("positions", [10, 25, 40, 55, 70]))
                        success = self._send_segments(packet, w, segments)
                        if params.get("fooling") == "badsum":
                            time.sleep(0.003)
                            self._send_fake_packet_with_badsum(packet, w, ttl=ttl + 1)
                elif task_type == "multidisorder":
                    # Префиксный fake, если задан
                    if params.get("pre_fake"):
                        ttl_pf = int(params.get("fake_ttl", self.current_params.get("fake_ttl", 1)))
                        fool = params.get("fooling") or []
                        if "badsum" in fool:
                            self._send_fake_packet_with_badsum(packet, w, ttl=ttl_pf)
                        elif "md5sig" in fool:
                            self._send_fake_packet_with_md5sig(packet, w, ttl=ttl_pf)
                        elif "badseq" in fool:
                            self._send_fake_packet_with_badseq(packet, w, ttl=ttl_pf)
                        else:
                            self._send_fake_packet(packet, w, ttl=ttl_pf)
                        time.sleep(0.003)
                    segments = self.techniques.apply_multidisorder(payload, params.get("positions", [10, 25, 40]))
                    success = self._send_segments(packet, w, segments)
                elif task_type == "seqovl":
                    try:
                        pre = params.get("preinject_fake", False)
                        fool = params.get("fooling", []) or []
                        if pre or fool:
                            ttl_fake = self.current_params.get("fake_ttl")
                            if "badsum" in fool:
                                self._send_fake_packet_with_badsum(packet, w, ttl=ttl_fake)
                            elif "md5sig" in fool:
                                self._send_fake_packet_with_md5sig(packet, w, ttl=ttl_fake)
                            elif "badseq" in fool:
                                self._send_fake_packet_with_badseq(packet, w, ttl=ttl_fake)
                            else:
                                self._send_fake_packet(packet, w, ttl=ttl_fake)
                            time.sleep(0.003)
                    except Exception:
                        pass
                    if params.get("fooling") == "badsum":
                        self._send_fake_packet_with_badsum(packet, w, ttl=self.current_params.get("fake_ttl"))
                        time.sleep(0.003)
                    segments = self.techniques.apply_seqovl(
                        payload, params.get("split_pos", 3), params.get("overlap_size", 20)
                    )
                    with self._tlock:
                        self._telemetry["overlaps"][int(params.get("overlap_size", 20))] += 1
                        self._telemetry["ttls"]["fake"][int(self.current_params.get("fake_ttl", 1))] += 1
                        self._telemetry["aggregate"]["fake_packets_sent"] += 1
                    success = self._send_segments(packet, w, segments)
                elif task_type == "tlsrec_split":
                    modified_payload = self.techniques.apply_tlsrec_split(payload, params.get("split_pos", 5))
                    success = self._send_modified_packet(packet, w, modified_payload)
                elif task_type == "wssize_limit":
                    segments = self.techniques.apply_wssize_limit(payload, params.get("window_size", 2))
                    success = self._send_segments_with_window(packet, w, segments)
                elif task_type == "badsum_race":
                    self._send_fake_packet_with_badsum(packet, w, ttl=self.current_params.get("fake_ttl"))
                    time.sleep(0.005)
                    w.send(packet)
                    success = True
                elif task_type == "md5sig_race":
                    self._send_fake_packet_with_md5sig(packet, w, ttl=self.current_params.get("fake_ttl"))
                    time.sleep(0.007)
                    w.send(packet)
                    success = True
                elif task_type == "fake":
                    # Простой режим fake: отправляем фейковый пакет и затем оригинал (с учетом split_pos)
                    fooling = params.get("fooling", []) or []
                    if isinstance(fooling, str):
                        fooling = [f.strip() for f in fooling.split(",") if f.strip()]
                    ttl_fake = self.current_params.get("fake_ttl")
                    if "badsum" in fooling:
                        self._send_fake_packet_with_badsum(packet, w, ttl=ttl_fake)
                    elif "md5sig" in fooling:
                        self._send_fake_packet_with_md5sig(packet, w, ttl=ttl_fake)
                    elif "badseq" in fooling:
                        self._send_fake_packet_with_badseq(packet, w, ttl=ttl_fake)
                    else:
                        self._send_fake_packet(packet, w, ttl=ttl_fake)
                    # Небольшая задержка перед оригиналом
                    time.sleep(params.get("delay_ms", 3) / 1000.0 if isinstance(params.get("delay_ms"), (int, float)) else 0.003)
                    # Если указан split_pos — применим TLS record split к payload перед отправкой
                    sp = params.get("split_pos")
                    if isinstance(sp, int) and sp > 0:
                        modified_payload = self.techniques.apply_tlsrec_split(payload, sp)
                        self._send_modified_packet(packet, w, modified_payload)
                    else:
                        w.send(packet)
                    success = True
                else:
                    self.logger.warning(f"Неизвестный тип задачи '{task_type}', применяем простую фрагментацию.")
                    self._send_fragmented_fallback(packet, w)
                    success = True

                if not success:
                    self.logger.error("Strategy failed, sending original packet.")
                    w.send(packet)

            except Exception as e:
                self.logger.error(f"❌ Ошибка применения bypass: {e}", exc_info=self.debug)
                w.send(packet)
            finally:
                try:
                    self._inject_sema.release()
                except Exception:
                    pass

        def _send_segments(self, original_packet, w, segments: List[Tuple[bytes, int]]):
            """
            Тяжёлая версия без options: пересчитывает IP/TCP checksum, корректирует длины.
            Для fakeddisorder разумно задать TTL низким у второго сегмента (перекрывающего).
            """
            try:
                raw = bytearray(original_packet.raw)
                ip_ver = (raw[0] >> 4) & 0xF
                if ip_ver != 4:
                    w.send(original_packet)
                    return False

                ip_hl = (raw[0] & 0x0F) * 4
                tcp_hl = ((raw[ip_hl + 12] >> 4) & 0x0F) * 4
                if tcp_hl < 20:
                    tcp_hl = 20
                base_seq = struct.unpack("!I", raw[ip_hl+4:ip_hl+8])[0]
                base_ack = struct.unpack("!I", raw[ip_hl+8:ip_hl+12])[0]
                base_flags = raw[ip_hl+13]
                base_win = struct.unpack("!H", raw[ip_hl+14:ip_hl+16])[0]
                base_ttl = raw[8]
                window_div = self.current_params.get("window_div", 8)
                reduced_win = max(base_win // window_div, 1024)
                base_ip_id = struct.unpack("!H", raw[4:6])[0]
                ipid_step = self.current_params.get("ipid_step", 2048)

                for i, (seg_payload, rel_off) in enumerate(segments):
                    if not seg_payload:
                        continue

                    # Копия IP+TCP базового заголовка
                    ip_hdr = bytearray(raw[:ip_hl])
                    tcp_hdr = bytearray(raw[ip_hl:ip_hl+tcp_hl])

                    # Seq/Ack/Flags/Win
                    new_seq = (base_seq + rel_off) & 0xFFFFFFFF
                    tcp_hdr[4:8] = struct.pack("!I", new_seq)
                    tcp_hdr[8:12] = struct.pack("!I", base_ack)

                    # Стабильно даём PSH+ACK на обоих сегментах для flush
                    tcp_hdr[13] = 0x18

                    tcp_hdr[14:16] = struct.pack("!H", reduced_win)

                    # TTL для реальных сегментов всегда берется из исходного пакета (base_ttl),
                    # который уже установлен в ip_hdr. self.current_params["real_ttl"]
                    # устанавливается в apply_bypass для информации и здесь не используется
                    # напрямую, но base_ttl ему эквивалентен.
                    # Старая логика с low_ttl удалена для консистентности.
                    ip_hdr[8] = base_ttl

                    # IP ID
                    new_ip_id = (base_ip_id + i * ipid_step) & 0xFFFF
                    ip_hdr[4:6] = struct.pack("!H", new_ip_id)

                    seg_raw = bytearray(ip_hdr + tcp_hdr + seg_payload)

                    # Total Length
                    total_len = len(seg_raw)
                    seg_raw[2:4] = struct.pack("!H", total_len)

                    # Checksums
                    # IP
                    seg_raw[10:12] = b"\x00\x00"
                    ip_csum = self._ip_header_checksum(seg_raw[:ip_hl])
                    seg_raw[10:12] = struct.pack("!H", ip_csum)

                    # TCP
                    tcp_hl_new = ((seg_raw[ip_hl+12] >> 4) & 0x0F) * 4
                    tcp_start = ip_hl
                    tcp_end = ip_hl + tcp_hl_new
                    csum = self._tcp_checksum(seg_raw[:ip_hl], seg_raw[tcp_start:tcp_end], seg_raw[tcp_end:])
                    seg_raw[tcp_start+16:tcp_start+18] = struct.pack("!H", csum)

                    # Безопасная отправка с повтором/пересчетом checksum
                    ok = self._safe_send_packet(w, bytes(seg_raw), original_packet)
                    if not ok:
                        self.logger.error("WinDivert send failed for segment (basic). Aborting.")
                        return False

                    self.stats["fragments_sent"] += 1

                    # Между сегментами небольшая задержка
                    delay_ms = self.current_params.get("delay_ms", 2)
                    if i < len(segments) - 1 and delay_ms > 0:
                        time.sleep(delay_ms / 1000.0)

                self.logger.debug(f"✨ Отправлено {len(segments)} сегментов (heavy/basic)")
                return True
            except Exception as e:
                self.logger.error(f"Ошибка отправки сегментов: {e}", exc_info=self.debug)
                return False
            finally:
                # Телеметрия: учёт сегментов, TTL, seq_offset на каждый отправленный сегмент
                try:
                    with self._tlock:
                        if 'segments' in locals() and segments:
                            self._telemetry["aggregate"]["segments_sent"] += len(segments)
                            tgt = original_packet.dst_addr
                            per = self._telemetry["per_target"][tgt]
                            per["segments_sent"] += len(segments)
                            # учёт seq_offsets и реального TTL
                            for seg_payload, rel_off in segments:
                                self._telemetry["seq_offsets"][int(rel_off)] += 1
                                per["seq_offsets"][int(rel_off)] += 1
                            real_ttl = int(bytearray(original_packet.raw)[8])
                            self._telemetry["ttls"]["real"][real_ttl] += 1
                            per["ttls_real"][real_ttl] += 1
                except Exception:
                    pass

        def _send_udp_segments(self, original_packet, w, segments: List[Tuple[bytes, int]]) -> bool:
            """
            Отправляет список UDP дейтаграмм, построенных на основе заголовков исходного пакета.
            segments: [(payload_bytes, delay_ms), ...]
            Пересчитывает IPv4 total_length, IP checksum, UDP length, UDP checksum (RFC 768).
            """
            try:
                if not segments:
                    return False
                raw = bytearray(original_packet.raw)
                # Проверка IPv4
                ip_ver = (raw[0] >> 4) & 0xF
                if ip_ver != 4:
                    self.logger.warning("Non-IPv4 UDP packet, forwarding original")
                    w.send(original_packet)
                    return False
                ip_hl = (raw[0] & 0x0F) * 4
                # UDP header: 8 bytes
                udp_start = ip_hl
                udp_end = udp_start + 8
                base_ip_id = struct.unpack("!H", raw[4:6])[0]
                ipid_step = int(self.current_params.get("ipid_step", 2048))
                base_ttl = raw[8]
                # IP src/dst for pseudo header
                src_ip = bytes(raw[12:16])
                dst_ip = bytes(raw[16:20])
                # UDP src/dst ports
                src_port = struct.unpack("!H", raw[udp_start:udp_start+2])[0]
                dst_port = struct.unpack("!H", raw[udp_start+2:udp_start+4])[0]
                # Отправка
                for i, item in enumerate(segments):
                    if isinstance(item, tuple) and len(item) >= 1:
                        data = item[0]
                        delay_ms = int(item[1]) if len(item) >= 2 else 0
                    else:
                        data = item; delay_ms = 0
                    if not data:
                        continue
                    # Собираем IP+UDP
                    ip_hdr = bytearray(raw[:ip_hl])
                    udp_hdr = bytearray(raw[udp_start:udp_end])
                    # IPv4: total length
                    total_len = ip_hl + 8 + len(data)
                    ip_hdr[2:4] = struct.pack("!H", total_len)
                    # TTL, IP ID
                    ip_hdr[8] = base_ttl
                    new_ip_id = (base_ip_id + i * ipid_step) & 0xFFFF
                    ip_hdr[4:6] = struct.pack("!H", new_ip_id)
                    # UDP length
                    udp_len = 8 + len(data)
                    udp_hdr[4:6] = struct.pack("!H", udp_len)
                    # UDP checksum: compute on pseudo header + UDP hdr (csum=0) + data
                    udp_hdr[6:8] = b"\x00\x00"
                    seg_raw = bytearray(ip_hdr + udp_hdr + data)
                    # IP checksum
                    seg_raw[10:12] = b"\x00\x00"
                    ip_csum = self._ip_header_checksum(seg_raw[:ip_hl])
                    seg_raw[10:12] = struct.pack("!H", ip_csum)
                    # UDP checksum
                    udp_csum = self._udp_checksum(seg_raw[:ip_hl], seg_raw[ip_hl:ip_hl+8], seg_raw[ip_hl+8:])
                    seg_raw[ip_hl+6:ip_hl+8] = struct.pack("!H", udp_csum)
                    # Safe send
                    ok = self._safe_send_packet(w, bytes(seg_raw), original_packet)
                    if not ok:
                        self.logger.error("WinDivert send failed for UDP segment")
                        return False
                    # задержка между датаграммами
                    if i < len(segments) - 1 and delay_ms > 0:
                        time.sleep(delay_ms / 1000.0)
                return True
            except Exception as e:
                self.logger.error(f"UDP send error: {e}", exc_info=self.debug)
                return False

        def _send_fake_packet(self, original_packet, w, ttl: Optional[int] = 64):
            """
            Send fake packet with specified TTL.
            
            CRITICAL TTL FIX: Added comprehensive TTL logging and validation.
            Changed default TTL from 2 to 64 for better compatibility.
            """
            try:
                raw_data = bytearray(original_packet.raw)
                ip_header_len = (raw_data[0] & 15) * 4
                tcp_header_len = (raw_data[ip_header_len + 12] >> 4 & 15) * 4
                payload_start = ip_header_len + tcp_header_len
                fake_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
                seg_raw = bytearray(raw_data[:payload_start] + fake_payload[:20])
                # TTL
                if ttl is not None and 1 <= ttl <= 255:
                    seg_raw[8] = ttl
                    self.logger.debug(f"🔧 Set fake packet TTL to {ttl}")
                else:
                    # fallback: используем текущие вычисленные параметры, либо безопасный 2
                    fallback_ttl = int(self.current_params.get("fake_ttl", 2))
                    seg_raw[8] = fallback_ttl
                    self.logger.warning(f"⚠️ Invalid TTL {ttl}, using fallback {fallback_ttl}")
                # Total length
                seg_raw[2:4] = struct.pack("!H", len(seg_raw))
                # IP checksum
                ip_hl = (seg_raw[0] & 0x0F) * 4
                seg_raw[10:12] = b"\x00\x00"
                ip_csum = self._ip_header_checksum(seg_raw[:ip_hl])
                seg_raw[10:12] = struct.pack("!H", ip_csum)
                # TCP checksum
                tcp_hl = ((seg_raw[ip_hl + 12] >> 4) & 0x0F) * 4
                tcp_start = ip_hl
                tcp_end = ip_hl + tcp_hl
                csum = self._tcp_checksum(seg_raw[:ip_hl], seg_raw[tcp_start:tcp_end], seg_raw[tcp_end:])
                seg_raw[tcp_start+16:tcp_start+18] = struct.pack("!H", csum)
                # Safe send
                self._safe_send_packet(w, bytes(seg_raw), original_packet)
                self.stats["fake_packets_sent"] += 1
                # Телеметрия
                with self._tlock:
                    self._telemetry["aggregate"]["fake_packets_sent"] += 1
                    self._telemetry["ttls"]["fake"][int(seg_raw[8])] += 1
                    try:
                        tgt = original_packet.dst_addr
                        per = self._telemetry["per_target"][tgt]
                        per["fake_packets_sent"] += 1
                        per["ttls_fake"][int(seg_raw[8])] += 1
                    except Exception:
                        pass
                self.logger.debug(f"✅ Sent fake packet with TTL={seg_raw[8]} to {original_packet.dst_addr}")
                time.sleep(0.002)
            except Exception as e:
                self.logger.debug(f"Ошибка отправки fake packet: {e}")

        def _send_fake_packet_with_badsum(
            self, original_packet, w, ttl: Optional[int] = 64
        ):
            """
            Send fake packet with bad checksum and specified TTL.
            
            CRITICAL TTL FIX: Added comprehensive TTL logging and validation.
            Changed default TTL from 2 to 64 for better compatibility.
            """
            try:
                raw_data = bytearray(original_packet.raw)
                ip_header_len = (raw_data[0] & 15) * 4
                tcp_header_len = (raw_data[ip_header_len + 12] >> 4 & 15) * 4
                payload_start = ip_header_len + tcp_header_len
                fake_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
                seg_raw = bytearray(raw_data[:payload_start] + fake_payload[:20])
                # TTL
                if ttl is not None and 1 <= ttl <= 255:
                    seg_raw[8] = ttl
                    self.logger.debug(f"🔧 Set fake packet (badsum) TTL to {ttl}")
                else:
                    fallback_ttl = int(self.current_params.get("fake_ttl", 2))
                    seg_raw[8] = fallback_ttl
                    self.logger.warning(f"⚠️ Invalid TTL {ttl}, using fallback {fallback_ttl} for badsum packet")
                # Length
                seg_raw[2:4] = struct.pack("!H", len(seg_raw))
                # IP checksum
                ip_hl = (seg_raw[0] & 0x0F) * 4
                seg_raw[10:12] = b"\x00\x00"
                ip_csum = self._ip_header_checksum(seg_raw[:ip_hl])
                seg_raw[10:12] = struct.pack("!H", ip_csum)
                # TCP checksum -> then corrupt
                tcp_hl = ((seg_raw[ip_hl + 12] >> 4) & 0x0F) * 4
                tcp_start = ip_hl
                tcp_end = ip_hl + tcp_hl
                good_csum = self._tcp_checksum(seg_raw[:ip_hl], seg_raw[tcp_start:tcp_end], seg_raw[tcp_end:])
                bad_csum = good_csum ^ 0xFFFF
                seg_raw[tcp_start+16:tcp_start+18] = struct.pack("!H", bad_csum)
                # Safe send
                self._safe_send_packet(w, bytes(seg_raw), original_packet)
                self.stats["fake_packets_sent"] += 1
                with self._tlock:
                    self._telemetry["aggregate"]["fake_packets_sent"] += 1
                    self._telemetry["ttls"]["fake"][int(seg_raw[8])] += 1
                    tgt = original_packet.dst_addr
                    per = self._telemetry["per_target"][tgt]
                    per["fake_packets_sent"] += 1; per["ttls_fake"][int(seg_raw[8])] += 1
                self.logger.debug(f"✅ Sent fake packet (badsum) with TTL={seg_raw[8]} to {original_packet.dst_addr}")
            except Exception as e:
                self.logger.debug(f"Ошибка fake packet with badsum: {e}")

        def _send_fake_packet_with_md5sig(
            self, original_packet, w, ttl: Optional[int] = 64
        ):
            """
            Send fake packet with MD5 signature and specified TTL.
            
            CRITICAL TTL FIX: Added comprehensive TTL logging and validation.
            Changed default TTL from 3 to 64 for better compatibility.
            """
            try:
                raw_data = bytearray(original_packet.raw)
                ip_header_len = (raw_data[0] & 15) * 4
                tcp_header_len = (raw_data[ip_header_len + 12] >> 4 & 15) * 4
                payload_start = ip_header_len + tcp_header_len
                fake_payload = b"EHLO example.com\r\n"
                seg_raw = bytearray(raw_data[:payload_start] + fake_payload)
                # TTL
                if ttl is not None and 1 <= ttl <= 255:
                    seg_raw[8] = ttl
                    self.logger.debug(f"🔧 Set fake packet (md5sig) TTL to {ttl}")
                else:
                    fallback_ttl = int(self.current_params.get("fake_ttl", 2))
                    seg_raw[8] = fallback_ttl
                    self.logger.warning(f"⚠️ Invalid TTL {ttl}, using fallback {fallback_ttl} for md5sig packet")
                # Length
                seg_raw[2:4] = struct.pack("!H", len(seg_raw))
                # IP checksum
                ip_hl = (seg_raw[0] & 0x0F) * 4
                seg_raw[10:12] = b"\x00\x00"
                ip_csum = self._ip_header_checksum(seg_raw[:ip_hl])
                seg_raw[10:12] = struct.pack("!H", ip_csum)
                # TCP checksum -> corrupt (md5sig "fooling")
                tcp_hl = ((seg_raw[ip_hl + 12] >> 4) & 0x0F) * 4
                tcp_start = ip_hl
                tcp_end = ip_hl + tcp_hl
                good_csum = self._tcp_checksum(seg_raw[:ip_hl], seg_raw[tcp_start:tcp_end], seg_raw[tcp_end:])
                bad_csum = good_csum ^ 0xFFFF
                seg_raw[tcp_start+16:tcp_start+18] = struct.pack("!H", bad_csum)
                # Safe send
                self._safe_send_packet(w, bytes(seg_raw), original_packet)
                self.stats["fake_packets_sent"] += 1
                with self._tlock:
                    self._telemetry["aggregate"]["fake_packets_sent"] += 1
                    self._telemetry["ttls"]["fake"][int(seg_raw[8])] += 1
                    tgt = original_packet.dst_addr
                    per = self._telemetry["per_target"][tgt]
                    per["fake_packets_sent"] += 1; per["ttls_fake"][int(seg_raw[8])] += 1
                self.logger.debug(f"✅ Sent fake packet (md5sig) with TTL={seg_raw[8]} to {original_packet.dst_addr}")
            except Exception as e:
                self.logger.debug(f"Ошибка fake packet with md5sig: {e}")

        def _send_fake_packet_with_badseq(
            self, original_packet, w, ttl: Optional[int] = 64
        ):
            """
            Send fake packet with bad sequence number and specified TTL.
            
            CRITICAL TTL FIX: Added missing badseq method with comprehensive TTL logging.
            """
            try:
                raw_data = bytearray(original_packet.raw)
                ip_header_len = (raw_data[0] & 15) * 4
                tcp_header_len = (raw_data[ip_header_len + 12] >> 4 & 15) * 4
                payload_start = ip_header_len + tcp_header_len
                fake_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
                seg_raw = bytearray(raw_data[:payload_start] + fake_payload[:20])
                # TTL
                if ttl is not None and 1 <= ttl <= 255:
                    seg_raw[8] = ttl
                    self.logger.debug(f"🔧 Set fake packet (badseq) TTL to {ttl}")
                else:
                    fallback_ttl = int(self.current_params.get("fake_ttl", 2))
                    seg_raw[8] = fallback_ttl
                    self.logger.warning(f"⚠️ Invalid TTL {ttl}, using fallback {fallback_ttl} for badseq packet")
                # Apply bad sequence number (offset by -10000 as per zapret)
                ip_header_len = (seg_raw[0] & 15) * 4
                tcp_header_len = (seg_raw[ip_header_len + 12] >> 4 & 15) * 4
                seq_offset = ip_header_len + 4
                original_seq = struct.unpack("!I", seg_raw[seq_offset:seq_offset+4])[0]
                bad_seq = (original_seq - 10000) & 0xFFFFFFFF  # Zapret-style badseq
                seg_raw[seq_offset:seq_offset+4] = struct.pack("!I", bad_seq)
                # Length & checksums
                seg_raw[2:4] = struct.pack("!H", len(seg_raw))
                seg_raw[10:12] = b"\x00\x00"
                ip_csum = self._ip_header_checksum(seg_raw[:ip_header_len])
                seg_raw[10:12] = struct.pack("!H", ip_csum)
                tcp_start = ip_header_len
                tcp_end = ip_header_len + tcp_header_len
                csum = self._tcp_checksum(seg_raw[:ip_header_len], seg_raw[tcp_start:tcp_end], seg_raw[tcp_end:])
                seg_raw[tcp_start+16:tcp_start+18] = struct.pack("!H", csum)
                # Safe send
                self._safe_send_packet(w, bytes(seg_raw), original_packet)
                self.stats["fake_packets_sent"] += 1
                with self._tlock:
                    self._telemetry["aggregate"]["fake_packets_sent"] += 1
                    self._telemetry["ttls"]["fake"][int(seg_raw[8])] += 1
                    tgt = original_packet.dst_addr
                    per = self._telemetry["per_target"][tgt]
                    per["fake_packets_sent"] += 1; per["ttls_fake"][int(seg_raw[8])] += 1
                self.logger.debug(f"✅ Sent fake packet (badseq) with TTL={seg_raw[8]} to {original_packet.dst_addr}")
            except Exception as e:
                self.logger.debug(f"Ошибка fake packet with badseq: {e}")

        def _send_modified_packet(self, original_packet, w, modified_payload):
            try:
                raw_data = bytearray(original_packet.raw)
                ip_header_len = (raw_data[0] & 15) * 4
                tcp_header_len = (raw_data[ip_header_len + 12] >> 4 & 15) * 4
                payload_start = ip_header_len + tcp_header_len
                seg_raw = bytearray(raw_data[:payload_start] + modified_payload)
                # Total length
                seg_raw[2:4] = struct.pack("!H", len(seg_raw))
                # IP checksum
                seg_raw[10:12] = b"\x00\x00"
                ip_csum = self._ip_header_checksum(seg_raw[:ip_header_len])
                seg_raw[10:12] = struct.pack("!H", ip_csum)
                # TCP checksum
                tcp_start = ip_header_len
                tcp_end = ip_header_len + tcp_header_len
                csum = self._tcp_checksum(seg_raw[:ip_header_len], seg_raw[tcp_start:tcp_end], seg_raw[tcp_end:])
                seg_raw[tcp_start+16:tcp_start+18] = struct.pack("!H", csum)
                # Safe send
                self._safe_send_packet(w, bytes(seg_raw), original_packet)
                self.stats["fragments_sent"] += 1
                return True
            except Exception as e:
                self.logger.error(
                    f"Ошибка отправки модифицированного пакета: {e}",
                    exc_info=self.debug,
                )
                return False

        def _send_segments_with_window(self, original_packet, w, segments):
            try:
                raw_data = bytearray(original_packet.raw)
                ip_header_len = (raw_data[0] & 15) * 4
                tcp_header_len = (raw_data[ip_header_len + 12] >> 4 & 15) * 4
                payload_start = ip_header_len + tcp_header_len
                tcp_seq_start = ip_header_len + 4
                tcp_window_start = ip_header_len + 14
                base_seq = struct.unpack(
                    "!I", raw_data[tcp_seq_start : tcp_seq_start + 4]
                )[0]
                for i, (segment_data, seq_offset) in enumerate(segments):
                    if not segment_data:
                        continue
                    seg_raw = bytearray(raw_data[:payload_start] + segment_data)
                    new_seq = base_seq + seq_offset & 4294967295
                    seg_raw[tcp_seq_start : tcp_seq_start + 4] = struct.pack(
                        "!I", new_seq
                    )
                    window_size = min(len(segment_data), 2)
                    seg_raw[tcp_window_start : tcp_window_start + 2] = struct.pack(
                        "!H", window_size
                    )
                    # Total length & checksums
                    seg_raw[2:4] = struct.pack("!H", len(seg_raw))
                    # IP checksum
                    seg_raw[10:12] = b"\x00\x00"
                    ip_csum = self._ip_header_checksum(seg_raw[:ip_header_len])
                    seg_raw[10:12] = struct.pack("!H", ip_csum)
                    # TCP checksum
                    csum = self._tcp_checksum(seg_raw[:ip_header_len], seg_raw[ip_header_len:payload_start], seg_raw[payload_start:])
                    seg_raw[ip_header_len+16:ip_header_len+18] = struct.pack("!H", csum)
                    if i == len(segments) - 1:
                        seg_raw[ip_header_len + 13] |= 8
                    self._safe_send_packet(w, bytes(seg_raw), original_packet)
                    self.stats["fragments_sent"] += 1
                    if i < len(segments) - 1:
                        time.sleep(0.05)
                return True
            except Exception as e:
                self.logger.error(
                    f"Ошибка отправки сегментов с window: {e}", exc_info=self.debug
                )
                return False

        def _ones_complement_sum(self, data: bytes) -> int:
            if len(data) % 2:
                data += b"\x00"
            s = 0
            for i in range(0, len(data), 2):
                s += (data[i] << 8) + data[i+1]
                s = (s & 0xFFFF) + (s >> 16)
            return s

        def _checksum16(self, data: bytes) -> int:
            s = self._ones_complement_sum(data)
            return (~s) & 0xFFFF

        def _ip_header_checksum(self, ip_hdr: bytearray) -> int:
            ip_hdr[10:12] = b"\x00\x00"
            return self._checksum16(bytes(ip_hdr))

        def _tcp_checksum(self, ip_hdr: bytes, tcp_hdr: bytes, payload: bytes) -> int:
            src = ip_hdr[12:16]
            dst = ip_hdr[16:20]
            proto = ip_hdr[9]
            tcp_len = len(tcp_hdr) + len(payload)
            pseudo = src + dst + bytes([0, proto]) + tcp_len.to_bytes(2, "big")
            tcp_hdr_wo_csum = bytearray(tcp_hdr)
            tcp_hdr_wo_csum[16:18] = b"\x00\x00"
            s = self._ones_complement_sum(pseudo + bytes(tcp_hdr_wo_csum) + payload)
            return (~s) & 0xFFFF

        def _udp_checksum(self, ip_hdr: bytes, udp_hdr: bytes, payload: bytes) -> int:
            """
            RFC 768: checksum of pseudo-header (IPv4), UDP header (csum=0) and data.
            For IPv4, 0 means no checksum, но мы рассчитываем реальную.
            """
            try:
                src = ip_hdr[12:16]
                dst = ip_hdr[16:20]
                proto = ip_hdr[9]
                udp_len = len(udp_hdr) + len(payload)
                pseudo = src + dst + bytes([0, proto]) + struct.pack("!H", udp_len)
                hdr = bytearray(udp_hdr)
                hdr[6:8] = b"\x00\x00"
                s = self._ones_complement_sum(pseudo + bytes(hdr) + payload)
                csum = (~s) & 0xFFFF
                # Если checksum получился 0 — оставляем 0 (допустимо в IPv4), но чаще ставят 0xFFFF
                return csum if csum != 0 else 0xFFFF
            except Exception:
                return 0

        def _inject_md5sig_option(self, tcp_hdr: bytes) -> bytes:
            """
            Добавляет TCP MD5SIG (kind=19,len=18). Если суммарная длина TCP заголовка > 60,
            пропускаем добавление и возвращаем исходный заголовок.
            """
            MAX_TCP_HDR = 60  # байт
            hdr = bytearray(tcp_hdr)
            data_offset_words = (hdr[12] >> 4) & 0x0F
            base_len = max(20, data_offset_words * 4)  # минимум 20

            # Нормализуем заголовок, если кто-то указал некорректную длину > 60
            if base_len > MAX_TCP_HDR:
                self.logger.warning(f"TCP header base_len={base_len} > 60, clamping to 60")
                base_len = MAX_TCP_HDR
                hdr = hdr[:base_len]
                hdr[12] = ((base_len // 4) << 4) | (hdr[12] & 0x0F)

            fixed = hdr[:20]
            opts = hdr[20:base_len]

            md5opt = b"\x13\x12" + b"\x00" * 16  # kind=19,len=18
            new_opts = bytes(opts) + md5opt
            # пэддинг до 4 байт
            pad_len = (4 - ((20 + len(new_opts)) % 4)) % 4
            new_total_len = 20 + len(new_opts) + pad_len

            if new_total_len > MAX_TCP_HDR:
                # Слишком длинно — пропускаем MD5SIG
                self.logger.warning(
                    f"MD5SIG would exceed TCP header limit ({new_total_len} > 60). Skipping MD5SIG."
                )
                return bytes(hdr[:base_len])

            new_opts += b"\x01" * pad_len  # NOP padding
            new_hdr = bytearray(fixed + new_opts)
            new_hdr[12] = ((new_total_len // 4) << 4) | (new_hdr[12] & 0x0F)
            new_hdr[16:18] = b"\x00\x00"  # checksum обнулим (пересчитаем позже)
            return bytes(new_hdr)
        
        def _send_attack_segments(self, original_packet, w, segments):
            try:
                raw = bytearray(original_packet.raw)
                ip_ver = (raw[0] >> 4) & 0xF
                if ip_ver != 4:
                    self.logger.warning("Non-IPv4 packet, fallback to original send")
                    w.send(original_packet)
                    return False

                ip_hl = (raw[0] & 0x0F) * 4
                tcp_hl = ((raw[ip_hl + 12] >> 4) & 0x0F) * 4
                if tcp_hl < 20:
                    tcp_hl = 20

                payload_start = ip_hl + tcp_hl
                base_seq = struct.unpack("!I", raw[ip_hl+4:ip_hl+8])[0]
                base_ack = struct.unpack("!I", raw[ip_hl+8:ip_hl+12])[0]
                base_win = struct.unpack("!H", raw[ip_hl+14:ip_hl+16])[0]
                base_ttl = raw[8]
                window_div = self.current_params.get("window_div", 8)
                reduced_win = max(base_win // window_div, 1024)
                base_ip_id = struct.unpack("!H", raw[4:6])[0]
                ipid_step = self.current_params.get("ipid_step", 2048)
                MAX_TCP_HDR = 60

                for i, seg in enumerate(segments):
                    if len(seg) == 3:
                        seg_payload, rel_off, opts = seg
                    elif len(seg) == 2:
                        seg_payload, rel_off = seg
                        opts = {}
                    else:
                        self.logger.error(f"Bad segment tuple size: {len(seg)}")
                        continue

                    if not seg_payload:
                        continue

                    ip_hdr = bytearray(raw[:ip_hl])
                    orig_tcp_hdr = bytearray(raw[ip_hl:ip_hl+max(20, tcp_hl)])
                    tcp_hdr = bytearray(orig_tcp_hdr)

                    seq_extra = opts.get("seq_offset", 0) if opts.get("corrupt_sequence") else 0
                    seq = (base_seq + rel_off + seq_extra) & 0xFFFFFFFF
                    tcp_hdr[4:8] = struct.pack("!I", seq)
                    tcp_hdr[8:12] = struct.pack("!I", base_ack)

                    flags = opts.get("tcp_flags")
                    if flags is None:
                        flags = 0x10
                        if i == len(segments) - 1:
                            flags |= 0x08
                    tcp_hdr[13] = flags & 0xFF
                    tcp_hdr[14:16] = struct.pack("!H", reduced_win)

                    ttl = opts.get("ttl", base_ttl)
                    if not isinstance(ttl, int) or not (1 <= ttl <= 255):
                        ttl = base_ttl
                    ip_hdr[8] = ttl

                    new_ip_id = (base_ip_id + i * ipid_step) & 0xFFFF
                    ip_hdr[4:6] = struct.pack("!H", new_ip_id)

                    # MD5SIG — пробуем добавить
                    if opts.get("is_fake") and opts.get("add_md5sig_option"):
                        tcp_hdr = bytearray(self._inject_md5sig_option(bytes(tcp_hdr)))
                    # Контроль: не превысили ли 60?
                    tcp_hl_new = ((tcp_hdr[12] >> 4) & 0x0F) * 4
                    if tcp_hl_new > MAX_TCP_HDR:
                        self.logger.warning(
                            f"TCP header len {tcp_hl_new} > 60 after options. Reverting to original header."
                        )
                        tcp_hdr = bytearray(orig_tcp_hdr)
                        tcp_hl_new = ((tcp_hdr[12] >> 4) & 0x0F) * 4
                        if tcp_hl_new < 20:
                            tcp_hdr[12] = (5 << 4) | (tcp_hdr[12] & 0x0F)
                            tcp_hl_new = 20

                    seg_raw = bytearray(ip_hdr + tcp_hdr + seg_payload)
                    total_len = len(seg_raw)
                    seg_raw[2:4] = struct.pack("!H", total_len)

                    # IP checksum
                    seg_raw[10:12] = b"\x00\x00"
                    ip_csum = self._ip_header_checksum(seg_raw[:ip_hl])
                    seg_raw[10:12] = struct.pack("!H", ip_csum)

                    # TCP checksum
                    tcp_start = ip_hl
                    tcp_end = ip_hl + tcp_hl_new
                    tcp_hdr_bytes = bytes(seg_raw[tcp_start:tcp_end])
                    payload_bytes = bytes(seg_raw[tcp_end:])

                    if opts.get("is_fake") and opts.get("corrupt_tcp_checksum"):
                        good_csum = self._tcp_checksum(seg_raw[:ip_hl], tcp_hdr_bytes, payload_bytes)
                        bad_csum = good_csum ^ 0xFFFF
                        seg_raw[tcp_start+16:tcp_start+18] = struct.pack("!H", bad_csum)
                    else:
                        csum = self._tcp_checksum(seg_raw[:ip_hl], tcp_hdr_bytes, payload_bytes)
                        seg_raw[tcp_start+16:tcp_start+18] = struct.pack("!H", csum)

                    ok = self._safe_send_packet(w, bytes(seg_raw), original_packet)
                    if not ok:
                        self.logger.error("WinDivert send failed for segment (options). Aborting.")
                        return False
                    self.stats["fragments_sent"] += 1

                    delay_ms = float(opts.get("delay_ms", self.current_params.get("delay_ms", 2)))
                    if i < len(segments) - 1 and delay_ms > 0:
                        time.sleep(delay_ms / 1000.0)

                self.logger.debug(f"✨ Отправлено {len(segments)} сегментов (heavy/options)")
                return True
            except Exception as e:
                self.logger.error(f"Ошибка в _send_attack_segments: {e}", exc_info=self.debug)
                return False
            finally:
                try:
                    with self._tlock:
                        if 'segments' in locals() and segments:
                            self._telemetry["aggregate"]["segments_sent"] += len(segments)
                            tgt = original_packet.dst_addr
                            per = self._telemetry["per_target"][tgt]
                            per["segments_sent"] += len(segments)
                            for seg in segments:
                                if len(seg) == 3:
                                    _, rel_off, opts = seg
                                elif len(seg) == 2:
                                    _, rel_off = seg; opts = {}
                                else:
                                    continue
                                self._telemetry["seq_offsets"][int(rel_off)] += 1
                                per["seq_offsets"][int(rel_off)] += 1
                            real_ttl = int(bytearray(original_packet.raw)[8])
                            self._telemetry["ttls"]["real"][real_ttl] += 1
                            per["ttls_real"][real_ttl] += 1
                except Exception:
                    pass

        def _send_aligned_fake_segment(self, original_packet, w, seq_offset: int, data: bytes, ttl: int, fooling: List[str]) -> bool:
            """
            Отправляет фейковый сегмент, выровненный по реальному SEQ (base_seq + seq_offset)
            с переданным payload `data`. Поддерживает:
              - md5sig: инъекция TCP MD5SIG опции (kind=19,len=18) с защитой от >60 байт заголовка
              - badseq: сдвиг SEQ на -10000
              - badsum: порча TCP checksum (инверсия) после корректного пересчёта
            TTL выставляется для этого «фейкового» сегмента (обычно 1..2 при autottl).
            """
            try:
                raw = bytearray(original_packet.raw)
                ip_hl = (raw[0] & 0x0F) * 4
                tcp_hl = ((raw[ip_hl + 12] >> 4) & 0x0F) * 4
                if tcp_hl < 20:
                    tcp_hl = 20

                # Базовые поля из оригинального пакета
                base_seq = struct.unpack("!I", raw[ip_hl+4:ip_hl+8])[0]
                base_ack = struct.unpack("!I", raw[ip_hl+8:ip_hl+12])[0]
                base_win = struct.unpack("!H", raw[ip_hl+14:ip_hl+16])[0]

                # Заголовки IP и TCP (без payload)
                ip_hdr = bytearray(raw[:ip_hl])
                tcp_hdr = bytearray(raw[ip_hl:ip_hl+tcp_hl])

                # Устанавливаем SEQ = base_seq + seq_offset, ACK как в оригинале
                seq = (base_seq + (seq_offset or 0)) & 0xFFFFFFFF
                tcp_hdr[4:8]  = struct.pack("!I", seq)
                tcp_hdr[8:12] = struct.pack("!I", base_ack)

                # Флаги: PSH+ACK, окно можно немного уменьшить (как в основной логике)
                tcp_hdr[13] = 0x18
                # Оставим исходное окно (или слегка уменьшенное при желании)
                # tcp_hdr[14:16] = struct.pack("!H", max(base_win // 2, 1024))

                # TTL для фейкового сегмента
                ip_hdr[8] = ttl if isinstance(ttl, int) and 1 <= ttl <= 255 else 1

                # Применяем md5sig (если задано) — инъекция TCP опции с учётом лимита 60 байт
                if "md5sig" in (fooling or []):
                    tcp_hdr = bytearray(self._inject_md5sig_option(bytes(tcp_hdr)))
                    # Убедимся, что новый data offset корректен (>=20 байт)
                    tcp_hl_new = ((tcp_hdr[12] >> 4) & 0x0F) * 4
                    if tcp_hl_new < 20:
                        tcp_hdr[12] = (5 << 4) | (tcp_hdr[12] & 0x0F)

                # Применяем badseq — сдвиг sequence на -10000
                if "badseq" in (fooling or []):
                    bad_seq = (seq - 10000) & 0xFFFFFFFF
                    tcp_hdr[4:8] = struct.pack("!I", bad_seq)

                # Собираем пакет: IP + TCP + payload
                seg_raw = bytearray(ip_hdr + tcp_hdr + (data or b""))

                # Проставляем Total Length
                seg_raw[2:4] = struct.pack("!H", len(seg_raw))

                # Пересчёт checksums
                # IP
                seg_raw[10:12] = b"\x00\x00"
                ip_csum = self._ip_header_checksum(seg_raw[:ip_hl])
                seg_raw[10:12] = struct.pack("!H", ip_csum)

                # TCP
                tcp_hl_effective = ((seg_raw[ip_hl+12] >> 4) & 0x0F) * 4
                tcp_start = ip_hl
                tcp_end   = ip_hl + tcp_hl_effective
                tcp_hdr_bytes = bytes(seg_raw[tcp_start:tcp_end])
                payload_bytes = bytes(seg_raw[tcp_end:])
                tcp_csum = self._tcp_checksum(seg_raw[:ip_hl], tcp_hdr_bytes, payload_bytes)
                if "badsum" in (fooling or []):
                    tcp_csum ^= 0xFFFF
                seg_raw[tcp_start+16:tcp_start+18] = struct.pack("!H", tcp_csum)

                # Отправляем через safe-отправку (с меткой и ретраем при 258)
                return self._safe_send_packet(w, bytes(seg_raw), original_packet)
            except Exception as e:
                self.logger.debug(f"_send_aligned_fake_segment error: {e}")
                return False

        def _safe_send_packet(self, w: "pydivert.WinDivert", pkt_bytes: bytes, original_packet: "pydivert.Packet") -> bool:
            """
            Безопасная отправка пакета через WinDivert:
            - помечает инжект пакеты mark'ом (чтобы не перехватывать их повторно);
            - при таймауте (WinError 258) делает небольшой ретрай с пересчетом checksum helper'ом.
            """
            try:
                pkt = pydivert.Packet(pkt_bytes, original_packet.interface, original_packet.direction)
                # Отметим наш пакет, чтобы в recv() его пропустить
                try:
                    pkt.mark = self._INJECT_MARK
                except Exception:
                    pass
                w.send(pkt)
                return True
            except OSError as e:
                winerr = getattr(e, "winerror", None)
                if winerr == 258:
                    # Таймаут очереди — небольшой ретрай + попытка пересчитать checksum helper'ом
                    self.logger.debug("WinDivert send timeout (258). Retrying with checksum helper...")
                    time.sleep(0.001)
                    buf = bytearray(pkt_bytes)
                    try:
                        from pydivert.windivert import WinDivertHelper, WinDivertLayer
                        WinDivertHelper.calc_checksums(buf, WinDivertLayer.NETWORK)
                        pkt2 = pydivert.Packet(bytes(buf), original_packet.interface, original_packet.direction)
                        try:
                            pkt2.mark = self._INJECT_MARK
                        except Exception:
                            pass
                        w.send(pkt2)
                        return True
                    except Exception as e2:
                        # Helper недоступен — повторим отправку как есть
                        self.logger.debug(f"Checksum helper not available or failed: {e2}")
                        try:
                            pkt2 = pydivert.Packet(pkt_bytes, original_packet.interface, original_packet.direction)
                            try:
                                pkt2.mark = self._INJECT_MARK
                            except Exception:
                                pass
                            w.send(pkt2)
                            return True
                        except Exception as e3:
                            self.logger.error(f"WinDivert retry failed after 258: {e3}")
                            return False
                self.logger.error(f"WinDivert send error: {e}", exc_info=self.debug)
                return False
            except Exception as e:
                self.logger.error(f"Unexpected send error: {e}", exc_info=self.debug)
                return False

        def _send_fragmented_fallback(self, packet, w):
            """Резервный метод простой фрагментации."""
            payload = bytes(packet.payload)
            fragments = [(payload[0:1], 0), (payload[1:3], 1), (payload[3:], 3)]
            self._send_segments(packet, w, fragments)

        def get_telemetry_snapshot(self) -> Dict[str, Any]:
            """
            Возвращает срез телеметрии текущего запуска движка.
            """
            try:
                with self._tlock:
                    snap = copy.deepcopy(self._telemetry)
                snap["duration_sec"] = time.time() - snap.get("start_ts", time.time())
                # Конвертировать defaultdict -> dict для сериализации
                for k in ["fake", "real"]:
                    snap["ttls"][k] = dict(snap["ttls"][k])
                snap["seq_offsets"] = dict(snap["seq_offsets"])
                snap["overlaps"] = dict(snap["overlaps"])
                snap["per_target"] = {t: {
                    **v,
                    "seq_offsets": dict(v["seq_offsets"]),
                    "ttls_fake": dict(v["ttls_fake"]),
                    "ttls_real": dict(v["ttls_real"]),
                    "overlaps": dict(v["overlaps"])
                } for t, v in snap["per_target"].items()}
                return snap
            except Exception:
                return {}

else:

    class BypassEngine:
        def __init__(self, debug=True):
            self.logger = logging.getLogger("BypassEngine")
            self.logger.warning(
                "Pydivert is not supported on this platform. BypassEngine is disabled."
            )

        def start(self, *args, **kwargs):
            self.logger.warning("BypassEngine is disabled.")
            return None

        def stop(self, *args, **kwargs):
            pass

        def start_with_config(self, *args, **kwargs):
            self.logger.warning("BypassEngine is disabled.")
            return None
