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
# Use unified primitives implementation
import warnings
from core.bypass.techniques.primitives import BypassTechniques as _UnifiedBypassTechniques
from core.bypass.packet import (
    PacketBuilder,
    PacketSender,
    TCPSegmentSpec,
    UDPDatagramSpec,
)

warnings.warn(
    "core.bypass_engine.BypassTechniques is deprecated; using core.bypass.techniques.primitives.BypassTechniques",
    DeprecationWarning,
    stacklevel=2,
)
BypassTechniques = _UnifiedBypassTechniques
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


class LegacyBypassTechniques:
    """Библиотека продвинутых техник обхода DPI (legacy, не используется движком)."""

    @staticmethod
    def apply_fakeddisorder(
        payload: bytes, split_pos: int = 76, overlap_size: int = 336
    ) -> List[Tuple[bytes, int]]:
        if split_pos >= len(payload):
            return [(payload, 0)]
        part1, part2 = (payload[:split_pos], payload[split_pos:])
        ov = int(overlap_size) if isinstance(overlap_size, int) else 336
        if ov <= 0:
            return [(part2, split_pos), (part1, 0)]
        if ov > 4096:
            ov = 4096
        offset_part2 = split_pos
        offset_part1 = split_pos - ov
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
        segments = LegacyBypassTechniques.apply_multisplit(payload, positions)
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
        try:
            if not payload or len(payload) < 5:
                return payload
            if (
                payload[0] != 0x16
                or payload[1] != 0x03
                or payload[2] not in (0x00, 0x01, 0x02, 0x03)
            ):
                return payload
            rec_len = int.from_bytes(payload[3:5], "big")
            content = (
                payload[5 : 5 + rec_len]
                if 5 + rec_len <= len(payload)
                else payload[5:]
            )
            tail = payload[5 + rec_len :] if 5 + rec_len <= len(payload) else b""
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
        def __init__(self, debug=True, *args, **kwargs):
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
            self._INJECT_MARK = 0xC0DE

            # Initialize packet handling components
            self._packet_builder = PacketBuilder(debug=debug)
            self._packet_sender = PacketSender(
                builder=self._packet_builder,
                logger=self.logger,
                inject_mark=self._INJECT_MARK,
                debug=debug,
            )

            self.controller = None
            self.flow_table = {}
            self._lock = threading.Lock()
            self._inbound_thread = None
            self._active_flows: Set[Tuple[str, int, str, int]] = set()
            self._flow_ttl_sec = 3.0
            self._inbound_events: Dict[
                Tuple[str, int, str, int], threading.Event
            ] = {}
            self._inbound_results: Dict[Tuple[str, int, str, int], str] = {}
            self._max_injections = 12
            self._inject_sema = threading.Semaphore(self._max_injections)
            self.cdn_profiles: Dict[str, Dict[str, Any]] = {}
            self._tlock = threading.Lock()
            self._telemetry = self._init_telemetry()
            self._strategy_manager = None
            self.strategy_override = None
            self._forced_strategy_active = False
            self._exec_handlers = {}
            try:
                from core.bypass.attacks.exec_handlers import EXEC_HANDLERS

                self._exec_handlers.update(EXEC_HANDLERS)
            except Exception:
                pass

        def attach_controller(
            self,
            base_rules,
            zapret_parser,
            task_translator,
            store_path="learned_strategies.json",
            epsilon=0.1,
        ):
            try:
                from core.optimizer.adaptive_controller import (
                    AdaptiveStrategyController,
                )
            except Exception as e:
                self.logger.error(f"Adaptive controller not available: {e}")
                return False
            self.controller = AdaptiveStrategyController(
                base_rules=base_rules,
                zapret_parser=zapret_parser,
                task_translator=task_translator,
                store_path=store_path,
                epsilon=epsilon,
            )
            self.logger.info("✅ AdaptiveStrategyController attached")
            return True

        def start(
            self,
            target_ips: Set[str],
            strategy_map: Dict[str, Dict],
            reset_telemetry: bool = False,
            strategy_override: Optional[Dict[str, Any]] = None,
        ):
            if reset_telemetry:
                with self._tlock:
                    self._telemetry = self._init_telemetry()
            self.strategy_override = strategy_override
            self.running = True
            self.logger.info("🚀 Запуск универсального движка обхода DPI...")
            thread = threading.Thread(
                target=self._run_bypass_loop,
                args=(target_ips, strategy_map),
                daemon=True,
            )
            thread.start()
            if not self._inbound_thread:
                self._inbound_thread = self._start_inbound_observer()
            return thread

        def start_with_config(
            self, config: dict, strategy_override: Optional[Dict[str, Any]] = None
        ):
            strategy_task = self._config_to_strategy_task(config)
            target_ips = set()
            strategy_map = {"default": strategy_task}
            self.strategy_override = strategy_override
            self.logger.info(f"🚀 Starting service mode with strategy: {strategy_task}")
            return self.start(
                target_ips, strategy_map, strategy_override=strategy_override
            )

        def set_strategy_override(self, strategy_task: Dict[str, Any]) -> None:
            task = (
                dict(strategy_task)
                if isinstance(strategy_task, dict)
                else {"type": str(strategy_task), "params": {}}
            )
            params = dict(task.get("params", {}))

            if "fooling" in params and not isinstance(params["fooling"], (list, tuple)):
                if isinstance(params["fooling"], str):
                    if "," in params["fooling"]:
                        params["fooling"] = [
                            f.strip() for f in params["fooling"].split(",") if f.strip()
                        ]
                    elif params["fooling"]:
                        params["fooling"] = [params["fooling"]]

            if "fake_ttl" not in params:
                if "ttl" in params and params["ttl"] is not None:
                    try:
                        params["fake_ttl"] = int(params["ttl"])
                    except Exception:
                        pass
                if (
                    "fake_ttl" not in params
                    and str(task.get("type", "")).lower() == "fakeddisorder"
                ):
                    params["fake_ttl"] = 1

            task["params"] = params
            task["no_fallbacks"] = True

            self.strategy_override = task
            self._forced_strategy_active = True

            try:
                self.logger.info(
                    f"Принудительная стратегия установлена: {self._format_task(task) if hasattr(self, '_format_task') else task}"
                )
            except Exception:
                self.logger.info(f"Принудительная стратегия установлена: {task}")

        def _config_to_strategy_task(self, config: dict) -> dict:
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
                    task_type = "fakeddisorder"
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
                    "quic_segments_sent": 0,
                },
                "ttls": {"fake": defaultdict(int), "real": defaultdict(int)},
                "seq_offsets": defaultdict(int),
                "overlaps": defaultdict(int),
                "clienthellos": 0,
                "serverhellos": 0,
                "rst_count": 0,
                "per_target": defaultdict(
                    lambda: {
                        "segments_sent": 0,
                        "fake_packets_sent": 0,
                        "seq_offsets": defaultdict(int),
                        "ttls_fake": defaultdict(int),
                        "ttls_real": defaultdict(int),
                        "overlaps": defaultdict(int),
                        "last_outcome": None,
                        "last_outcome_ts": None,
                    }
                ),
            }

        def _cleanup_old_telemetry(self):
            with self._tlock:
                if len(self._telemetry["per_target"]) > self._telemetry_max_targets:
                    sorted_targets = sorted(
                        self._telemetry["per_target"].items(),
                        key=lambda x: x[1].get("last_outcome_ts", 0) or 0,
                        reverse=True,
                    )
                    self._telemetry["per_target"] = dict(
                        sorted_targets[: self._telemetry_max_targets]
                    )
            try:
                with self._lock:
                    current_time = time.time()
                    old_flows = [
                        k
                        for k, v in self.flow_table.items()
                        if current_time - v.get("start_ts", 0) > 30
                    ]
                    for flow in old_flows:
                        self.flow_table.pop(flow, None)
            except Exception:
                pass

        def _is_target_ip(self, ip_str: str, target_ips: Set[str]) -> bool:
            if not target_ips:
                return True
            if ip_str in target_ips:
                return True
            cdn_prefixes = {
                "104.", "172.64.", "172.67.", "162.158.", "162.159.", "104.16.",
                "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.",
                "104.23.", "104.24.", "104.25.", "104.26.", "104.27.", "104.28.",
                "104.29.", "104.30.", "151.101.", "199.232.", "23.", "184.",
                "2.16.", "95.100.", "185.199.", "87.240.", "93.186.", "54.192.",
                "54.230.", "54.239.", "54.182.", "216.58.", "172.217.", "142.250.",
                "172.253.", "13.107.", "40.96.", "40.97.", "40.98.", "40.99.",
                "77.88.", "5.255.", "128.140.", "217.20.", "51.89.", "51.91.",
                "104.131.", "104.236.", "91.108.", "149.154.",
            }
            for prefix in cdn_prefixes:
                if ip_str.startswith(prefix):
                    self.logger.debug(
                        f"IP {ip_str} соответствует CDN префиксу {prefix}"
                    )
                    return True
            return False

        def _resolve_midsld_pos(self, payload: bytes) -> Optional[int]:
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
                            name_len = int.from_bytes(
                                payload[pos + 7 : pos + 9], "big"
                            )
                            name_start = pos + 9
                            if name_start + name_len <= len(payload):
                                domain_bytes = payload[name_start : name_start + name_len]
                                domain_str = domain_bytes.decode("idna", errors="strict")
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
            mapping = {
                "104.": "cloudflare", "172.64.": "cloudflare", "172.67.": "cloudflare",
                "162.158.": "cloudflare", "162.159.": "cloudflare",
                "151.101.": "fastly", "199.232.": "fastly",
                "23.": "akamai", "2.16.": "akamai", "95.100.": "akamai",
                "54.192.": "cloudfront", "54.230.": "cloudfront", "54.239.": "cloudfront",
                "54.182.": "cloudfront", "216.58.": "google", "172.217.": "google",
                "142.250.": "google", "172.253.": "google", "157.240.": "meta",
                "69.171.": "meta", "31.13.": "meta", "77.88.": "yandex",
                "5.255.": "yandex", "104.244.": "twitter", "199.59.": "twitter",
                "91.108.": "telegram", "149.154.": "telegram", "13.107.": "microsoft",
                "40.96.": "microsoft", "40.97.": "microsoft", "40.98.": "microsoft",
                "40.99.": "microsoft", "104.131.": "digitalocean", "104.236.": "digitalocean",
            }
            for pref, name in mapping.items():
                if ip_str.startswith(pref):
                    return name
            return "generic"

        def _get_cdn_profile(self, cdn: str) -> Dict[str, Any]:
            prof = self.cdn_profiles.get(cdn)
            if not prof:
                prof = {
                    "md5sig_allowed": None,
                    "badsum_allowed": None,
                    "best_fakeddisorder": None,
                }
                self.cdn_profiles[cdn] = prof
            return prof

        def _estimate_split_pos_from_ch(self, payload: bytes) -> Optional[int]:
            try:
                if not self._is_tls_clienthello(payload):
                    return None
                if len(payload) < 43:
                    return None
                if payload[5] != 0x01:
                    return None
                pos = 9
                pos += 2 + 32
                if pos + 1 >= len(payload):
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
                if ext_start + ext_len > len(payload):
                    ext_len = max(0, len(payload) - ext_start)
                s = ext_start
                sni_mid_abs = None
                while s + 4 <= ext_start + ext_len:
                    etype = int.from_bytes(payload[s : s + 2], "big")
                    elen = int.from_bytes(payload[s + 2 : s + 4], "big")
                    epos = s + 4
                    if epos + elen > len(payload):
                        break
                    if etype == 0 and elen >= 5:
                        try:
                            list_len = int.from_bytes(payload[epos : epos + 2], "big")
                            npos = epos + 2
                            if npos + list_len <= epos + elen:
                                if npos + 3 <= len(payload):
                                    ntype = payload[npos]
                                    nlen = int.from_bytes(
                                        payload[npos + 1 : npos + 3], "big"
                                    )
                                    nstart = npos + 3
                                    if ntype == 0 and nstart + nlen <= len(payload):
                                        try:
                                            name = payload[
                                                nstart : nstart + nlen
                                            ].decode("idna")
                                            parts = name.split(".")
                                            if len(parts) >= 2:
                                                sld = parts[-2]
                                                sld_start_dom = name.rfind(sld)
                                                sld_mid = sld_start_dom + len(sld) // 2
                                                sni_mid_abs = nstart + sld_mid
                                        except Exception:
                                            pass
                        except Exception:
                            pass
                        break
                    s = epos + elen
                if sni_mid_abs:
                    sp = max(32, min(sni_mid_abs, len(payload) - 1))
                else:
                    sp = max(48, min(ext_start + min(32, ext_len // 8), len(payload) - 1))
                return sp
            except Exception:
                return None

        def _estimate_overlap(
            self, part1_len: int, part2_len: int, split_pos: int
        ) -> int:
            cap = min(part1_len, part2_len, split_pos)
            for cand in (336, 160, 96, 64, 32):
                if cap >= cand:
                    return cand
            return max(8, min(cap, 24))

        def _get_inbound_event_for_flow(
            self, packet: "pydivert.Packet"
        ) -> threading.Event:
            rev_key = (
                packet.dst_addr,
                packet.dst_port,
                packet.src_addr,
                packet.src_port,
            )
            with self._lock:
                ev = self._inbound_events.get(rev_key)
                if not ev:
                    ev = threading.Event()
                    self._inbound_events[rev_key] = ev
                return ev

        def _start_inbound_observer(self):
            def run():
                try:
                    with pydivert.WinDivert(
                        "inbound and tcp.SrcPort == 443", priority=900
                    ) as wi:
                        self.logger.info("👂 Inbound observer started")
                        while self.running:
                            pkt = wi.recv()
                            if not pkt:
                                continue
                            outcome = None
                            try:
                                payload = bytes(pkt.payload) if pkt.payload else b""
                                if (
                                    len(payload) > 6
                                    and payload[0] == 0x16
                                    and payload[5] == 0x02
                                ):
                                    outcome = "ok"
                                elif pkt.tcp and pkt.tcp.rst:
                                    outcome = "rst"
                            except Exception:
                                pass
                            if outcome:
                                try:
                                    with self._tlock:
                                        if outcome == "ok":
                                            self._telemetry["serverhellos"] += 1
                                        elif outcome == "rst":
                                            self._telemetry["rst_count"] += 1
                                except Exception:
                                    pass
                            if outcome:
                                rev_key = (
                                    pkt.dst_addr,
                                    pkt.dst_port,
                                    pkt.src_addr,
                                    pkt.src_port,
                                )
                                try:
                                    with self._lock:
                                        ev = self._inbound_events.get(rev_key)
                                    if ev:
                                        self._inbound_results[rev_key] = outcome
                                        ev.set()
                                except Exception:
                                    pass
                                if self.controller:
                                    with self._lock:
                                        info = self.flow_table.pop(rev_key, None)
                                    if info:
                                        rtt_ms = int(
                                            (time.time() - info["start_ts"]) * 1000
                                        )
                                        self.controller.record_outcome(
                                            info["key"],
                                            info["strategy"],
                                            outcome,
                                            rtt_ms,
                                        )
                                try:
                                    tgt = pkt.src_addr
                                    with self._tlock:
                                        per = self._telemetry["per_target"][tgt]
                                        per["last_outcome"] = outcome
                                        per["last_outcome_ts"] = time.time()
                                except Exception:
                                    pass
                            wi.send(pkt)
                except Exception as e:
                    if self.running:
                        self.logger.error(
                            f"Inbound observer error: {e}", exc_info=self.debug
                        )

            t = threading.Thread(target=run, daemon=True)
            t.start()
            return t

        def _run_bypass_loop(
            self, target_ips: Set[str], strategy_map: Dict[str, Dict]
        ):
            filter_str = "outbound and (tcp.DstPort == 443 or udp.DstPort == 443 or tcp.DstPort == 80)"
            self.logger.info(f"🔍 Фильтр pydivert: {filter_str}")
            try:
                with pydivert.WinDivert(filter_str, priority=1000) as w:
                    try:
                        from pydivert.windivert import WinDivertParam

                        w.set_param(WinDivertParam.QueueLen, 8192)
                        w.set_param(WinDivertParam.QueueTime, 2048)
                        w.set_param(WinDivertParam.QueueSize, 64 * 1024)
                        self.logger.debug(
                            "WinDivert queue params set: Len=8192, Time=2048, Size=64KB"
                        )
                    except Exception as e:
                        self.logger.debug(f"WinDivert set_param failed: {e}")

                    self.logger.info("✅ WinDivert запущен успешно.")
                    last_cleanup = time.time()
                    while self.running:
                        packet = w.recv()
                        if packet is None:
                            continue
                        if time.time() - last_cleanup >= 5.0:
                            last_cleanup = time.time()
                            self._cleanup_old_telemetry()
                        try:
                            pkt_mark = getattr(packet, "mark", 0)
                        except Exception:
                            pkt_mark = 0
                        if pkt_mark == self._INJECT_MARK:
                            w.send(packet)
                            continue
                        self.stats["packets_captured"] += 1
                        if self._is_target_ip(packet.dst_addr, target_ips) and packet.payload:
                            try:
                                if self._is_tls_clienthello(packet.payload):
                                    with self._tlock:
                                        self._telemetry["clienthellos"] += 1
                                        _ = self._telemetry["per_target"][
                                            packet.dst_addr
                                        ]
                            except Exception:
                                pass
                            if self.strategy_override:
                                strategy_task = self.strategy_override
                                try:
                                    flow_id = (
                                        packet.src_addr,
                                        packet.src_port,
                                        packet.dst_addr,
                                        packet.dst_port,
                                    )
                                    sni = (
                                        self._extract_sni(packet.payload)
                                        if packet.payload
                                        else None
                                    )
                                    with self._lock:
                                        self.flow_table[flow_id] = {
                                            "start_ts": time.time(),
                                            "key": sni or packet.dst_addr,
                                            "strategy": strategy_task,
                                        }
                                    with self._tlock:
                                        self._telemetry[
                                            "strategy_key"
                                        ] = self._strategy_key(strategy_task)
                                except Exception:
                                    pass
                                if self._is_udp(packet) and packet.dst_port == 443:
                                    if (
                                        strategy_task
                                        and self.quic_handler.is_quic_initial(
                                            packet.payload
                                        )
                                    ):
                                        self.stats["quic_packets_bypassed"] += 1
                                        self.logger.info(
                                            f"Обнаружен QUIC Initial к {packet.dst_addr}. Применяем принудительную стратегию..."
                                        )
                                        self.apply_bypass(packet, w, strategy_task)
                                    else:
                                        w.send(packet)
                                elif strategy_task and self._is_tls_clienthello(
                                    packet.payload
                                ):
                                    self.stats["tls_packets_bypassed"] += 1
                                    self.logger.info(
                                        f"Обнаружен TLS ClientHello к {packet.dst_addr}. Применяем принудительную стратегию..."
                                    )
                                    self.apply_bypass(packet, w, strategy_task)
                                else:
                                    w.send(packet)
                                continue
                            if self.controller and self._is_tls_clienthello(
                                packet.payload
                            ):
                                sni = self._extract_sni(packet.payload)
                                strategy_task, why = self.controller.choose(
                                    sni, packet.dst_addr
                                )
                                self.logger.info(
                                    f"🎯 Strategy pick ({why}): {strategy_task} for SNI={sni} IP={packet.dst_addr}"
                                )
                                flow_id = (
                                    packet.src_addr,
                                    packet.src_port,
                                    packet.dst_addr,
                                    packet.dst_port,
                                )
                                with self._lock:
                                    self.flow_table[flow_id] = {
                                        "start_ts": time.time(),
                                        "key": sni or packet.dst_addr,
                                        "strategy": strategy_task,
                                    }
                                try:
                                    with self._tlock:
                                        self._telemetry[
                                            "strategy_key"
                                        ] = self._strategy_key(strategy_task)
                                except Exception:
                                    pass
                                if self._is_udp(packet) and packet.dst_port == 443:
                                    if (
                                        strategy_task
                                        and self.quic_handler.is_quic_initial(
                                            packet.payload
                                        )
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
                                continue
                            strategy_task = strategy_map.get(
                                packet.dst_addr
                            ) or strategy_map.get("default")
                            if strategy_task and self._is_tls_clienthello(
                                packet.payload
                            ):
                                try:
                                    flow_id = (
                                        packet.src_addr,
                                        packet.src_port,
                                        packet.dst_addr,
                                        packet.dst_port,
                                    )
                                    with self._lock:
                                        self.flow_table[flow_id] = {
                                            "start_ts": time.time(),
                                            "key": packet.dst_addr,
                                            "strategy": strategy_task,
                                        }
                                    with self._tlock:
                                        self._telemetry[
                                            "strategy_key"
                                        ] = self._strategy_key(strategy_task)
                                except Exception:
                                    pass
                            if self._is_udp(packet) and packet.dst_port == 443:
                                if (
                                    strategy_task
                                    and self.quic_handler.is_quic_initial(
                                        packet.payload
                                    )
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
            return (
                payload
                and len(payload) > 6
                and (payload[0] == 22)
                and (payload[5] == 1)
            )

        def _is_udp(self, packet: pydivert.Packet) -> bool:
            return packet.protocol == 17

        def _is_tcp(self, packet: pydivert.Packet) -> bool:
            return packet.protocol == 6

        def apply_bypass(
            self, packet: pydivert.Packet, w: pydivert.WinDivert, strategy_task: Dict
        ):
            try:
                acquired = self._inject_sema.acquire(timeout=0.5)
                if not acquired:
                    self.logger.debug(
                        "Injection semaphore limit reached, forwarding original"
                    )
                    w.send(packet)
                    return
                params = strategy_task.get("params", {}).copy()
                if "fooling" not in params and "fooling_methods" in params:
                    params["fooling"] = params.get("fooling_methods", [])
                if "fooling" in params and not isinstance(
                    params["fooling"], (list, tuple)
                ):
                    if isinstance(params["fooling"], str):
                        if "," in params["fooling"]:
                            params["fooling"] = [
                                f.strip()
                                for f in params["fooling"].split(",")
                                if f.strip()
                            ]
                        elif params["fooling"]:
                            params["fooling"] = [params["fooling"]]
                self.current_params = params
                task_type = normalize_attack_name(strategy_task.get("type"))
                if "fake_ttl" not in params:
                    if "ttl" in params and params["ttl"] is not None:
                        try:
                            params["fake_ttl"] = int(params["ttl"])
                        except Exception:
                            pass
                    elif task_type == "fakeddisorder":
                        params["fake_ttl"] = 1
                try:
                    strategy_task["params"] = params
                except Exception:
                    pass

                fake_ttl_source = params.get("autottl") or params.get("ttl")
                if fake_ttl_source is not None:
                    try:
                        fake_ttl = int(fake_ttl_source)
                        if not (1 <= fake_ttl <= 255):
                            self.logger.warning(
                                f"Invalid fake TTL {fake_ttl}, using default 1 for fakes."
                            )
                            fake_ttl = 1
                    except (ValueError, TypeError):
                        self.logger.warning(
                            f"Invalid fake TTL format '{fake_ttl_source}', using default 1."
                        )
                        fake_ttl = 1
                else:
                    fake_ttl = 1 if task_type == "fakeddisorder" else 3
                if task_type in (
                    "fakeddisorder",
                    "multidisorder",
                    "multisplit",
                    "badsum_race",
                    "md5sig_race",
                    "fake",
                ):
                    if fake_ttl > 8:
                        self.logger.debug(
                            f"Clamping fake TTL from {fake_ttl} to 8 for {task_type}"
                        )
                        fake_ttl = 8
                self.current_params["fake_ttl"] = fake_ttl
                self.logger.info(f"Base TTL for FAKE packets set to: {fake_ttl}")

                orig_ttl = bytearray(packet.raw)[8]
                real_ttl = orig_ttl if 1 <= orig_ttl <= 255 else 64
                self.current_params["real_ttl"] = real_ttl
                self.logger.info(
                    f"TTL for REAL segments set to: {real_ttl} (from original packet)"
                )

                self.logger.info(
                    f"🎯 Applying bypass for {packet.dst_addr} -> Type: {task_type}, Params: {params}"
                )

                payload = bytes(packet.payload)
                success = False
                try:
                    with self._tlock:
                        _ = self._telemetry["per_target"][packet.dst_addr]
                except Exception:
                    pass

                if self._is_udp(packet) and packet.dst_port == 443:
                    try:
                        from core.bypass.attacks.tunneling.quic_fragmentation import (
                            QUICFragmentationAttack,
                        )
                        from core.bypass.attacks.base import AttackContext

                        sni = self._extract_sni(payload)
                        attack = QUICFragmentationAttack()
                        ap = (
                            strategy_task.get("params", {})
                            if isinstance(strategy_task, dict)
                            else {}
                        )
                        ap.setdefault("fragment_size", 120)
                        ap.setdefault("split_by_frames", True)
                        ap.setdefault("coalesce_count", 0)
                        ap.setdefault("padding_ratio", 0.0)
                        ctx = AttackContext(
                            dst_ip=packet.dst_addr,
                            dst_port=packet.dst_port,
                            src_ip=packet.src_addr,
                            src_port=packet.src_port,
                            domain=sni or getattr(packet, "domain", None),
                            payload=None,
                            protocol="udp",
                            params=ap,
                            timeout=1.0,
                            debug=self.debug,
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
                        if not udp_segments:
                            positions = ap.get("positions") or [10, 25, 40, 80, 160]
                            split_segs = self.quic_handler.split_quic_initial(
                                payload, positions
                            )
                            udp_segments = []
                            for seg, _ in split_segs:
                                udp_segments.append((seg, 0))
                        ok = self._send_udp_segments(packet, w, udp_segments)
                        if ok:
                            with self._tlock:
                                self._telemetry["aggregate"][
                                    "quic_segments_sent"
                                ] += len(udp_segments or [])
                        if not ok:
                            self.logger.error(
                                "UDP/QUIC send failed; forwarding original"
                            )
                            w.send(packet)
                        return
                    except Exception as e:
                        self.logger.debug(f"QUIC fragmentation path failed: {e}")
                        w.send(packet)
                        return

                if params.get("split_pos") == "midsld":
                    params["split_pos"] = self._resolve_midsld_pos(payload) or 3

                if task_type == "fakeddisorder":
                    forced_nofallback = bool(self.strategy_override) and bool(
                        strategy_task.get("no_fallbacks", False)
                        or getattr(self, "_forced_strategy_active", False)
                    )
                    try:
                        if (
                            forced_nofallback
                            or params.get("simple", False)
                            or params.get("force_simple", False)
                        ):
                            if forced_nofallback:
                                self.logger.info(
                                    "Forced strategy active: skipping calibrator/fallback paths"
                                )
                            payload = bytes(packet.payload)
                            split_pos = int(params.get("split_pos", 76))
                            overlap = int(params.get("overlap_size", 336))
                            ttl_simple_src = params.get(
                                "fake_ttl",
                                params.get("ttl", self.current_params.get("fake_ttl", 1)),
                            )
                            try:
                                ttl_simple = int(ttl_simple_src)
                            except Exception:
                                ttl_simple = int(self.current_params.get("fake_ttl", 1))

                            fooling_list = params.get("fooling", []) or []
                            if isinstance(fooling_list, str):
                                fooling_list = [
                                    f.strip()
                                    for f in fooling_list.split(",")
                                    if f.strip()
                                ]

                            left = (
                                payload[:split_pos]
                                if split_pos < len(payload)
                                else payload
                            )
                            right = (
                                payload[split_pos:]
                                if split_pos < len(payload)
                                else b""
                            )

                            segs = []
                            opts1 = {
                                "is_fake": True,
                                "ttl": max(1, min(255, int(ttl_simple))),
                                "delay_ms": 2,
                            }
                            if "badsum" in fooling_list:
                                opts1["corrupt_tcp_checksum"] = True
                            if "md5sig" in fooling_list:
                                opts1["add_md5sig_option"] = True
                            if "badseq" in fooling_list:
                                opts1["corrupt_sequence"] = True

                            segs.append((right, split_pos, opts1))
                            segs.append(
                                (left, split_pos - int(overlap), {"tcp_flags": 0x18, "delay_ms": 2})
                            )

                            if self._send_attack_segments(packet, w, segs):
                                self.logger.debug(
                                    "Simple/forced fakeddisorder path succeeded"
                                )
                                return
                            if forced_nofallback:
                                w.send(packet)
                                return
                    except Exception:
                        if forced_nofallback:
                            w.send(packet)
                            return
                    flow_id = (
                        packet.src_addr,
                        packet.src_port,
                        packet.dst_addr,
                        packet.dst_port,
                    )
                    if flow_id in self._active_flows:
                        self.logger.debug(
                            "Flow already processed, forwarding original"
                        )
                        w.send(packet)
                        return
                    self._active_flows.add(flow_id)
                    threading.Timer(
                        self._flow_ttl_sec, lambda: self._active_flows.discard(flow_id)
                    ).start()

                    inbound_ev = self._get_inbound_event_for_flow(packet)
                    rev_key = (
                        packet.dst_addr,
                        packet.dst_port,
                        packet.src_addr,
                        packet.src_port,
                    )
                    if inbound_ev.is_set():
                        inbound_ev.clear()
                    self._inbound_results.pop(rev_key, None)

                    is_tls_ch = self._is_tls_clienthello(payload)
                    sp_guess = (
                        self._estimate_split_pos_from_ch(payload) if is_tls_ch else None
                    )
                    init_sp = params.get("split_pos") or sp_guess or (76 if is_tls_ch else max(16, len(payload)//2))

                    seed = None
                    if StrategyManager and self._strategy_manager is None:
                        try:
                            self._strategy_manager = StrategyManager()
                        except Exception:
                            self._strategy_manager = False
                    if self._strategy_manager:
                        try:
                            sm = self._strategy_manager
                            sni = self._extract_sni(payload)
                            key_domain = (
                                getattr(packet, "domain", None) or sni or packet.dst_addr
                            )
                            ds = sm.get_strategy(key_domain)
                            if ds and ds.split_pos and ds.overlap_size:
                                seed = CalibCandidate(
                                    split_pos=int(ds.split_pos),
                                    overlap_size=int(ds.overlap_size),
                                )
                                self.logger.info(
                                    f"Calibrator seed from StrategyManager: sp={seed.split_pos}, ov={seed.overlap_size}"
                                )
                        except Exception as e:
                            self.logger.debug(f"Seed fetch failed: {e}")

                    cand_list = Calibrator.prepare_candidates(
                        payload, initial_split_pos=init_sp
                    )
                    if seed:
                        cand_list = [seed] + [
                            c
                            for c in cand_list
                            if (c.split_pos, c.overlap_size)
                            != (seed.split_pos, seed.overlap_size)
                        ]
                    elif "split_pos" in params and "overlap_size" in params:
                        head = CalibCandidate(
                            split_pos=int(params["split_pos"]),
                            overlap_size=int(params["overlap_size"]),
                        )
                        cand_list = [head] + [
                            c
                            for c in cand_list
                            if (c.split_pos, c.overlap_size)
                            != (head.split_pos, head.overlap_size)
                        ]

                    cdn = self._classify_cdn(packet.dst_addr)
                    prof = self._get_cdn_profile(cdn)
                    fooling_list = params.get("fooling", []) or []
                    if isinstance(fooling_list, str):
                        fooling_list = [
                            f.strip() for f in fooling_list.split(",") if f.strip()
                        ]
                    try:
                        inbound_ev = self._get_inbound_event_for_flow(packet)
                        if inbound_ev.is_set():
                            inbound_ev.clear()
                        rev_key = (
                            packet.dst_addr,
                            packet.dst_port,
                            packet.src_addr,
                            packet.src_port,
                        )
                        self._inbound_results.pop(rev_key, None)
                        if prof["md5sig_allowed"] is None:
                            self._send_aligned_fake_segment(
                                packet,
                                w,
                                init_sp,
                                b"",
                                max(1, self.current_params["fake_ttl"]),
                                ["md5sig"],
                            )
                            got = inbound_ev.wait(timeout=0.2)
                            outcome = (
                                self._inbound_results.pop(rev_key, None) if got else None
                            )
                            prof["md5sig_allowed"] = outcome != "rst"
                        if prof["badsum_allowed"] is None:
                            inbound_ev.clear()
                            self._send_aligned_fake_segment(
                                packet,
                                w,
                                init_sp,
                                b"",
                                max(1, self.current_params["fake_ttl"]),
                                ["badsum"],
                            )
                            got = inbound_ev.wait(timeout=0.2)
                            outcome = (
                                self._inbound_results.pop(rev_key, None) if got else None
                            )
                            prof["badsum_allowed"] = outcome != "rst"
                    except Exception:
                        pass
                    if "md5sig" in fooling_list and prof["md5sig_allowed"] is False:
                        fooling_list = [f for f in fooling_list if f != "md5sig"]
                    if "badsum" in fooling_list and prof["badsum_allowed"] is False:
                        fooling_list = [f for f in fooling_list if f != "badsum"]
                    autottl = params.get("autottl")
                    ttl_list = (
                        list(range(1, min(int(autottl), 8) + 1))
                        if autottl
                        else [self.current_params["fake_ttl"]]
                    )
                    try:
                        cf = packet.dst_addr.startswith(
                            ("104.", "172.64.", "172.66.", "172.67.", "162.158.", "162.159.")
                        )
                        if cf or ("badsum" in (fooling_list or [])):
                            ttl_list = [1, 2, 3]
                    except Exception:
                        pass

                    def _send_try(cand: CalibCandidate, ttl: int, d_ms: int):
                        self._send_aligned_fake_segment(
                            packet,
                            w,
                            cand.split_pos,
                            payload[cand.split_pos : cand.split_pos + 100],
                            ttl,
                            fooling_list,
                        )
                        time.sleep((d_ms * random.uniform(0.85, 1.35)) / 1000.0)
                        self.current_params["delay_ms"] = d_ms
                        segments = self.techniques.apply_fakeddisorder(
                            payload, cand.split_pos, cand.overlap_size
                        )
                        with self._tlock:
                            self._telemetry["overlaps"][int(cand.overlap_size)] += 1
                            for _, rel_off in segments:
                                self._telemetry["seq_offsets"][int(rel_off)] += 1
                        self._send_segments(packet, w, segments)

                    def _wait_outcome(timeout: float = 0.25) -> Optional[str]:
                        got = inbound_ev.wait(timeout=timeout)
                        if not got:
                            return None
                        return self._inbound_results.get(rev_key)

                    best_cand = Calibrator.sweep(
                        payload=payload,
                        candidates=cand_list,
                        ttl_list=ttl_list,
                        delays=[1, 2, 3],
                        send_func=_send_try,
                        wait_func=_wait_outcome,
                        time_budget_ms=450,
                    )
                    got_inbound = best_cand is not None
                    if got_inbound:
                        with self._lock:
                            self._inbound_events.pop(rev_key, None)
                            self._inbound_results.pop(rev_key, None)
                        self.logger.info(
                            f"✅ Calibrator: success with sp={best_cand.split_pos}, ov={best_cand.overlap_size}, delay={self.current_params.get('delay_ms',2)}ms"
                        )

                    if best_cand and StrategyManager:
                        try:
                            sm = StrategyManager()
                            sni = self._extract_sni(payload)
                            key_domain = (
                                getattr(packet, "domain", sni or packet.dst_addr)
                            )
                            strategy_str = f"fakeddisorder(overlap_size={best_cand.overlap_size}, split_pos={best_cand.split_pos})"
                            sm.add_strategy(
                                key_domain,
                                strategy_str,
                                1.0,
                                200.0,
                                split_pos=best_cand.split_pos,
                                overlap_size=best_cand.overlap_size,
                                fooling_modes=fooling_list,
                                fake_ttl_source=autottl
                                or self.current_params.get("fake_ttl"),
                                delay_ms=self.current_params.get("delay_ms", 2),
                            )
                            sm.save_strategies()
                            self.logger.info(
                                f"Saved best params for {key_domain} via StrategyManager."
                            )
                        except Exception as e:
                            self.logger.debug(
                                f"StrategyManager immediate update failed: {e}"
                            )

                    try:
                        if best_cand:
                            self.current_params["delay_ms"] = max(
                                2, int(self.current_params.get("delay_ms", 2))
                            )
                    except Exception:
                        pass

                    success = best_cand is not None
                    if not success:
                        self.logger.warning(
                            "Calibrator failed. Trying fallbacks (seqovl -> multisplit)..."
                        )
                        try:
                            sp_fb = init_sp
                            ov_fb = params.get("overlap_size", 20)
                            segments = self.techniques.apply_seqovl(
                                payload, sp_fb, ov_fb
                            )
                            if self._send_segments(packet, w, segments):
                                _ev = self._get_inbound_event_for_flow(packet)
                                if (
                                    _ev.wait(timeout=0.25)
                                    and self._inbound_results.get(rev_key) == "ok"
                                ):
                                    success = True
                            if not success:
                                positions = [
                                    max(6, sp_fb // 4),
                                    max(12, sp_fb // 2),
                                    max(18, (3 * sp_fb) // 4),
                                ]
                                segments = self.techniques.apply_multisplit(
                                    payload, positions
                                )
                                if self._send_segments(packet, w, segments):
                                    _ev = self._get_inbound_event_for_flow(packet)
                                    if (
                                        _ev.wait(timeout=0.25)
                                        and self._inbound_results.get(rev_key) == "ok"
                                    ):
                                        success = True
                            if not success:
                                self.logger.warning("Fallback race (fake+badsum)...")
                                self._send_fake_packet_with_badsum(packet, w, ttl=1)
                                time.sleep(0.003)
                                w.send(packet)
                                _ev = self._get_inbound_event_for_flow(packet)
                                if (
                                    _ev.wait(timeout=0.3)
                                    and self._inbound_results.get(rev_key) == "ok"
                                ):
                                    success = True
                        except Exception:
                            pass

                elif task_type == "multisplit":
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
                        (
                            packet.dst_addr.startswith(prefix)
                            for prefix in ["157.240.", "69.171.", "31.13."]
                        )
                    )
                    is_twitter_ip = packet.dst_addr.startswith(
                        "104.244."
                    ) or packet.dst_addr.startswith("199.59.")
                    if is_meta_ip or is_twitter_ip:
                        for fake_ttl in [ttl - 1, ttl, ttl + 1]:
                            self._send_fake_packet_with_badsum(packet, w, ttl=fake_ttl)
                            with self._tlock:
                                self._telemetry["ttls"]["fake"][int(fake_ttl)] += 1
                                self._telemetry["aggregate"]["fake_packets_sent"] += 1
                            time.sleep(0.002)
                        segments = self.techniques.apply_multisplit(
                            payload, params.get("positions", [6, 14, 26, 42, 64])
                        )
                        success = self._send_segments(packet, w, segments)
                        time.sleep(0.002)
                        self._send_fake_packet_with_badsum(packet, w, ttl=ttl + 2)
                    else:
                        if params.get("fooling") == "badsum":
                            self._send_fake_packet_with_badsum(packet, w, ttl=ttl)
                            time.sleep(0.005)
                        segments = self.techniques.apply_multisplit(
                            payload, params.get("positions", [10, 25, 40, 55, 70])
                        )
                        success = self._send_segments(packet, w, segments)
                        if params.get("fooling") == "badsum":
                            time.sleep(0.003)
                            self._send_fake_packet_with_badsum(packet, w, ttl=ttl + 1)
                elif task_type == "multidisorder":
                    if params.get("pre_fake"):
                        ttl_pf = int(
                            params.get("fake_ttl", self.current_params.get("fake_ttl", 1))
                        )
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
                    segments = self.techniques.apply_multidisorder(
                        payload, params.get("positions", [10, 25, 40])
                    )
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
                        self._send_fake_packet_with_badsum(
                            packet, w, ttl=self.current_params.get("fake_ttl")
                        )
                        time.sleep(0.003)
                    segments = self.techniques.apply_seqovl(
                        payload,
                        params.get("split_pos", 3),
                        params.get("overlap_size", 20),
                    )
                    with self._tlock:
                        self._telemetry["overlaps"][
                            int(params.get("overlap_size", 20))
                        ] += 1
                        self._telemetry["ttls"]["fake"][
                            int(self.current_params.get("fake_ttl", 1))
                        ] += 1
                        self._telemetry["aggregate"]["fake_packets_sent"] += 1
                    success = self._send_segments(packet, w, segments)
                elif task_type in ("tlsrec_split", "wssize_limit"):
                    handler = self._exec_handlers.get(task_type)
                    if handler:
                        success = handler(self, packet, w, params, payload)
                    else:
                        if task_type == "tlsrec_split":
                            sp = int(params.get("split_pos", 5))
                            modified_payload = self.techniques.apply_tlsrec_split(
                                payload, sp
                            )
                            success = self._send_modified_packet(
                                packet, w, modified_payload
                            )
                        else:
                            segments = self.techniques.apply_wssize_limit(
                                payload, params.get("window_size", 2)
                            )
                            success = self._send_segments_with_window(
                                packet, w, segments
                            )
                elif task_type == "badsum_race":
                    self._send_fake_packet_with_badsum(
                        packet, w, ttl=self.current_params.get("fake_ttl")
                    )
                    time.sleep(0.005)
                    w.send(packet)
                    success = True
                elif task_type == "md5sig_race":
                    self._send_fake_packet_with_md5sig(
                        packet, w, ttl=self.current_params.get("fake_ttl")
                    )
                    time.sleep(0.007)
                    w.send(packet)
                    success = True
                elif task_type == "fake":
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
                    time.sleep(
                        params.get("delay_ms", 3) / 1000.0
                        if isinstance(params.get("delay_ms"), (int, float))
                        else 0.003
                    )
                    sp = params.get("split_pos")
                    if isinstance(sp, int) and sp > 0:
                        modified_payload = self.techniques.apply_tlsrec_split(
                            payload, sp
                        )
                        self._send_modified_packet(packet, w, modified_payload)
                    else:
                        w.send(packet)
                    success = True
                else:
                    self.logger.warning(
                        f"Неизвестный тип задачи '{task_type}', применяем простую фрагментацию."
                    )
                    self._send_fragmented_fallback(packet, w)
                    success = True

                if not success:
                    self.logger.error("Strategy failed, sending original packet.")
                    w.send(packet)

            except Exception as e:
                self.logger.error(
                    f"❌ Ошибка применения bypass: {e}", exc_info=self.debug
                )
                w.send(packet)
            finally:
                try:
                    self._inject_sema.release()
                except Exception:
                    pass

        def _send_segments(
            self, original_packet, w, segments: List[Tuple[bytes, int]]
        ):
            """Send TCP segments using new packet sender."""
            try:
                specs = []
                delay_ms = int(self.current_params.get("delay_ms", 2))

                for i, (payload, rel_off) in enumerate(segments):
                    if not payload:
                        continue

                    specs.append(
                        TCPSegmentSpec(
                            payload=payload,
                            rel_seq=rel_off,
                            flags=0x18,
                            delay_ms_after=delay_ms if i < len(segments) - 1 else 0,
                        )
                    )

                success = self._packet_sender.send_tcp_segments(
                    w,
                    original_packet,
                    specs,
                    window_div=int(self.current_params.get("window_div", 8)),
                    ipid_step=int(self.current_params.get("ipid_step", 2048)),
                )

                if success:
                    try:
                        with self._tlock:
                            self._telemetry["aggregate"]["segments_sent"] += len(specs)
                            tgt = original_packet.dst_addr
                            per = self._telemetry["per_target"][tgt]
                            per["segments_sent"] += len(specs)

                            for spec in specs:
                                self._telemetry["seq_offsets"][int(spec.rel_seq)] += 1
                                per["seq_offsets"][int(spec.rel_seq)] += 1

                            real_ttl = int(bytearray(original_packet.raw)[8])
                            self._telemetry["ttls"]["real"][real_ttl] += len(specs)
                            per["ttls_real"][real_ttl] += len(specs)
                    except Exception:
                        pass

                return success

            except Exception as e:
                self.logger.error(f"Error in _send_segments: {e}", exc_info=self.debug)
                return False

        def _send_attack_segments(self, original_packet, w, segments):
            """Send attack segments using new packet sender."""
            try:
                specs = []
                base_delay_ms = int(self.current_params.get("delay_ms", 2))

                for i, seg_tuple in enumerate(segments):
                    if len(seg_tuple) == 3:
                        payload, rel_off, opts = seg_tuple
                    elif len(seg_tuple) == 2:
                        payload, rel_off = seg_tuple
                        opts = {}
                    else:
                        continue

                    if not payload:
                        continue

                    flags = opts.get("tcp_flags")
                    if flags is None:
                        flags = 0x10
                        if i == len(segments) - 1:
                            flags |= 0x08

                    ttl = opts.get("ttl")
                    if ttl is None and opts.get("is_fake"):
                        ttl = int(self.current_params.get("fake_ttl", 2))

                    seq_extra = int(opts.get("seq_offset", 0))
                    if not seq_extra and opts.get("corrupt_sequence"):
                        seq_extra = -10000

                    specs.append(
                        TCPSegmentSpec(
                            payload=payload,
                            rel_seq=rel_off,
                            flags=flags,
                            ttl=ttl,
                            corrupt_tcp_checksum=bool(
                                opts.get("corrupt_tcp_checksum")
                            ),
                            add_md5sig_option=bool(opts.get("add_md5sig_option")),
                            seq_extra=seq_extra,
                            delay_ms_after=opts.get("delay_ms", base_delay_ms)
                            if i < len(segments) - 1
                            else 0,
                        )
                    )

                success = self._packet_sender.send_tcp_segments(
                    w,
                    original_packet,
                    specs,
                    window_div=int(self.current_params.get("window_div", 8)),
                    ipid_step=int(self.current_params.get("ipid_step", 2048)),
                )

                if success:
                    self.stats["fragments_sent"] += len(specs)
                    try:
                        with self._tlock:
                            self._telemetry["aggregate"]["segments_sent"] += len(specs)
                    except Exception:
                        pass

                return success

            except Exception as e:
                self.logger.error(
                    f"Error in _send_attack_segments: {e}", exc_info=self.debug
                )
                return False

        def _send_udp_segments(
            self, original_packet, w, segments: List[Tuple[bytes, int]]
        ) -> bool:
            """Send UDP segments using new packet sender."""
            success = self._packet_sender.send_udp_datagrams(
                w,
                original_packet,
                segments,
                ipid_step=int(self.current_params.get("ipid_step", 2048)),
            )

            if success:
                try:
                    with self._tlock:
                        self._telemetry["aggregate"]["quic_segments_sent"] += len(
                            segments
                        )
                except Exception:
                    pass

            return success

        def _send_fake_packet(self, original_packet, w, ttl: Optional[int] = 64):
            """Send fake packet using new packet sender."""
            return self._packet_sender.send_fake_packet(
                w,
                original_packet,
                fake_payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
                ttl=ttl or int(self.current_params.get("fake_ttl", 2)),
                fooling=[],
            )

        def _send_fake_packet_with_badsum(
            self, original_packet, w, ttl: Optional[int] = 64
        ):
            """Send fake packet with bad checksum using new packet sender."""
            return self._packet_sender.send_fake_packet(
                w,
                original_packet,
                ttl=ttl or int(self.current_params.get("fake_ttl", 2)),
                fooling=["badsum"],
            )

        def _send_fake_packet_with_md5sig(
            self, original_packet, w, ttl: Optional[int] = 64
        ):
            """Send fake packet with MD5 signature using new packet sender."""
            return self._packet_sender.send_fake_packet(
                w,
                original_packet,
                ttl=ttl or int(self.current_params.get("fake_ttl", 2)),
                fooling=["md5sig"],
            )

        def _send_fake_packet_with_badseq(
            self, original_packet, w, ttl: Optional[int] = 64
        ):
            """Send fake packet with bad sequence using new packet sender."""
            return self._packet_sender.send_fake_packet(
                w,
                original_packet,
                ttl=ttl or int(self.current_params.get("fake_ttl", 2)),
                fooling=["badseq"],
            )

        def _send_aligned_fake_segment(
            self,
            original_packet,
            w,
            seq_offset: int,
            data: bytes,
            ttl: int,
            fooling: List[str],
        ) -> bool:
            """Sends a fake segment aligned to the real SEQ."""
            spec = TCPSegmentSpec(
                payload=data,
                rel_seq=seq_offset,
                flags=0x18,  # PSH+ACK
                ttl=ttl,
                corrupt_tcp_checksum="badsum" in fooling,
                add_md5sig_option="md5sig" in fooling,
                seq_extra=-10000 if "badseq" in fooling else 0,
            )
            return self._packet_sender.send_tcp_segments(w, original_packet, [spec])

        def _send_modified_packet(self, original_packet, w, modified_payload):
            """Sends a single TCP segment with a modified payload."""
            spec = TCPSegmentSpec(payload=modified_payload, rel_seq=0)
            return self._packet_sender.send_tcp_segments(w, original_packet, [spec])

        def _send_segments_with_window(self, original_packet, w, segments):
            """Sends TCP segments with a small, fixed window size in the TCP header."""
            specs = [
                TCPSegmentSpec(payload=payload, rel_seq=rel_off)
                for payload, rel_off in segments
            ]
            return self._packet_sender.send_tcp_segments(
                w, original_packet, specs, window_size=2
            )

        def _send_fragmented_fallback(self, packet, w):
            """Fallback method for simple fragmentation."""
            payload = bytes(packet.payload)
            fragments = [(payload[0:1], 0), (payload[1:3], 1), (payload[3:], 3)]
            self._send_segments(packet, w, fragments)

        def get_telemetry_snapshot(self) -> Dict[str, Any]:
            try:
                with self._tlock:
                    snap = copy.deepcopy(self._telemetry)
                snap["duration_sec"] = time.time() - snap.get("start_ts", time.time())
                for k in ["fake", "real"]:
                    snap["ttls"][k] = dict(snap["ttls"][k])
                snap["seq_offsets"] = dict(snap["seq_offsets"])
                snap["overlaps"] = dict(snap["overlaps"])
                snap["per_target"] = {
                    t: {
                        **v,
                        "seq_offsets": dict(v["seq_offsets"]),
                        "ttls_fake": dict(v["ttls_fake"]),
                        "ttls_real": dict(v["ttls_real"]),
                        "overlaps": dict(v["overlaps"]),
                    }
                    for t, v in snap["per_target"].items()
                }
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
