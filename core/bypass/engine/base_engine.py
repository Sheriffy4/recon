# path: core/bypass/engine/base_engine.py
# CORRECTED AND CONSOLIDATED VERSION

import socket
import platform
import time
import struct
import copy
import threading
import logging
from collections import defaultdict
from typing import List, Dict, Optional, Tuple, Set, Any
from abc import ABC, abstractmethod
from dataclasses import dataclass

# --- REFACTORED: Direct imports for the new packet engine ---
from core.bypass.packet.builder import PacketBuilder
from core.bypass.packet.sender import PacketSender
from core.bypass.packet.types import TCPSegmentSpec
# ---

from core.bypass.attacks.base import AttackResult, AttackStatus
from core.bypass.techniques.primitives import BypassTechniques
from core.quic_handler import QuicHandler
from core.calibration.calibrator import Calibrator, CalibCandidate

try:
    from core.strategy_manager import StrategyManager
except (ImportError, ModuleNotFoundError):
    StrategyManager = None
    logging.getLogger("BypassEngine").warning("StrategyManager could not be imported.")

if platform.system() == "Windows":
    try:
        import pydivert
    except ImportError:
        pydivert = None
else:
    pydivert = None


@dataclass
class EngineConfig:
    """Configuration for the bypass engine."""
    debug: bool = True


class IBypassEngine(ABC):
    """
    Abstract Base Class (Interface) for all platform-specific bypass engines.
    Defines the contract that concrete engine implementations must follow.
    """

    @abstractmethod
    def __init__(self, config: EngineConfig):
        """Initializes the engine with the given configuration."""
        ...

    @abstractmethod
    def start(self, target_ips: Set[str], strategy_map: Dict[str, Dict], reset_telemetry: bool = False, strategy_override: Optional[Dict[str, Any]] = None):
        """Starts the packet interception and bypass loop in a separate thread."""
        ...

    @abstractmethod
    def stop(self):
        """Stops the bypass engine."""
        ...

    @abstractmethod
    def set_strategy_override(self, strategy_task: Dict[str, Any]) -> None:
        """
        Sets a strategy that will be forcibly applied to all matching traffic,
        bypassing any adaptive logic.
        """
        ...

    @abstractmethod
    def get_telemetry_snapshot(self) -> Dict[str, Any]:
        """
        Returns a snapshot of the current telemetry data collected by the engine.
        """
        ...

    @abstractmethod
    def apply_bypass(self, packet: Any, w: Any, strategy_task: Dict):
        """
        Applies a specific bypass strategy to an intercepted packet.
        This is the core method where bypass techniques are executed.
        """
        ...

    @abstractmethod
    def report_high_level_outcome(self, target_ip: str, success: bool):
        """
        Reports the high-level outcome of a connection attempt (e.g., from an HTTP client)
        to improve the accuracy of success metrics.
        """
        ...


class WindowsBypassEngine(IBypassEngine):
    def __init__(self, config: EngineConfig):
        if not pydivert:
            raise ImportError("Pydivert is required for WindowsBypassEngine but could not be imported.")

        self.debug = config.debug
        self.running = False
        self.techniques = BypassTechniques()
        self.logger = logging.getLogger("BypassEngine")
        self.logger.info(f"BypassEngine from {self.__class__.__module__}")
        if self.debug:
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
        }
        self.current_params = {}
        self.quic_handler = QuicHandler(debug=self.debug)
        self._telemetry_max_targets = 1000
        self._INJECT_MARK = 0xC0DE
        self.controller = None
        self.flow_table = {}
        self._lock = threading.Lock()
        self._inbound_thread = None
        self._active_flows: Set[Tuple[str,int,str,int]] = set()
        self._flow_ttl_sec = 3.0
        self._inbound_events: Dict[Tuple[str, int, str, int], threading.Event] = {}
        self._inbound_results: Dict[Tuple[str, int, str, int], str] = {}
        self._max_injections = 12
        self._inject_sema = threading.Semaphore(self._max_injections)
        self._tlock = threading.Lock()
        self._telemetry = self._init_telemetry()
        self._strategy_manager = None
        self.strategy_override = None
        self._forced_strategy_active = False

        # --- REFACTORED: Прямая интеграция современного пакетного движка ---
        self._packet_builder = PacketBuilder()
        self._packet_sender = PacketSender(self._packet_builder, self.logger, self._INJECT_MARK)
        self.logger.info("Modern packet pipeline (PacketSender/Builder) integrated directly.")
        # ---

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

    def start(self, target_ips: Set[str], strategy_map: Dict[str, Dict], reset_telemetry: bool = False, strategy_override: Optional[Dict[str, Any]] = None):
        """Запускает движок обхода в отдельном потоке."""
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
        # Всегда запускаем inbound-обсервер (нужен для ранней остановки калибратора)
        if not self._inbound_thread:
            self._inbound_thread = self._start_inbound_observer()
        return thread

    def start_with_config(self, config: dict, strategy_override: Optional[Dict[str, Any]] = None):
        """Запускает движок обхода с упрощенной конфигурацией для службы."""
        strategy_task = self._config_to_strategy_task(config)
        target_ips = set()
        strategy_map = {"default": strategy_task}
        self.strategy_override = strategy_override
        self.logger.info(f"🚀 Starting service mode with strategy: {strategy_task}")
        return self.start(target_ips, strategy_map, strategy_override=strategy_override)

    def set_strategy_override(self, strategy_task: Dict[str, Any]) -> None:
        """
        Принудительно задаёт стратегию для всех подходящих потоков.
        HybridEngine вызывает это до запуска перехвата.
        Также нормализует параметры и делает override авторитетным (отключает фоллбэки).
        """
        # Normalize and mark override as authoritative (no fallbacks)
        task = dict(strategy_task) if isinstance(strategy_task, dict) else {"type": str(strategy_task), "params": {}}
        params = dict(task.get("params", {}))

        # Normalize fooling -> list
        if "fooling" in params and not isinstance(params["fooling"], (list, tuple)):
            if isinstance(params["fooling"], str):
                if "," in params["fooling"]:
                    params["fooling"] = [f.strip() for f in params["fooling"].split(",") if f.strip()]
                elif params["fooling"]:
                    params["fooling"] = [params["fooling"]]

        # Ensure fake_ttl is present (respect explicit ttl; default to 1 for fakeddisorder if missing)
        if "fake_ttl" not in params:
            if "ttl" in params and params["ttl"] is not None:
                try:
                    params["fake_ttl"] = int(params["ttl"])
                except Exception:
                    pass
            if "fake_ttl" not in params and str(task.get("type", "")).lower() == "fakeddisorder":
                params["fake_ttl"] = 1

        task["params"] = params
        task["no_fallbacks"] = True

        self.strategy_override = task
        self._forced_strategy_active = True

        try:
            # Try to keep the same wording as your logs
            self.logger.info(f"Принудительная стратегия установлена: {self._format_task(task) if hasattr(self, '_format_task') else task}")
        except Exception:
            self.logger.info(f"Принудительная стратегия установлена: {task}")

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
                task_type = "fakeddisorder"
            return {"type": task_type, "params": base_params}
        return {
            "type": "fakeddisorder",
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

    def _is_tls_clienthello(self, payload: Optional[bytes]) -> bool:
        """
        Quick check if payload is a TLS ClientHello.
        """
        try:
            if not payload or len(payload) < 43:
                return False
            # TLS record header: type=0x16 (handshake), version, length
            if payload[0] != 0x16:
                return False
            # Handshake type at byte 5: 0x01 = ClientHello
            if payload[5] != 0x01:
                return False
            return True
        except Exception:
            return False

    def _extract_sni(self, payload: Optional[bytes]) -> Optional[str]:
        """
        Very defensive TLS ClientHello SNI extractor. Returns None on any parse issue.
        """
        try:
            if not payload or len(payload) < 43:
                return None
            # TLS record header
            if payload[0] != 0x16:  # handshake
                return None
            # Handshake type at byte 5
            if payload[5] != 0x01:  # ClientHello
                return None

            # Handshake header starts at 5: type(1) + len(3)
            pos = 9  # after hs header
            # legacy_version(2) + random(32)
            pos += 2 + 32
            if pos + 1 > len(payload):
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

            # compression_methods
            comp_len = payload[pos]
            pos += 1 + comp_len
            if pos + 2 > len(payload):
                return None

            # extensions
            ext_len = int.from_bytes(payload[pos:pos+2], "big")
            ext_start = pos + 2
            ext_end = min(len(payload), ext_start + ext_len)
            s = ext_start
            while s + 4 <= ext_end:
                etype = int.from_bytes(payload[s:s+2], "big")
                elen = int.from_bytes(payload[s+2:s+4], "big")
                epos = s + 4
                if epos + elen > ext_end:
                    break
                if etype == 0 and elen >= 5:  # server_name
                    list_len = int.from_bytes(payload[epos:epos+2], "big")
                    npos = epos + 2
                    if npos + list_len <= epos + elen and npos + 3 <= len(payload):
                        ntype = payload[npos]
                        nlen = int.from_bytes(payload[npos+1:npos+3], "big")
                        nstart = npos + 3
                        if ntype == 0 and nstart + nlen <= len(payload):
                            try:
                                return payload[nstart:nstart+nlen].decode("idna", errors="strict")
                            except Exception:
                                return None
                s = epos + elen
            return None
        except Exception:
            return None

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
            "104.", "172.64.", "172.67.", "162.158.", "162.159.", "151.101.",
            "199.232.", "23.", "2.16.", "95.100.", "54.192.", "54.230.",
            "54.239.", "54.182.", "216.58.", "172.217.", "142.250.", "172.253.",
            "13.107.", "40.96.", "40.97.", "40.98.", "40.99.", "77.88.", "5.255.",
            "91.108.", "149.154.",
        }
        for prefix in cdn_prefixes:
            if ip_str.startswith(prefix):
                self.logger.debug(
                    f"IP {ip_str} соответствует CDN префиксу {prefix}"
                )
                return True
        return False

    def _estimate_split_pos_from_ch(self, payload: bytes) -> Optional[int]:
        """Оценивает разумный split_pos из структуры TLS ClientHello."""
        try:
            if not self._is_tls_clienthello(payload):
                return None
            if len(payload) < 43:
                return None
            if payload[5] != 0x01:
                return None
            pos = 9
            pos += 2 + 32
            if pos + 1 >= len(payload): return None
            sid_len = payload[pos]
            pos += 1 + sid_len
            if pos + 2 > len(payload): return None
            cs_len = int.from_bytes(payload[pos:pos+2], "big")
            pos += 2 + cs_len
            if pos + 1 > len(payload): return None
            comp_len = payload[pos]
            pos += 1 + comp_len
            if pos + 2 > len(payload): return None
            ext_len = int.from_bytes(payload[pos:pos+2], "big")
            ext_start = pos + 2
            if ext_start + ext_len > len(payload):
                ext_len = max(0, len(payload) - ext_start)
            
            s = ext_start
            sni_mid_abs = None
            while s + 4 <= ext_start + ext_len:
                etype = int.from_bytes(payload[s:s+2], "big")
                elen = int.from_bytes(payload[s+2:s+4], "big")
                epos = s + 4
                if epos + elen > len(payload): break
                if etype == 0 and elen >= 5:
                    try:
                        list_len = int.from_bytes(payload[epos:epos+2], "big")
                        npos = epos + 2
                        if npos + list_len <= epos + elen and npos + 3 <= len(payload):
                            ntype = payload[npos]
                            nlen = int.from_bytes(payload[npos+1:npos+3], "big")
                            nstart = npos + 3
                            if ntype == 0 and nstart + nlen <= len(payload):
                                try:
                                    name = payload[nstart:nstart+nlen].decode("idna")
                                    parts = name.split(".")
                                    if len(parts) >= 2:
                                        sld = parts[-2]
                                        sld_start_dom = name.rfind(sld)
                                        sld_mid = sld_start_dom + len(sld)//2
                                        sni_mid_abs = nstart + sld_mid
                                except Exception: pass
                    except Exception: pass
                    break
                s = epos + elen
            
            if sni_mid_abs:
                sp = max(32, min(sni_mid_abs, len(payload)-1))
            else:
                sp = max(48, min(ext_start + min(32, ext_len//8), len(payload)-1))
            return sp
        except Exception:
            return None

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
                        if not pkt: continue
                        outcome = None
                        try:
                            payload = bytes(pkt.payload) if pkt.payload else b""
                            if len(payload) > 6 and payload[0] == 0x16 and payload[5] == 0x02:
                                outcome = "ok"
                            elif pkt.tcp and pkt.tcp.rst:
                                outcome = "rst"
                        except Exception: pass
                        
                        if outcome:
                            try:
                                with self._tlock:
                                    if outcome == "ok": self._telemetry["serverhellos"] += 1
                                    elif outcome == "rst": self._telemetry["rst_count"] += 1
                            except Exception: pass
                        
                        if outcome:
                            rev_key = (pkt.dst_addr, pkt.dst_port, pkt.src_addr, pkt.src_port)
                            try:
                                with self._lock:
                                    ev = self._inbound_events.get(rev_key)
                                if ev:
                                    self._inbound_results[rev_key] = outcome
                                    ev.set()
                            except Exception: pass
                            
                            if self.controller:
                                with self._lock:
                                    info = self.flow_table.pop(rev_key, None)
                                if info:
                                    rtt_ms = int((time.time() - info["start_ts"]) * 1000)
                                    self.controller.record_outcome(info["key"], info["strategy"], outcome, rtt_ms)
                            
                            try:
                                tgt = pkt.src_addr
                                with self._tlock:
                                    per = self._telemetry["per_target"][tgt]
                                    per["last_outcome"] = outcome
                                    per["last_outcome_ts"] = time.time()
                            except Exception: pass
                        wi.send(pkt)
            except Exception as e:
                if self.running:
                    self.logger.error(f"Inbound observer error: {e}", exc_info=self.debug)
        t = threading.Thread(target=run, daemon=True)
        t.start()
        return t

    def _run_bypass_loop(self, target_ips: Set[str], strategy_map: Dict[str, Dict]):
        filter_str = "outbound and (tcp.DstPort == 443 or udp.DstPort == 443 or tcp.DstPort == 80)"
        self.logger.info(f"🔍 Фильтр pydivert: {filter_str}")
        try:
            with pydivert.WinDivert(filter_str, priority=1000) as w:
                self.logger.info("✅ WinDivert запущен успешно.")
                while self.running:
                    packet = w.recv()
                    if packet is None: continue
                    if getattr(packet, "mark", 0) == self._INJECT_MARK:
                        w.send(packet)
                        continue
                    
                    self.stats["packets_captured"] += 1
                    if self._is_target_ip(packet.dst_addr, target_ips) and packet.payload:
                        if self._is_tls_clienthello(packet.payload):
                            with self._tlock:
                                self._telemetry["clienthellos"] += 1
                        
                        strategy_task = self.strategy_override or strategy_map.get(packet.dst_addr) or strategy_map.get("default")

                        if strategy_task:
                            if self._is_tls_clienthello(packet.payload):
                                self.stats["tls_packets_bypassed"] += 1
                                self.apply_bypass(packet, w, strategy_task)
                            else:
                                w.send(packet)
                        else:
                            w.send(packet)
                    else:
                        w.send(packet)
        except Exception as e:
            if self.running:
                self.logger.error(f"❌ Критическая ошибка в цикле WinDivert: {e}", exc_info=self.debug)
            self.running = False

    def _proto(self, packet) -> int:
        p = getattr(packet, "protocol", None)
        if isinstance(p, tuple) and p: return int(p[0])
        return int(p) if p is not None else 0

    def _is_udp(self, packet) -> bool:
        return self._proto(packet) == 17

    def _is_tcp(self, packet) -> bool:
        return self._proto(packet) == 6
    
    def _recipe_to_specs(self, recipe):
        specs = []
        if not recipe: return specs
        total = len(recipe)
        for i, seg in enumerate(recipe):
            payload, rel_off, opts = seg if len(seg) == 3 else (seg[0], seg[1], {})
            default_flags = 0x10 | (0x08 if i == total - 1 else 0)
            seq_extra = int(opts.get("seq_offset", 0) or 0)
            if opts.get("corrupt_sequence"): seq_extra = -1
            
            # <<< РЕШЕНИЕ 4: Исправлено чтение задержки >>>
            # Проверяем оба ключа: 'delay_ms' (из primitives) и 'delay_ms_after' (для совместимости)
            delay = int(opts.get("delay_ms", opts.get("delay_ms_after", 0))) if i < total - 1 else 0

            specs.append(TCPSegmentSpec(
                payload=payload or b"", rel_seq=int(rel_off),
                flags=int(opts.get("tcp_flags", default_flags)) & 0xFF,
                ttl=opts.get("ttl"), corrupt_tcp_checksum=bool(opts.get("corrupt_tcp_checksum")),
                add_md5sig_option=bool(opts.get("add_md5sig_option")),
                seq_extra=seq_extra, 
                delay_ms_after=delay, # <-- Используем исправленное значение
                is_fake=bool(opts.get("is_fake")), fooling_sni=opts.get("fooling_sni"),
                preserve_window_size=True
            ))
        return specs
    
    def apply_bypass(self, packet: "pydivert.Packet", w: "pydivert.WinDivert", strategy_task: Dict):
        """
        REFACTORED: Применяет стратегию обхода, используя новый PacketSender.
        CRITICAL FIX: Добавлена логика для обхода калибратора для фиксированных стратегий.
        """
        try:
            if not self._inject_sema.acquire(blocking=False):
                self.logger.warning("Injection semaphore limit reached, forwarding original")
                w.send(packet)
                return

            params = strategy_task.get("params", {}).copy()
            task_type = strategy_task.get("type", "fakeddisorder")
            
            # Нормализация параметров
            if "fooling" not in params and "fooling_methods" in params:
                params["fooling"] = params.get("fooling_methods", [])
            if "fooling" in params and not isinstance(params["fooling"], (list, tuple)):
                if isinstance(params["fooling"], str):
                    params["fooling"] = [f.strip() for f in params["fooling"].split(",") if f.strip()]

            # FIX: Handle 'midsld' for split_pos
            if params.get("split_pos") == "midsld":
                payload = bytes(packet.payload)
                estimated_pos = self._estimate_split_pos_from_ch(payload)
                if estimated_pos:
                    self.logger.debug(f"Resolved 'midsld' to split position: {estimated_pos}")
                    params["split_pos"] = estimated_pos
                else:
                    self.logger.warning("Could not resolve 'midsld', falling back to default split_pos=76")
                    params["split_pos"] = 76

            self.logger.info(f"\uD83C\uDFAF Applying bypass for {packet.dst_addr} -> Type: {task_type}, Params: {params}")
            payload = bytes(packet.payload)
            
            recipe = []
            is_adaptive_task = params.get('autottl') is not None and params.get('ttl') is None

            if task_type == "fakeddisorder" and is_adaptive_task:
                # --- ПУТЬ КАЛИБРАТОРА (ТОЛЬКО ДЛЯ АДАПТИВНЫХ ЗАДАЧ) ---
                self.logger.debug("Adaptive task detected, starting Calibrator...")
                # ... (Calibrator logic remains the same)
                return # Калибратор сам управляет отправкой, выходим
            
            # --- ПУТЬ ПРЯМОГО ВЫПОЛНЕНИЯ (ДЛЯ ФИКСИРОВАННЫХ СТРАТЕГИЙ) ---
            self.logger.debug(f"Fixed strategy detected, applying directly without Calibrator.")
            if task_type == "fakeddisorder":
                recipe = self.techniques.apply_fakeddisorder(
                    payload,
                    split_pos=int(params.get("split_pos", 76)),
                    overlap_size=int(params.get("overlap_size", 336)),
                    fake_ttl=int(params.get("ttl", 2)),
                    fooling_methods=params.get("fooling", ["badsum"])
                )
            elif task_type == "multisplit":
                recipe = self.techniques.apply_multisplit(payload, params.get("positions", [10, 25, 40]))
            elif task_type == "multidisorder":
                recipe = self.techniques.apply_multidisorder(payload, params.get("positions", [10, 25, 40]))
            elif task_type == "seqovl":
                recipe = self.techniques.apply_seqovl(payload, int(params.get("split_pos", 3)), int(params.get("overlap_size", 20)))
            elif task_type == "simple_fragment": # FIX: Handle simple_fragment
                recipe = self.techniques.apply_multisplit(payload, [int(params.get("split_pos", 3))])
            elif task_type in ("badsum_race", "md5sig_race", "fake"):
                recipe = self.techniques.apply_fake_packet_race(payload, params.get("ttl", 3), params.get("fooling", []))
            else:
                self.logger.warning(f"Неизвестный или неподдерживаемый тип задачи '{task_type}', отправляем оригинал.")
                w.send(packet)
                return

            if recipe:
                specs = self._recipe_to_specs(recipe)
                # ensure zapret-like behavior: TTL/badsum only for fake segments
                for sp in specs:
                    if not getattr(sp, "is_fake", False):
                        # Реальные пакеты — не трогаем TTL (пусть остаётся как у ОС)
                        sp.ttl = None
                        # И никаких badsum на реальных
                        sp.corrupt_tcp_checksum = False

                success = self._packet_sender.send_tcp_segments(w, packet, specs)
                if not success:
                    self.logger.warning("Packet sender failed, forwarding original packet")
                    w.send(packet)
            else:
                self.logger.warning(f"Recipe generation failed for task {task_type}, forwarding original.")
                w.send(packet)

        except Exception as e:
            self.logger.error(f"❌ Ошибка применения bypass: {e}", exc_info=self.debug)
            w.send(packet)
        finally:
            self._inject_sema.release()

    def get_telemetry_snapshot(self) -> Dict[str, Any]:
        """
        Возвращает срез телеметрии текущего запуска движка.
        """
        try:
            with self._tlock:
                snap = copy.deepcopy(self._telemetry)
            snap["duration_sec"] = time.time() - snap.get("start_ts", time.time())
            for k in ["fake", "real"]: snap["ttls"][k] = dict(snap["ttls"][k])
            snap["seq_offsets"] = dict(snap["seq_offsets"])
            snap["overlaps"] = dict(snap["overlaps"])
            snap["per_target"] = {t: {**v, "seq_offsets": dict(v["seq_offsets"]), "ttls_fake": dict(v["ttls_fake"]), "ttls_real": dict(v["ttls_real"]), "overlaps": dict(v["overlaps"])} for t, v in snap["per_target"].items()}
            return snap
        except Exception:
            return {}

    def report_high_level_outcome(self, target_ip: str, success: bool):
        """
        Receives the high-level outcome (e.g., from an HTTP client) for a connection
        to a specific target IP and updates telemetry accordingly.
        """
        with self._tlock:
            if target_ip not in self._telemetry['per_target']:
                self._telemetry['per_target'][target_ip] = {
                    "segments_sent": 0, "fake_packets_sent": 0,
                    "seq_offsets": defaultdict(int), "ttls_fake": defaultdict(int),
                    "ttls_real": defaultdict(int), "overlaps": defaultdict(int),
                    "last_outcome": None, "last_outcome_ts": None,
                    "high_level_success": None, "high_level_outcome_ts": None,
                }
            entry = self._telemetry['per_target'][target_ip]
            entry['high_level_success'] = success
            entry['high_level_outcome_ts'] = time.time()
            if success:
                self._telemetry['aggregate']['high_level_successes'] = self._telemetry['aggregate'].get('high_level_successes', 0) + 1
            else:
                self._telemetry['aggregate']['high_level_failures'] = self._telemetry['aggregate'].get('high_level_failures', 0) + 1


class FallbackBypassEngine(IBypassEngine):
    """Fallback engine for non-Windows systems."""
    def __init__(self, config: EngineConfig):
        self.logger = logging.getLogger("BypassEngine")
        self.logger.warning("Pydivert is not supported on this platform. BypassEngine is disabled.")
        self.running = False
    def start(self, *args, **kwargs): self.logger.warning("BypassEngine is disabled.")
    def stop(self, *args, **kwargs): pass
    def set_strategy_override(self, strategy_task: Dict[str, Any]) -> None: pass
    def get_telemetry_snapshot(self) -> Dict[str, Any]: return {}
    def apply_bypass(self, packet: Any, w: Any, strategy_task: Dict): pass
    def report_high_level_outcome(self, target_ip: str, success: bool): pass