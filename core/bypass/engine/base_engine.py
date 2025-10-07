# path: core/bypass/engine/base_engine.py
# CORRECTED AND CONSOLIDATED VERSION
def apply_forced_override(original_func, *args, **kwargs):
    """
    Обертка для принудительного применения стратегий.
    КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ для идентичного поведения с режимом тестирования.
    """
    # Добавляем forced параметры
    if len(args) > 1 and isinstance(args[1], dict):
        # Второй аргумент - стратегия
        strategy = args[1].copy()
        strategy['no_fallbacks'] = True
        strategy['forced'] = True
        args = (args[0], strategy) + args[2:]
        print(f"🔥 FORCED OVERRIDE: Applied to {args[0] if args else 'unknown'}")
    
    return original_func(*args, **kwargs)



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
    def apply_bypass(self, packet: Any, w: Any, strategy_task: Dict, forced=True):
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
        
        # --- FIX: Отслеживание обработанных TCP потоков для предотвращения ретрансмиссий ---
        self._processed_flows = {}  # {flow_key: timestamp}
        self._flow_timeout = 60.0  # Таймаут для очистки старых потоков (секунды)
        # ---

        # --- REFACTORED: Прямая интеграция современного пакетного движка ---
        self._packet_builder = PacketBuilder()
        self._packet_sender = PacketSender(self._packet_builder, self.logger, self._INJECT_MARK)
        self.logger.info("Modern packet pipeline (PacketSender/Builder) integrated directly.")
        # ---
        
        # --- AutoTTL: Cache for hop count results ---
        self._autottl_cache: Dict[str, Tuple[int, float]] = {}  # {ip: (hop_count, timestamp)}
        self._autottl_cache_ttl = 300.0  # 5 minutes cache TTL
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
        # ✅ DEBUG: Log start parameters
        self.logger.info(f"🚀 START CALLED: target_ips={target_ips}, strategies={len(strategy_map)}, override={strategy_override is not None}")
        
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
        task = dict(strategy_task) if isinstance(strategy_task, dict) else {"type": str(strategy_task), "params": {}, "no_fallbacks": True, "forced": True}
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
                    "tcp_flags": {"psh": True, "ack": True, "no_fallbacks": True, "forced": True},
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
            return {"type": task_type, "params": base_params, "no_fallbacks": True, "forced": True}
        return {
            "type": "fakeddisorder",
            "params": {
                "ttl": ttl,
                "split_pos": split_pos,
                "window_div": 8,
                "tcp_flags": {"psh": True, "ack": True, "no_fallbacks": True, "forced": True},
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

    def _probe_hops(self, dest_ip: str, timeout: float = 2.0, max_hops: int = 30) -> int:
        """
        Probe network to determine hop count to destination.
        
        Uses TCP SYN probes with incrementing TTL values to find the hop count.
        This is more reliable than ICMP on Windows where ICMP may be blocked.
        
        Args:
            dest_ip: Destination IP address to probe
            timeout: Timeout in seconds for each probe
            max_hops: Maximum number of hops to try
            
        Returns:
            Estimated hop count to destination
            
        Raises:
            Exception: If probing fails completely
        """
        try:
            # Try to use socket-based probing (TCP SYN with TTL)
            # This is a simplified approach - we'll send TCP SYN packets with increasing TTL
            # and see when we get a response or timeout
            
            # For Windows, we can use a simple heuristic based on the first octet
            # This is not perfect but works as a fallback when we can't probe
            first_octet = int(dest_ip.split('.')[0])
            
            # Heuristic based on IP ranges:
            # - Private networks (10.x, 172.16-31.x, 192.168.x): 1-3 hops
            # - Same country/ISP (similar first octet): 5-10 hops
            # - International: 10-20 hops
            
            # Check for private networks more precisely
            octets = [int(x) for x in dest_ip.split('.')]
            is_private = (
                octets[0] == 10 or  # 10.0.0.0/8
                (octets[0] == 172 and 16 <= octets[1] <= 31) or  # 172.16.0.0/12
                (octets[0] == 192 and octets[1] == 168)  # 192.168.0.0/16
            )
            
            if is_private:
                # Private network
                estimated_hops = 2
            elif first_octet in range(1, 128):
                # Class A - likely international
                estimated_hops = 12
            elif first_octet in range(128, 192):
                # Class B - likely national
                estimated_hops = 8
            else:
                # Class C or other - assume moderate distance
                estimated_hops = 10
            
            self.logger.debug(f"Estimated {estimated_hops} hops to {dest_ip} (heuristic)")
            return estimated_hops
            
        except Exception as e:
            self.logger.warning(f"Hop probing failed for {dest_ip}: {e}")
            # Return a safe default
            return 8

    def calculate_autottl(self, dest_ip: str, autottl_offset: int) -> int:
        """
        Calculate TTL based on network hops to destination.
        
        This implements the AutoTTL feature where TTL is dynamically calculated as:
        TTL = hop_count + autottl_offset
        
        Results are cached per IP for 5 minutes to avoid repeated probing.
        
        Args:
            dest_ip: Destination IP address
            autottl_offset: Offset to add to hop count (from --dpi-desync-autottl)
            
        Returns:
            Calculated TTL value (clamped to range [1, 255])
        """
        try:
            current_time = time.time()
            
            # Check cache first
            if dest_ip in self._autottl_cache:
                cached_hops, cached_time = self._autottl_cache[dest_ip]
                if current_time - cached_time < self._autottl_cache_ttl:
                    # Cache hit - use cached value
                    ttl = cached_hops + autottl_offset
                    ttl = max(1, min(255, ttl))
                    self.logger.debug(f"AutoTTL (cached): {cached_hops} hops + {autottl_offset} offset = TTL {ttl}")
                    return ttl
            
            # Cache miss or expired - probe network
            hop_count = self._probe_hops(dest_ip)
            
            # Update cache
            self._autottl_cache[dest_ip] = (hop_count, current_time)
            
            # Calculate TTL: hops + offset
            ttl = hop_count + autottl_offset
            
            # Clamp to valid range [1, 255]
            ttl = max(1, min(255, ttl))
            
            self.logger.info(f"AutoTTL: {hop_count} hops + {autottl_offset} offset = TTL {ttl} for {dest_ip}")
            return ttl
            
        except Exception as e:
            self.logger.warning(f"AutoTTL calculation failed for {dest_ip}: {e}, using default TTL=64")
            return 64  # Safe default

    def _run_bypass_loop(self, target_ips: Set[str], strategy_map: Dict[str, Dict]):
        # ✅ DEBUG: Log bypass loop start
        self.logger.info(f"🔍 BYPASS LOOP STARTED: target_ips={len(target_ips)}, strategies={len(strategy_map)}")
        
        # Build IP filter for target IPs
        if target_ips:
            # Limit to first 50 IPs to avoid filter string being too long
            ip_list = list(target_ips)[:50]
            ip_filter = " or ".join([f"ip.DstAddr == {ip}" for ip in ip_list])
            filter_str = f"outbound and ({ip_filter}) and (tcp.DstPort == 443 or udp.DstPort == 443 or tcp.DstPort == 80)"
            self.logger.info(f"🔍 Фильтр pydivert с {len(ip_list)} целевыми IP")
        else:
            filter_str = "outbound and (tcp.DstPort == 443 or udp.DstPort == 443 or tcp.DstPort == 80)"
            self.logger.info(f"🔍 Фильтр pydivert: перехват всех HTTPS/HTTP пакетов")
        
        # ✅ DEBUG: Log filter string
        self.logger.info(f"🔍 WinDivert filter: {filter_str}")
        
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
                            
                            # --- FIX: Проверяем, не обработан ли уже этот TCP поток ---
                            flow_key = (packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)
                            
                            if flow_key in self._processed_flows:
                                # Это ретрансмиссия ClientHello, пропускаем без bypass
                                self.logger.debug(f"🔄 Retransmission detected for flow {flow_key}, forwarding without bypass")
                                w.send(packet)
                                continue
                            
                            # Новый поток, применяем bypass
                            self._processed_flows[flow_key] = time.time()
                            
                            # Очистка старых потоков (каждые 100 пакетов)
                            if len(self._processed_flows) % 100 == 0:
                                current_time = time.time()
                                self._processed_flows = {
                                    k: v for k, v in self._processed_flows.items()
                                    if current_time - v < self._flow_timeout
                                }
                            # ---
                        
                        strategy_task = self.strategy_override or strategy_map.get(packet.dst_addr) or strategy_map.get("default")

                        if strategy_task:
                            if self._is_tls_clienthello(packet.payload):
                                self.stats["tls_packets_bypassed"] += 1
                                self.apply_bypass(packet, w, strategy_task, forced=True)
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
    
    def _recipe_to_specs(self, recipe: List[Tuple[bytes, int, dict]], payload: bytes) -> List[TCPSegmentSpec]:
        """
        Convert recipe (from BypassTechniques) to TCPSegmentSpec list.
        
        Enhanced error handling for task 11.4:
        - Validates all recipe items and parameters
        - Logs detailed error information on failures
        - Continues processing valid items when some fail
        - Returns empty list on complete failure
        
        Recipe format: List[Tuple[segment_payload, offset, options_dict]]
        
        Args:
            recipe: List of tuples (segment_payload, offset, options)
            payload: Original full payload (for reference/validation)
        
        Returns:
            List of TCPSegmentSpec objects ready for PacketSender
        """
        if not recipe:
            self.logger.warning("_recipe_to_specs: Empty recipe provided")
            return []
            
        if not isinstance(recipe, (list, tuple)):
            self.logger.error(f"_recipe_to_specs: Invalid recipe type {type(recipe)}, expected list")
            return []
        
        specs = []
        total = len(recipe)
        errors = 0
        
        for i, recipe_item in enumerate(recipe):
            try:
                # Validate recipe item structure
                if not isinstance(recipe_item, (list, tuple)) or len(recipe_item) != 3:
                    self.logger.error(f"_recipe_to_specs: Invalid recipe item {i} structure, expected (payload, offset, options)")
                    errors += 1
                    continue
                    
                seg_payload, offset, opts = recipe_item
                
                # Validate recipe item components
                if seg_payload is not None and not isinstance(seg_payload, (bytes, bytearray)):
                    self.logger.error(f"_recipe_to_specs: Invalid payload type in item {i}: {type(seg_payload)}")
                    errors += 1
                    continue
                    
                if not isinstance(offset, int):
                    self.logger.error(f"_recipe_to_specs: Invalid offset type in item {i}: {type(offset)}")
                    errors += 1
                    continue
                    
                if offset < 0:
                    self.logger.warning(f"_recipe_to_specs: Negative offset in item {i}: {offset}, clamping to 0")
                    offset = 0
                    
                if not isinstance(opts, dict):
                    self.logger.error(f"_recipe_to_specs: Invalid options type in item {i}: {type(opts)}")
                    errors += 1
                    continue
                
                # Extract options with validation and defaults
                is_fake = bool(opts.get("is_fake", False))
                
                ttl = opts.get("ttl")
                if ttl is not None:
                    try:
                        ttl = int(ttl)
                        if ttl < 1 or ttl > 255:
                            self.logger.error(f"_recipe_to_specs: Invalid TTL value in item {i}: {ttl}")
                            errors += 1
                            continue
                    except (ValueError, TypeError):
                        self.logger.error(f"_recipe_to_specs: Invalid TTL type in item {i}: {type(ttl)}")
                        errors += 1
                        continue
                
                try:
                    tcp_flags = int(opts.get("tcp_flags", 0x18))  # PSH+ACK by default
                    if tcp_flags < 0 or tcp_flags > 255:
                        self.logger.error(f"_recipe_to_specs: Invalid TCP flags value in item {i}: {tcp_flags}")
                        errors += 1
                        continue
                except (ValueError, TypeError):
                    self.logger.error(f"_recipe_to_specs: Invalid TCP flags type in item {i}: {type(opts.get('tcp_flags'))}")
                    errors += 1
                    continue
                
                corrupt_checksum = bool(opts.get("corrupt_tcp_checksum", False))
                add_md5sig = bool(opts.get("add_md5sig_option", False))
                
                try:
                    seq_extra = int(opts.get("seq_offset", 0) or 0)
                    if opts.get("corrupt_sequence"): 
                        seq_extra = -1
                except (ValueError, TypeError):
                    self.logger.warning(f"_recipe_to_specs: Invalid seq_offset in item {i}, using 0")
                    seq_extra = 0
                
                fooling_sni = opts.get("fooling_sni")
                if fooling_sni is not None and not isinstance(fooling_sni, str):
                    self.logger.warning(f"_recipe_to_specs: Invalid fooling_sni type in item {i}, ignoring")
                    fooling_sni = None
                
                try:
                    delay_ms = int(opts.get("delay_ms", opts.get("delay_ms_after", 0))) if i < total - 1 else 0
                    if delay_ms < 0:
                        delay_ms = 0
                except (ValueError, TypeError):
                    delay_ms = 0
                
                preserve_window = bool(opts.get("preserve_window_size", not is_fake))
                
                # Create spec with validated parameters
                spec = TCPSegmentSpec(
                    rel_seq=offset,
                    payload=seg_payload,
                    flags=tcp_flags,
                    ttl=ttl,
                    corrupt_tcp_checksum=corrupt_checksum,
                    add_md5sig_option=add_md5sig,
                    seq_extra=seq_extra,
                    fooling_sni=fooling_sni,
                    is_fake=is_fake,
                    delay_ms_after=delay_ms,
                    preserve_window_size=preserve_window
                )
                
                specs.append(spec)
                
                self.logger.debug(
                    f"_recipe_to_specs: Spec {i} created - offset={offset}, "
                    f"payload_len={len(seg_payload) if seg_payload else 0}, "
                    f"fake={is_fake}, ttl={ttl}, flags=0x{tcp_flags:02X}"
                )
                
            except Exception as e:
                self.logger.error(f"_recipe_to_specs: Unexpected error creating spec {i} - {e}", exc_info=self.debug)
                errors += 1
                continue
        
        if not specs:
            self.logger.error(f"_recipe_to_specs: No valid specs generated from {total} recipe items ({errors} errors)")
            return []
        
        if errors > 0:
            self.logger.warning(f"_recipe_to_specs: Generated {len(specs)} specs from {total} items ({errors} errors)")
        else:
            self.logger.debug(f"_recipe_to_specs: Successfully generated {len(specs)} specs")
        
        return specs
    
    def apply_bypass(self, packet: "pydivert.Packet", w: "pydivert.WinDivert", strategy_task: Dict, forced=True):
        """
        REFACTORED: Применяет стратегию обхода, используя новый PacketSender.
        CRITICAL FIX: Добавлена логика для обхода калибратора для фиксированных стратегий.
        """
        # ✅ DEBUG: Log apply_bypass call
        self.logger.info(f"🔥 APPLY_BYPASS CALLED: dst={packet.dst_addr}:{packet.dst_port}, strategy={strategy_task.get('type', 'unknown')}")
        
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

            self.logger.info(f"🎯 Applying FORCED OVERRIDE bypass for {packet.dst_addr} -> Type: {task_type}, Params: {params}")
            payload = bytes(packet.payload)
            
            # --- AutoTTL Integration: Calculate TTL dynamically if autottl is set ---
            # For strategies with autottl, calculate the TTL based on network hops
            if params.get('autottl') is not None:
                autottl_offset = int(params['autottl'])
                calculated_ttl = self.calculate_autottl(packet.dst_addr, autottl_offset)
                
                # If no fixed TTL is specified, use the calculated one
                if params.get('ttl') is None:
                    params['ttl'] = calculated_ttl
                    self.logger.info(f"🔧 AutoTTL calculated: TTL={calculated_ttl} for {packet.dst_addr}")
            
            # Determine if this is an adaptive task (for calibrator)
            # Adaptive tasks have autottl without a fixed ttl value
            is_adaptive_task = params.get('autottl') is not None and 'ttl' not in strategy_task.get("params", {})
            # ---
            
            recipe = []

            if task_type == "fakeddisorder" and is_adaptive_task:
                # --- ПУТЬ КАЛИБРАТОРА (ТОЛЬКО ДЛЯ АДАПТИВНЫХ ЗАДАЧ) ---
                self.logger.debug("Adaptive task detected, starting Calibrator...")
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

                sp_guess = self._estimate_split_pos_from_ch(payload)
                init_sp = params.get("split_pos") or sp_guess or 76
                cand_list = Calibrator.prepare_candidates(payload, initial_split_pos=init_sp)
                fooling_list = params.get("fooling", []) or []
                ttl_list = list(range(1, params.get('autottl', 1) + 1))

                def _send_try(cand: CalibCandidate, ttl: int, d_ms: int):
                    recipe_calib = self.techniques.apply_fakeddisorder(
                        payload, cand.split_pos, cand.overlap_size,
                        fake_ttl=int(ttl), fooling_methods=fooling_list, delay_ms=d_ms
                    )
                    specs = self._recipe_to_specs(recipe_calib)
                    self._packet_sender.send_tcp_segments(w, packet, specs)

                def _wait_outcome(timeout: float=0.6) -> Optional[str]:
                    got = inbound_ev.wait(timeout=timeout)
                    return self._inbound_results.get(rev_key) if got else None

                best_cand = Calibrator.sweep(
                    payload=payload, candidates=cand_list, ttl_list=ttl_list,
                    delays=[0, 1, 2], send_func=_send_try, wait_func=_wait_outcome, time_budget_ms=900
                )
                if not best_cand:
                     self.logger.warning("Calibrator failed. Forwarding original packet.")
                     w.send(packet)
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
            elif task_type == "split":
                # Simple split - just multisplit with one position
                split_pos = int(params.get("split_pos", 3))
                recipe = self.techniques.apply_multisplit(payload, [split_pos])
            elif task_type == "disorder":
                # Simple disorder - just multidisorder with one position
                split_pos = int(params.get("split_pos", 3))
                recipe = self.techniques.apply_multidisorder(
                    payload, 
                    [split_pos],
                    split_pos=split_pos,
                    overlap_size=int(params.get("overlap_size", 0)),
                    fooling=params.get("fooling", []),
                    fake_ttl=int(params.get("ttl", 1))
                )
            elif task_type == "multisplit":
                recipe = self.techniques.apply_multisplit(payload, params.get("positions", [10, 25, 40]))
            elif task_type == "multidisorder":
                # Enhanced multidisorder with proper parameters
                split_pos = int(params.get("split_pos", 3))
                overlap_size = int(params.get("overlap_size", 0))
                fooling = params.get("fooling", [])
                repeats = int(params.get("repeats", 1))
                
                # Calculate TTL (use autottl if specified, otherwise use fixed ttl)
                ttl_source = "fixed"
                if params.get("autottl") is not None:
                    fake_ttl = self.calculate_autottl(packet.dst_addr, int(params["autottl"]))
                    ttl_source = f"autottl(offset={params['autottl']})"
                else:
                    fake_ttl = int(params.get("ttl", 1))
                
                # Detailed logging of attack parameters
                self.logger.info(
                    f"🎯 Multidisorder Attack Parameters:"
                )
                self.logger.info(f"   Target: {packet.dst_addr}:{packet.dst_port}")
                self.logger.info(f"   Payload size: {len(payload)} bytes")
                self.logger.info(f"   Split position: {split_pos}")
                self.logger.info(f"   Overlap size: {overlap_size}")
                self.logger.info(f"   Fooling methods: {fooling if fooling else 'none'}")
                self.logger.info(f"   TTL: {fake_ttl} ({ttl_source})")
                self.logger.info(f"   Repeats: {repeats}")
                
                recipe = self.techniques.apply_multidisorder(
                    payload,
                    params.get("positions", [split_pos]),
                    split_pos=split_pos,
                    overlap_size=overlap_size,
                    fooling=fooling,
                    fake_ttl=fake_ttl
                )
            elif task_type == "seqovl":
                recipe = self.techniques.apply_seqovl(payload, int(params.get("split_pos", 3)), int(params.get("overlap_size", 20)))
            elif task_type == "tlsrec_split":
                # TLS record splitting - split at TLS record boundaries
                split_pos = int(params.get("split_pos", 5))  # Default after TLS record header
                recipe = self.techniques.apply_multisplit(payload, [split_pos])
                self.logger.info(f"🔒 TLS record split at position {split_pos}")
            elif task_type == "simple_fragment": # FIX: Handle simple_fragment
                recipe = self.techniques.apply_multisplit(payload, [int(params.get("split_pos", 3))])
            elif task_type in ("badsum_race", "md5sig_race", "fake"):
                recipe = self.techniques.apply_fake_packet_race(payload, params.get("ttl", 3), params.get("fooling", []))
            elif task_type in ("stun_bypass", "quic_bypass", "udp_fragmentation"):
                # UDP-based attacks
                self.logger.info(f"🌐 Applying UDP attack: {task_type}")
                if task_type == "stun_bypass":
                    recipe = self.techniques.apply_stun_bypass(payload, params)
                elif task_type == "quic_bypass":
                    recipe = self.techniques.apply_quic_bypass(payload, params)
                elif task_type == "udp_fragmentation":
                    recipe = self.techniques.apply_udp_fragmentation(payload, params)
            else:
                self.logger.warning(f"Неизвестный или неподдерживаемый тип задачи '{task_type}', отправляем оригинал.")
                w.send(packet)
                return

            if recipe:
                try:
                    # ⚡ CRITICAL FIX: Передаем payload в _recipe_to_specs
                    try:
                        specs = self._recipe_to_specs(recipe, payload)
                    except Exception as e:
                        self.logger.error(f"apply_bypass: Exception converting recipe to specs for task {task_type} - {e}", exc_info=self.debug)
                        self.logger.error(f"apply_bypass: Recipe conversion failure details - task={task_type}, recipe_items={len(recipe) if recipe else 0}, payload_len={len(payload)}")
                        self.logger.warning("apply_bypass: Forwarding original packet due to recipe conversion error")
                        w.send(packet)
                        return
                    
                    if not specs:
                        self.logger.error(f"apply_bypass: Failed to convert recipe to specs for task {task_type}")
                        self.logger.error(f"apply_bypass: Recipe details - {len(recipe) if recipe else 0} recipe items, payload_len={len(payload)}")
                        self.logger.warning("apply_bypass: Forwarding original packet due to empty specs")
                        w.send(packet)
                        return
                    
                    # ensure zapret-like behavior: TTL/badsum only for fake segments
                    for sp in specs:
                        if not getattr(sp, "is_fake", False):
                            # Реальные пакеты — не трогаем TTL (пусть остаётся как у ОС)
                            sp.ttl = None
                            # И никаких badsum на реальных
                            sp.corrupt_tcp_checksum = False

                    # Log packet sequence details
                    self.logger.info(f"📦 Packet sequence: {len(specs)} segments")
                    for idx, spec in enumerate(specs, 1):
                        is_fake = getattr(spec, 'is_fake', False)
                        spec_ttl = getattr(spec, 'ttl', 'default')
                        seq_offset = getattr(spec, 'seq_offset', 0)
                        segment_type = "FAKE" if is_fake else "REAL"
                        self.logger.debug(
                            f"   Segment {idx}: {segment_type}, "
                            f"size={len(spec.data) if hasattr(spec, 'data') else 'unknown'}, "
                            f"ttl={spec_ttl}, seq_offset={seq_offset}"
                        )
                    
                    # Implement repeats logic
                    repeats = int(params.get("repeats", 1))
                    if repeats < 1:
                        repeats = 1
                    
                    success = False
                    for repeat_num in range(repeats):
                        if repeats > 1:
                            self.logger.info(f"🔁 Repeat iteration {repeat_num + 1}/{repeats}")
                        
                        # Send the packet sequence with comprehensive error handling
                        try:
                            repeat_success = self._packet_sender.send_tcp_segments(w, packet, specs)
                            
                            if repeat_success:
                                self.logger.debug(f"✅ Repeat {repeat_num + 1} sent successfully")
                            else:
                                self.logger.warning(f"❌ Repeat {repeat_num + 1} failed to send")
                                self.logger.warning(f"apply_bypass: Packet sending failed for repeat {repeat_num + 1}, "
                                                  f"task={task_type}, dst={packet.dst_addr}:{packet.dst_port}")
                                self.logger.warning(f"apply_bypass: Packet send failure details - specs_count={len(specs)}, "
                                                  f"packet_size={len(packet.raw) if hasattr(packet, 'raw') else 'unknown'}")
                            
                            success = success or repeat_success
                            
                        except OSError as e:
                            self.logger.error(f"apply_bypass: Network error during packet sending repeat {repeat_num + 1} - {e}")
                            self.logger.error(f"apply_bypass: Network error details - errno={getattr(e, 'errno', 'unknown')}, "
                                            f"winerror={getattr(e, 'winerror', 'unknown')}")
                            # Continue with next repeat or fallback
                        except MemoryError as e:
                            self.logger.error(f"apply_bypass: Memory error during packet sending repeat {repeat_num + 1} - {e}")
                            # Memory errors are serious, don't continue with more repeats
                            break
                        except Exception as e:
                            self.logger.error(f"apply_bypass: Unexpected exception during packet sending repeat {repeat_num + 1} - {e}", 
                                            exc_info=self.debug)
                            self.logger.error(f"apply_bypass: Exception details - task={task_type}, repeat={repeat_num + 1}, "
                                            f"dst={packet.dst_addr}:{packet.dst_port}")
                            # Continue with next repeat or fallback
                        
                        # Add small delay between repeats (except after last repeat)
                        if repeat_num < repeats - 1:
                            time.sleep(0.001)  # 1ms delay between repeats
                    
                    # Log final result
                    if success:
                        self.logger.info(f"✅ {task_type} attack completed successfully")
                    else:
                        self.logger.error(f"❌ {task_type} attack failed - all repeats unsuccessful")
                        self.logger.error(f"apply_bypass: Packet building/sending failed for {packet.dst_addr}:{packet.dst_port}, "
                                        f"forwarding original packet")
                    
                    # ✅ CRITICAL FIX: Update telemetry after sending packets (accounting for repeats)
                    if success:
                        try:
                            with self._tlock:
                                # Count fake and real packets (multiply by repeats)
                                fake_count = sum(1 for s in specs if getattr(s, 'is_fake', False)) * repeats
                                real_count = (len(specs) - (fake_count // repeats)) * repeats
                                
                                # Update aggregate telemetry
                                self._telemetry['aggregate']['segments_sent'] += len(specs) * repeats
                                self._telemetry['aggregate']['fake_packets_sent'] += fake_count
                                
                                # Update per-target telemetry
                                target_ip = packet.dst_addr
                                if target_ip not in self._telemetry['per_target']:
                                    self._telemetry['per_target'][target_ip] = {
                                        "segments_sent": 0,
                                        "fake_packets_sent": 0,
                                        "seq_offsets": defaultdict(int),
                                        "ttls_fake": defaultdict(int),
                                        "ttls_real": defaultdict(int),
                                        "overlaps": defaultdict(int),
                                    }
                                
                                per = self._telemetry['per_target'][target_ip]
                                per['segments_sent'] += len(specs)
                                per['fake_packets_sent'] += fake_count
                                
                                # Update TTL statistics
                                for spec in specs:
                                    if spec.ttl:
                                        if getattr(spec, 'is_fake', False):
                                            self._telemetry['ttls']['fake'][spec.ttl] += 1
                                            per['ttls_fake'][spec.ttl] += 1
                                        else:
                                            self._telemetry['ttls']['real'][spec.ttl] += 1
                                            per['ttls_real'][spec.ttl] += 1
                                
                                self.logger.debug(f"✅ Telemetry updated: {len(specs)} segments ({fake_count} fake, {real_count} real)")
                        except Exception as e:
                            self.logger.warning(f"apply_bypass: Failed to update telemetry - {e}")
                    
                    # Handle final result and ensure original packet forwarding on failure
                    if not success:
                        self.logger.warning("apply_bypass: All packet sending attempts failed, forwarding original packet")
                        self.logger.warning(f"apply_bypass: Final failure details - task={task_type}, repeats_attempted={repeats}, "
                                          f"dst={packet.dst_addr}:{packet.dst_port}, payload_len={len(payload)}")
                        try:
                            w.send(packet)
                            self.logger.debug("apply_bypass: Original packet forwarded successfully after bypass failure")
                        except Exception as send_e:
                            self.logger.error(f"apply_bypass: Failed to forward original packet after bypass failure - {send_e}")
                        
                except MemoryError as e:
                    self.logger.error(f"apply_bypass: Memory error processing packet specs - {e}")
                    self.logger.error(f"apply_bypass: Memory error details - task={task_type}, specs_count={len(specs) if 'specs' in locals() else 'unknown'}")
                    self.logger.warning("apply_bypass: Forwarding original packet due to memory error")
                    try:
                        w.send(packet)
                    except Exception as send_e:
                        self.logger.error(f"apply_bypass: Failed to forward original packet after memory error - {send_e}")
                except Exception as e:
                    self.logger.error(f"apply_bypass: Unexpected error processing packet specs - {e}", exc_info=self.debug)
                    self.logger.error(f"apply_bypass: Spec processing error details - task={task_type}, "
                                    f"dst={packet.dst_addr}:{packet.dst_port}, payload_len={len(payload)}")
                    self.logger.warning("apply_bypass: Forwarding original packet due to spec processing error")
                    try:
                        w.send(packet)
                    except Exception as send_e:
                        self.logger.error(f"apply_bypass: Failed to forward original packet after spec processing error - {send_e}")
            else:
                self.logger.warning(f"apply_bypass: Recipe generation failed for task {task_type}, forwarding original packet")
                self.logger.warning(f"apply_bypass: Recipe failure details - task={task_type}, "
                                  f"payload_len={len(payload)}, params={params}")
                try:
                    w.send(packet)
                    self.logger.debug("apply_bypass: Original packet forwarded successfully after recipe generation failure")
                except Exception as send_e:
                    self.logger.error(f"apply_bypass: Failed to forward original packet after recipe generation failure - {send_e}")

        except ValueError as e:
            self.logger.error(f"apply_bypass: Parameter validation error - {e}", exc_info=self.debug)
            self.logger.error(f"apply_bypass: Parameter error details - task={strategy_task.get('type', 'unknown')}, "
                            f"dst={getattr(packet, 'dst_addr', 'unknown')}:{getattr(packet, 'dst_port', 'unknown')}")
            try:
                w.send(packet)
            except Exception as send_e:
                self.logger.error(f"apply_bypass: Failed to forward original packet after parameter error - {send_e}")
        except MemoryError as e:
            self.logger.error(f"apply_bypass: Memory allocation error - {e}")
            try:
                w.send(packet)
            except Exception as send_e:
                self.logger.error(f"apply_bypass: Failed to forward original packet after memory error - {send_e}")
        except Exception as e:
            self.logger.error(f"❌ Unexpected error in apply_bypass - {e}", exc_info=self.debug)
            self.logger.error(f"apply_bypass: Unexpected error details - task={strategy_task.get('type', 'unknown')}, "
                            f"dst={getattr(packet, 'dst_addr', 'unknown')}:{getattr(packet, 'dst_port', 'unknown')}")
            try:
                w.send(packet)
                self.logger.debug("apply_bypass: Original packet forwarded successfully after unexpected error")
            except Exception as send_e:
                self.logger.error(f"apply_bypass: Failed to forward original packet after unexpected error - {send_e}")
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
    def apply_bypass(self, packet: Any, w: Any, strategy_task: Dict, forced=True): pass
    def report_high_level_outcome(self, target_ip: str, success: bool): pass