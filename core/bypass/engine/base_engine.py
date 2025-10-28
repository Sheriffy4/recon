# path: core/bypass/engine/base_engine.py
# CORRECTED AND CONSOLIDATED VERSION
def apply_forced_override(original_func, *args, **kwargs):
    """
    Обертка для принудительного применения стратегий.
    КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ для идентичного поведения с режимом тестирования.
    """
    if len(args) > 1 and isinstance(args[1], dict):
        strategy = args[1].copy()
        strategy["no_fallbacks"] = True
        strategy["forced"] = True
        args = (args[0], strategy) + args[2:]
        print(f"🔥 FORCED OVERRIDE: Applied to {args[0] if args else 'unknown'}")

    return original_func(*args, **kwargs)


# Standard library imports
import copy
import logging
import platform
import threading
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

# Core imports
from core.bypass.strategies.sni_detector import SNIDetector
from core.domain_watchlist import DomainWatchlist
from core.bypass.engine.attack_dispatcher import AttackDispatcher
from core.bypass.packet.builder import PacketBuilder
from core.bypass.packet.sender import PacketSender
from core.bypass.packet.types import TCPSegmentSpec
from core.bypass.strategies import PositionResolver
from core.bypass.techniques.primitives import BypassTechniques
from core.quic_handler import QuicHandler

try:
    from core.strategy_manager import StrategyManager
except (ImportError, ModuleNotFoundError):
    StrategyManager = None
    logging.getLogger("BypassEngine").warning("StrategyManager could not be imported.")


def safe_split_pos_conversion(split_pos_value, default=3):
    """
    Безопасно преобразует значение split_pos, поддерживая специальные значения.
    """
    if split_pos_value is None:
        return default

    if isinstance(split_pos_value, int):
        return split_pos_value

    if isinstance(split_pos_value, str):
        special_values = ["cipher", "midsld", "sni"]
        if split_pos_value in special_values:
            return split_pos_value
        try:
            return int(split_pos_value)
        except ValueError:
            logging.getLogger("BypassEngine").warning(
                f"Invalid split_pos value: {split_pos_value}, using default: {default}"
            )
            return default

    if isinstance(split_pos_value, list) and len(split_pos_value) > 0:
        return safe_split_pos_conversion(split_pos_value[0], default)

    logging.getLogger("BypassEngine").warning(
        f"Unsupported split_pos type: {type(split_pos_value)}, using default: {default}"
    )
    return default


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
    """

    @abstractmethod
    def __init__(self, config: EngineConfig): ...

    @abstractmethod
    def start(
        self,
        target_ips: Set[str],
        strategy_map: Dict[str, Dict],
        reset_telemetry: bool = False,
        strategy_override: Optional[Dict[str, Any]] = None,
    ): ...

    @abstractmethod
    def stop(self): ...

    @abstractmethod
    def set_strategy_override(self, strategy_task: Dict[str, Any]) -> None: ...

    @abstractmethod
    def get_telemetry_snapshot(self) -> Dict[str, Any]: ...

    @abstractmethod
    def apply_bypass(self, packet: Any, w: Any, strategy_task: Dict, forced=True): ...

    @abstractmethod
    def report_high_level_outcome(self, target_ip: str, success: bool): ...


class WindowsBypassEngine(IBypassEngine):
    def __init__(self, config: EngineConfig):
        if not pydivert:
            raise ImportError(
                "Pydivert is required for WindowsBypassEngine but could not be imported."
            )

        self.debug = config.debug
        self.running = False
        self.techniques = BypassTechniques()
        self.logger = logging.getLogger("BypassEngine")
        self.logger.info(f"BypassEngine from {self.__class__.__module__}")

        # Логируем версию primitives для диагностики
        import inspect

        primitives_file = inspect.getsourcefile(BypassTechniques)
        primitives_version = getattr(BypassTechniques, "API_VER", "unknown")
        self.logger.info(
            f"Primitives file: {primitives_file}; ver={primitives_version}"
        )
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
        self._active_flows: Set[Tuple[str, int, str, int]] = set()
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

        self._processed_flows = {}
        self._flow_timeout = 15.0

        self._packet_builder = PacketBuilder()
        self._packet_sender = PacketSender(
            self._packet_builder, self.logger, self._INJECT_MARK
        )
        self.logger.info(
            "Modern packet pipeline (PacketSender/Builder) integrated directly."
        )

        self._autottl_cache: Dict[str, Tuple[int, float]] = {}
        self._autottl_cache_ttl = 300.0

        self._position_resolver = PositionResolver()
        self._split_pos_cache: Dict[Tuple[str, int, str, int], int] = {}

        # Инициализируем диспетчер атак
        self._attack_dispatcher = AttackDispatcher(self.techniques)
        self.logger.info("AttackDispatcher initialized")

        # Инициализируем компоненты для SNI-фильтрации
        self._sni_detector = SNIDetector()
        self._domain_watchlist = DomainWatchlist() # Можно передать путь к файлу, если нужно
        self.logger.info("SNI Detector and Domain Watchlist initialized for in-flight filtering.")

    def attach_controller(
        self,
        base_rules,
        zapret_parser,
        task_translator,
        store_path="learned_strategies.json",
        epsilon=0.1,
    ):
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
        self.logger.info(
            f"🚀 START CALLED: target_ips={target_ips}, strategies={len(strategy_map)}, override={strategy_override is not None}"
        )

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
        return self.start(target_ips, strategy_map, strategy_override=strategy_override)

    def set_strategy_override(self, strategy_task: Dict[str, Any]) -> None:
        task = (
            dict(strategy_task)
            if isinstance(strategy_task, dict)
            else {
                "type": str(strategy_task),
                "params": {},
                "no_fallbacks": True,
                "forced": True,
            }
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

    def clear_strategy_override(self) -> None:
        self.strategy_override = None
        self._forced_strategy_active = False
        self.logger.info("🔄 Глобальное переопределение стратегии сброшено.")

    def _config_to_strategy_task(self, config: dict) -> dict:
        desync_method = config.get("desync_method", "fake")
        fooling = config.get("fooling", "badsum")
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
                    "tcp_flags": {
                        "psh": True,
                        "ack": True,
                        "no_fallbacks": True,
                        "forced": True,
                    },
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
            return {
                "type": task_type,
                "params": base_params,
                "no_fallbacks": True,
                "forced": True,
            }
        return {
            "type": "fakeddisorder",
            "params": {
                "ttl": ttl,
                "split_pos": split_pos,
                "window_div": 8,
                "tcp_flags": {
                    "psh": True,
                    "ack": True,
                    "no_fallbacks": True,
                    "forced": True,
                },
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

    def _is_tls_clienthello(self, payload: Optional[bytes]) -> bool:
        try:
            if not payload or len(payload) < 43:
                return False
            if payload[0] != 0x16:
                return False
            if payload[5] != 0x01:
                return False
            return True
        except Exception:
            return False

    def _extract_sni(self, payload: Optional[bytes]) -> Optional[str]:
        try:
            if not payload or len(payload) < 43:
                return None
            if payload[0] != 0x16:
                return None
            if payload[5] != 0x01:
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
                            try:
                                return payload[nstart : nstart + nlen].decode(
                                    "idna", errors="strict"
                                )
                            except Exception:
                                return None
                s = epos + elen
            return None
        except Exception:
            return None

    def _is_target_ip(self, ip_str: str, target_ips: Set[str]) -> bool:
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
            "151.101.",
            "199.232.",
            "23.",
            "2.16.",
            "95.100.",
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
            "91.108.",
            "149.154.",
        }
        for prefix in cdn_prefixes:
            if ip_str.startswith(prefix):
                self.logger.debug(f"IP {ip_str} соответствует CDN префиксу {prefix}")
                return True
        return False

    def _estimate_split_pos_from_ch(self, payload: bytes) -> Optional[int]:
        try:
            if not self._is_tls_clienthello(payload) or len(payload) < 43:
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
                        if npos + list_len <= epos + elen and npos + 3 <= len(payload):
                            ntype = payload[npos]
                            nlen = int.from_bytes(payload[npos + 1 : npos + 3], "big")
                            nstart = npos + 3
                            if ntype == 0 and nstart + nlen <= len(payload):
                                try:
                                    name = payload[nstart : nstart + nlen].decode(
                                        "idna"
                                    )
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
                                        info["key"], info["strategy"], outcome, rtt_ms
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

    def _probe_hops(
        self, dest_ip: str, timeout: float = 2.0, max_hops: int = 30
    ) -> int:
        try:
            first_octet = int(dest_ip.split(".")[0])

            octets = [int(x) for x in dest_ip.split(".")]
            is_private = (
                octets[0] == 10
                or (octets[0] == 172 and 16 <= octets[1] <= 31)
                or (octets[0] == 192 and octets[1] == 168)
            )

            if is_private:
                estimated_hops = 2
            elif first_octet in range(1, 128):
                estimated_hops = 12
            elif first_octet in range(128, 192):
                estimated_hops = 8
            else:
                estimated_hops = 10

            self.logger.debug(
                f"Estimated {estimated_hops} hops to {dest_ip} (heuristic)"
            )
            return estimated_hops

        except Exception as e:
            self.logger.warning(f"Hop probing failed for {dest_ip}: {e}")
            return 8

    def calculate_autottl(self, dest_ip: str, autottl_offset: int) -> int:
        try:
            current_time = time.time()

            if dest_ip in self._autottl_cache:
                cached_hops, cached_time = self._autottl_cache[dest_ip]
                if current_time - cached_time < self._autottl_cache_ttl:
                    ttl = cached_hops + autottl_offset
                    ttl = max(1, min(255, ttl))
                    self.logger.debug(
                        f"AutoTTL (cached): {cached_hops} hops + {autottl_offset} offset = TTL {ttl}"
                    )
                    return ttl

            hop_count = self._probe_hops(dest_ip)

            self._autottl_cache[dest_ip] = (hop_count, current_time)

            ttl = hop_count + autottl_offset

            ttl = max(1, min(255, ttl))

            self.logger.info(
                f"AutoTTL: {hop_count} hops + {autottl_offset} offset = TTL {ttl} for {dest_ip}"
            )
            return ttl

        except Exception as e:
            self.logger.warning(
                f"AutoTTL calculation failed for {dest_ip}: {e}, using default TTL=64"
            )
            return 64

    def _resolve_cipher_pos(self, payload: bytes) -> Optional[int]:
        try:
            if not self._is_tls_clienthello(payload) or len(payload) < 43:
                return None

            pos = 9
            pos += 2 + 32
            if pos + 1 > len(payload):
                return None

            sid_len = payload[pos]
            pos += 1 + sid_len

            if pos + 2 <= len(payload):
                return pos

            return None
        except Exception:
            return None

    def _calculate_max_ips_for_filter(self, target_ips: Set[str]) -> int:
        """Calculate maximum number of IPs that can fit in WinDivert filter without exceeding length limit."""
        base_filter = "outbound and () and (tcp.DstPort == 443 or udp.DstPort == 443 or tcp.DstPort == 80)"
        max_filter_length = 1024  # Conservative WinDivert filter length limit
        
        if not target_ips:
            return 0
            
        # Calculate average IP string length
        sample_ips = list(target_ips)[:5]
        avg_ip_length = sum(len(f"ip.DstAddr == {ip}") for ip in sample_ips) / len(sample_ips)
        avg_ip_length += 4  # Add space for " or " separator
        
        available_space = max_filter_length - len(base_filter)
        max_ips = max(1, int(available_space / avg_ip_length))
        
        return min(max_ips, 15)  # Conservative limit of 15 IPs

    def _run_bypass_loop(self, target_ips: Set[str], strategy_map: Dict[str, Dict]):
        self.logger.info(
            f"🔍 BYPASS LOOP STARTED: target_ips={len(target_ips)}, strategies={len(strategy_map)}"
        )

        if target_ips:
            # Calculate optimal number of IPs for filter
            max_ips = self._calculate_max_ips_for_filter(target_ips)
            ip_list = list(target_ips)[:max_ips]
            ip_filter = " or ".join([f"ip.DstAddr == {ip}" for ip in ip_list])
            filter_str = f"outbound and ({ip_filter}) and (tcp.DstPort == 443 or udp.DstPort == 443 or tcp.DstPort == 80)"
            self.logger.info(f"🔍 Фильтр pydivert с {len(ip_list)}/{len(target_ips)} целевыми IP (ограничено для избежания ошибок WinDivert)")
        else:
            filter_str = "outbound and (tcp.DstPort == 443 or udp.DstPort == 443 or tcp.DstPort == 80)"
            self.logger.info("🔍 Фильтр pydivert: перехват всех HTTPS/HTTP пакетов")

        self.logger.info(f"🔍 WinDivert filter: {filter_str}")

        # Try with the constructed filter first
        try:
            with pydivert.WinDivert(filter_str, priority=1000) as w:
                self.logger.info("✅ WinDivert запущен успешно.")
                while self.running:
                    packet = w.recv()
                    if packet is None:
                        continue
                    if getattr(packet, "mark", 0) == self._INJECT_MARK:
                        w.send(packet)
                        continue

                    self.stats["packets_captured"] += 1
                    if (
                        self._is_target_ip(packet.dst_addr, target_ips)
                        and packet.payload
                    ):
                        if self._is_tls_clienthello(packet.payload):
                            with self._tlock:
                                self._telemetry["clienthellos"] += 1

                            strategy_task = (
                                self.strategy_override
                                or strategy_map.get(packet.dst_addr)
                                or strategy_map.get("default")
                            )

                            if strategy_task:
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
                # If filter is too long, try with a simpler filter
                if "Параметр задан неверно" in str(e) or "Invalid parameter" in str(e):
                    self.logger.warning(f"⚠️ WinDivert фильтр слишком длинный, пробуем упрощенный фильтр...")
                    try:
                        # Fallback to a simple filter without IP restrictions
                        simple_filter = "outbound and (tcp.DstPort == 443 or udp.DstPort == 443 or tcp.DstPort == 80)"
                        self.logger.info(f"🔍 Fallback WinDivert filter: {simple_filter}")
                        
                        with pydivert.WinDivert(simple_filter, priority=1000) as w:
                            self.logger.info("✅ WinDivert запущен с упрощенным фильтром.")
                            while self.running:
                                packet = w.recv()
                                if packet is None:
                                    continue
                                if getattr(packet, "mark", 0) == self._INJECT_MARK:
                                    w.send(packet)
                                    continue

                                self.stats["packets_captured"] += 1
                                if (
                                    self._is_target_ip(packet.dst_addr, target_ips)
                                    and packet.payload
                                ):
                                    if self._is_tls_clienthello(packet.payload):
                                        with self._tlock:
                                            self._telemetry["clienthellos"] += 1

                                        strategy_task = (
                                            self.strategy_override
                                            or strategy_map.get(packet.dst_addr)
                                            or strategy_map.get("default")
                                        )

                                        if strategy_task:
                                            self.stats["tls_packets_bypassed"] += 1
                                            self.apply_bypass(packet, w, strategy_task, forced=True)
                                        else:
                                            w.send(packet)
                                    else:
                                        w.send(packet)
                                else:
                                    w.send(packet)
                    except Exception as fallback_e:
                        self.logger.error(
                            f"❌ Критическая ошибка даже с упрощенным фильтром: {fallback_e}", exc_info=self.debug
                        )
                        self.running = False
                else:
                    self.logger.error(
                        f"❌ Критическая ошибка в цикле WinDivert: {e}", exc_info=self.debug
                    )
                    self.running = False

    def _proto(self, packet) -> int:
        p = getattr(packet, "protocol", None)
        if isinstance(p, tuple) and p:
            return int(p[0])
        return int(p) if p is not None else 0

    def _is_udp(self, packet) -> bool:
        return self._proto(packet) == 17

    def _is_tcp(self, packet) -> bool:
        return self._proto(packet) == 6

    def _recipe_to_specs(
        self, recipe: List[Tuple[bytes, int, dict]], payload: bytes
    ) -> List[TCPSegmentSpec]:
        if not recipe or not isinstance(recipe, (list, tuple)):
            self.logger.error(
                f"_recipe_to_specs: Получен невалидный 'рецепт' (тип: {type(recipe)})."
            )
            return []

        specs = []
        total_items = len(recipe)

        for i, recipe_item in enumerate(recipe):
            try:
                if not isinstance(recipe_item, (list, tuple)) or len(recipe_item) != 3:
                    self.logger.error(
                        f"Элемент рецепта #{i} имеет неверную структуру. Пропуск."
                    )
                    continue

                seg_payload, offset, opts = recipe_item

                if not isinstance(offset, int):
                    self.logger.error(
                        f"Offset в элементе #{i} не является числом. Пропуск."
                    )
                    continue
                if not isinstance(opts, dict):
                    self.logger.error(
                        f"Опции в элементе #{i} не являются словарем. Пропуск."
                    )
                    continue

                is_fake = bool(opts.get("is_fake", False))
                ttl = int(opts["ttl"]) if opts.get("ttl") is not None else None

                tcp_flags = int(opts.get("tcp_flags", 0x18))

                if tcp_flags & 0x01:
                    if not opts.get("allow_fin", False):
                        self.logger.warning(
                            f"🛡️ FIN-Sanitizer: Удален флаг FIN в сегменте #{i}."
                        )
                        tcp_flags &= ~0x01

                valid_real_flags = [0x10, 0x18]
                if not is_fake and tcp_flags not in valid_real_flags:
                    self.logger.warning(
                        f"🛡️ Flag-Normalizer: Нестандартные TCP флаги 0x{tcp_flags:02X} в реальном сегменте #{i}, нормализация до PSH+ACK (0x18)."
                    )
                    tcp_flags = 0x18

                spec = TCPSegmentSpec(
                    rel_seq=offset,
                    payload=seg_payload,
                    flags=tcp_flags,
                    ttl=ttl,
                    corrupt_tcp_checksum=bool(opts.get("corrupt_tcp_checksum", False)),
                    add_md5sig_option=bool(opts.get("add_md5sig_option", False)),
                    seq_extra=int(
                        opts.get("seq_extra", -1 if opts.get("corrupt_sequence") else 0)
                    ),
                    fooling_sni=opts.get("fooling_sni"),
                    is_fake=is_fake,
                    delay_ms_after=(
                        int(opts.get("delay_ms", opts.get("delay_ms_after", 0)))
                        if i < total_items - 1
                        else 0
                    ),
                    preserve_window_size=bool(
                        opts.get("preserve_window_size", not is_fake)
                    ),
                )
                specs.append(spec)

            except Exception as e:
                self.logger.error(
                    f"Ошибка при обработке элемента рецепта #{i}: {e}",
                    exc_info=self.debug,
                )
                continue

        if not specs:
            self.logger.error(
                "Не удалось сгенерировать ни одного валидного сегмента из рецепта."
            )
            return []

        try:
            L = len(payload or b"")
            if L > 0:
                covered = [False] * L
                for s in specs:
                    if getattr(s, "is_fake", False):
                        continue
                    off, data_len = int(s.rel_seq), len(s.payload or b"")
                    for j in range(max(0, off), min(L, off + data_len)):
                        covered[j] = True

                holes = [idx for idx, ok in enumerate(covered) if not ok]
                if holes:
                    # Для seqovl атак небольшие дыры могут быть нормальными из-за overlap логики
                    strategy_name = (
                        strategy_task.get("type", "")
                        if isinstance(strategy_task, dict)
                        else ""
                    )
                    if strategy_name == "seqovl" and len(holes) <= 20:
                        self.logger.warning(
                            f"⚠️ Seqovl overlap: {len(holes)} байт не покрыто (нормально для overlap). "
                            f"Позиции: {holes[:10]}"
                        )
                    else:
                        self.logger.error(
                            f"‼️ КРИТИЧЕСКАЯ ОШИБКА СБОРКИ! "
                            f"Реальный payload имеет 'дыры' ({len(holes)} байт не покрыто). "
                            f"Первые пропуски на позициях: {holes[:16]}"
                        )
                        if self.debug:
                            raise ValueError(
                                f"TCP stream has holes at positions: {holes[:16]}"
                            )
        except Exception as e:
            self.logger.debug(f"Ошибка при проверке покрытия payload: {e}")

        self.logger.debug(f"Успешно сгенерировано {len(specs)} спецификаций сегментов.")
        return specs

    # --- START OF FINAL FIX: UNIFIED PACKET SUPPRESSION LOGIC ---
    def apply_bypass(
        self,
        packet: "pydivert.Packet",
        w: "pydivert.WinDivert",
        strategy_task: Dict,
        forced=True,
    ):
        """
        Унифицированный метод применения обхода DPI с SNI-фильтрацией "на лету".
        """
        payload = bytes(packet.payload or b"")

        # --- НОВАЯ ЛОГИКА ФИЛЬТРАЦИИ ---
        # 1. Проверяем, является ли пакет TLS ClientHello
        if self._sni_detector.is_client_hello(payload):
            # 2. Извлекаем SNI
            domain = self._sni_detector.extract_sni_value(payload)

            # 3. Проверяем, нужен ли обход для этого домена
            if domain and self._domain_watchlist.is_bypass_required(domain):
                self.logger.debug(f"SNI '{domain}' in watchlist. Applying bypass.")
                # Если домен в списке, продолжаем выполнение старой логики обхода
            else:
                # Если домена нет в списке, просто отправляем пакет без изменений
                self.logger.debug(f"SNI '{domain or 'not found'}' not in watchlist. Forwarding original packet.")
                w.send(packet)
                return
        else:
            # Если это не ClientHello (например, HTTP или другой TCP-трафик),
            # пока просто пропускаем. Можно добавить логику для HTTP Host.
            w.send(packet)
            return
        # --- КОНЕЦ НОВОЙ ЛОГИКИ ---

        flow_key = (packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)
        now = time.time()

        # Блокируем оригинальный/повторный пакет, если мы уже обработали этот поток.
        # Это ключевое исправление для унификации поведения.
        with self._lock:
            if (
                flow_key in self._processed_flows
                and now - self._processed_flows[flow_key] < 1.5
            ):
                self.logger.debug(
                    f"🔪 Dropping subsequent packet for already processed flow {flow_key}"
                )
                # Просто выходим, не вызывая w.send(). Это уничтожает пакет.
                return

            self._processed_flows[flow_key] = now

            # Очистка старых записей для предотвращения утечки памяти
            if len(self._processed_flows) > 2000:
                cutoff = now - self._flow_timeout
                self._processed_flows = {
                    k: t for k, t in self._processed_flows.items() if t >= cutoff
                }

        try:
            if not self._inject_sema.acquire(blocking=False):
                self.logger.warning(
                    "Injection semaphore limit reached, forwarding original"
                )
                w.send(packet)
                return

            params = dict(strategy_task.get("params", {}))
            self.logger.info(
                f"🔥 APPLY_BYPASS FIXED: dst={packet.dst_addr}:{packet.dst_port}, strategy={strategy_task.get('type', 'unknown')}, params={params}"
            )
            task_type = (strategy_task.get("type") or "fakeddisorder").lower()
            payload = bytes(packet.payload or b"")
            L = len(payload)

            if L == 0:
                w.send(packet)
                return

            dst_ip = packet.dst_addr
            autottl_offset = params.get("autottl")
            if autottl_offset is not None:
                fake_ttl = self.calculate_autottl(dst_ip, int(autottl_offset))
            else:
                race_attack_types = (
                    "fakeddisorder",
                    "multidisorder",
                    "disorder",
                    "disorder2",
                    "seqovl",
                    "fake_race",
                    "fake",
                )
                if task_type in race_attack_types:
                    fake_ttl = int(params.get("fake_ttl", params.get("ttl", 3)))
                else:
                    fake_ttl = int(params.get("fake_ttl", params.get("ttl", 64)))

            # AttackDispatcher теперь сам обрабатывает разрешение специальных значений

            # ✅ НОВАЯ ДИСПЕТЧЕРИЗАЦИЯ ЧЕРЕЗ AttackDispatcher
            packet_info = {
                "src_addr": packet.src_addr,
                "dst_addr": packet.dst_addr,
                "src_port": packet.src_port,
                "dst_port": packet.dst_port,
            }

            # Подготавливаем параметры для диспетчера
            dispatch_params = params.copy()

            # Устанавливаем правильные параметры TTL для каждого типа атаки
            if task_type in ["seqovl", "fakeddisorder", "multidisorder"]:
                dispatch_params["fake_ttl"] = fake_ttl
            elif task_type in ["fake", "fake_race"]:
                dispatch_params["ttl"] = fake_ttl
            else:
                dispatch_params["fake_ttl"] = fake_ttl
                dispatch_params["ttl"] = fake_ttl

            # Добавляем overlap_size для seqovl
            if task_type == "seqovl":
                dispatch_params["overlap_size"] = int(
                    params.get("overlap_size", params.get("split_seqovl", 20))
                )

            try:
                self.logger.debug(
                    f"🎯 Dispatching {task_type} attack via AttackDispatcher"
                )
                recipe = self._attack_dispatcher.dispatch_attack(
                    task_type, dispatch_params, payload, packet_info
                )
            except ValueError as e:
                self.logger.error(
                    f"❌ Attack dispatch validation failed for '{task_type}': {e}"
                )
                w.send(packet)
                return
            except Exception as e:
                self.logger.error(f"❌ Attack dispatch failed for '{task_type}': {e}")
                w.send(packet)
                return

            if not recipe:
                self.logger.warning(
                    f"Recipe for {task_type} was not generated. Forwarding original."
                )
                w.send(packet)
                return

            specs = self._recipe_to_specs(recipe, payload)
            if not specs:
                self.logger.error(
                    f"Failed to convert recipe to specs for {task_type}. Forwarding original."
                )
                w.send(packet)
                return

            self.logger.info(
                f"📦 Packet sequence: {len(specs)} segments for {task_type}"
            )

            ok = self._packet_sender.send_tcp_segments(w, packet, specs)
            if not ok:
                self.logger.error(
                    f"❌ PacketSender failed for {task_type}. Forwarding original."
                )
                w.send(packet)
            # После успешной инъекции оригинальный пакет уже был уничтожен в начале функции.

        except Exception as e:
            self.logger.error(
                f"❌ CRITICAL ERROR in apply_bypass: {e}", exc_info=self.debug
            )
            try:
                w.send(packet)
            except Exception:
                pass
        finally:
            self._inject_sema.release()

    # --- END OF FINAL FIX ---

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

    def report_high_level_outcome(self, target_ip: str, success: bool):
        with self._tlock:
            if target_ip not in self._telemetry["per_target"]:
                self._telemetry["per_target"][target_ip] = {
                    "segments_sent": 0,
                    "fake_packets_sent": 0,
                    "seq_offsets": defaultdict(int),
                    "ttls_fake": defaultdict(int),
                    "ttls_real": defaultdict(int),
                    "overlaps": defaultdict(int),
                    "last_outcome": None,
                    "last_outcome_ts": None,
                    "high_level_success": None,
                    "high_level_outcome_ts": None,
                }
            entry = self._telemetry["per_target"][target_ip]
            entry["high_level_success"] = success
            entry["high_level_outcome_ts"] = time.time()
            if success:
                self._telemetry["aggregate"]["high_level_successes"] = (
                    self._telemetry["aggregate"].get("high_level_successes", 0) + 1
                )
            else:
                self._telemetry["aggregate"]["high_level_failures"] = (
                    self._telemetry["aggregate"].get("high_level_failures", 0) + 1
                )


class FallbackBypassEngine(IBypassEngine):
    """Fallback engine for non-Windows systems."""

    def __init__(self, config: EngineConfig):
        self.logger = logging.getLogger("BypassEngine")
        self.logger.warning(
            "Pydivert is not supported on this platform. BypassEngine is disabled."
        )
        self.running = False

    def start(self, *args, **kwargs):
        self.logger.warning("BypassEngine is disabled.")

    def stop(self, *args, **kwargs):
        pass

    def set_strategy_override(self, strategy_task: Dict[str, Any]) -> None:
        pass

    def get_telemetry_snapshot(self) -> Dict[str, Any]:
        return {}

    def apply_bypass(self, packet: Any, w: Any, strategy_task: Dict, forced=True):
        pass

    def report_high_level_outcome(self, target_ip: str, success: bool):
        pass
