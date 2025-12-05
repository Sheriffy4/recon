# path: core/bypass/engine/base_engine.py
# CORRECTED AND CONSOLIDATED VERSION
def apply_forced_override(original_func, *args, **kwargs):
    """
    Обёртка для принудительного применения стратегий.

    Не изменяет исходный словарь стратегии и не использует print,
    чтобы не ломать сервисные сценарии.
    """
    if len(args) > 1 and isinstance(args[1], dict):
        # Не мутируем исходный dict – создаём копию
        strategy = args[1].copy()
        strategy["no_fallbacks"] = True
        strategy["forced"] = True
        args = (args[0], strategy) + args[2:]
        try:
            import logging
            logging.getLogger("BypassEngine").debug(
                "FORCED OVERRIDE: Applied to %s", args[0] if args else "unknown"
            )
        except Exception:
            # Логирование не критично – в крайнем случае просто молча продолжаем
            pass

    return original_func(*args, **kwargs)


# Standard library imports
import copy
import logging
import platform
import struct
import threading
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Core imports
from core.bypass.engine.attack_dispatcher import AttackDispatcher
from core.bypass.engine.unified_attack_executor import UnifiedAttackExecutor, ExecutionContext, ExecutionResult
from core.bypass.packet.builder import PacketBuilder
from core.bypass.packet.sender import PacketSender
from core.bypass.packet.types import TCPSegmentSpec
from core.bypass.strategies import PositionResolver
from core.bypass.techniques.primitives import BypassTechniques
from core.quic_handler import QuicHandler

# Runtime filtering imports
try:
    from core.bypass.filtering.runtime_filter import RuntimePacketFilter
    from core.bypass.filtering.config import FilterConfig, FilterMode
    from core.windivert_filter import WinDivertFilterGenerator
    from core.bypass.filtering.feature_flags import is_runtime_filtering_enabled, is_domain_based_filtering_enabled
except ImportError as e:
    RuntimePacketFilter = None
    FilterConfig = None
    FilterMode = None
    WinDivertFilterGenerator = None
    is_runtime_filtering_enabled = None
    is_domain_based_filtering_enabled = None
    logging.getLogger("BypassEngine").warning(f"Runtime filtering components not available: {e}")

# Domain-based strategy engine imports
try:
    from core.bypass.engine.domain_strategy_engine import DomainStrategyEngine
    from core.bypass.engine.domain_rule_registry import DomainRuleRegistry
except ImportError as e:
    DomainStrategyEngine = None
    DomainRuleRegistry = None
    logging.getLogger("BypassEngine").warning(f"Domain strategy engine components not available: {e}")

try:
    from core.strategy_manager import StrategyManager
except (ImportError, ModuleNotFoundError):
    StrategyManager = None
    logging.getLogger("BypassEngine").warning("StrategyManager could not be imported.")

CDN_PREFIXES: Tuple[str, ...] = (
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
)

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


class ProcessedPacketCache:
    """
    Кэш обработанных пакетов для предотвращения повторной обработки TCP ретрансмиссий.
    
    Requirement 11: Deduplication TCP ретрансмиссий
    - Хранит (flow_id, seq) → timestamp для обработанных пакетов
    - Автоматически удаляет устаревшие записи (> 60 секунд)
    - Thread-safe для concurrent access
    """
    
    def __init__(self, ttl_seconds: int = 60):
        self._cache: Dict[Tuple[Tuple[str, int, str, int], int], float] = {}
        self._lock = threading.Lock()
        self._ttl_seconds = ttl_seconds
        self._cleanup_thread = None
        self._stop_cleanup = threading.Event()
        self.logger = logging.getLogger("ProcessedPacketCache")
        
    def start_cleanup_thread(self):
        """Запускает background thread для периодической очистки кэша"""
        if self._cleanup_thread is None or not self._cleanup_thread.is_alive():
            self._stop_cleanup.clear()
            self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
            self._cleanup_thread.start()
            self.logger.debug("Cleanup thread started")
    
    def stop_cleanup_thread(self):
        """Останавливает background thread очистки"""
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._stop_cleanup.set()
            self._cleanup_thread.join(timeout=2.0)
            self.logger.debug("Cleanup thread stopped")
    
    def _cleanup_loop(self):
        """Background loop для очистки устаревших записей каждые 10 секунд"""
        while not self._stop_cleanup.wait(timeout=10.0):
            removed = self.cleanup_expired()
            if removed > 0:
                self.logger.debug(f"Cache cleanup: removed {removed} expired entries")
    
    def is_processed(self, flow_id: Tuple[str, int, str, int], seq: int) -> bool:
        """
        Проверяет, был ли пакет уже обработан.
        
        Args:
            flow_id: (src_ip, src_port, dst_ip, dst_port)
            seq: TCP sequence number
            
        Returns:
            True если пакет уже обработан, False иначе
        """
        key = (flow_id, seq)
        with self._lock:
            if key in self._cache:
                timestamp = self._cache[key]
                # Проверяем не истек ли TTL
                if time.time() - timestamp < self._ttl_seconds:
                    return True
                else:
                    # Удаляем устаревшую запись
                    del self._cache[key]
            return False
    
    def mark_processed(self, flow_id: Tuple[str, int, str, int], seq: int):
        """
        Помечает пакет как обработанный.
        
        Args:
            flow_id: (src_ip, src_port, dst_ip, dst_port)
            seq: TCP sequence number
        """
        key = (flow_id, seq)
        with self._lock:
            self._cache[key] = time.time()
    
    def cleanup_expired(self) -> int:
        """
        Удаляет устаревшие записи (> TTL).
        
        Returns:
            Количество удаленных записей
        """
        now = time.time()
        with self._lock:
            expired_keys = [
                key for key, timestamp in self._cache.items()
                if now - timestamp >= self._ttl_seconds
            ]
            for key in expired_keys:
                del self._cache[key]
            return len(expired_keys)
    
    def remove_flow(self, flow_id: Tuple[str, int, str, int]):
        """
        Удаляет все записи для указанного flow (при закрытии соединения).
        
        Args:
            flow_id: (src_ip, src_port, dst_ip, dst_port)
        """
        with self._lock:
            keys_to_remove = [key for key in self._cache.keys() if key[0] == flow_id]
            for key in keys_to_remove:
                del self._cache[key]
            if keys_to_remove:
                self.logger.debug(f"Connection closed: flow={flow_id}, removed {len(keys_to_remove)} cache entries")
    
    def get_stats(self) -> Dict[str, int]:
        """Возвращает статистику кэша"""
        with self._lock:
            return {
                "total_entries": len(self._cache),
                "ttl_seconds": self._ttl_seconds
            }


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
    def apply_bypass(self, packet: Any, w: Any, strategy_task: Dict, forced=True, strategy_result=None): ...

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
        
        # Fallback metrics for tracking bypass failures (Requirement 9.4)
        self._fallback_metrics = {
            "total_attempts": 0,
            "total_successes": 0,
            "total_fallbacks": 0,
            "fallback_reasons": {},
            "consecutive_fallbacks": 0,
            "last_fallback_time": 0,
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
        
        # CRITICAL FIX: Initialize shared PCAP file for continuous capture
        self._shared_pcap_file = None

        self._processed_flows = {}
        self._flow_timeout = 15.0

        self._packet_builder = PacketBuilder()
        self._packet_sender = PacketSender(
            self._packet_builder, self.logger, self._INJECT_MARK
        )
        self.logger.info(
            "Modern packet pipeline (PacketSender/Builder) integrated directly."
        )
        
        # Set default mode to production (Requirement 9.1)
        self._packet_sender.set_mode("production")

        self._autottl_cache: Dict[str, Tuple[int, float]] = {}
        self._autottl_cache_ttl = 300.0

        self._position_resolver = PositionResolver()
        self._split_pos_cache: Dict[Tuple[str, int, str, int], int] = {}

        # Инициализируем диспетчер атак
        self._attack_dispatcher = AttackDispatcher(self.techniques)
        self.logger.info("AttackDispatcher initialized")
        
        # Initialize unified attack executor (CRITICAL for testing-production parity)
        self._unified_executor = UnifiedAttackExecutor(
            attack_dispatcher=self._attack_dispatcher,
            packet_sender=self._packet_sender
        )
        self.logger.info("✅ UnifiedAttackExecutor initialized for testing-production parity")
        
        # Domain extraction failure tracking for automatic fallback
        self._domain_extraction_failures = 0
        self._domain_extraction_failure_threshold = 10  # Fallback after 10 consecutive failures
        self._domain_extraction_success_count = 0
        self._last_domain_extraction_failure_time = 0
        
        # Initialize domain strategy engine
        self._domain_strategy_engine = None
        self._use_domain_based_filtering = False
        self._initialize_domain_strategy_engine()
        
        # Check legacy configuration compatibility and provide guidance
        self._check_legacy_configuration_compatibility()
        
        # Initialize retransmission deduplication cache (Requirement 11)
        self._processed_packet_cache = ProcessedPacketCache(ttl_seconds=60)
        self._processed_packet_cache.start_cleanup_thread()
        self._retransmission_count = 0  # Metric for retransmissions detected
        
        # Track failed strategies for automatic fallback
        self._failed_strategies = {}  # domain -> {strategy_type: failure_count}
        self._strategy_failure_threshold = 3  # Number of retransmissions before marking strategy as failed
        
        self.logger.info("ProcessedPacketCache initialized for retransmission deduplication")
        
        # Initialize runtime packet filter and WinDivert filter generator
        self._runtime_filter = None
        self._windivert_generator = None
        self._use_runtime_filtering = False

        if RuntimePacketFilter and FilterConfig and WinDivertFilterGenerator:
            try:
                # Initialize with blacklist mode and load domains from sites.txt
                domains = self._load_domains_from_sites_file()
                default_config = FilterConfig(mode=FilterMode.BLACKLIST, domains=domains)
                self._runtime_filter = RuntimePacketFilter(default_config)
                self._windivert_generator = WinDivertFilterGenerator()

                # Simple port-based filtering is now always enabled
                self.logger.info(
                    "Using simple port-based WinDivert filtering (no IP list based filtering)"
                )

                self.logger.info("Runtime packet filtering components initialized")
            except Exception as e:
                self.logger.warning(f"Failed to initialize runtime filtering: {e}")
                self._runtime_filter = None
                self._windivert_generator = None
        else:
            self.logger.warning(
                "Runtime filtering components not available, using legacy IP-based filtering"
            )

        # Автоматически включаем runtime‑фильтрацию, если её разрешает фича‑флаг
        self._check_and_enable_runtime_filtering()

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

    def set_shared_pcap_file(self, pcap_file: str) -> None:
        """
        Set shared PCAP file for continuous packet capture.
        
        Args:
            pcap_file: Path to PCAP file where packets will be written
        """
        self._shared_pcap_file = pcap_file
        self.logger.info(f"📝 Shared PCAP file set: {pcap_file}")
    
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
    
    def enable_domain_based_filtering(self) -> bool:
        """
        Enable domain-based filtering at runtime.
        
        Returns:
            True if domain-based filtering was enabled successfully
        """
        if self._use_domain_based_filtering and self._domain_strategy_engine:
            self.logger.info("✅ Domain-based filtering is already enabled")
            return True
        
        # Try to initialize domain strategy engine
        self._initialize_domain_strategy_engine()
        
        if self._use_domain_based_filtering and self._domain_strategy_engine:
            self.logger.info("✅ Domain-based filtering enabled successfully")
            return True
        else:
            self.logger.error("❌ Failed to enable domain-based filtering")
            return False
    
    def disable_domain_based_filtering(self) -> bool:
        """
        Disable domain-based filtering and fall back to legacy IP-based filtering.
        
        Returns:
            True if domain-based filtering was disabled successfully
        """
        if not self._use_domain_based_filtering:
            self.logger.info("✅ Domain-based filtering is already disabled (using legacy IP-based filtering)")
            return True
        
        try:
            self._domain_strategy_engine = None
            self._use_domain_based_filtering = False
            
            self.logger.warning("🔄 Domain-based filtering disabled, using legacy IP-based filtering")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Failed to disable domain-based filtering: {e}")
            return False
    
    def enable_runtime_ip_resolution(self) -> bool:
        """
        Enable runtime IP-to-domain resolution in the domain strategy engine.
        
        Returns:
            True if runtime IP resolution was enabled successfully
        """
        if not self._use_domain_based_filtering or not self._domain_strategy_engine:
            self.logger.error("❌ Domain-based filtering is not enabled, cannot enable IP resolution")
            return False
        
        try:
            return self._domain_strategy_engine.enable_ip_resolution()
        except Exception as e:
            self.logger.error(f"❌ Failed to enable runtime IP resolution: {e}")
            return False
    
    def disable_runtime_ip_resolution(self) -> bool:
        """
        Disable runtime IP-to-domain resolution and fall back to SNI-only domain extraction.
        
        When disabled, packets without SNI will use the default strategy instead of
        performing reverse DNS lookups.
        
        Returns:
            True if runtime IP resolution was disabled successfully
        """
        if not self._use_domain_based_filtering or not self._domain_strategy_engine:
            self.logger.error("❌ Domain-based filtering is not enabled, cannot disable IP resolution")
            return False
        
        try:
            return self._domain_strategy_engine.disable_ip_resolution()
        except Exception as e:
            self.logger.error(f"❌ Failed to disable runtime IP resolution: {e}")
            return False
    
    def is_runtime_ip_resolution_enabled(self) -> bool:
        """
        Check if runtime IP resolution is currently enabled.
        
        Returns:
            True if IP resolution is enabled, False otherwise
        """
        if not self._use_domain_based_filtering or not self._domain_strategy_engine:
            return False
        
        try:
            return self._domain_strategy_engine.is_ip_resolution_enabled()
        except Exception as e:
            self.logger.error(f"❌ Failed to check IP resolution status: {e}")
            return False
    
    def get_filtering_mode(self) -> str:
        """
        Get the current filtering mode.
        
        Returns:
            String describing the current filtering mode
        """
        if self._use_domain_based_filtering and self._domain_strategy_engine:
            return "domain-based"
        elif self._use_runtime_filtering and self._runtime_filter:
            return "runtime-filtering"
        else:
            return "legacy-ip-based"
    
    def _handle_domain_extraction_failure(self) -> None:
        """
        Handle domain extraction failure and implement automatic fallback logic.
        
        If domain extraction fails repeatedly, automatically fall back to legacy
        IP-based filtering to maintain system stability.
        """
        import time
        
        self._domain_extraction_failures += 1
        self._last_domain_extraction_failure_time = time.time()
        
        if self._domain_extraction_failures >= self._domain_extraction_failure_threshold:
            self.logger.error(
                f"❌ Domain extraction failed {self._domain_extraction_failures} times consecutively"
            )
            self.logger.error("🔄 Automatically falling back to legacy IP-based filtering")
            
            # Disable domain-based filtering
            self._domain_strategy_engine = None
            self._use_domain_based_filtering = False
            
            # Reset failure counter
            self._domain_extraction_failures = 0
            
            self.logger.warning("⚠️ AUTOMATIC FALLBACK: Domain-based filtering disabled due to repeated failures")
            self.logger.info("   System will continue using legacy IP-based filtering")
            self.logger.info("   To re-enable domain filtering, restart the service or call enable_domain_based_filtering()")
    
    def _handle_domain_extraction_success(self) -> None:
        """
        Handle successful domain extraction.
        
        Resets failure counters when domain extraction succeeds.
        """
        if self._domain_extraction_failures > 0:
            self.logger.debug(f"Domain extraction recovered after {self._domain_extraction_failures} failures")
            self._domain_extraction_failures = 0
        
        self._domain_extraction_success_count += 1
    
    def create_configuration_rollback_point(self) -> str:
        """
        Create a rollback point for current configuration.
        
        This method creates backups of current configuration files that can be
        used to rollback in case of issues with domain-based filtering.
        
        Returns:
            Path to the rollback directory
        """
        import shutil
        import time
        
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        rollback_dir = Path(f"config_rollback_{timestamp}")
        
        try:
            rollback_dir.mkdir(exist_ok=True)
            
            # Files to backup
            config_files = [
                "domain_rules.json",
                "sites.txt", 
                "config/engine_config.json",
                "config/feature_flags.json",
                "strategies.txt",
                "domain_strategies.json"
            ]
            
            backed_up_files = []
            for config_file in config_files:
                source_path = Path(config_file)
                if source_path.exists():
                    dest_path = rollback_dir / source_path.name
                    shutil.copy2(source_path, dest_path)
                    backed_up_files.append(config_file)
            
            # Create rollback info file
            rollback_info = {
                "timestamp": timestamp,
                "filtering_mode": self.get_filtering_mode(),
                "domain_based_filtering_enabled": self._use_domain_based_filtering,
                "backed_up_files": backed_up_files,
                "instructions": [
                    "To rollback: copy files from this directory back to their original locations",
                    "Restart the service after rollback",
                    "Check logs for any configuration issues"
                ]
            }
            
            import json
            with open(rollback_dir / "rollback_info.json", 'w') as f:
                json.dump(rollback_info, f, indent=2)
            
            self.logger.info(f"✅ Configuration rollback point created: {rollback_dir}")
            self.logger.info(f"   Backed up {len(backed_up_files)} configuration files")
            
            return str(rollback_dir)
            
        except Exception as e:
            self.logger.error(f"❌ Failed to create rollback point: {e}")
            raise
    
    def emergency_rollback_to_legacy(self) -> bool:
        """
        Emergency rollback to legacy IP-based filtering.
        
        This method immediately disables domain-based filtering and falls back
        to legacy IP-based filtering without requiring restart.
        
        Returns:
            True if rollback was successful
        """
        try:
            # Create rollback point first
            rollback_dir = self.create_configuration_rollback_point()
            
            # Disable domain-based filtering
            self._domain_strategy_engine = None
            self._use_domain_based_filtering = False
            
            # Reset failure counters
            self._domain_extraction_failures = 0
            self._domain_extraction_success_count = 0
            
            # Disable runtime filtering if active
            if self._use_runtime_filtering:
                self.disable_runtime_filtering()
            
            self.logger.warning("🚨 EMERGENCY ROLLBACK: Switched to legacy IP-based filtering")
            self.logger.info(f"   Configuration backed up to: {rollback_dir}")
            self.logger.info("   System will continue with legacy IP-based filtering")
            self.logger.info("   Review logs and configuration before re-enabling domain-based filtering")
            
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Emergency rollback failed: {e}")
            return False
    
    def enable_runtime_filtering(self, filter_config: Optional[Dict[str, Any]] = None) -> bool:
        """
        Enable runtime packet filtering mode.
        
        Args:
            filter_config: Optional filter configuration dict with 'mode' and 'domains'
            
        Returns:
            True if runtime filtering was enabled successfully
        """
        if not self._runtime_filter or not self._windivert_generator:
            self.logger.error("Runtime filtering components not available")
            return False
        
        try:
            if filter_config:
                # Parse filter configuration
                mode_str = filter_config.get('mode', 'blacklist')  # Default to blacklist
                domains = set(filter_config.get('domains', []))
                
                if mode_str == 'blacklist':
                    mode = FilterMode.BLACKLIST
                elif mode_str == 'whitelist':
                    mode = FilterMode.WHITELIST
                else:
                    mode = FilterMode.NONE
                
                # If no domains provided, load from sites.txt
                if not domains and mode != FilterMode.NONE:
                    domains = self._load_domains_from_sites_file()
                
                config = FilterConfig(mode=mode, domains=domains)
                self._runtime_filter.update_configuration(config)
            else:
                # Default configuration: blacklist mode with domains from sites.txt
                domains = self._load_domains_from_sites_file()
                config = FilterConfig(mode=FilterMode.BLACKLIST, domains=domains)
                self._runtime_filter.update_configuration(config)
            
            # Enable runtime filtering
            # Note: WinDivertFilterGenerator doesn't need explicit enable call
            self._use_runtime_filtering = True
            
            self.logger.info("Runtime packet filtering enabled")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to enable runtime filtering: {e}")
            return False
    
    def _initialize_domain_strategy_engine(self) -> None:
        """
        Initialize domain-based strategy engine components.
        
        This method checks feature flags and environment variables to determine
        if domain-based filtering should be enabled, then loads domain rules
        from configuration and initializes the domain strategy engine.
        """
        # Check environment variable first (highest priority)
        import os
        env_enabled = os.getenv('USE_DOMAIN_BASED_FILTERING', '').lower() in ('true', '1', 'yes', 'on')
        
        # Check feature flag
        feature_flag_enabled = False
        if is_domain_based_filtering_enabled:
            try:
                feature_flag_enabled = is_domain_based_filtering_enabled()
            except Exception as e:
                self.logger.warning(f"Failed to check domain-based filtering feature flag: {e}")
        
        # Determine if domain-based filtering should be enabled
        should_enable = env_enabled or feature_flag_enabled
        
        if not should_enable:
            self.logger.info("🔄 Domain-based filtering disabled (using legacy IP-based filtering)")
            self.logger.info("   To enable: set USE_DOMAIN_BASED_FILTERING=true or enable feature flag")
            self._domain_strategy_engine = None
            self._use_domain_based_filtering = False
            return
        
        if not DomainStrategyEngine or not DomainRuleRegistry:
            self.logger.error("❌ Domain strategy engine components not available, falling back to legacy IP-based filtering")
            self.logger.error("   This may indicate missing domain engine modules")
            self._domain_strategy_engine = None
            self._use_domain_based_filtering = False
            return
        
        try:
            # Initialize domain rule registry
            domain_registry = DomainRuleRegistry("domain_rules.json")
            
            # Get domain rules and default strategy
            domain_rules = domain_registry.get_all_domain_rules()
            default_strategy = domain_registry.get_default_strategy()
            
            # Initialize domain strategy engine
            self._domain_strategy_engine = DomainStrategyEngine(domain_rules, default_strategy)
            self._use_domain_based_filtering = True
            
            # Log which method enabled domain-based filtering
            if env_enabled:
                self.logger.info(f"✅ Domain-based filtering enabled via environment variable")
            else:
                self.logger.info(f"✅ Domain-based filtering enabled via feature flag")
            
            self.logger.info(f"✅ Domain strategy engine initialized with {len(domain_rules)} domain rules")
            
        except Exception as e:
            self.logger.error(f"❌ Failed to initialize domain strategy engine: {e}")
            self.logger.error("   Falling back to legacy IP-based filtering")
            self._domain_strategy_engine = None
            self._use_domain_based_filtering = False

    def _check_and_enable_runtime_filtering(self) -> None:
        """
        Check feature flags and automatically enable runtime filtering if enabled.
        """
        if not is_runtime_filtering_enabled:
            self.logger.warning("Feature flags system not available, using legacy IP-based filtering")
            return
            
        try:
            if is_runtime_filtering_enabled():
                self.logger.info("Runtime filtering feature flag is enabled, activating runtime filtering")
                
                # Enable runtime filtering with default configuration
                success = self.enable_runtime_filtering()
                if success:
                    self.logger.info("✅ Runtime packet filtering activated via feature flag")
                else:
                    self.logger.error("❌ Failed to activate runtime filtering despite feature flag being enabled")
            else:
                self.logger.info("Runtime filtering feature flag is disabled, using legacy IP-based filtering")
                
        except Exception as e:
            self.logger.error(f"Error checking runtime filtering feature flag: {e}")

    def disable_runtime_filtering(self) -> bool:
        """
        Disable runtime packet filtering mode (use legacy IP-based filtering).
        
        Returns:
            True if runtime filtering was disabled successfully
        """
        if not self._windivert_generator:
            self.logger.error("WinDivert filter generator not available")
            return False
        
        try:
            self._windivert_generator.disable_runtime_filtering()
            self._use_runtime_filtering = False
            
            self.logger.info("Runtime packet filtering disabled, using legacy IP-based filtering")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to disable runtime filtering: {e}")
            return False
    
    def update_runtime_filter_config(self, filter_config: Dict[str, Any]) -> bool:
        """
        Update runtime filter configuration.
        
        Args:
            filter_config: Filter configuration dict with 'mode' and 'domains'
            
        Returns:
            True if configuration was updated successfully
        """
        if not self._runtime_filter:
            self.logger.error("Runtime filter not available")
            return False
        
        try:
            # Parse filter configuration
            mode_str = filter_config.get('mode', 'none')
            domains = set(filter_config.get('domains', []))
            
            if mode_str == 'blacklist':
                mode = FilterMode.BLACKLIST
            elif mode_str == 'whitelist':
                mode = FilterMode.WHITELIST
            else:
                mode = FilterMode.NONE
            
            config = FilterConfig(mode=mode, domains=domains)
            self._runtime_filter.update_configuration(config)
            
            self.logger.info(f"Runtime filter configuration updated: mode={mode.value}, domains={len(domains)}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update runtime filter configuration: {e}")
            return False

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
        
        # Stop cleanup thread for processed packet cache (Requirement 11.4)
        if hasattr(self, '_processed_packet_cache'):
            self._processed_packet_cache.stop_cleanup_thread()
            self.logger.info(f"🧹 Processed packet cache cleanup stopped. Total retransmissions detected: {self._retransmission_count}")

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
    
    def _is_tcp_handshake(self, packet) -> bool:
        """
        Check if packet is part of TCP 3-way handshake.
        
        Task 19: Fix TCP handshake issue - Don't apply strategy to TCP handshake packets.
        This ensures curl can establish TCP connection before TLS handshake.
        
        Returns:
            True if packet is TCP handshake (SYN, SYN-ACK, or ACK without data)
            False otherwise
        """
        try:
            # Check if packet has TCP layer
            if not packet.tcp or len(packet.tcp.raw) < 14:
                return False
            
            # Extract TCP flags (byte 13 in TCP header)
            tcp_flags = bytes(packet.tcp.raw)[13]
            
            # TCP flag constants
            SYN_FLAG = 0x02
            ACK_FLAG = 0x10
            
            # Check for SYN (with or without ACK) - this is SYN or SYN-ACK
            if tcp_flags & SYN_FLAG:
                return True
            
            # Check for pure ACK without payload (final handshake ACK)
            if tcp_flags == ACK_FLAG and not packet.payload:
                return True
            
            return False
            
        except Exception as e:
            self.logger.debug(f"Error checking TCP handshake: {e}")
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
        """
        Проверка, подпадает ли IP под целевые.

        - Если target_ips пуст – считаем, что целевой любой IP.
        - Если IP явно в списке – целевой.
        - Иначе проверяем по известным CDN‑префиксам.
        """
        if not target_ips:
            return True
        if ip_str in target_ips:
            return True

        if any(ip_str.startswith(prefix) for prefix in CDN_PREFIXES):
            self.logger.debug("IP %s соответствует одному из CDN‑префиксов", ip_str)
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

    def _run_bypass_loop(self, target_ips: Set[str], strategy_map: Dict[str, Dict]):
        filtering_mode = self.get_filtering_mode()
        self.logger.info(
            f"🔍 BYPASS LOOP STARTED: target_ips={len(target_ips)} (for reference only), "
            f"strategies={len(strategy_map)}, filtering_mode={filtering_mode}"
        )

        if filtering_mode == "domain-based":
            self.logger.info("   ℹ️  Domain-based filtering: packets filtered by SNI, not by IP")
            self.logger.info("   ℹ️  IP addresses above are for logging only, actual filtering uses TLS SNI")

        # Generate WinDivert filter based on filtering mode
        filter_str = self._generate_windivert_filter(target_ips)
        self.logger.info(f"🔍 WinDivert filter: {filter_str}")

        try:
            # Подробная документация по жизненному циклу пакетов WinDivert
            #
            # См. комментарий в исходном коде – оставлен без изменений,
            # чтобы не терять объяснения по flags=0 и priority=1000.
            with pydivert.WinDivert(filter_str, priority=1000, flags=0) as w:
                self.logger.info("✅ WinDivert запущен успешно.")
                self.logger.info("🔒 Original packet blocking enabled (identical to testing mode)")

                # CRITICAL FIX: Initialize PCAP writer if shared PCAP file is set
                pcap_writer = None
                IP_layer = None  # тип scapy слоя IP, если scapy доступен

                if hasattr(self, "_shared_pcap_file") and self._shared_pcap_file:
                    try:
                        from scapy.all import PcapWriter, IP as _ScapyIP

                        IP_layer = _ScapyIP
                        pcap_writer = PcapWriter(
                            self._shared_pcap_file, append=True, sync=True
                        )
                        self.logger.info(
                            f"📝 PCAP writer initialized: {self._shared_pcap_file}"
                        )
                        
                        # CRITICAL FIX: Pass PCAP writer to PacketSender so sent packets are recorded
                        if hasattr(self, "_packet_sender") and self._packet_sender:
                            self._packet_sender.set_pcap_writer(pcap_writer)
                            self.logger.debug("📝 PCAP writer passed to PacketSender")
                    except Exception as e:
                        self.logger.warning(
                            f"⚠️ Failed to initialize PCAP writer: {e}"
                        )
                        pcap_writer = None
                        IP_layer = None

                try:
                    while self.running:
                        packet = w.recv()

                        # В норме pydivert.WinDivert.recv() не возвращает None,
                        # но оставим защиту на случай нестандартного поведения.
                        if packet is None:
                            self.logger.warning(
                                "⏱️ WinDivert timeout: recv() returned None. "
                                "With flags=0, packets should NOT be auto-forwarded. "
                                "This may indicate a WinDivert driver issue or system overload."
                            )
                            continue

                        # Пропускаем наши же инжектированные пакеты
                        pkt_mark = getattr(packet, "mark", 0)
                        if pkt_mark == self._INJECT_MARK:
                            self.logger.debug(
                                "✅ Passing through marked packet (mark=%s)", pkt_mark
                            )
                            w.send(packet)
                            continue
                        elif pkt_mark != 0:
                            self.logger.warning(
                                "⚠️ Packet with unexpected mark: %s (expected %s)",
                                pkt_mark,
                                self._INJECT_MARK,
                            )

                        self.stats["packets_captured"] += 1

                        # Запись в PCAP (если включена)
                        if pcap_writer and IP_layer is not None:
                            try:
                                # Convert memoryview to bytes for Scapy
                                raw_bytes = bytes(packet.raw) if isinstance(packet.raw, memoryview) else packet.raw
                                scapy_pkt = IP_layer(raw_bytes)
                                pcap_writer.write(scapy_pkt)
                            except Exception as e:
                                # Чтобы не заспамить лог – пишем только первые несколько ошибок
                                if self.stats["packets_captured"] <= 5:
                                    self.logger.debug(
                                        "Failed to write packet to PCAP: %s", e
                                    )

                        # Решаем, применять ли обход к этому пакету
                        try:
                            should_apply = self._should_apply_bypass_to_packet(
                                packet, target_ips
                            )
                        except Exception as e:
                            self.logger.error(
                                "Error in _should_apply_bypass_to_packet: %s", e
                            )
                            should_apply = False

                        if should_apply and getattr(packet, "payload", None):
                            # Не трогаем TCP‑handshake – только последующий трафик
                            if self._is_tcp_handshake(packet):
                                self.logger.debug(
                                    "⏭️ Skipping TCP handshake packet: %s:%s → %s:%s",
                                    packet.src_addr,
                                    packet.src_port,
                                    packet.dst_addr,
                                    packet.dst_port,
                                )
                                w.send(packet)
                                continue

                            payload_bytes = bytes(packet.payload)
                            if self._is_tls_clienthello(payload_bytes):
                                with self._tlock:
                                    self._telemetry["clienthellos"] += 1

                                strategy_result = None
                                strategy_task = None

                                # Доменные стратегии, если включены
                                if (
                                    self._use_domain_based_filtering
                                    and self._domain_strategy_engine
                                ):
                                    try:
                                        strategy_result = (
                                            self._domain_strategy_engine.get_strategy_for_packet(
                                                packet
                                            )
                                        )
                                        if strategy_result and strategy_result.strategy:
                                            if self.strategy_override:
                                                strategy_task = self.strategy_override
                                                self.logger.debug(
                                                    "🧪 Using override strategy "
                                                    "(testing mode): %s",
                                                    self.strategy_override.get(
                                                        "type", "unknown"
                                                    ),
                                                )
                                            else:
                                                strategy_task = (
                                                    strategy_result.strategy
                                                )
                                                self.logger.debug(
                                                    "📋 Using domain strategy: %s",
                                                    strategy_task.get(
                                                        "type", "unknown"
                                                    ),
                                                )
                                            self._handle_domain_extraction_success()
                                        else:
                                            # Не удалось извлечь домен/стратегию
                                            self._handle_domain_extraction_failure()
                                    except Exception as e:
                                        self.logger.warning(
                                            "Domain strategy engine failed: %s", e
                                        )
                                        self._handle_domain_extraction_failure()

                                # Если доменная стратегия не выбрана или доменный движок
                                # отключён/упал – используем легаси‑логику.
                                if not strategy_task:
                                    strategy_task = (
                                        self.strategy_override
                                        or strategy_map.get(packet.dst_addr)
                                        or strategy_map.get("default")
                                    )
                                    strategy_result = None

                                if strategy_task:
                                    # Предварительная валидация стратегии
                                    packet_info = {
                                        "src_addr": packet.src_addr,
                                        "src_port": packet.src_port,
                                        "dst_addr": packet.dst_addr,
                                        "dst_port": packet.dst_port,
                                    }
                                    if not self._validate_strategy_before_application(
                                        packet_info, strategy_task
                                    ):
                                        self.logger.warning(
                                            "Strategy validation failed, "
                                            "forwarding packet without bypass"
                                        )
                                        w.send(packet)
                                        continue

                                    self.stats["tls_packets_bypassed"] += 1
                                    self.apply_bypass(
                                        packet,
                                        w,
                                        strategy_task,
                                        forced=True,
                                        strategy_result=strategy_result,
                                    )
                                else:
                                    # Нет подходящей стратегии – просто форвардим пакет
                                    w.send(packet)
                            else:
                                # Не ClientHello – пропускаем без модификаций
                                w.send(packet)
                        else:
                            # Для остальных пакетов просто форвардинг
                            w.send(packet)
                finally:
                    # CRITICAL FIX: Close PCAP writer
                    if pcap_writer:
                        try:
                            pcap_writer.close()
                            self.logger.info(
                                f"📝 PCAP writer closed: {self._shared_pcap_file}"
                            )
                        except Exception as e:
                            self.logger.warning(
                                f"⚠️ Failed to close PCAP writer: {e}"
                            )
        except Exception as e:
            if self.running:
                self.logger.error(
                    f"❌ Критическая ошибка в цикле WinDivert: {e}", exc_info=self.debug
                )
            self.running = False
    
    def _generate_windivert_filter(self, target_ips: Set[str] = None) -> str:
        """
        Generate WinDivert filter with loopback exclusion and IPv6 support.
        
        Based on expert recommendations to prevent duplicate capture and support IPv6.
        
        Filter components:
        - outbound: Only outbound traffic (no inbound)
        - !loopback: Exclude loopback traffic (prevents duplicate capture)
        - (ip or ipv6): Support both IPv4 and IPv6
        - tcp: Only TCP protocol
        - Port filter: 443 (HTTPS) and 80 (HTTP)
        
        Args:
            target_ips: Ignored - IP addresses are no longer used for filtering
            
        Returns:
            WinDivert filter string with loopback exclusion and IPv6 support
        """
        # Согласно требованиям 4.1, 4.2 и рекомендациям экспертов
        target_ports = {80, 443}
        
        if self._windivert_generator:
            # Используем генератор фильтров с улучшенными параметрами
            try:
                filter_str = self._windivert_generator.generate(
                    target_ports=target_ports,
                    direction="outbound",
                    protocols=("tcp",),  # Only TCP, no UDP
                    exclude_loopback=True,  # Exclude loopback
                    ipv6_support=True  # Support IPv6
                )
                self.logger.info(f"Generated WinDivert filter using generator: {filter_str}")
                return filter_str
            except TypeError:
                # Generator doesn't support new parameters, fall back
                self.logger.warning("WinDivert generator doesn't support new parameters, using fallback")
        
        # Fallback к ручной генерации улучшенного фильтра
        # WinDivert filter syntax: exclude loopback by checking IP addresses
        # Loopback: 127.0.0.0/8 for IPv4, ::1 for IPv6
        # Note: WinDivert uses "ip.DstAddr" and "ipv6.DstAddr" for destination addresses
        fallback_filter = (
            "outbound and tcp and "
            "(tcp.DstPort == 443 or tcp.DstPort == 80) and "
            "((ip and ip.DstAddr != 127.0.0.1) or "
            "(ipv6 and ipv6.DstAddr != ::1))"
        )
        self.logger.info(f"Generated enhanced WinDivert filter: {fallback_filter}")
        self.logger.info("  ✅ Loopback excluded (prevents duplicate capture)")
        self.logger.info("  ✅ IPv6 supported (handles AAAA records)")
        self.logger.info("  ✅ TCP only (no UDP/QUIC)")
        return fallback_filter
    
    def _should_apply_bypass_to_packet(self, packet, target_ips: Set[str]) -> bool:
        """
        Determine if bypass should be applied to this packet.
        """
        if self._use_domain_based_filtering and self._domain_strategy_engine:
            # Для доменной фильтрации обрабатываем весь TCP‑трафик на целевых портах,
            # само решение по домену принимается позже.
            target_ports = {80, 443}
            return (
                self._is_tcp(packet)
                and hasattr(packet, "dst_port")
                and packet.dst_port in target_ports
            )
        elif self._use_runtime_filtering and self._runtime_filter:
            # Используем runtime‑фильтр
            try:
                return self._runtime_filter.should_apply_bypass(packet)
            except Exception as e:
                self.logger.warning(f"Runtime filter error: {e}")
                # Fallback к легаси‑логике при ошибке
                return self._is_target_ip(packet.dst_addr, target_ips)
        else:
            # Легаси‑режим: по IP
            return self._is_target_ip(packet.dst_addr, target_ips)

    def _proto(self, packet) -> int:
        p = getattr(packet, "protocol", None)
        if isinstance(p, tuple) and p:
            return int(p[0])
        return int(p) if p is not None else 0

    def _is_udp(self, packet) -> bool:
        return self._proto(packet) == 17

    def _is_tcp(self, packet) -> bool:
        return self._proto(packet) == 6

    def _execute_attack_unified(
        self,
        strategy_task: Dict[str, Any],
        payload: bytes,
        packet_info: Dict[str, Any],
        mode: str = "production"
    ) -> Optional[ExecutionResult]:
        """
        Execute attack using UnifiedAttackExecutor for testing-production parity.
        
        This method is the SINGLE entry point for attack execution in both testing
        and production modes, ensuring identical behavior.
        
        Args:
            strategy_task: Strategy configuration
            payload: Packet payload
            packet_info: Packet information (src_addr, dst_addr, src_port, dst_port)
            mode: Execution mode ("testing" or "production")
            
        Returns:
            ExecutionResult with success status and segments, or None on error
        """
        import uuid
        
        # Generate correlation ID for tracing
        correlation_id = str(uuid.uuid4())[:8]
        
        # Create execution context
        context = ExecutionContext(
            mode=mode,
            payload=payload,
            packet_info=packet_info,
            strategy=strategy_task,
            correlation_id=correlation_id
        )
        
        # Execute attack through unified executor
        result = self._unified_executor.execute_attack(context)
        
        return result
    
    def _recipe_to_specs(
        self, recipe: List[Tuple[bytes, int, dict]], payload: bytes, strategy_task: Optional[Dict] = None
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

                # Handle tcp_flags - can be int, hex string, or TCP flag string like 'PA'
                tcp_flags_raw = opts.get("tcp_flags", 0x18)
                if isinstance(tcp_flags_raw, int):
                    tcp_flags = tcp_flags_raw
                elif isinstance(tcp_flags_raw, str):
                    # Handle TCP flag strings like 'PA', 'PSH', 'ACK', etc.
                    flag_map = {
                        'PA': 0x18, 'PSH+ACK': 0x18, 'AP': 0x18,
                        'A': 0x10, 'ACK': 0x10,
                        'S': 0x02, 'SYN': 0x02,
                        'SA': 0x12, 'SYN+ACK': 0x12, 'AS': 0x12,
                        'F': 0x01, 'FIN': 0x01,
                        'R': 0x04, 'RST': 0x04,
                        'P': 0x08, 'PSH': 0x08,
                    }
                    tcp_flags = flag_map.get(tcp_flags_raw.upper())
                    if tcp_flags is None:
                        try:
                            tcp_flags = int(tcp_flags_raw, 0)
                        except ValueError:
                            self.logger.warning(f"Unknown tcp_flags format: {tcp_flags_raw}, using default 0x18")
                            tcp_flags = 0x18
                else:
                    tcp_flags = 0x18

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

                # Task 6.1: Validate rel_seq before creating spec (Requirements 6.1, 6.2)
                payload_len = len(payload or b"")
                
                # CRITICAL FIX: Allow negative rel_seq for disorder attacks
                # Disorder=reverse creates segments with negative offsets (e.g., 0, -99, -198...)
                # These are valid because they represent positions relative to the END of payload
                # The actual TCP sequence number will be calculated as: base_seq + rel_seq
                # For disorder, this means segments are sent in reverse order
                
                # Only validate that rel_seq is within reasonable bounds
                # For real segments: rel_seq should be within [-payload_len, payload_len)
                # For fake segments: any rel_seq is allowed (they're meant to be invalid)
                
                if not is_fake and payload_len > 0:
                    # For real segments, validate bounds
                    if offset >= payload_len:
                        self.logger.error(
                            f"❌ INVALID rel_seq in REAL segment #{i}: rel_seq={offset} >= payload_len={payload_len}. "
                            f"This would create a sequence number beyond the payload boundary. "
                            f"Segment will be skipped."
                        )
                        continue
                    # Note: Negative offsets are allowed for disorder attacks
                    # They represent positions relative to the end of payload
                
                # Log validation success for debugging
                if self.debug:
                    self.logger.debug(
                        f"✅ rel_seq validation passed for segment #{i}: "
                        f"rel_seq={offset}, payload_len={payload_len}, is_fake={is_fake}"
                    )

                # CRITICAL FIX: Use seq_offset from options (new approach) instead of seq_extra (legacy)
                # seq_offset is set by badseq fooling method to 0x10000000 to avoid sequence overlaps
                # If seq_offset is not in options, fall back to seq_extra for backward compatibility
                seq_offset_value = opts.get("seq_offset", None)
                seq_extra_value = opts.get("seq_extra", None)
                
                # Determine which offset to use:
                # 1. If seq_offset is present, use it (new behavior from badseq fooling)
                # 2. Otherwise, use seq_extra if present (legacy behavior)
                # 3. Otherwise, use default based on corrupt_sequence flag
                if seq_offset_value is not None:
                    # New approach: use seq_offset
                    final_seq_offset = int(seq_offset_value)
                    final_seq_extra = None
                elif seq_extra_value is not None:
                    # Legacy approach: use seq_extra
                    final_seq_offset = 0
                    final_seq_extra = int(seq_extra_value)
                else:
                    # Default: no offset, or -1 if corrupt_sequence is set
                    final_seq_offset = 0
                    final_seq_extra = -1 if opts.get("corrupt_sequence") else None
                
                spec = TCPSegmentSpec(
                    rel_seq=offset,
                    payload=seg_payload,
                    flags=tcp_flags,
                    ttl=ttl,
                    corrupt_tcp_checksum=bool(opts.get("corrupt_tcp_checksum", False)),
                    add_md5sig_option=bool(opts.get("add_md5sig_option", False)),
                    seq_offset=final_seq_offset,
                    seq_extra=final_seq_extra,
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

        # Task 2.4: Enhanced payload coverage validation
        try:
            L = len(payload or b"")
            if L > 0:
                # Create coverage array to track which bytes are covered by real segments
                covered = [False] * L
                
                # Track coverage by each segment for detailed logging
                segment_coverage = []
                
                for idx, s in enumerate(specs):
                    if getattr(s, "is_fake", False):
                        continue
                    
                    off, data_len = int(s.rel_seq), len(s.payload or b"")
                    segment_start = max(0, off)
                    segment_end = min(L, off + data_len)
                    
                    # Mark covered bytes
                    for j in range(segment_start, segment_end):
                        covered[j] = True
                    
                    # Log segment coverage for debugging
                    segment_coverage.append({
                        "segment_idx": idx,
                        "rel_seq": off,
                        "length": data_len,
                        "covers": f"[{segment_start}:{segment_end}]"
                    })
                    self.logger.debug(
                        f"📊 Segment {idx}: rel_seq={off}, len={data_len}, covers bytes [{segment_start}:{segment_end}]"
                    )

                # Find holes (uncovered byte ranges)
                holes = []
                hole_start = None
                for idx, is_covered in enumerate(covered):
                    if not is_covered:
                        if hole_start is None:
                            hole_start = idx
                    else:
                        if hole_start is not None:
                            holes.append((hole_start, idx))
                            hole_start = None
                # Handle hole at end
                if hole_start is not None:
                    holes.append((hole_start, L))
                
                if holes:
                    total_hole_bytes = sum(end - start for start, end in holes)
                    
                    # Task 6.4: Enhanced overlap detection for seqovl attacks (Requirement 6.4)
                    strategy_name = (
                        strategy_task.get("type", "")
                        if isinstance(strategy_task, dict)
                        else ""
                    )
                    
                    # For seqovl attacks, validate overlap size
                    if strategy_name == "seqovl":
                        # Get expected overlap_size from strategy parameters
                        params = strategy_task.get("params", {}) if isinstance(strategy_task, dict) else {}
                        expected_overlap = params.get("overlap_size", 0)
                        
                        # Seqovl attacks should have holes equal to overlap_size
                        # Allow some tolerance (±20%) for edge cases
                        if expected_overlap > 0:
                            min_expected = int(expected_overlap * 0.8)
                            max_expected = int(expected_overlap * 1.2)
                            
                            if total_hole_bytes < min_expected:
                                self.logger.warning(
                                    f"⚠️ Seqovl overlap too small: {total_hole_bytes} bytes < expected {expected_overlap} bytes. "
                                    f"Hole ranges: {holes[:5]}. This may indicate incorrect overlap calculation."
                                )
                            elif total_hole_bytes > max_expected:
                                self.logger.warning(
                                    f"⚠️ Seqovl overlap too large: {total_hole_bytes} bytes > expected {expected_overlap} bytes. "
                                    f"Hole ranges: {holes[:5]}. This may cause connection issues."
                                )
                            else:
                                self.logger.debug(
                                    f"✅ Seqovl overlap validated: {total_hole_bytes} bytes matches expected {expected_overlap} bytes. "
                                    f"Hole ranges: {holes[:5]}"
                                )
                        else:
                            # No overlap_size specified, allow small holes (legacy behavior)
                            if total_hole_bytes <= 20:
                                self.logger.warning(
                                    f"⚠️ Seqovl overlap: {total_hole_bytes} bytes not covered (normal for overlap). "
                                    f"Hole ranges: {holes[:5]}"
                                )
                            else:
                                self.logger.error(
                                    f"‼️ Seqovl overlap too large: {total_hole_bytes} bytes without overlap_size parameter. "
                                    f"Hole ranges: {holes[:10]}"
                                )
                    else:
                        # Non-seqovl attacks should not have holes
                        # Log detailed error for payload coverage issues
                        self.logger.error(
                            f"‼️ CRITICAL PAYLOAD COVERAGE ERROR! "
                            f"Real segments have {len(holes)} hole(s) totaling {total_hole_bytes} bytes. "
                            f"Payload length: {L} bytes"
                        )
                        self.logger.error(f"Hole ranges: {holes[:10]}")
                        self.logger.error(f"Segment coverage: {segment_coverage}")
                        
                        if self.debug:
                            raise ValueError(
                                f"TCP stream has {len(holes)} holes totaling {total_hole_bytes} bytes at ranges: {holes[:10]}"
                            )
                else:
                    self.logger.debug(f"✅ Payload coverage validation passed: all {L} bytes covered by {len([s for s in specs if not getattr(s, 'is_fake', False)])} real segments")
                    
        except Exception as e:
            self.logger.debug(f"Error during payload coverage validation: {e}")

        self.logger.debug(f"Успешно сгенерировано {len(specs)} спецификаций сегментов.")
        return specs

    def _validate_strategy_before_application(
        self, packet_info: Dict[str, Any], strategy: Dict[str, Any]
    ) -> bool:
        """
        Validate strategy before applying it to a packet.
        """
        if not strategy:
            self.logger.error("❌ Strategy validation failed: strategy is None/empty")
            return False

        if not isinstance(strategy, dict):
            self.logger.error(
                "❌ Strategy validation failed: expected dict, got %s", type(strategy)
            )
            return False

        # Validation 1: Check strategy has 'type' field (Requirement 3.1)
        if "type" not in strategy:
            self.logger.error("❌ Strategy validation failed: missing 'type' field")
            self.logger.error("   Strategy: %s", strategy)
            self.logger.error(
                "   💡 Recommendation: Check domain_rules.json for malformed strategy entries"
            )
            return False

        strategy_type = strategy["type"]

        # Validation 2: Check strategy has 'params' field (Requirement 3.2)
        if "params" not in strategy:
            self.logger.warning(
                "⚠️ Strategy missing 'params' field, using empty params "
                "(type=%s)",
                strategy_type,
            )
            self.logger.warning(
                "   💡 Recommendation: Add 'params' field to strategy in domain_rules.json"
            )
            strategy["params"] = {}

        params = strategy.get("params", {})

        # Validation 3: Validate parameters are correct for strategy type (Requirement 3.3)
        if not self._validate_strategy_params(strategy_type, params):
            self.logger.error(
                "❌ Strategy validation failed: invalid parameters for strategy type '%s'",
                strategy_type,
            )
            self.logger.error("   Parameters: %s", params)
            self.logger.error(
                "   💡 Recommendation: Check parameter values in domain_rules.json"
            )
            return False

        # Validation 4: For combo strategies, check attacks field consistency (Requirement 3.4)
        attacks = strategy.get("attacks")
        if isinstance(attacks, (list, tuple)) and len(attacks) > 1:
            # Check that first attack matches strategy type
            if strategy_type != attacks[0]:
                self.logger.warning(
                    "⚠️ Strategy type mismatch: type='%s', attacks[0]='%s'",
                    strategy_type,
                    attacks[0],
                )
                self.logger.warning(
                    "   This may indicate a combo strategy configuration issue"
                )
                self.logger.warning(
                    "   💡 Recommendation: Ensure strategy type matches first attack in combo"
                )
                # Не считаем это фатальной ошибкой – только предупреждение.

            valid_attack_types = {
                "fake",
                "disorder",
                "disorder2",
                "split",
                "multisplit",
                "fakeddisorder",
                "multidisorder",
                "seqovl",
                "badseq",
            }

            for attack in attacks:
                if attack not in valid_attack_types:
                    self.logger.error("❌ Invalid attack type in combo: '%s'", attack)
                    self.logger.error("   Valid types: %s", valid_attack_types)
                    self.logger.error(
                        "   💡 Recommendation: Fix attack types in domain_rules.json"
                    )
                    return False

        self.logger.debug(
            "✅ Strategy validation passed: type='%s', params=%s",
            strategy_type,
            params,
        )
        return True
    
    def _validate_strategy_params(self, strategy_type: str, params: Dict) -> bool:
        """
        Validate that parameters are appropriate for the given strategy type.
        """
        # Validate split_pos if present
        if "split_pos" in params:
            split_pos = params["split_pos"]

            if isinstance(split_pos, int):
                if split_pos < 0:
                    self.logger.error("Invalid split_pos: %s (must be >= 0)", split_pos)
                    return False
            elif isinstance(split_pos, str):
                # Допускаем специальные значения и числовые строки
                valid_special = ["cipher", "midsld", "sni"]
                if split_pos in valid_special:
                    pass
                else:
                    try:
                        int(split_pos)
                    except ValueError:
                        self.logger.error(
                            "Invalid split_pos string: '%s' (valid specials: %s or int)",
                            split_pos,
                            valid_special,
                        )
                        return False
            elif isinstance(split_pos, list):
                if not all(
                    isinstance(p, int) and p >= 0
                    for p in split_pos  # список позиций
                ):
                    self.logger.error(
                        "Invalid split_pos list: %s (all entries must be int >= 0)",
                        split_pos,
                    )
                    return False
            else:
                self.logger.error(
                    "Invalid split_pos type: %s (must be int, str, or list)",
                    type(split_pos),
                )
                return False

        # Validate split_count if present
        if "split_count" in params:
            split_count = params["split_count"]
            if split_count is None:
                self.logger.warning("⚠️ split_count is None, setting default value: 8")
                params["split_count"] = 8
            else:
                if isinstance(split_count, str):
                    try:
                        split_count = int(split_count)
                        params["split_count"] = split_count
                    except ValueError:
                        self.logger.error(
                            "Invalid split_count string: %s (must be int >= 1)",
                            split_count,
                        )
                        return False
                if not isinstance(split_count, int) or split_count < 1:
                    self.logger.error(
                        "Invalid split_count: %s (must be int >= 1)", split_count
                    )
                    return False

        # Validate ttl/fake_ttl if present
        for ttl_param in ["ttl", "fake_ttl"]:
            if ttl_param in params:
                ttl = params[ttl_param]
                if isinstance(ttl, str):
                    try:
                        ttl = int(ttl)
                        params[ttl_param] = ttl
                    except ValueError:
                        self.logger.error(
                            "Invalid %s string: %s (must be int 1-255)",
                            ttl_param,
                            ttl,
                        )
                        return False
                if not isinstance(ttl, int) or ttl < 1 or ttl > 255:
                    self.logger.error(
                        "Invalid %s: %s (must be int 1-255)", ttl_param, ttl
                    )
                    return False

        # Validate autottl if present
        if "autottl" in params:
            autottl = params["autottl"]
            if isinstance(autottl, str):
                try:
                    autottl = int(autottl)
                    params["autottl"] = autottl
                except ValueError:
                    self.logger.error(
                        "Invalid autottl string: %s (must be int)", autottl
                    )
                    return False
            if not isinstance(autottl, int):
                self.logger.error("Invalid autottl: %s (must be int)", autottl)
                return False

        # Validate fooling if present
        if "fooling" in params:
            fooling = params["fooling"]
            valid_fooling = ["md5sig", "badsum", "badseq", "ts", "none"]

            if isinstance(fooling, str):
                if fooling not in valid_fooling:
                    self.logger.error(
                        "Invalid fooling method: '%s' (valid: %s)",
                        fooling,
                        valid_fooling,
                    )
                    return False
            elif isinstance(fooling, (list, tuple)):
                for method in fooling:
                    if method not in valid_fooling:
                        self.logger.error(
                            "Invalid fooling method in list: '%s' (valid: %s)",
                            method,
                            valid_fooling,
                        )
                        return False
            else:
                self.logger.error(
                    "Invalid fooling type: %s (must be str or list/tuple)",
                    type(fooling),
                )
                return False

        # Validate disorder_method if present
        if "disorder_method" in params:
            disorder_method = params["disorder_method"]
            valid_methods = ["swap", "reverse"]
            if disorder_method not in valid_methods:
                self.logger.error(
                    "Invalid disorder_method: '%s' (valid: %s)",
                    disorder_method,
                    valid_methods,
                )
                return False

        # Validate overlap_size if present (for seqovl)
        if "overlap_size" in params:
            overlap_size = params["overlap_size"]
            if isinstance(overlap_size, str):
                try:
                    overlap_size = int(overlap_size)
                    params["overlap_size"] = overlap_size
                except ValueError:
                    self.logger.error(
                        "Invalid overlap_size string: %s (must be int >= 0)",
                        overlap_size,
                    )
                    return False
            if not isinstance(overlap_size, int) or overlap_size < 0:
                self.logger.error(
                    "Invalid overlap_size: %s (must be int >= 0)", overlap_size
                )
                return False

        # Validate positions if present (for multisplit)
        if "positions" in params:
            positions = params["positions"]

            if positions is None:
                split_count = params.get("split_count", 8)
                if isinstance(split_count, str):
                    try:
                        split_count = int(split_count)
                        params["split_count"] = split_count
                    except ValueError:
                        self.logger.warning(
                            "Invalid split_count string for positions default: %s, using 8",
                            split_count,
                        )
                        split_count = 8
                split_pos = params.get("split_pos", 3)
                if isinstance(split_pos, str):
                    try:
                        split_pos = int(split_pos)
                    except ValueError:
                        split_pos = 3
                default_positions = [int(split_pos) + i * 6 for i in range(split_count)]
                self.logger.warning(
                    "⚠️ positions is None, generating default: %s", default_positions
                )
                params["positions"] = default_positions
            elif not isinstance(positions, list):
                self.logger.error("Invalid positions: %s (must be list)", positions)
                return False
            else:
                normalized_positions = []
                for p in positions:
                    if isinstance(p, str):
                        try:
                            p = int(p)
                        except ValueError:
                            self.logger.error(
                                "Invalid position value: %s (must be int >= 0)", p
                            )
                            return False
                    if not isinstance(p, int) or p < 0:
                        self.logger.error(
                            "Invalid positions list: %s (all must be int >= 0)",
                            positions,
                        )
                        return False
                    normalized_positions.append(p)
                params["positions"] = normalized_positions

        # Все проверки параметров успешно пройдены
        return True

    # --- START OF FINAL FIX: UNIFIED PACKET SUPPRESSION LOGIC ---
    def apply_bypass(
        self,
        packet: "pydivert.Packet",
        w: "pydivert.WinDivert",
        strategy_task: Dict,
        forced=True,
        strategy_result=None,
    ):
        """
        Унифицированный метод применения обхода DPI с правильной диспетчеризацией атак.
        """
        flow_key = (packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)
        now = time.time()

        # --- Извлекаем TCP‑последовательность и флаги один раз ---
        seq_num = None
        tcp_flags = 0
        if getattr(packet, "tcp", None) and getattr(packet.tcp, "raw", None):
            tcp_raw = bytes(packet.tcp.raw)
            if len(tcp_raw) >= 14:
                seq_num = struct.unpack("!I", tcp_raw[4:8])[0]
                tcp_flags = tcp_raw[13]

        # --- Обработка FIN/RST: очистка кэша и нормальная передача ---
        FIN_FLAG = 0x01
        RST_FLAG = 0x04
        if tcp_flags & (FIN_FLAG | RST_FLAG):
            self._processed_packet_cache.remove_flow(flow_key)
            flag_name = "FIN" if (tcp_flags & FIN_FLAG) else "RST"
            self.logger.debug(
                "🔌 Connection closing (%s): flow=%s, cleaning cache", flag_name, flow_key
            )
            w.send(packet)
            return

        # --- Дедупликация ретрансмиссий по (flow, seq) ---
        if seq_num is not None and self._processed_packet_cache.is_processed(
            flow_key, seq_num
        ):
            self._retransmission_count += 1
            self.logger.info(
                "🔄 RETRANSMISSION DETECTED: flow=%s, seq=0x%08X, total_retrans=%d",
                flow_key,
                seq_num,
                self._retransmission_count,
            )

            # Отслеживание неудачных стратегий по домену
            if strategy_result and getattr(strategy_result, "domain", None):
                domain = strategy_result.domain
                strategy_type = strategy_task.get("type", "unknown")

                domain_failures = self._failed_strategies.setdefault(domain, {})
                domain_failures[strategy_type] = domain_failures.get(strategy_type, 0) + 1
                failure_count = domain_failures[strategy_type]

                # Логирование через StrategyApplicationLogger (если есть)
                if (
                    self._domain_strategy_engine
                    and hasattr(
                        self._domain_strategy_engine, "strategy_application_logger"
                    )
                ):
                    self._domain_strategy_engine.strategy_application_logger.log_retransmission_detected(
                        domain=domain,
                        strategy=strategy_task,
                        retransmission_number=failure_count,
                        flow_key=flow_key,
                        seq_num=seq_num,
                    )
                else:
                    self.logger.warning(
                        "⚠️ Retransmission #%d for domain '%s' using strategy '%s'",
                        failure_count,
                        domain,
                        strategy_type,
                    )

                # Проверка порога неудач стратегии
                if failure_count >= self._strategy_failure_threshold:
                    needs_revalidation = False
                    if (
                        self._domain_strategy_engine
                        and hasattr(
                            self._domain_strategy_engine, "record_strategy_failure"
                        )
                    ):
                        needs_revalidation = (
                            self._domain_strategy_engine.record_strategy_failure(
                                domain=domain,
                                strategy=strategy_task,
                                retransmissions=failure_count,
                                reason=(
                                    f"Strategy failed with {failure_count} "
                                    f"retransmissions"
                                ),
                            )
                        )

                    if (
                        self._domain_strategy_engine
                        and hasattr(
                            self._domain_strategy_engine, "strategy_application_logger"
                        )
                    ):
                        self._domain_strategy_engine.strategy_application_logger.log_strategy_failure(
                            domain=domain,
                            strategy=strategy_task,
                            retransmissions=failure_count,
                            reason=(
                                f"Strategy failed with {failure_count} retransmissions"
                            ),
                        )

                    self.logger.error(
                        "❌ STRATEGY FAILURE: %s with strategy '%s' has %d retransmissions "
                        "(threshold: %d)",
                        domain,
                        strategy_type,
                        failure_count,
                        self._strategy_failure_threshold,
                    )
                    self.logger.error("💡 RECOMMENDATIONS:")

                    if needs_revalidation:
                        self.logger.error(
                            "   1. Run 'python cli.py revalidate %s' to find a new working strategy",
                            domain,
                        )
                        self.logger.error(
                            "   2. Run 'python cli.py list-failures' to see all failed strategies"
                        )
                    else:
                        self.logger.error(
                            "   1. Run 'cli.py test %s' to re-test the strategy", domain
                        )
                        self.logger.error(
                            "   2. Run 'cli.py auto %s' to find a new working strategy", domain
                        )

                    if "." in domain:
                        parts = domain.split(".")
                        if len(parts) > 2:
                            parent_domain = ".".join(parts[1:])
                            self.logger.error(
                                "   3. Try removing '%s' rule from domain_rules.json "
                                "to use parent domain '%s' strategy",
                                domain,
                                parent_domain,
                            )
                        else:
                            self.logger.error(
                                "   3. Check if DPI behavior has changed for this domain"
                            )
                    else:
                        self.logger.error(
                            "   3. Check if DPI behavior has changed for this domain"
                        )

                    if (
                        self._domain_strategy_engine
                        and hasattr(
                            self._domain_strategy_engine,
                            "parent_domain_recommender",
                        )
                    ):
                        recommendation = (
                            self._domain_strategy_engine.parent_domain_recommender.detect_and_recommend(
                                domain=domain,
                                failure_count=failure_count,
                                strategy=strategy_task,
                            )
                        )
                        if recommendation:
                            self.logger.info(
                                "✅ Parent domain recommendation generated for '%s'",
                                domain,
                            )

                    self._create_strategy_failure_diagnostic_report(
                        domain=domain,
                        strategy=strategy_task,
                        retransmissions=failure_count,
                        strategy_result=strategy_result,
                    )

            # Ретрансмиссию просто отбрасываем без повторного обхода
            return

        # --- Резервная защита от повторной обработки потока без seq_num ---
        # Используем flow‑уровень только если не удалось прочитать seq_num
        if seq_num is None:
            with self._lock:
                last_ts = self._processed_flows.get(flow_key)
                if last_ts is not None and (now - last_ts) < 1.5:
                    self.logger.debug(
                        "🔪 Dropping subsequent packet for already processed flow %s "
                        "(no seq_num available)",
                        flow_key,
                    )
                    return
                self._processed_flows[flow_key] = now
        else:
            # Для нормальных TCP‑пакетов ведём только seq‑кэш, flow‑кэш не нужен
            with self._lock:
                if len(self._processed_flows) > 2000:
                    cutoff = now - self._flow_timeout
                    self._processed_flows = {
                        k: t for k, t in self._processed_flows.items() if t >= cutoff
                    }

        injection_acquired = False
        try:
            # Семафор ограничивает количество одновременных инъекций
            if not self._inject_sema.acquire(blocking=False):
                self.logger.warning(
                    "Injection semaphore limit reached, forwarding original packet"
                )
                w.send(packet)
                return
            injection_acquired = True

            params = dict(strategy_task.get("params", {}))
            payload = bytes(packet.payload or b"")
            payload_len = len(payload)

            # Лог начала обработки пакета
            seq_display = f"0x{seq_num:08X}" if seq_num is not None else "N/A"
            self.logger.info(
                "Processing packet: src_port=%s, dst=%s:%s, seq=%s, len=%d",
                packet.src_port,
                packet.dst_addr,
                packet.dst_port,
                seq_display,
                payload_len,
            )

            # Расширенное логирование по домену / источнику
            if strategy_result:
                src = getattr(strategy_result, "source", "unknown")
                dom = getattr(strategy_result, "domain", "unknown")
                domain_part = f"{dom} [{str(src).upper()}]"
                log_msg = (
                    f"🔥 APPLY_BYPASS FIXED: dst={packet.dst_addr}:{packet.dst_port} "
                    f"({domain_part}), strategy={strategy_task.get('type', 'unknown')}, "
                    f"params={params}"
                )

                if src == "reverse_dns" and dom:
                    self.logger.info(
                        "🆕 NEW IP discovered: %s → %s", packet.dst_addr, dom
                    )
                    if getattr(strategy_result, "matched_rule", None):
                        self.logger.info(
                            "📋 Matched to parent domain: %s",
                            strategy_result.matched_rule,
                        )
                    self.logger.info("💾 Cached IP-to-domain mapping (TTL: 300s)")
                elif src == "cache" and dom:
                    self.logger.debug("✅ Cache hit: %s → %s", packet.dst_addr, dom)
            else:
                log_msg = (
                    f"🔥 APPLY_BYPASS FIXED: dst={packet.dst_addr}:{packet.dst_port}, "
                    f"strategy={strategy_task.get('type', 'unknown')}, params={params}"
                )

            self.logger.info(log_msg)

            # Валидация стратегии перед применением
            packet_info_for_validation = {
                "src_addr": packet.src_addr,
                "src_port": packet.src_port,
                "dst_addr": packet.dst_addr,
                "dst_port": packet.dst_port,
                "payload": payload,
            }

            if not self._validate_strategy_before_application(
                packet_info_for_validation, strategy_task
            ):
                self.logger.error(
                    "❌ Strategy validation failed, skipping packet "
                    "(forwarding original)"
                )
                self.logger.error(
                    "   💡 Recommendation: Check domain_rules.json "
                    "for correct strategy configuration"
                )
                w.send(packet)
                return

            # Определяем тип атаки с учётом combo‑стратегий
            attacks = strategy_task.get("attacks")
            if isinstance(attacks, (list, tuple)) and len(attacks) > 1:
                try:
                    attacks_str_list = [str(a) for a in attacks]
                    task_type = ",".join(attacks_str_list).lower()
                    self.logger.info(
                        "🔗 Using combination attack from 'attacks' field: %s "
                        "(attacks=%s)",
                        task_type,
                        attacks_str_list,
                    )
                except Exception as e:
                    self.logger.warning(
                        "Failed to build combo attack type from 'attacks': %s, "
                        "falling back to 'type' field (%s)",
                        e,
                        strategy_task.get("type"),
                    )
                    task_type = (strategy_task.get("type") or "fakeddisorder").lower()
            else:
                task_type = (strategy_task.get("type") or "fakeddisorder").lower()

            if payload_len == 0:
                w.send(packet)
                return

            # Расчёт TTL / fake_ttl
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

            # Подготовка packet_info для AttackDispatcher
            packet_info = {
                "src_addr": packet.src_addr,
                "dst_addr": packet.dst_addr,
                "src_port": packet.src_port,
                "dst_port": packet.dst_port,
            }
            if "_strategy_id" in strategy_task:
                packet_info["strategy_id"] = strategy_task["_strategy_id"]
            if strategy_result and getattr(strategy_result, "domain", None):
                packet_info["domain"] = strategy_result.domain

            dispatch_params = params.copy()

            # Расстановка TTL по типу атаки
            if task_type in ["seqovl", "fakeddisorder", "multidisorder"]:
                dispatch_params["fake_ttl"] = fake_ttl
            elif task_type in ["fake", "fake_race"]:
                dispatch_params["ttl"] = fake_ttl
            else:
                dispatch_params.setdefault("fake_ttl", fake_ttl)
                dispatch_params.setdefault("ttl", fake_ttl)

            if task_type == "seqovl":
                dispatch_params["overlap_size"] = int(
                    params.get("overlap_size", params.get("split_seqovl", 20))
                )

            # Диспетчеризация атаки
            try:
                self.logger.debug("🎯 Dispatching %s attack via AttackDispatcher", task_type)
                recipe = self._attack_dispatcher.dispatch_attack(
                    task_type, dispatch_params, payload, packet_info
                )
            except ValueError as e:
                self.logger.error(
                    "❌ Attack dispatch validation failed for '%s': %s", task_type, e
                )
                self.logger.warning(
                    "⚠️ FALLBACK: Sending original packet due to validation error"
                )
                self._update_fallback_metrics("validation_error")
                w.send(packet)
                return
            except Exception as e:
                self.logger.error(
                    "❌ Attack dispatch failed for '%s': %s", task_type, e, exc_info=self.debug
                )
                self.logger.warning(
                    "⚠️ FALLBACK: Sending original packet due to dispatch error"
                )
                self._update_fallback_metrics("dispatch_error")
                w.send(packet)
                return

            if not recipe:
                self.logger.error("❌ Recipe for %s was not generated", task_type)
                self.logger.warning(
                    "⚠️ FALLBACK: Sending original packet due to empty recipe"
                )
                self._update_fallback_metrics("empty_recipe")
                w.send(packet)
                return

            # Конвертация рецепта в спецификации сегментов
            try:
                specs = self._recipe_to_specs(recipe, payload, strategy_task)
            except Exception as e:
                self.logger.error(
                    "❌ Exception during recipe to specs conversion: %s", e, exc_info=self.debug
                )
                self.logger.warning(
                    "⚠️ FALLBACK: Sending original packet due to spec conversion exception"
                )
                self._update_fallback_metrics("spec_conversion_exception")
                w.send(packet)
                return

            if not specs:
                self.logger.error(
                    "❌ Failed to convert recipe to specs for %s", task_type
                )
                self.logger.warning(
                    "⚠️ FALLBACK: Sending original packet due to spec conversion failure"
                )
                self._update_fallback_metrics("spec_conversion_failure")
                w.send(packet)
                return

            self.logger.info(
                "📦 Sending %d bypass segments for %s", len(specs), task_type
            )

            # Контекст стратегии для PacketSender
            domain = getattr(strategy_result, "domain", None) if strategy_result else None
            multisplit_positions = None
            split_pos = params.get("split_pos")
            split_count = params.get("split_count")

            if task_type in ["multisplit", "multidisorder"]:
                if "positions" in params:
                    multisplit_positions = params["positions"]
                elif split_pos is not None and split_count is not None:
                    multisplit_positions = self._generate_multisplit_positions(
                        split_pos, split_count
                    )

            # Extract strategy_id from strategy_task if available
            strategy_id = strategy_task.get("_strategy_id") if strategy_task else None
            
            self._packet_sender.set_strategy_context(
                strategy_type=task_type,
                domain=domain,
                multisplit_positions=multisplit_positions,
                split_pos=split_pos,
                split_count=split_count,
                strategy_id=strategy_id,
                phase=None,  # Can be set for combo attacks if needed
            )

            # Отправка сегментов
            try:
                ok = self._packet_sender.send_tcp_segments(w, packet, specs)
                self.logger.debug("send_tcp_segments returned: %s", ok)
            except Exception as e:
                self.logger.error(
                    "❌ Exception during packet sending: %s", e, exc_info=self.debug
                )
                self.logger.warning(
                    "⚠️ FALLBACK: Sending original packet due to packet sending exception"
                )
                self._update_fallback_metrics("packet_sending_exception")
                w.send(packet)
                return

            # --- КРИТИЧЕСКАЯ ЛОГИКА: что делать с оригинальным пакетом ---
            if ok:
                # Оригинальный пакет НЕ отправляем — он дропается по умолчанию
                self.logger.info("🔒 Original packet DROPPED (bypass successful)")
                self._update_success_metrics()

                # Помечаем этот (flow, seq) как обработанный для дедупликации
                if seq_num is not None:
                    self._processed_packet_cache.mark_processed(flow_key, seq_num)
                    self.logger.debug(
                        "✅ Packet marked as processed: flow=%s, seq=0x%08X",
                        flow_key,
                        seq_num,
                    )

                # Сбрасываем счётчик неудач для данной стратегии
                if strategy_result and getattr(strategy_result, "domain", None):
                    dom = strategy_result.domain
                    stype = strategy_task.get("type", "unknown")
                    if dom in self._failed_strategies and stype in self._failed_strategies[dom]:
                        self._failed_strategies[dom][stype] = 0
            else:
                # Не удалось выполнить обход — пересылаем оригинальный пакет
                self.logger.warning("⚠️ Bypass failed, forwarding original packet")
                self._update_fallback_metrics("packet_sending_failure")
                w.send(packet)

        except Exception as e:
            self.logger.error(
                "❌ CRITICAL ERROR in apply_bypass: %s", e, exc_info=self.debug
            )
            self.logger.warning(
                "⚠️ FALLBACK: Sending original packet due to critical error"
            )
            self._update_fallback_metrics("critical_error")
            try:
                w.send(packet)
            except Exception as send_error:
                self.logger.error(
                    "❌ Failed to send original packet in fallback: %s", send_error
                )
        finally:
            # Корректно освобождаем семафор только если он был захвачен
            if injection_acquired:
                self._inject_sema.release()

    # --- END OF FINAL FIX ---

    def _generate_multisplit_positions(self, split_pos: int, split_count: int) -> List[int]:
        """
        Generate multisplit positions for comparison purposes.
        """
        # Нормализуем входные параметры в int с безопасным fallback
        try:
            split_pos_int = int(split_pos)
        except (TypeError, ValueError):
            self.logger.warning(
                "Invalid split_pos for _generate_multisplit_positions: %r, using 3",
                split_pos,
            )
            split_pos_int = 3

        try:
            split_count_int = int(split_count)
        except (TypeError, ValueError):
            self.logger.warning(
                "Invalid split_count for _generate_multisplit_positions: %r, using 1",
                split_count,
            )
            split_count_int = 1

        if split_count_int < 1:
            split_count_int = 1

        positions: List[int] = []
        current_pos = split_pos_int

        for _ in range(split_count_int):
            positions.append(current_pos)
            current_pos += 6  # стандартный шаг

        return positions
    
    def compare_testing_production_parity(
        self,
        strategy_type: str,
        domain: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Compare testing and production mode behavior for a strategy.
        
        This method uses the TestingModeComparator to verify that production
        mode uses the same packet sending functions and parameters as testing mode.
        
        Args:
            strategy_type: Type of strategy to compare
            domain: Domain name to compare (optional)
            
        Returns:
            Dictionary with comparison results (Requirement 9.5)
        """
        if not self._packet_sender or not self._packet_sender.get_comparator():
            return {
                "error": "TestingModeComparator not available",
                "recommendation": "Ensure testing_mode_comparator.py is imported correctly"
            }
        
        comparator = self._packet_sender.get_comparator()
        return comparator.compare_modes(strategy_type, domain)
    
    def get_testing_production_parity_summary(self) -> Dict[str, Any]:
        """
        Get summary of all testing-production parity comparisons.
        
        Returns:
            Dictionary with summary statistics (Requirement 9.5)
        """
        if not self._packet_sender or not self._packet_sender.get_comparator():
            return {
                "error": "TestingModeComparator not available"
            }
        
        comparator = self._packet_sender.get_comparator()
        return comparator.get_comparison_summary()
    
    def _update_fallback_metrics(self, reason: str) -> None:
        """
        Update fallback metrics when bypass fails and original packet is forwarded.
        
        Tracks fallback statistics and logs warnings when fallback rate is high.
        Implements Requirements 9.3, 9.4.
        
        Args:
            reason: The reason for fallback (e.g., "validation_error", "dispatch_error")
        """
        with self._tlock:
            self._fallback_metrics["total_attempts"] += 1
            self._fallback_metrics["total_fallbacks"] += 1
            self._fallback_metrics["consecutive_fallbacks"] += 1
            self._fallback_metrics["last_fallback_time"] = time.time()
            
            # Track fallback reasons
            if reason not in self._fallback_metrics["fallback_reasons"]:
                self._fallback_metrics["fallback_reasons"][reason] = 0
            self._fallback_metrics["fallback_reasons"][reason] += 1
            
            # Log warning if consecutive fallbacks exceed threshold (Requirement 9.3)
            consecutive = self._fallback_metrics["consecutive_fallbacks"]
            if consecutive >= 10:
                self.logger.error(
                    f"🚨 CRITICAL: {consecutive} consecutive bypass failures detected"
                )
                self.logger.error(
                    f"   Most common reason: {self._get_most_common_fallback_reason()}"
                )
                self.logger.error(
                    "   Consider disabling bypass or investigating the issue"
                )
    
    def _update_success_metrics(self) -> None:
        """
        Update metrics when bypass succeeds.
        
        Resets consecutive fallback counter and tracks success rate.
        Implements Requirement 9.4.
        """
        with self._tlock:
            self._fallback_metrics["total_attempts"] += 1
            self._fallback_metrics["total_successes"] += 1
            self._fallback_metrics["consecutive_fallbacks"] = 0
    
    def _get_most_common_fallback_reason(self) -> str:
        """
        Get the most common fallback reason from metrics.
        
        Returns:
            The most common fallback reason or "unknown" if no fallbacks recorded
        """
        reasons = self._fallback_metrics["fallback_reasons"]
        if not reasons:
            return "unknown"
        return max(reasons.items(), key=lambda x: x[1])[0]
    
    def get_fallback_metrics(self) -> Dict[str, Any]:
        """
        Get current fallback metrics snapshot.
        
        Returns:
            Dictionary containing fallback statistics including:
            - total_attempts: Total bypass attempts
            - total_successes: Successful bypass operations
            - total_fallbacks: Failed bypass operations (fallback activated)
            - fallback_rate: Percentage of operations that fell back
            - consecutive_fallbacks: Current consecutive fallback count
            - fallback_reasons: Breakdown of fallback reasons
        """
        with self._tlock:
            metrics = self._fallback_metrics.copy()
            metrics["fallback_reasons"] = dict(metrics["fallback_reasons"])
            
            # Calculate fallback rate
            if metrics["total_attempts"] > 0:
                metrics["fallback_rate"] = (
                    metrics["total_fallbacks"] / metrics["total_attempts"] * 100
                )
            else:
                metrics["fallback_rate"] = 0.0
            
            return metrics

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
    
    def _load_domains_from_sites_file(self) -> Set[str]:
        """
        Load domains from sites.txt file.
        
        Returns:
            Set of domains from sites.txt, empty set if file not found
        """
        domains = set()
        sites_file = Path("sites.txt")
        
        if sites_file.exists():
            try:
                with open(sites_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            domains.add(line.lower())
                
                self.logger.info(f"✅ Loaded {len(domains)} domains from sites.txt for runtime filtering")
                
            except Exception as e:
                self.logger.warning(f"Failed to load domains from sites.txt: {e}")
        else:
            self.logger.warning("sites.txt not found, runtime filtering will use empty domain list")
        
        return domains
    
    def _create_strategy_failure_diagnostic_report(
        self,
        domain: str,
        strategy: Dict[str, Any],
        retransmissions: int,
        strategy_result: Optional[Any] = None,
    ) -> None:
        """
        Create a diagnostic report for strategy failures.
        """
        import json
        from datetime import datetime
        from pathlib import Path

        try:
            reports_dir = Path("reports")
            reports_dir.mkdir(exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_domain = domain.replace(".", "_") if domain else "unknown"
            report_file = reports_dir / f"strategy_failure_{safe_domain}_{timestamp}.json"

            diagnostic_report: Dict[str, Any] = {
                "timestamp": datetime.now().isoformat(),
                "domain": domain,
                "retransmissions": retransmissions,
                "strategy": {
                    "type": strategy.get("type", "unknown"),
                    "params": strategy.get("params", {}),
                    "attacks": strategy.get("attacks", []),
                },
                "failure_threshold": self._strategy_failure_threshold,
                "total_retransmissions_detected": self._retransmission_count,
                "recommendations": [
                    f"Run 'cli.py test {domain}' to re-test the strategy",
                    f"Run 'cli.py auto {domain}' to find a new working strategy",
                    "Check if DPI behavior has changed",
                    "Verify domain_rules.json has correct strategy configuration",
                ],
            }

            # Безопасно добавляем информацию о strategy_result
            if strategy_result:
                diagnostic_report["strategy_result"] = {
                    "domain": getattr(strategy_result, "domain", None),
                    "source": getattr(strategy_result, "source", None),
                    "ip_address": getattr(strategy_result, "ip_address", None),
                    "matched_rule": getattr(strategy_result, "matched_rule", None),
                    "conflict_detected": getattr(
                        strategy_result, "conflict_detected", None
                    ),
                    "sni_domain": getattr(strategy_result, "sni_domain", None),
                    "ip_domain": getattr(strategy_result, "ip_domain", None),
                }

            # Рекомендация по родительскому домену
            if domain and "." in domain:
                parts = domain.split(".")
                if len(parts) > 2:
                    parent_domain = ".".join(parts[1:])
                    diagnostic_report["parent_domain_suggestion"] = {
                        "parent_domain": parent_domain,
                        "recommendation": (
                            f"Try removing '{domain}' rule to use parent domain "
                            f"'{parent_domain}' strategy"
                        ),
                    }

            # Проверка на расхождения тест/прод — чтение domain_rules.json
            domain_rules_file = Path("domain_rules.json")
            if domain_rules_file.exists():
                try:
                    with open(domain_rules_file, "r", encoding="utf-8") as f:
                        domain_rules = json.load(f)

                    if isinstance(domain_rules, dict) and domain in domain_rules:
                        expected_strategy = domain_rules[domain]
                        diagnostic_report["expected_strategy"] = {
                            "type": expected_strategy.get("type", "unknown"),
                            "params": expected_strategy.get("params", {}),
                            "attacks": expected_strategy.get("attacks", []),
                        }

                        discrepancies = []
                        if expected_strategy.get("type") != strategy.get("type"):
                            discrepancies.append(
                                "Strategy type mismatch: expected={}, applied={}".format(
                                    expected_strategy.get("type"),
                                    strategy.get("type"),
                                )
                            )

                        expected_params = expected_strategy.get("params", {})
                        applied_params = strategy.get("params", {})
                        for param in [
                            "split_pos",
                            "split_count",
                            "fooling",
                            "ttl",
                            "fake_ttl",
                        ]:
                            if param in expected_params:
                                if expected_params[param] != applied_params.get(param):
                                    discrepancies.append(
                                        "Parameter '{}' mismatch: expected={}, applied={}".format(
                                            param,
                                            expected_params[param],
                                            applied_params.get(param),
                                        )
                                    )

                        if discrepancies:
                            diagnostic_report[
                                "testing_production_discrepancies"
                            ] = discrepancies
                            diagnostic_report["recommendations"].insert(
                                0,
                                "CRITICAL: Testing-production discrepancy detected - "
                                "verify domain_rules.json",
                            )
                except Exception as e:
                    self.logger.warning(
                        "Failed to load or parse domain_rules.json for comparison: %s",
                        e,
                    )

            with open(report_file, "w", encoding="utf-8") as f:
                json.dump(diagnostic_report, f, indent=2, ensure_ascii=False)

            self.logger.error("📊 Diagnostic report created: %s", report_file)
            self.logger.error(
                "   Review this report to identify testing-production discrepancies"
            )

        except Exception as e:
            self.logger.error("Failed to create diagnostic report: %s", e)
    
    def _check_legacy_configuration_compatibility(self) -> None:
        """
        Check for existing configuration files and provide migration warnings.
        
        This method helps users understand configuration compatibility and
        provides guidance for migrating to domain-based filtering.
        """
        legacy_files = [
            ("sites.txt", "Domain list for IP-based filtering"),
            ("config/engine_config.json", "Engine configuration"),
            ("strategies.txt", "Strategy definitions"),
            ("domain_strategies.json", "Domain-specific strategies")
        ]
        
        found_legacy_files = []
        for file_path, description in legacy_files:
            if Path(file_path).exists():
                found_legacy_files.append((file_path, description))
        
        if found_legacy_files:
            self.logger.info("📋 Legacy configuration files detected:")
            for file_path, description in found_legacy_files:
                self.logger.info(f"   - {file_path}: {description}")
            
            if self._use_domain_based_filtering:
                self.logger.info("ℹ️  Domain-based filtering is enabled - legacy IP-based configs will be ignored")
                self.logger.info("   To use legacy configuration, disable domain-based filtering:")
                self.logger.info("   - Set USE_DOMAIN_BASED_FILTERING=false")
                self.logger.info("   - Or disable the 'domain_based_filtering' feature flag")
            else:
                self.logger.info("ℹ️  Using legacy IP-based filtering with existing configuration files")
                self.logger.info("   To enable new domain-based filtering:")
                self.logger.info("   - Set USE_DOMAIN_BASED_FILTERING=true")
                self.logger.info("   - Or enable the 'domain_based_filtering' feature flag")
                self.logger.info("   - Ensure domain_rules.json exists (use migration tools if needed)")
        
        # Check for domain_rules.json when domain-based filtering is enabled
        if self._use_domain_based_filtering:
            domain_rules_file = Path("domain_rules.json")
            if not domain_rules_file.exists():
                self.logger.warning("⚠️  domain_rules.json not found for domain-based filtering")
                self.logger.warning("   Create domain_rules.json or use migration tools:")
                self.logger.warning("   - python tools/migrate_to_domain_rules.py")
                self.logger.warning("   - Or manually create domain_rules.json with domain → strategy mappings")


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

    def apply_bypass(self, packet: Any, w: Any, strategy_task: Dict, forced=True, strategy_result=None):
        pass

    def report_high_level_outcome(self, target_ip: str, success: bool):
        pass
