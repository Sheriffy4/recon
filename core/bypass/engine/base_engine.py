# path: core/bypass/engine/base_engine.py
# CORRECTED AND CONSOLIDATED VERSION
"""
Platform engine (Windows / fallback) + packet processing pipeline.

Important:
- Keep public interfaces stable.
- Avoid heavy imports in package __init__ (handled via lazy exports).
"""


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

LOG = logging.getLogger("BypassEngine")

# Core imports
from core.bypass.engine.attack_dispatcher import AttackDispatcher
from core.bypass.engine.unified_attack_executor import (
    UnifiedAttackExecutor,
    ExecutionContext,
    ExecutionResult,
)
from core.bypass.engine import protocol_utils
from core.bypass.engine import sni_utils
from core.bypass.engine import telemetry_init
from core.bypass.engine import strategy_converter
from core.bypass.engine import domain_init
from core.bypass.engine import config_rollback
from core.bypass.engine import packet_pipeline_init
from core.bypass.engine import cache_init
from core.bypass.engine import filtering_init
from core.bypass.engine.filtering_manager import (
    FilteringManager,
    parse_filter_config,
    load_domains_from_sites_file,
)
from core.bypass.engine import strategy_validator
from core.bypass.engine import domain_resolver
from core.bypass.engine import position_calculator
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
    from core.bypass.filtering.feature_flags import (
        is_runtime_filtering_enabled,
        is_domain_based_filtering_enabled,
    )
except ImportError as e:
    RuntimePacketFilter = None
    FilterConfig = None
    FilterMode = None
    WinDivertFilterGenerator = None
    is_runtime_filtering_enabled = None
    is_domain_based_filtering_enabled = None
    LOG.warning("Runtime filtering components not available: %s", e)

# Domain-based strategy engine imports
try:
    from core.bypass.engine.domain_strategy_engine import DomainStrategyEngine
    from core.bypass.engine.domain_rule_registry import DomainRuleRegistry
except ImportError as e:
    DomainStrategyEngine = None
    DomainRuleRegistry = None
    LOG.warning("Domain strategy engine components not available: %s", e)

try:
    from core.strategy_manager import StrategyManager
except (ImportError, ModuleNotFoundError):
    StrategyManager = None
    LOG.warning("StrategyManager could not be imported.")

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
        special_values = ["cipher", "midsld", "sni", "random"]
        if split_pos_value in special_values:
            return split_pos_value
        try:
            return int(split_pos_value)
        except ValueError:
            LOG.warning("Invalid split_pos value: %r, using default: %r", split_pos_value, default)
            return default

    if isinstance(split_pos_value, (list, tuple)) and len(split_pos_value) > 0:
        return safe_split_pos_conversion(split_pos_value[0], default)

    LOG.warning("Unsupported split_pos type: %s, using default: %r", type(split_pos_value), default)
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


# Re-export ProcessedPacketCache for backward compatibility
from core.bypass.engine.packet_cache import ProcessedPacketCache


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
    def apply_bypass(
        self, packet: Any, w: Any, strategy_task: Dict, forced=True, strategy_result=None
    ): ...

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

        # Initialize core components
        self._init_logging()
        self._init_basic_state()
        self._init_caches_and_locks()
        self._init_telemetry_and_strategy()
        self._init_helpers_and_extractors()
        self._init_attack_pipeline()
        self._init_filtering_and_domain_strategy()
        self._init_retransmission_cache()
        self._init_runtime_filtering()

        # Initialize flow tracking for TLS ServerHello correlation
        self._last_processed_flow = None

    def _init_logging(self):
        """Initialize logging configuration."""
        self.techniques = BypassTechniques()
        self.logger = logging.getLogger("BypassEngine")
        self.logger.info(f"BypassEngine from {self.__class__.__module__}")

        # Логируем версию primitives для диагностики
        import inspect

        primitives_file = inspect.getsourcefile(BypassTechniques)
        primitives_version = getattr(BypassTechniques, "API_VER", "unknown")
        self.logger.info(f"Primitives file: {primitives_file}; ver={primitives_version}")

        if self.debug:
            if self.logger.level == logging.NOTSET:
                self.logger.setLevel(logging.DEBUG)
            if not any((isinstance(h, logging.StreamHandler) for h in self.logger.handlers)):
                logging.basicConfig(
                    level=logging.DEBUG,
                    format="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
                )

    def _init_basic_state(self):
        """Initialize basic state variables and metrics."""
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
        self._inbound_thread = None
        self._max_injections = 12

    def _init_caches_and_locks(self):
        """Initialize caches and synchronization primitives."""
        caches = cache_init.initialize_caches_and_locks(
            max_injections=self._max_injections,
            flow_ttl_sec=3.0,
            flow_timeout=15.0,
            autottl_cache_ttl=300.0,
        )
        self.flow_table = caches["flow_table"]
        self._lock = caches["lock"]
        self._active_flows = caches["active_flows"]
        self._flow_ttl_sec = caches["flow_ttl_sec"]
        self._inbound_events = caches["inbound_events"]
        self._inbound_results = caches["inbound_results"]
        self._inject_sema = caches["inject_sema"]
        self._tlock = caches["tlock"]
        self._processed_flows = caches["processed_flows"]
        self._flow_timeout = caches["flow_timeout"]
        self._autottl_cache = caches["autottl_cache"]
        self._autottl_cache_ttl = caches["autottl_cache_ttl"]
        self._split_pos_cache = caches["split_pos_cache"]

    def _init_telemetry_and_strategy(self):
        """Initialize telemetry and strategy management."""
        self._telemetry = self._init_telemetry()
        self._strategy_manager = None
        self.strategy_override = None
        self._forced_strategy_active = False
        self._discovery_mode_active = False
        self._shared_pcap_file = None
        self._position_resolver = PositionResolver()

    def _init_helpers_and_extractors(self):
        """Initialize internal helpers and domain extractors."""
        # Rate-limited logging state to reduce log-flood on hot-path
        self._log_rl_state: Dict[Any, float] = {}
        self._log_rl_lock = threading.Lock()

        # Cached domain extractor for strategy context
        self._sni_domain_extractor = None
        try:
            from core.bypass.engine.sni_domain_extractor import SNIDomainExtractor

            self._sni_domain_extractor = SNIDomainExtractor()
        except Exception:
            self._sni_domain_extractor = None

    def _init_attack_pipeline(self):
        """Initialize attack dispatcher and packet pipeline."""
        self._attack_dispatcher = AttackDispatcher(self.techniques)
        self.logger.info("AttackDispatcher initialized")

        # Initialize packet pipeline
        (
            self._packet_builder,
            self._packet_sender,
            self._unified_executor,
        ) = packet_pipeline_init.initialize_packet_pipeline(
            packet_builder_class=PacketBuilder,
            packet_sender_class=PacketSender,
            unified_executor_class=UnifiedAttackExecutor,
            attack_dispatcher=self._attack_dispatcher,
            logger=self.logger,
            inject_mark=self._INJECT_MARK,
        )

    def _init_filtering_and_domain_strategy(self):
        """Initialize filtering manager and domain strategy engine."""
        # Initialize filtering manager for domain extraction failure tracking
        self._filtering_manager = FilteringManager(
            logger=self.logger,
            domain_extraction_failure_threshold=10,
        )

        # Initialize domain strategy engine
        self._domain_strategy_engine = None
        self._use_domain_based_filtering = False
        self._initialize_domain_strategy_engine()

        # Check legacy configuration compatibility and provide guidance
        self._check_legacy_configuration_compatibility()

    def _init_retransmission_cache(self):
        """Initialize retransmission deduplication cache."""
        self._processed_packet_cache = ProcessedPacketCache(ttl_seconds=60)
        self._processed_packet_cache.start_cleanup_thread()
        self._retransmission_count = 0

        # Track failed strategies for automatic fallback
        self._failed_strategies = {}
        self._strategy_failure_threshold = 3

        self.logger.info("ProcessedPacketCache initialized for retransmission deduplication")

    def _init_runtime_filtering(self):
        """Initialize runtime packet filter and WinDivert filter generator."""
        (
            self._runtime_filter,
            self._windivert_generator,
            self._use_runtime_filtering,
        ) = filtering_init.initialize_runtime_filtering(
            runtime_filter_class=RuntimePacketFilter,
            filter_config_class=FilterConfig,
            windivert_generator_class=WinDivertFilterGenerator,
            filter_mode_enum=FilterMode,
            logger=self.logger,
            sites_file_path="sites.txt",
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
        except (ImportError, ModuleNotFoundError) as e:
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

    def enable_discovery_mode(self):
        """Enable discovery mode - disables domain strategy overrides during testing."""
        self._discovery_mode_active = True
        self.logger.info("🔍 Discovery mode enabled - domain strategy overrides disabled")
        self.logger.info(f"🔍 DEBUG: _discovery_mode_active={self._discovery_mode_active}")

    def disable_discovery_mode(self):
        """Disable discovery mode - re-enables domain strategy overrides."""
        self._discovery_mode_active = False
        self.logger.info("🔍 Discovery mode disabled - domain strategy overrides re-enabled")

    def is_discovery_mode_active(self) -> bool:
        """Check if discovery mode is currently active."""
        return self._discovery_mode_active

    def should_bypass_domain_strategy_override(self) -> bool:
        """Check if domain strategy override should be bypassed (during discovery mode)."""
        return self._discovery_mode_active

    def is_parity_override_active(self) -> bool:
        """Check if CLI/service parity override is currently active."""
        return (
            self._use_domain_based_filtering
            and self._domain_strategy_engine
            and not self._discovery_mode_active
            and self.strategy_override is not None
        )

    def set_target_domain(self, domain: str):
        """
        Set the target domain for bypass operations.

        This is used by the discovery system to ensure the correct domain
        is used for strategy context instead of extracting from PCAP traffic.

        Args:
            domain: Target domain name (e.g., www.googlevideo.com)
        """
        self._target_domain = domain
        self.logger.info(f"🎯 Target domain set: {domain}")

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
            # Сброс внутренних счетчиков
            self._retransmission_count = 0
            self.stats["packets_captured"] = 0

            # IMPORTANT: Reset flow tracking to avoid stale data from previous attempts
            self._last_processed_flow = None

            self.logger.debug("🔄 Telemetry and retransmission counters reset")

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

    def start_with_config(self, config: dict, strategy_override: Optional[Dict[str, Any]] = None):
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
            if "fake_ttl" not in params and str(task.get("type", "")).lower() == "fakeddisorder":
                # КРИТИЧЕСКОЕ ИСПРАВЛЕНИЕ: TTL=3 вместо TTL=1 для fake пакетов
                # Проблема: TTL=1 приводил к проблемам маршрутизации и ретрансмиссиям
                # Решение: TTL=3 обеспечивает корректную доставку fake пакетов до DPI
                params["fake_ttl"] = 3

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
            self.logger.info(
                "✅ Domain-based filtering is already disabled (using legacy IP-based filtering)"
            )
            return True

        try:
            self._domain_strategy_engine = None
            self._use_domain_based_filtering = False

            self.logger.warning(
                "🔄 Domain-based filtering disabled, using legacy IP-based filtering"
            )
            return True

        except (AttributeError, RuntimeError) as e:
            self.logger.error(f"❌ Failed to disable domain-based filtering: {e}")
            return False

    def enable_runtime_ip_resolution(self) -> bool:
        """
        Enable runtime IP-to-domain resolution in the domain strategy engine.

        Returns:
            True if runtime IP resolution was enabled successfully
        """
        if not self._use_domain_based_filtering or not self._domain_strategy_engine:
            self.logger.error(
                "❌ Domain-based filtering is not enabled, cannot enable IP resolution"
            )
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
            self.logger.error(
                "❌ Domain-based filtering is not enabled, cannot disable IP resolution"
            )
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
        return self._filtering_manager.get_filtering_mode(
            use_domain_based_filtering=self._use_domain_based_filtering,
            domain_strategy_engine=self._domain_strategy_engine,
            use_runtime_filtering=self._use_runtime_filtering,
            runtime_filter=self._runtime_filter,
        )

    def _handle_domain_extraction_failure(self) -> None:
        """
        Handle domain extraction failure and implement automatic fallback logic.

        If domain extraction fails repeatedly, automatically fall back to legacy
        IP-based filtering to maintain system stability.
        """
        engine_ref = {"value": self._domain_strategy_engine}
        filtering_ref = {"value": self._use_domain_based_filtering}

        self._filtering_manager.handle_domain_extraction_failure(
            domain_strategy_engine_ref=engine_ref,
            use_domain_based_filtering_ref=filtering_ref,
        )

        # Update instance variables
        self._domain_strategy_engine = engine_ref["value"]
        self._use_domain_based_filtering = filtering_ref["value"]

    def _handle_domain_extraction_success(self) -> None:
        """
        Handle successful domain extraction.

        Resets failure counters when domain extraction succeeds.
        """
        self._filtering_manager.handle_domain_extraction_success()

    def create_configuration_rollback_point(self) -> str:
        """
        Create a rollback point for current configuration.

        This method delegates to config_rollback.create_rollback_point()
        for the actual rollback point creation logic.

        The function creates backups of current configuration files that can be
        used to rollback in case of issues with domain-based filtering.

        Returns:
            Path to the rollback directory
        """
        return config_rollback.create_rollback_point(
            filtering_mode=self.get_filtering_mode(),
            domain_based_filtering_enabled=self._use_domain_based_filtering,
            logger=self.logger,
        )

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
            self._filtering_manager.reset_failure_counters()

            # Disable runtime filtering if active
            if self._use_runtime_filtering:
                self.disable_runtime_filtering()

            self.logger.warning("🚨 EMERGENCY ROLLBACK: Switched to legacy IP-based filtering")
            self.logger.info(f"   Configuration backed up to: {rollback_dir}")
            self.logger.info("   System will continue with legacy IP-based filtering")
            self.logger.info(
                "   Review logs and configuration before re-enabling domain-based filtering"
            )

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
                # Parse filter configuration using helper
                mode, domains = parse_filter_config(filter_config, FilterMode)

                # If no domains provided, load from sites.txt
                if not domains and mode != FilterMode.NONE:
                    domains = load_domains_from_sites_file()

                config = FilterConfig(mode=mode, domains=domains)
                self._runtime_filter.update_configuration(config)
            else:
                # Default configuration: blacklist mode with domains from sites.txt
                domains = load_domains_from_sites_file()
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

        This method delegates to domain_init.initialize_domain_strategy_engine()
        for the actual initialization logic.

        The function checks feature flags and environment variables to determine
        if domain-based filtering should be enabled, then loads domain rules
        from configuration and initializes the domain strategy engine.
        """
        self._domain_strategy_engine, self._use_domain_based_filtering = (
            domain_init.initialize_domain_strategy_engine(
                logger=self.logger,
                strategy_failure_threshold=getattr(self, "_strategy_failure_threshold", 5),
                is_domain_based_filtering_enabled=is_domain_based_filtering_enabled,
            )
        )

    def _check_and_enable_runtime_filtering(self) -> None:
        """
        Check feature flags and automatically enable runtime filtering if enabled.
        """
        if not is_runtime_filtering_enabled:
            self.logger.warning(
                "Feature flags system not available, using legacy IP-based filtering"
            )
            return

        try:
            if is_runtime_filtering_enabled():
                self.logger.info(
                    "Runtime filtering feature flag is enabled, activating runtime filtering"
                )

                # Enable runtime filtering with default configuration
                success = self.enable_runtime_filtering()
                if success:
                    self.logger.info("✅ Runtime packet filtering activated via feature flag")
                else:
                    self.logger.error(
                        "❌ Failed to activate runtime filtering despite feature flag being enabled"
                    )
            else:
                self.logger.info(
                    "Runtime filtering feature flag is disabled, using legacy IP-based filtering"
                )

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
            # Parse filter configuration using helper
            mode, domains = parse_filter_config(filter_config, FilterMode)

            config = FilterConfig(mode=mode, domains=domains)
            self._runtime_filter.update_configuration(config)

            self.logger.info(
                f"Runtime filter configuration updated: mode={mode.value}, domains={len(domains)}"
            )
            return True

        except Exception as e:
            self.logger.error(f"Failed to update runtime filter configuration: {e}")
            return False

    def _config_to_strategy_task(self, config: dict) -> dict:
        """
        Convert strategy configuration to strategy task dictionary.

        This method delegates to strategy_converter.config_to_strategy_task()
        for the actual conversion logic.

        Args:
            config: Strategy configuration dictionary

        Returns:
            Strategy task dictionary ready for execution
        """
        return strategy_converter.config_to_strategy_task(config)

    def stop(self):
        self.running = False
        self.logger.info("🛑 Остановка движка обхода DPI...")

        # Stop cleanup thread for processed packet cache (Requirement 11.4)
        if hasattr(self, "_processed_packet_cache"):
            self._processed_packet_cache.stop_cleanup_thread()
            self.logger.info(
                f"🧹 Processed packet cache cleanup stopped. Total retransmissions detected: {self._retransmission_count}"
            )

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
        """
        Initialize telemetry data structure.

        This method delegates to telemetry_init.create_telemetry_structure()
        for the actual initialization logic.

        Returns:
            Dictionary containing initialized telemetry structure
        """
        return telemetry_init.create_telemetry_structure(max_targets=self._telemetry_max_targets)

    def _cleanup_old_telemetry(self):
        with self._tlock:
            if len(self._telemetry["per_target"]) > self._telemetry_max_targets:
                sorted_targets = sorted(
                    self._telemetry["per_target"].items(),
                    key=lambda x: x[1].get("last_outcome_ts", 0) or 0,
                    reverse=True,
                )
                self._telemetry["per_target"] = dict(sorted_targets[: self._telemetry_max_targets])
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
        """
        Detect TLS ClientHello messages.

        Requirement 6.1: Accurate ClientHello counting for telemetry.

        Args:
            payload: Raw packet payload bytes

        Returns:
            True if payload contains TLS ClientHello, False otherwise
        """
        return protocol_utils.is_tls_clienthello(payload)

    def _is_tls_serverhello(self, payload: Optional[bytes]) -> bool:
        """
        Detect TLS ServerHello messages.

        Requirement 6.1: Accurate ServerHello counting for telemetry.

        Args:
            payload: Raw packet payload bytes

        Returns:
            True if payload contains TLS ServerHello, False otherwise
        """
        return protocol_utils.is_tls_serverhello(payload)

    def _is_tcp_handshake(self, packet) -> bool:
        """
        Check if packet is part of TCP 3-way handshake.

        Task 19: Fix TCP handshake issue - Don't apply strategy to TCP handshake packets.
        This ensures curl can establish TCP connection before TLS handshake.

        Returns:
            True if packet is TCP handshake (SYN, SYN-ACK, or ACK without data)
            False otherwise
        """
        return protocol_utils.is_tcp_handshake(packet)

    def _extract_sni(self, payload: Optional[bytes]) -> Optional[str]:
        """
        Extract SNI (Server Name Indication) from TLS ClientHello payload.

        This method delegates to sni_utils.extract_sni_from_clienthello() for
        the actual parsing logic.

        Args:
            payload: Raw TLS ClientHello packet payload bytes

        Returns:
            Extracted SNI hostname as string, or None if not found
        """
        return sni_utils.extract_sni_from_clienthello(payload)

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
        """
        Estimate optimal split position from TLS ClientHello payload.

        Delegates to position_calculator.estimate_split_pos_from_clienthello()
        """
        return position_calculator.estimate_split_pos_from_clienthello(
            payload, self._is_tls_clienthello
        )

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
                                    rtt_ms = int((time.time() - info["start_ts"]) * 1000)
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
            except (OSError, RuntimeError) as e:
                if self.running:
                    self.logger.error(f"Inbound observer error: {e}", exc_info=self.debug)
            except Exception as e:
                # Unexpected error - log and re-raise
                self.logger.critical(f"Unexpected inbound observer error: {e}", exc_info=True)
                raise

        t = threading.Thread(target=run, daemon=True)
        t.start()
        return t

    def _probe_hops(self, dest_ip: str, timeout: float = 2.0, max_hops: int = 30) -> int:
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

            self.logger.debug(f"Estimated {estimated_hops} hops to {dest_ip} (heuristic)")
            return estimated_hops

        except (OSError, TimeoutError, ValueError) as e:
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

        except (OSError, ValueError, TypeError) as e:
            self.logger.warning(
                f"AutoTTL calculation failed for {dest_ip}: {e}, using default TTL=64"
            )
            return 64

    def _resolve_cipher_pos(self, payload: bytes) -> Optional[int]:
        """
        Resolve cipher suite position in TLS ClientHello.

        Delegates to position_calculator.resolve_cipher_pos() for implementation.
        """
        return position_calculator.resolve_cipher_pos(payload, self._is_tls_clienthello)

    def _run_bypass_loop(self, target_ips: Set[str], strategy_map: Dict[str, Dict]):
        """
        Main bypass packet processing loop using WinDivert.

        Delegates to bypass_loop.run_bypass_loop() for implementation.
        """
        from . import bypass_loop

        bypass_loop.run_bypass_loop(
            engine=self,
            target_ips=target_ips,
            strategy_map=strategy_map,
        )

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
                    ipv6_support=True,  # Support IPv6
                )
                self.logger.info(f"Generated WinDivert filter using generator: {filter_str}")
                return filter_str
            except TypeError:
                # Generator doesn't support new parameters, fall back
                self.logger.warning(
                    "WinDivert generator doesn't support new parameters, using fallback"
                )

        # Fallback к ручной генерации улучшенного фильтра
        # NOTE:
        # - WinDivert 2.0 filter language does NOT support CIDR (127.0.0.0/8)
        # - and also may not support ordering comparisons (<, >) on ip.DstAddr.
        # Use !loopback if supported by driver; otherwise we will retry with legacy filter.
        fallback_filter = (
            "outbound and !loopback and tcp and " "(tcp.DstPort == 443 or tcp.DstPort == 80)"
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
        """Get protocol number from packet."""
        return protocol_utils.get_protocol(packet)

    def _is_udp(self, packet) -> bool:
        """Check if packet is UDP."""
        return protocol_utils.is_udp(packet)

    def _is_tcp(self, packet) -> bool:
        """Check if packet is TCP."""
        return protocol_utils.is_tcp(packet)

    def _execute_attack_unified(
        self,
        strategy_task: Dict[str, Any],
        payload: bytes,
        packet_info: Dict[str, Any],
        mode: str = "production",
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

        # Ensure we don't mutate caller dict and provide original_packet for real sending
        packet_info_local = dict(packet_info or {})
        # Backward/compat: if some caller stored packet under "packet", map it
        if "original_packet" not in packet_info_local and "packet" in packet_info_local:
            packet_info_local["original_packet"] = packet_info_local.get("packet")

        # Create execution context
        context = ExecutionContext(
            mode=mode,
            payload=payload,
            packet_info=packet_info_local,
            strategy=strategy_task,
            correlation_id=correlation_id,
        )

        # Execute attack through unified executor
        result = self._unified_executor.execute_attack(context)

        return result

    def _recipe_to_specs(
        self,
        recipe: List[Tuple[bytes, int, dict]],
        payload: bytes,
        strategy_task: Optional[Dict] = None,
    ) -> List[TCPSegmentSpec]:
        """
        Convert attack recipe to TCP segment specifications.

        Delegates to recipe_converter.recipe_to_tcp_specs() for implementation.
        """
        from . import recipe_converter

        return recipe_converter.recipe_to_tcp_specs(
            recipe=recipe,
            payload=payload,
            strategy_task=strategy_task,
            logger=self.logger,
            debug=self.debug,
        )

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
                "⚠️ Strategy missing 'params' field, using empty params " "(type=%s)",
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
            self.logger.error("   💡 Recommendation: Check parameter values in domain_rules.json")
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
                self.logger.warning("   This may indicate a combo strategy configuration issue")
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
                    self.logger.error("   💡 Recommendation: Fix attack types in domain_rules.json")
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

        Delegates to strategy_validator.validate_strategy_params()
        """
        return strategy_validator.validate_strategy_params(strategy_type, params, self.logger)

    def _log_rate_limited(
        self,
        level: int,
        key: Any,
        interval_sec: float,
        msg: str,
        *args,
        **kwargs,
    ) -> None:
        """
        Rate-limited logger to reduce hot-path overhead.
        Does not affect public API.
        """
        try:
            if interval_sec <= 0:
                self.logger.log(level, msg, *args, **kwargs)
                return
            now = time.monotonic()
            with self._log_rl_lock:
                last = self._log_rl_state.get(key)
                if last is not None and (now - last) < interval_sec:
                    return
                self._log_rl_state[key] = now
            self.logger.log(level, msg, *args, **kwargs)
        except Exception:
            # Logging must never break packet processing
            pass

    def _matches_target_domain(
        self, extracted_domain: Optional[str], target_domain: Optional[str]
    ) -> bool:
        """
        Minimal domain match helper for discovery-mode isolation.

        Delegates to domain_resolver.matches_target_domain()
        """
        return domain_resolver.matches_target_domain(extracted_domain, target_domain)

    def _get_discovery_target_domain(self) -> Optional[str]:
        """
        Best-effort way to get the current discovery target domain.

        Delegates to domain_resolver.get_discovery_target_domain()
        """
        return domain_resolver.get_discovery_target_domain(self)

    def _resolve_domain_for_strategy_context(
        self,
        packet: "pydivert.Packet",
        strategy_result: Optional[Any],
        payload: Optional[bytes],
    ) -> Optional[str]:
        """
        Resolve domain for PacketSender context (best-effort).
        Priority:
          1) strategy_result.domain
          2) discovery session target domain (self._target_domain)
          3) cached SNIDomainExtractor (TLS SNI / HTTP Host)
          4) legacy simple TLS SNI extractor
        """
        domain = getattr(strategy_result, "domain", None) if strategy_result else None
        if domain:
            return domain

        target_domain = getattr(self, "_target_domain", None)
        if target_domain:
            return target_domain

        if payload and self._sni_domain_extractor is not None:
            try:
                res = self._sni_domain_extractor.extract_from_payload(payload)
                if res and getattr(res, "domain", None):
                    return res.domain
            except Exception:
                pass

        # last resort: minimal TLS ClientHello SNI parser
        if payload:
            try:
                return self._extract_sni(payload)
            except Exception:
                return None
        return None

    # --- START OF FINAL FIX: UNIFIED PACKET SUPPRESSION LOGIC ---
    def _extract_tcp_seq_and_flags(self, packet: Any) -> Tuple[Optional[int], int]:
        """
        Extract TCP seq and flags from packet.tcp.raw (fast path).

        Returns:
            (seq_num, tcp_flags)
        """
        seq_num = None
        tcp_flags = 0
        try:
            tcp = getattr(packet, "tcp", None)
            raw = getattr(tcp, "raw", None)
            if not raw:
                return None, 0
            tcp_raw = bytes(raw)
            if len(tcp_raw) >= 14:
                seq_num = struct.unpack("!I", tcp_raw[4:8])[0]
                tcp_flags = tcp_raw[13]
        except Exception:
            return None, 0
        return seq_num, tcp_flags

    def _is_fin_or_rst(self, tcp_flags: int) -> bool:
        FIN_FLAG = 0x01
        RST_FLAG = 0x04
        return bool(tcp_flags & (FIN_FLAG | RST_FLAG))

    def _dispatch_recipe_and_build_specs(
        self,
        *,
        task_type: str,
        dispatch_params: Dict[str, Any],
        payload: bytes,
        packet_info: Dict[str, Any],
        strategy_task: Dict[str, Any],
    ) -> Tuple[Optional[List], Optional[str]]:
        """
        Pipeline helper: dispatch -> recipe -> specs.

        Returns:
            (specs, error_reason)
            - specs != None on success
            - error_reason is one of:
              'validation_error', 'dispatch_error', 'empty_recipe',
              'spec_conversion_exception', 'spec_conversion_failure'
        """
        try:
            self.logger.debug("🎯 Dispatching %s attack via AttackDispatcher", task_type)
            recipe = self._attack_dispatcher.dispatch_attack(
                task_type, dispatch_params, payload, packet_info
            )
        except ValueError as e:
            self.logger.error("❌ Attack dispatch validation failed for '%s': %s", task_type, e)
            self.logger.warning("⚠️ FALLBACK: Sending original packet due to validation error")
            return None, "validation_error"
        except Exception as e:
            self.logger.error(
                "❌ Attack dispatch failed for '%s': %s", task_type, e, exc_info=self.debug
            )
            self.logger.warning("⚠️ FALLBACK: Sending original packet due to dispatch error")
            return None, "dispatch_error"

        if not recipe:
            self.logger.error("❌ Recipe for %s was not generated", task_type)
            self.logger.warning("⚠️ FALLBACK: Sending original packet due to empty recipe")
            return None, "empty_recipe"

        try:
            specs = self._recipe_to_specs(recipe, payload, strategy_task)
        except Exception as e:
            self.logger.error(
                "❌ Exception during recipe to specs conversion: %s", e, exc_info=self.debug
            )
            self.logger.warning(
                "⚠️ FALLBACK: Sending original packet due to spec conversion exception"
            )
            return None, "spec_conversion_exception"

        if not specs:
            self.logger.error("❌ Failed to convert recipe to specs for %s", task_type)
            self.logger.warning(
                "⚠️ FALLBACK: Sending original packet due to spec conversion failure"
            )
            return None, "spec_conversion_failure"

        return specs, None

    def _send_original_packet(
        self,
        w: Any,
        packet: Any,
        *,
        reason: Optional[str] = None,
        log_level: int = logging.WARNING,
        log_msg: Optional[str] = None,
        exc: Optional[BaseException] = None,
    ) -> None:
        """
        Unified fallback path:
        - optionally updates fallback metrics
        - sends original packet (best-effort)
        """
        try:
            if log_msg:
                self.logger.log(log_level, log_msg)
            if exc is not None:
                self.logger.log(
                    log_level, "Fallback reason exception: %s", exc, exc_info=self.debug
                )
        except Exception:
            pass

        # IMPORTANT: keep semantics: only update metrics when old code did.
        if reason:
            self._update_fallback_metrics(reason)

        try:
            w.send(packet)
        except Exception as send_error:
            self.logger.error("❌ Failed to send original packet in fallback: %s", send_error)

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
        seq_num, tcp_flags = self._extract_tcp_seq_and_flags(packet)

        # --- Обработка FIN/RST: очистка кэша и нормальная передача ---
        if self._is_fin_or_rst(tcp_flags):
            self._processed_packet_cache.remove_flow(flow_key)
            flag_name = "FIN" if (tcp_flags & 0x01) else "RST"
            self.logger.debug(
                "🔌 Connection closing (%s): flow=%s, cleaning cache", flag_name, flow_key
            )
            self._send_original_packet(w, packet)  # keep "normal pass" semantics
            return

        # --- Дедупликация ретрансмиссий по (flow, seq) ---
        if seq_num is not None and self._processed_packet_cache.is_processed(flow_key, seq_num):
            self._retransmission_count += 1
            with self._tlock:
                self._telemetry["total_retransmissions_detected"] = self._retransmission_count
                total_retr = self._retransmission_count

            self._log_rate_limited(
                logging.INFO,
                ("retrans", flow_key),
                2.0,
                "🔄 RETRANSMISSION DETECTED: flow=%s, seq=0x%08X, total_retrans=%d",
                flow_key,
                seq_num,
                total_retr,
            )

            # Отслеживание неудачных стратегий по домену
            if strategy_result and getattr(strategy_result, "domain", None):
                domain = strategy_result.domain
                strategy_type = strategy_task.get("type", "unknown")

                domain_failures = self._failed_strategies.setdefault(domain, {})
                domain_failures[strategy_type] = domain_failures.get(strategy_type, 0) + 1
                failure_count = domain_failures[strategy_type]

                # Логирование через StrategyApplicationLogger (если есть)
                if self._domain_strategy_engine and hasattr(
                    self._domain_strategy_engine, "strategy_application_logger"
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
                    if self._domain_strategy_engine and hasattr(
                        self._domain_strategy_engine, "record_strategy_failure"
                    ):
                        needs_revalidation = self._domain_strategy_engine.record_strategy_failure(
                            domain=domain,
                            strategy=strategy_task,
                            retransmissions=failure_count,
                            reason=(f"Strategy failed with {failure_count} " f"retransmissions"),
                        )

                    if self._domain_strategy_engine and hasattr(
                        self._domain_strategy_engine, "strategy_application_logger"
                    ):
                        self._domain_strategy_engine.strategy_application_logger.log_strategy_failure(
                            domain=domain,
                            strategy=strategy_task,
                            retransmissions=failure_count,
                            reason=(f"Strategy failed with {failure_count} retransmissions"),
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
                        self.logger.error("   3. Check if DPI behavior has changed for this domain")

                    if self._domain_strategy_engine and hasattr(
                        self._domain_strategy_engine,
                        "parent_domain_recommender",
                    ):
                        recommendation = self._domain_strategy_engine.parent_domain_recommender.detect_and_recommend(
                            domain=domain,
                            failure_count=failure_count,
                            strategy=strategy_task,
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
                self.logger.warning("Injection semaphore limit reached, forwarding original packet")
                w.send(packet)
                return
            injection_acquired = True

            params = dict(strategy_task.get("params", {}))
            payload = bytes(packet.payload or b"")
            payload_len = len(payload)

            # Лог начала обработки пакета
            seq_display = f"0x{seq_num:08X}" if seq_num is not None else "N/A"

            # === NEW: remember last processed flow for correlation with TLS ServerHello detector ===
            # This does NOT change any interfaces; UnifiedBypassEngine can read it via getattr(engine, "_last_processed_flow")
            try:
                self._last_processed_flow = {
                    "ts": time.time(),
                    "flow_key": flow_key,
                    "src_ip": getattr(packet, "src_addr", None),
                    "src_port": int(getattr(packet, "src_port", 0) or 0),
                    "dst_ip": getattr(packet, "dst_addr", None),
                    "dst_port": int(getattr(packet, "dst_port", 0) or 0),
                    "seq": int(seq_num) if seq_num is not None else None,
                    "seq_display": seq_display,
                    "payload_len": int(payload_len),
                }
            except Exception:
                # Do not break packet processing if telemetry capture fails
                pass

            self._log_rate_limited(
                logging.INFO,
                ("pkt", flow_key),
                1.0,
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

                # 🔍 DISCOVERY MODE DOMAIN FILTERING FIX
                # Check if we're in discovery mode and if the domain matches the target
                if hasattr(self, "_discovery_controller") and self._discovery_controller:
                    discovery_session = getattr(self._discovery_controller, "current_session", None)
                    if discovery_session and hasattr(discovery_session, "domain_filter"):
                        domain_filter = discovery_session.domain_filter
                        if domain_filter.is_discovery_mode():
                            target_domain = domain_filter.get_current_target()
                            if target_domain and dom and dom != "unknown":
                                # Check if discovered domain matches target domain
                                if not domain_filter._matches_target_domain(dom, target_domain):
                                    self.logger.debug(
                                        "🔍 Discovery mode: Skipping non-target domain %s (target: %s)",
                                        dom,
                                        target_domain,
                                    )
                                    # Forward the original packet without bypass
                                    w.send(packet)
                                    return

                domain_part = f"{dom} [{str(src).upper()}]"
                log_msg = (
                    f"🔥 APPLY_BYPASS FIXED: dst={packet.dst_addr}:{packet.dst_port} "
                    f"({domain_part}), strategy={strategy_task.get('type', 'unknown')}, "
                    f"params={params}"
                )

                if src == "reverse_dns" and dom:
                    self.logger.info("🆕 NEW IP discovered: %s → %s", packet.dst_addr, dom)
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

            self._log_rate_limited(
                logging.INFO,
                ("apply", flow_key),
                1.0,
                "%s",
                log_msg,
            )

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
                    "❌ Strategy validation failed, skipping packet " "(forwarding original)"
                )
                self.logger.error(
                    "   💡 Recommendation: Check domain_rules.json "
                    "for correct strategy configuration"
                )
                w.send(packet)
                return

            # Определяем тип атаки с учётом combo‑стратегий
            attacks = strategy_task.get("attacks")
            base_type = (strategy_task.get("type") or "").lower().strip()

            def _looks_like_dynamic_recipe(n: str) -> bool:
                n = (n or "").lower()
                # dynamic recipes generated by diversifier/generators
                if n.startswith(
                    (
                        "fake_",
                        "disorder_",
                        "seqovl_",
                        "multisplit_",
                        "fragmentation_",
                        "fooling_",
                        "tls_fragmentation_",
                        "tcp_frag_",
                        "http_fragmentation_",
                    )
                ):
                    return True
                if "_spl" in n:
                    return True
                return False

            if isinstance(attacks, (list, tuple)) and len(attacks) > 1:
                try:
                    attacks_str_list = [str(a) for a in attacks]
                    # SAFETY: if someone accidentally puts dynamic recipe names into attacks[],
                    # do NOT convert into "a,b,c" (zapret strategy string), it breaks recipe resolution.
                    if any(_looks_like_dynamic_recipe(x) for x in attacks_str_list):
                        task_type = base_type or attacks_str_list[0].lower()
                        self.logger.info(
                            "🧩 Detected dynamic recipe-like name inside attacks[]; using type='%s' instead of joined list",
                            task_type,
                        )
                    else:
                        task_type = ",".join(attacks_str_list).lower()
                    self.logger.info(
                        "🔗 Using combination attack from 'attacks' field: %s " "(attacks=%s)",
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
                    task_type = base_type or "fakeddisorder"
            else:
                task_type = base_type or "fakeddisorder"

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
            # Provide original_packet for UnifiedAttackExecutor/PacketSender.send_segment()
            # (doesn't affect AttackDispatcher; unknown keys are ignored)
            packet_info["original_packet"] = packet
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

            # dispatch -> recipe -> specs
            specs, err_reason = self._dispatch_recipe_and_build_specs(
                task_type=task_type,
                dispatch_params=dispatch_params,
                payload=payload,
                packet_info=packet_info,
                strategy_task=strategy_task,
            )
            if err_reason:
                self._send_original_packet(w, packet, reason=err_reason)
                return

            self._log_rate_limited(
                logging.INFO,
                ("send", task_type, getattr(strategy_result, "domain", None)),
                2.0,
                "📦 Sending %d bypass segments for %s",
                len(specs),
                task_type,
            )

            domain = self._resolve_domain_for_strategy_context(packet, strategy_result, payload)

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
                self.logger.error("❌ Exception during packet sending: %s", e, exc_info=self.debug)
                self.logger.warning(
                    "⚠️ FALLBACK: Sending original packet due to packet sending exception"
                )
                self._update_fallback_metrics("packet_sending_exception")
                w.send(packet)
                return

            # --- КРИТИЧЕСКАЯ ЛОГИКА: что делать с оригинальным пакетом ---
            if ok:
                # Оригинальный пакет НЕ отправляем — он дропается по умолчанию
                self._log_rate_limited(
                    logging.INFO,
                    ("drop", flow_key),
                    2.0,
                    "🔒 Original packet DROPPED (bypass applied - verifying effectiveness...)",
                )
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
            self.logger.error("❌ CRITICAL ERROR in apply_bypass: %s", e, exc_info=self.debug)
            self.logger.warning("⚠️ FALLBACK: Sending original packet due to critical error")
            self._update_fallback_metrics("critical_error")
            try:
                w.send(packet)
            except Exception as send_error:
                self.logger.error("❌ Failed to send original packet in fallback: %s", send_error)
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
        self, strategy_type: str, domain: Optional[str] = None
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
                "recommendation": "Ensure testing_mode_comparator.py is imported correctly",
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
            return {"error": "TestingModeComparator not available"}

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
                self.logger.error("   Consider disabling bypass or investigating the issue")

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
        """
        Get comprehensive telemetry snapshot.

        Requirements:
        - 6.1: Accurate ClientHello/ServerHello counting
        - 6.2: Retransmission tracking and rate calculation
        - 6.4: Structured, machine-readable metrics

        Returns:
            Dictionary containing structured telemetry data
        """
        try:
            with self._tlock:
                snap = copy.deepcopy(self._telemetry)

            # Add duration calculation
            snap["duration_sec"] = time.time() - snap.get("start_ts", time.time())

            # Convert defaultdicts to regular dicts for serialization
            for k in ["fake", "real"]:
                snap["ttls"][k] = dict(snap["ttls"][k])
            snap["seq_offsets"] = dict(snap["seq_offsets"])
            snap["overlaps"] = dict(snap["overlaps"])

            # Process per-target data
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

            # Add enhanced metrics for structured telemetry
            snap["enhanced_metrics"] = self._get_enhanced_telemetry_metrics(snap)

            return snap
        except Exception as e:
            self.logger.error(f"Failed to get telemetry snapshot: {e}")
            return self._get_empty_telemetry_snapshot()

    def _get_enhanced_telemetry_metrics(self, base_telemetry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate enhanced telemetry metrics.

        Args:
            base_telemetry: Base telemetry data

        Returns:
            Dictionary with enhanced metrics
        """
        try:
            # Basic counts
            client_hellos = base_telemetry.get("clienthellos", 0)
            server_hellos = base_telemetry.get("serverhellos", 0)
            total_retransmissions = base_telemetry.get("total_retransmissions_detected", 0)
            packets_captured = base_telemetry.get("packets_captured", 0)

            # Aggregate data
            aggregate = base_telemetry.get("aggregate", {})
            fake_packets_sent = aggregate.get("fake_packets_sent", 0)
            segments_sent = aggregate.get("segments_sent", 0)

            # Calculate derived metrics
            handshake_success_rate = 0.0
            if client_hellos > 0:
                handshake_success_rate = min(1.0, server_hellos / client_hellos)

            retransmission_rate = 0.0
            if packets_captured > 0:
                retransmission_rate = (total_retransmissions / packets_captured) * 100.0

            packet_efficiency = 0.0
            if packets_captured > 0:
                packet_efficiency = min(1.0, server_hellos / packets_captured)

            return {
                "handshake_success_rate": round(handshake_success_rate, 4),
                "retransmission_rate": round(retransmission_rate, 2),
                "packet_efficiency": round(packet_efficiency, 4),
                "total_handshakes_attempted": client_hellos,
                "total_handshakes_successful": server_hellos,
                "total_packets_processed": packets_captured,
                "total_fake_packets_sent": fake_packets_sent,
                "total_segments_sent": segments_sent,
                "bytes_processed_estimate": packets_captured
                * 1500,  # Estimate 1500 bytes per packet
                "connection_attempts": segments_sent,
                "successful_connections": server_hellos,
            }
        except Exception as e:
            self.logger.warning(f"Failed to calculate enhanced metrics: {e}")
            return {
                "handshake_success_rate": 0.0,
                "retransmission_rate": 0.0,
                "packet_efficiency": 0.0,
                "total_handshakes_attempted": 0,
                "total_handshakes_successful": 0,
                "total_packets_processed": 0,
                "total_fake_packets_sent": 0,
                "total_segments_sent": 0,
                "bytes_processed_estimate": 0,
                "connection_attempts": 0,
                "successful_connections": 0,
            }

    def _get_empty_telemetry_snapshot(self) -> Dict[str, Any]:
        """
        Get empty telemetry snapshot for error cases.

        Delegates to telemetry_reporter.get_empty_telemetry_snapshot() for implementation.
        """
        from . import telemetry_reporter

        return telemetry_reporter.get_empty_telemetry_snapshot()

    def reset_telemetry(self) -> None:
        """
        Reset telemetry counters for new test.

        Requirement 6.4: Telemetry reset capabilities
        """
        try:
            with self._tlock:
                self._telemetry = self._init_telemetry()

            # Reset internal counters
            self._retransmission_count = 0
            self.stats["packets_captured"] = 0

            self.logger.debug("🔄 Telemetry and retransmission counters reset")
        except Exception as e:
            self.logger.error(f"Failed to reset telemetry: {e}")

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

        This method delegates to filtering_init.load_domains_from_sites_file()
        for the actual domain loading logic.

        Returns:
            Set of domains from sites.txt, empty set if file not found
        """
        return filtering_init.load_domains_from_sites_file(
            sites_file_path="sites.txt", logger=self.logger
        )

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
                    "conflict_detected": getattr(strategy_result, "conflict_detected", None),
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
                            diagnostic_report["testing_production_discrepancies"] = discrepancies
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
            self.logger.error("   Review this report to identify testing-production discrepancies")

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
            ("domain_strategies.json", "Domain-specific strategies"),
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
                self.logger.info(
                    "ℹ️  Domain-based filtering is enabled - legacy IP-based configs will be ignored"
                )
                self.logger.info("   To use legacy configuration, disable domain-based filtering:")
                self.logger.info("   - Set USE_DOMAIN_BASED_FILTERING=false")
                self.logger.info("   - Or disable the 'domain_based_filtering' feature flag")
            else:
                self.logger.info(
                    "ℹ️  Using legacy IP-based filtering with existing configuration files"
                )
                self.logger.info("   To enable new domain-based filtering:")
                self.logger.info("   - Set USE_DOMAIN_BASED_FILTERING=true")
                self.logger.info("   - Or enable the 'domain_based_filtering' feature flag")
                self.logger.info(
                    "   - Ensure domain_rules.json exists (use migration tools if needed)"
                )

        # Check for domain_rules.json when domain-based filtering is enabled
        if self._use_domain_based_filtering:
            domain_rules_file = Path("domain_rules.json")
            if not domain_rules_file.exists():
                self.logger.warning("⚠️  domain_rules.json not found for domain-based filtering")
                self.logger.warning("   Create domain_rules.json or use migration tools:")
                self.logger.warning("   - python tools/migrate_to_domain_rules.py")
                self.logger.warning(
                    "   - Or manually create domain_rules.json with domain → strategy mappings"
                )


class FallbackBypassEngine(IBypassEngine):
    """Fallback engine for non-Windows systems."""

    def __init__(self, config: EngineConfig):  # pylint: disable=unused-argument
        """Initialize fallback engine (stub for non-Windows systems)."""
        self.logger = logging.getLogger("BypassEngine")
        self.logger.warning("Pydivert is not supported on this platform. BypassEngine is disabled.")
        self.running = False

    def start(self, *args, **kwargs):  # pylint: disable=unused-argument
        """Start engine (stub - does nothing on non-Windows systems)."""
        self.logger.warning("BypassEngine is disabled.")

    def stop(self, *args, **kwargs):  # pylint: disable=unused-argument
        """Stop engine (stub - does nothing on non-Windows systems)."""
        pass

    def set_strategy_override(
        self, strategy_task: Dict[str, Any]
    ) -> None:  # pylint: disable=unused-argument
        """Set strategy override (stub - does nothing on non-Windows systems)."""
        pass

    def get_telemetry_snapshot(self) -> Dict[str, Any]:
        return {}

    def _get_discovery_strategy(self, packet_info=None):  # pylint: disable=unused-argument
        """
        Get strategy from discovery controller if available.

        This method is called in discovery mode to get diverse strategies
        from the discovery controller instead of using fixed CLI strategies.

        Args:
            packet_info: Packet information (unused in fallback implementation)

        Returns:
            Dict with strategy configuration or None if no strategy available
        """
        if not hasattr(self, "_discovery_controller") or not self._discovery_controller:
            return None

        try:
            # Get strategy from discovery controller
            # First, we need to get the active session ID
            active_sessions = getattr(self._discovery_controller, "active_sessions", {})
            if not active_sessions:
                return None

            # Get the first active session (in CLI auto mode there should be only one)
            session_id = next(iter(active_sessions.keys()))

            # Get next strategy from discovery controller
            if hasattr(self._discovery_controller, "get_next_strategy"):
                strategy_variation = self._discovery_controller.get_next_strategy(session_id)
                if strategy_variation:
                    # Convert StrategyVariation to strategy dict format
                    params = strategy_variation.parameters.copy()

                    # Remove 'attacks' from params as it's a separate field
                    attacks_from_params = params.pop("attacks", None)

                    # Prefer real attack names if provided in parameters["attacks"].
                    attacks_list = None
                    if isinstance(attacks_from_params, list) and attacks_from_params:
                        attacks_list = [str(a).strip().lower() for a in attacks_from_params if a]

                    if attacks_list:
                        strategy_type = attacks_list[0]
                    else:
                        # Fallback mapping: attack_types are often CATEGORIES (fragmentation/disorder/...)
                        # not real engine attack names. Map categories to a safe default attack.
                        category_map = {
                            "fragmentation": "split",
                            "disorder": "disorder",
                            "fake": "fake",
                            "ttl_manipulation": "ttl",
                            "fooling": "fake",
                            "multisplit": "multisplit",
                            "seqovl": "seqovl",
                            "passthrough": "passthrough",
                        }
                        strategy_type = None
                        if getattr(strategy_variation, "attack_types", None):
                            try:
                                at0 = strategy_variation.attack_types[0]
                                at0_val = getattr(at0, "value", None) or str(at0)
                                strategy_type = category_map.get(str(at0_val).lower())
                            except Exception:
                                strategy_type = None

                        # Last resort: keep descriptive name (may be handled as recipe, e.g. fake_ttl3)
                        strategy_type = (
                            strategy_type or str(strategy_variation.name).strip().lower()
                        )

                    strategy_dict = {
                        "type": strategy_type,
                        "params": params,
                        "attacks": attacks_list or [strategy_type],
                        "forced": True,
                        "no_fallbacks": True,
                    }
                    self.logger.debug(
                        f"🎯 Got strategy from discovery controller: {strategy_variation.name} "
                        f"(type={strategy_type})"
                    )
                    return strategy_dict
        except Exception as e:
            self.logger.warning(f"Failed to get strategy from discovery controller: {e}")

        return None

    def set_discovery_controller(self, discovery_controller):
        """Set reference to discovery controller for strategy provision."""
        self._discovery_controller = discovery_controller
        self.logger.debug("🔗 Discovery controller reference set in base engine")

    def apply_bypass(  # pylint: disable=unused-argument
        self, packet: Any, w: Any, strategy_task: Dict, forced=True, strategy_result=None
    ):
        """Apply bypass (stub - does nothing on non-Windows systems)."""
        pass

    def report_high_level_outcome(  # pylint: disable=unused-argument
        self, target_ip: str, success: bool
    ):
        """Report outcome (stub - does nothing on non-Windows systems)."""
        pass


# Re-export protocol utilities for backward compatibility
from core.bypass.engine.protocol_utils import (
    is_tls_clienthello,
    is_tls_serverhello,
    get_protocol,
    is_tcp,
    is_udp,
)

# Re-export SNI utilities for backward compatibility
from core.bypass.engine.sni_utils import extract_sni_from_clienthello

# Re-export telemetry utilities for backward compatibility
from core.bypass.engine.telemetry_init import create_telemetry_structure

# Re-export strategy converter utilities for backward compatibility
from core.bypass.engine.strategy_converter import (
    config_to_strategy_task,
    build_multisplit_positions,
)

# Re-export domain initialization utilities for backward compatibility
from core.bypass.engine.domain_init import initialize_domain_strategy_engine

# Re-export configuration rollback utilities for backward compatibility
from core.bypass.engine.config_rollback import create_rollback_point

# Re-export packet pipeline initialization utilities for backward compatibility
from core.bypass.engine.packet_pipeline_init import initialize_packet_pipeline

# Re-export cache initialization utilities for backward compatibility
from core.bypass.engine.cache_init import initialize_caches_and_locks

# Re-export filtering initialization utilities for backward compatibility
from core.bypass.engine.filtering_init import initialize_runtime_filtering

__all__ = [
    # Main classes
    "EngineConfig",
    "ProcessedPacketCache",
    "IBypassEngine",
    "WindowsBypassEngine",
    "FallbackBypassEngine",
    # Utility functions
    "apply_forced_override",
    "safe_split_pos_conversion",
    # Re-exported protocol utilities
    "is_tls_clienthello",
    "is_tls_serverhello",
    "get_protocol",
    "is_tcp",
    "is_udp",
    # Re-exported SNI utilities
    "extract_sni_from_clienthello",
    # Re-exported telemetry utilities
    "create_telemetry_structure",
    # Re-exported strategy converter utilities
    "config_to_strategy_task",
    "build_multisplit_positions",
    # Re-exported domain initialization utilities
    "initialize_domain_strategy_engine",
    # Re-exported configuration rollback utilities
    "create_rollback_point",
    # Re-exported packet pipeline initialization utilities
    "initialize_packet_pipeline",
    # Re-exported cache initialization utilities
    "initialize_caches_and_locks",
    # Re-exported filtering initialization utilities
    "initialize_runtime_filtering",
    "load_domains_from_sites_file",
]
