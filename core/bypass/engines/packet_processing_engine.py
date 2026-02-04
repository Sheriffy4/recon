from __future__ import annotations

import logging
import threading
import time
import math
import socket
import struct
import asyncio
import concurrent.futures
from typing import Dict, Set, Optional, List, Tuple, Any, Union
from dataclasses import dataclass

try:
    import pydivert

    PYDIVERT_AVAILABLE = True
except ImportError:
    PYDIVERT_AVAILABLE = False
    pydivert = None  # type: ignore[assignment]
from core.bypass.engines.base import BaseBypassEngine, EngineConfig
from core.bypass.engines.health_check import (
    EngineHealthCheck,
    SystemHealthReport,
    HealthStatus,
)
from core.bypass.types import EngineStatus
from core.bypass.exceptions import EngineError
from core.bypass.attacks.base import AttackContext, AttackResult, AttackStatus
from core.diagnostics.metrics import MetricsCollector
from core.robust_packet_processor import RobustPacketProcessor
from core.packet_builder import EnhancedPacketBuilder
from core.integration.strategy_mapper import StrategyMapper
from core.integration.result_processor import ResultProcessor
from core.bypass.types import PacketInfo, StrategyResult
from core.packet_modification_validator import PacketModificationValidator
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass
try:
    from core.optimization.performance_optimizer import (
        PerformanceOptimizer,
        performance_timer,
    )

    PERFORMANCE_OPTIMIZATION_AVAILABLE = True
except ImportError:
    PERFORMANCE_OPTIMIZATION_AVAILABLE = False

    def performance_timer(func):
        return func


try:
    from core.combo_attacker import ComboAttacker

    COMBO_ATTACKER_AVAILABLE = True
except ImportError:
    COMBO_ATTACKER_AVAILABLE = False
LOG = logging.getLogger("PacketProcessingEngine")


@dataclass
class PacketProcessingResult:
    """Результат обработки пакета"""

    success: bool
    packets_sent: int = 0
    execution_time_ms: float = 0.0
    error_message: Optional[str] = None
    attack_used: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class PacketProcessingEngine(BaseBypassEngine):

    def __init__(
        self,
        attack_adapter,
        fingerprint_engine,
        diagnostic_system,
        packet_processor: Optional[RobustPacketProcessor] = None,
        strategy_mapper: Optional[StrategyMapper] = None,
        result_processor: Optional[ResultProcessor] = None,
        performance_optimizer: Optional["PerformanceOptimizer"] = None,
        combo_attacker: Optional["ComboAttacker"] = None,
        config: Optional[EngineConfig] = None,
    ):
        super().__init__(config)
        self._lock = threading.Lock()
        self._status = EngineStatus.STOPPED
        self._windivert_handle = None
        self._performance_optimizer = None
        self._effectiveness_validator = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self.metrics = MetricsCollector("PacketProcessingEngine")
        self.mod_validator = PacketModificationValidator()
        if not PYDIVERT_AVAILABLE:
            raise EngineError("PyDivert не установлен. Этот движок не может работать.")
        if not all([attack_adapter, fingerprint_engine, diagnostic_system]):
            raise ValueError(
                "AttackAdapter, UltimateAdvancedFingerprintEngine и DiagnosticSystem должны быть предоставлены через DI."
            )
        self.attack_adapter = attack_adapter
        self._domain_filter = None  # Domain filter for discovery mode
        self._shared_ip_sni_filter = None  # Shared IP SNI filter for discovery mode
        self.fingerprint_engine = fingerprint_engine
        self.diagnostic_system = diagnostic_system
        self.packet_processor = packet_processor or RobustPacketProcessor(debug=self.config.debug)
        self.strategy_mapper = strategy_mapper or StrategyMapper()
        self.result_processor = result_processor or ResultProcessor()
        self.performance_optimizer = performance_optimizer or (
            PerformanceOptimizer(self) if PERFORMANCE_OPTIMIZATION_AVAILABLE else None
        )
        self.combo_attacker = combo_attacker
        self.cloudflare_prefixes = (
            "104.",
            "172.64.",
            "172.67.",
            "162.158.",
            "162.159.",
        )
        self.standard_web_ports = {80, 443, 8080, 8443, 3128, 9050}
        self.custom_ports = {21117, 8000, 8888, 9000}
        self.strategy_cache: Dict[str, Tuple[Dict, float]] = {}
        self.fingerprint_cache: Dict[str, Tuple[Any, float]] = {}
        self.cache_ttl = 300
        self._initialize_optional_components()
        self.health_checker = EngineHealthCheck(debug=self.config.debug)
        self.last_health_report: Optional[SystemHealthReport] = None
        self.logger.info("PacketProcessingEngine инициализирован успешно через DI")
        self.logger.info("This engine is configured for PRODUCTION packet processing")

    def _run_coro_sync(self, coro, timeout: float = 30.0):
        """
        Safely run coroutine from sync code.
        - If no running loop in this thread -> asyncio.run
        - If running loop exists -> run in a dedicated thread with its own event loop
        """
        if not asyncio.iscoroutine(coro):
            return coro
        try:
            asyncio.get_running_loop()
            running_loop = True
        except RuntimeError:
            running_loop = False

        if not running_loop:
            return asyncio.run(coro)

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(lambda: asyncio.run(coro))
            return fut.result(timeout=timeout)

    def _change_status(self, new_status: EngineStatus):
        """Потокобезопасно изменяет статус движка."""
        with self._lock:
            if self._status != new_status:
                self._status = new_status
                self.logger.info(f"Engine status changed to: {new_status.value}")
                if new_status in [EngineStatus.RUNNING, EngineStatus.STARTING]:
                    self._running = True
                elif new_status in [
                    EngineStatus.STOPPED,
                    EngineStatus.STOPPING,
                    EngineStatus.ERROR,
                ]:
                    self._running = False

    def is_production_engine(self) -> bool:
        """
        Confirms that this engine is for production packet processing.

        Returns:
            True - this engine handles real-time packet processing
        """
        return True

    def get_stats(self) -> Dict[str, Any]:
        """
        Реализация абстрактного метода для получения статистики.
        Возвращает объединенную статистику всех компонентов.
        """
        return self.get_combined_stats()

    def is_healthy(self) -> bool:
        """
        Реализация абстрактного метода для проверки здоровья движка.
        Использует существующую логику проверки.
        """
        return self.is_engine_healthy()

    def perform_health_check(self) -> SystemHealthReport:
        """Выполняет полную проверку здоровья движка."""
        LOG.info("🏥 Performing engine health check...")
        self.last_health_report = self.health_checker.perform_full_health_check()
        return self.last_health_report

    def get_last_health_report(self) -> Optional[SystemHealthReport]:
        """Get the last health check report."""
        return self.last_health_report

    def is_engine_healthy(self) -> bool:
        """Проверяет, достаточно ли "здоров" движок для работы."""
        if not self.last_health_report:
            self.perform_health_check()
        return self.last_health_report.overall_status != HealthStatus.CRITICAL

    def get_fallback_recommendations(self) -> List[str]:
        """
        Get fallback recommendations when engine cannot operate normally.

        Returns:
            List of fallback options
        """
        if not self.last_health_report:
            self.perform_health_check()
        return self.last_health_report.fallback_options

    def apply_strategy(self, packet_info: PacketInfo, strategy: Dict[str, Any]) -> StrategyResult:
        """
        Применяет стратегию к пакету, используя AttackAdapter.
        Это реализация абстрактного метода из базового класса.
        """
        start_time = time.time()
        try:
            raw = packet_info.raw_data or b""
            payload_start = 0
            try:
                # IPv4 IHL + TCP data offset (best-effort, guarded)
                if len(raw) >= 1:
                    ip_hlen = (raw[0] & 0x0F) * 4
                    if len(raw) >= ip_hlen + 13:
                        tcp_hlen = ((raw[ip_hlen + 12] >> 4) & 0x0F) * 4
                        payload_start = ip_hlen + tcp_hlen
            except Exception:
                payload_start = 0

            context = AttackContext(
                dst_ip=packet_info.dst_ip,
                dst_port=packet_info.dst_port,
                src_ip=packet_info.src_ip,
                src_port=packet_info.src_port,
                payload=raw[payload_start:] if payload_start < len(raw) else b"",
                protocol=(
                    packet_info.protocol.value if hasattr(packet_info.protocol, "value") else "tcp"
                ),
                params=strategy.get("params", {}),
            )
            attack_name = strategy.get("type") or strategy.get("name")
            attack_result = self._execute_attack_by_name_sync(attack_name, context, timeout=10.0)
            return StrategyResult(
                success=attack_result.status == AttackStatus.SUCCESS,
                technique_used=attack_name,
                execution_time_ms=(time.time() - start_time) * 1000,
                packets_modified=attack_result.packets_sent,
                error_message=attack_result.error_message,
                metadata={"attack_result": attack_result},
            )
        except Exception as e:
            self.logger.error(f"Ошибка применения стратегии '{strategy.get('type')}': {e}")
            return StrategyResult(
                success=False,
                technique_used=strategy.get("type", "unknown"),
                execution_time_ms=(time.time() - start_time) * 1000,
                error_message=str(e),
            )

    def _execute_attack_by_name_sync(
        self, attack_name: str, context: AttackContext, timeout: float = 10.0
    ) -> AttackResult:
        """
        Выполняет async-атаку из sync-кода с учетом:
        - отсутствия event loop в текущем thread,
        - наличия running loop в другом thread,
        - потенциального deadlock при ожидании результата в том же loop-thread.
        Интерфейсы публичных методов не меняем — это внутренний helper.
        """
        try:
            result_or_coro = self.attack_adapter.execute_attack_by_name(attack_name, context)
        except Exception as e:
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=0)

        # Adapter might be sync in some deployments
        if not asyncio.iscoroutine(result_or_coro):
            return result_or_coro

        coro = result_or_coro

        # Are we already inside a running loop in THIS thread?
        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None

        # Get (possibly) configured loop for current thread (may fail in non-main threads)
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = None

        if loop is not None and loop.is_running():
            # Deadlock guard: if we're in the same loop thread, we must not block on result()
            if running_loop is loop:
                msg = "Cannot synchronously wait for attack execution from within the running event loop thread"
                LOG.error(msg)
                return AttackResult(status=AttackStatus.ERROR, error_message=msg, latency_ms=0)

            fut = asyncio.run_coroutine_threadsafe(coro, loop)
            return fut.result(timeout=timeout)

        # If we have a non-running loop bound to this thread, use it
        if loop is not None and not loop.is_closed():
            return loop.run_until_complete(coro)

        # No loop in this thread: create a temporary one
        return asyncio.run(coro)

    def _initialize_optional_components(self) -> None:
        """Инициализация опциональных компонентов."""
        if PERFORMANCE_OPTIMIZATION_AVAILABLE:
            try:
                # Do not override injected optimizer
                if self.performance_optimizer is None:
                    self.performance_optimizer = PerformanceOptimizer(self, debug=self.config.debug)
                    self.logger.info("PerformanceOptimizer инициализирован")
            except Exception as e:
                self.logger.warning(f"Не удалось инициализировать PerformanceOptimizer: {e}")
        if COMBO_ATTACKER_AVAILABLE:
            try:
                # Do not override injected combo attacker
                if self.combo_attacker is None:
                    self.combo_attacker = ComboAttacker(
                        attack_adapter=self.attack_adapter, debug=self.config.debug
                    )
                    self.logger.info("ComboAttacker инициализирован")
            except Exception as e:
                self.logger.warning(f"Не удалось инициализировать ComboAttacker: {e}")

    def start(
        self, target_ips: Set[str], strategy_map: Dict[str, Dict]
    ) -> Optional[threading.Thread]:
        """Запускает основной цикл перехвата пакетов."""
        if self._status == EngineStatus.RUNNING:
            LOG.warning("Движок уже запущен.")
            return None
        self._change_status(EngineStatus.STARTING)
        if not self.is_engine_healthy():
            LOG.error("❌ Критические проблемы со здоровьем системы. Запуск движка невозможен.")
            self.health_checker.log_health_report(self.last_health_report)
            raise EngineError("Engine health check failed - critical issues detected.")
        self.diagnostic_system.start_monitoring(self)
        if self.performance_optimizer:
            self.performance_optimizer.start_optimization()
        self._thread = threading.Thread(
            target=self._run,
            args=(target_ips, strategy_map),
            daemon=True,
            name="PacketProcessingEngine-Thread",
        )
        self._thread.start()
        return self._thread

    def stop(self) -> None:
        """Останавливает движок."""
        if self._status == EngineStatus.STOPPED:
            return
        self._change_status(EngineStatus.STOPPING)
        # Ensure WinDivert recv unblocks
        try:
            h = self._windivert_handle
            if h is not None:
                h.close()
        except Exception:
            pass
        self.diagnostic_system.stop_monitoring()
        if self.performance_optimizer:
            self.performance_optimizer.stop_optimization()
        super().stop()

    def update_strategy_map(self, new_strategy_map: Dict[str, Dict]):
        """Потокобезопасно обновляет карту стратегий для живой адаптации."""
        with self._lock:
            self.strategy_map.update(new_strategy_map)
            self.strategy_cache.clear()
            LOG.info(
                f"Карта стратегий обновлена. Новых/измененных записей: {len(new_strategy_map)}"
            )

    def _run(self, target_ips: Set[str], strategy_map: Dict[str, Dict]) -> None:
        """Основной цикл перехвата и обработки пакетов."""
        self.strategy_map = strategy_map
        from core.windivert_filter import WinDivertFilterGenerator

        gen = WinDivertFilterGenerator()
        ports: Set[int] = {d.get("target_port", 443) for d in (strategy_map or {}).values()} or {
            80,
            443,
        }
        candidates = gen.progressive_candidates(
            target_ports=ports,
            direction="outbound",
            protocols=("tcp",),
        )
        LOG.info(f"🔍 Запуск перехвата с {len(candidates)} кандидатами фильтра")
        try:
            w = None
            last_error = None
            for filter_str in candidates:
                LOG.info(f"Пробуем фильтр: '{filter_str}'")
                try:
                    w = pydivert.WinDivert(filter_str, priority=1000)
                    w.open()
                    break
                except Exception as e:
                    last_error = e
                    LOG.warning(f"Не удалось открыть WinDivert с фильтром: {e}")
                    w = None
            if w is None:
                simple_filter = "outbound and tcp"
                LOG.info(f"Пробуем простой фильтр: '{simple_filter}'")
                w = pydivert.WinDivert(simple_filter, priority=1000)
                w.open()
            try:
                self._windivert_handle = w
                self._change_status(EngineStatus.RUNNING)
                LOG.info("✅ WinDivert запущен успешно. Движок активен.")
                while self._running:
                    try:
                        packet = w.recv()
                        if not packet or not packet.raw:
                            continue
                        self.metrics.increment_counter("packets_captured")
                        if self._should_process_packet(packet, target_ips):
                            self._process_packet(packet, w)
                        else:
                            self._safe_send_packet(w, packet)
                    except Exception as e:
                        self.metrics.increment_counter("processing_errors")
                        LOG.error(f"Ошибка обработки пакета: {e}", exc_info=self.config.debug)
            finally:
                try:
                    if w is not None:
                        w.close()
                except Exception:
                    pass
        except Exception as e:
            self._change_status(EngineStatus.ERROR)
            LOG.error(f"❌ Критическая ошибка WinDivert: {e}", exc_info=self.config.debug)
        finally:
            try:
                self._windivert_handle = None
            except Exception:
                pass
            self._change_status(EngineStatus.STOPPED)
            LOG.info("🛑 Движок остановлен")

    def _should_process_packet(self, packet: pydivert.Packet, target_ips: Set[str]) -> bool:
        """Определяет, нужно ли обрабатывать пакет."""
        if not self.packet_processor.validate_packet(packet):
            self.metrics.increment_counter("invalid_packets")
            return False
        if self.packet_processor.handle_localhost_packets(packet):
            return False

        # Basic IP filtering
        if packet.dst_addr not in target_ips:
            return False

        # Apply domain filtering if discovery mode is active
        if (
            hasattr(self, "_domain_filter")
            and self._domain_filter
            and self._domain_filter.is_discovery_mode()
        ):
            try:
                # Extract packet payload for domain filtering
                if packet.tcp and packet.tcp.payload:
                    packet_data = bytes(packet.tcp.payload)

                    # Check if we have a shared IP SNI filter for this scenario
                    if hasattr(self, "_shared_ip_sni_filter") and self._shared_ip_sni_filter:
                        if not self._shared_ip_sni_filter.should_process_packet_for_shared_ip(
                            packet_data, packet.dst_addr
                        ):
                            self.metrics.increment_counter("shared_ip_filtered_packets")
                            LOG.debug(f"Shared IP SNI filter rejected packet to {packet.dst_addr}")
                            return False
                    elif not self._domain_filter.should_process_packet(packet_data):
                        self.metrics.increment_counter("domain_filtered_packets")
                        LOG.debug(f"Domain filter rejected packet to {packet.dst_addr}")
                        return False
            except Exception as e:
                LOG.warning(f"Error in domain filtering: {e}")
                # In case of error, allow packet processing to avoid breaking functionality

        return True

    @performance_timer
    def _process_packet(self, packet: pydivert.Packet, w: pydivert.WinDivert) -> None:
        """Обработка пакета с применением стратегии."""
        strategy = self._get_strategy_for_packet(packet)
        if not strategy:
            self._safe_send_packet(w, packet)
            return
        try:
            context = self._create_attack_context_from_packet(packet, strategy)
            attack_result = self._execute_attack_by_name_sync(
                strategy["type"], context, timeout=10.0
            )
        except Exception as e:
            self.metrics.increment_counter("processing_errors")
            LOG.error(f"Ошибка исполнения атаки: {e}", exc_info=self.config.debug)
            self._safe_send_packet(w, packet)
            return

        processing_result = self._handle_attack_result(attack_result, packet, w)
        self._log_processing_result(packet, strategy, processing_result)

    def set_domain_filter(self, domain_filter) -> None:
        """Set domain filter for discovery mode integration."""
        self._domain_filter = domain_filter
        LOG.info(
            f"Domain filter {'enabled' if domain_filter else 'disabled'} for packet processing engine"
        )

    def set_shared_ip_sni_filter(self, shared_ip_filter) -> None:
        """Set shared IP SNI filter for discovery mode integration."""
        self._shared_ip_sni_filter = shared_ip_filter
        LOG.info(
            f"Shared IP SNI filter {'enabled' if shared_ip_filter else 'disabled'} for packet processing engine"
        )

    def _handle_attack_result(
        self,
        result: AttackResult,
        original_packet: pydivert.Packet,
        w: pydivert.WinDivert,
    ) -> PacketProcessingResult:
        """Обрабатывает результат атаки и отправляет пакеты."""
        if result.status != AttackStatus.SUCCESS:
            meta_params_missing = (
                (result.metadata or {}).get("params_missing_required") if result.metadata else None
            )
            meta_params_unexpected = (
                (result.metadata or {}).get("params_unexpected") if result.metadata else None
            )
            if meta_params_missing or meta_params_unexpected:
                LOG.warning(
                    f"Strategy param issues: missing={meta_params_missing or []}, unexpected={meta_params_unexpected or []}"
                )
            self._safe_send_packet(w, original_packet)
            return PacketProcessingResult(
                success=False,
                packets_sent=1,
                error_message=result.error_message,
                attack_used=result.technique_used,
            )
        metadata = result.metadata or {}
        packets_sent = 0

        # Prefer the public API (property). It is the single source of truth and
        # keeps future validation/normalization centralized in AttackResult.
        segments = result.segments
        if segments:
            packets_sent = self._send_attack_segments(w, original_packet, segments)
        elif "modified_payload" in metadata:
            if self._send_modified_payload(w, original_packet, metadata["modified_payload"]):
                packets_sent = 1
        elif "raw_packets" in metadata:
            for packet_data in metadata["raw_packets"]:
                if self._send_raw_packet(w, packet_data, original_packet):
                    packets_sent += 1
        else:
            self._safe_send_packet(w, original_packet)
            packets_sent = 1
        return PacketProcessingResult(
            success=True,
            packets_sent=packets_sent,
            attack_used=result.technique_used,
            metadata=metadata,
        )

    def _create_attack_context_from_packet(
        self, packet: pydivert.Packet, strategy: Dict
    ) -> AttackContext:
        """Создает AttackContext из пакета PyDivert."""
        tcp = getattr(packet, "tcp", None)
        dst_port = getattr(tcp, "dst_port", getattr(tcp, "dport", 0)) if tcp else 0
        src_port = getattr(tcp, "src_port", getattr(tcp, "sport", 0)) if tcp else 0
        return AttackContext(
            dst_ip=packet.dst_addr,
            dst_port=dst_port,
            src_ip=packet.src_addr,
            src_port=src_port,
            payload=bytes(packet.payload),
            protocol="tcp",
            seq=packet.tcp.seq if tcp else 0,
            ack=packet.tcp.ack if tcp else 0,
            params=strategy.get("params", {}).copy(),
            debug=self.config.debug,
        )

    def _execute_strategy_through_adapter(
        self, strategy: Dict[str, Any], context: AttackContext
    ) -> AttackResult:
        """Выполняет стратегию через AttackAdapter."""
        strategy_type = strategy.get("type", "unknown")
        try:
            if strategy_type == "combo_strategy":
                return self._execute_combo_strategy(strategy, context)
            available_attacks = self.attack_adapter.get_available_attacks()
            if strategy_type in available_attacks:
                return self.attack_adapter.execute_attack_by_name(strategy_type, context)
            else:
                legacy_result = self.attack_adapter.execute_legacy_technique(
                    strategy_type, self._context_to_legacy_params(context)
                )
                return self._legacy_result_to_attack_result(legacy_result)
        except Exception as e:
            self.logger.error(f"Ошибка выполнения стратегии '{strategy_type}': {e}")
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=0)

    def _execute_combo_strategy(
        self, strategy: Dict[str, Any], context: AttackContext
    ) -> AttackResult:
        """Выполняет combo стратегию."""
        if not self.combo_attacker:
            return AttackResult(
                status=AttackStatus.ERROR, error_message="ComboAttacker не доступен"
            )
        params = strategy.get("params", {})
        combo_name = params.get("combo_name")
        domain = params.get("domain") or context.domain
        try:
            if combo_name:
                combo_result = self.combo_attacker.execute_combo_by_name(combo_name, context)
            else:
                fingerprint = None
                if domain:
                    fingerprint = self._get_or_create_fingerprint(domain, [context.dst_ip])
                combo = self.combo_attacker.create_adaptive_combo(fingerprint, domain)
                if not combo:
                    raise Exception("Не удалось создать адаптивную combo стратегию")
                combo_result = self.combo_attacker.execute_combo(combo, context)
            return combo_result
        except Exception as e:
            self.logger.error(f"Ошибка выполнения combo стратегии: {e}")
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e))

    def _tcp_flags_int_to_str(self, flags: int) -> str:
        """
        Convert common TCP flags bitmask to WinDivert-style string representation.
        """
        try:
            f = int(flags)
        except Exception:
            return "A"
        mapping = [
            ("F", 0x01),
            ("S", 0x02),
            ("R", 0x04),
            ("P", 0x08),
            ("A", 0x10),
            ("U", 0x20),
        ]
        s = "".join((ch for ch, mask in mapping if (f & mask)))
        return s or "A"

    def _apply_ipv4_ttl(self, packet_raw: bytes, ttl: int) -> bytes:
        """
        Best-effort IPv4 TTL rewrite (does nothing for non-IPv4 packets).
        """
        try:
            t = int(ttl)
            if t < 0 or t > 255:
                return packet_raw
            b = bytearray(packet_raw)
            if len(b) < 20:
                return packet_raw
            version = b[0] >> 4
            if version != 4:
                return packet_raw
            # IPv4 TTL is byte 8
            b[8] = t
            return bytes(b)
        except Exception:
            return packet_raw

    def _apply_tcp_window_size(self, packet_raw: bytes, window_size: int) -> bytes:
        """
        Best-effort TCP window rewrite for IPv4 packets.
        """
        try:
            w = int(window_size)
            if w < 0 or w > 0xFFFF:
                return packet_raw
            b = bytearray(packet_raw)
            if len(b) < 40:
                return packet_raw
            version = b[0] >> 4
            if version != 4:
                return packet_raw
            ip_hlen = (b[0] & 0x0F) * 4
            tcp_window_pos = ip_hlen + 14
            if len(b) >= tcp_window_pos + 2:
                b[tcp_window_pos : tcp_window_pos + 2] = struct.pack("!H", w)
            return bytes(b)
        except Exception:
            return packet_raw

    def _send_attack_segments(
        self,
        w: pydivert.WinDivert,
        original_packet: pydivert.Packet,
        segments: List[Tuple],
    ) -> int:
        """Отправляет сегменты, сгенерированные атакой, с корректным расчетом SEQ."""
        log = self.logger
        packets_sent = 0
        # Базовый Sequence Number из оригинального пакета
        base_seq = original_packet.tcp.seq
        original_payload = bytes(original_packet.payload)
        prev_delay_after_ms: float = 0.0

        for i, segment_info in enumerate(segments):
            data, seq_offset, delay_ms, options = self._parse_segment_info(segment_info)

            # Support both:
            # - delay_ms (before this segment)
            # - delay_ms_after (after previous segment; applied before this one)
            try:
                delay_before_ms = float(delay_ms or 0.0)
            except Exception:
                delay_before_ms = 0.0
            try:
                delay_after_ms = float((options or {}).get("delay_ms_after", 0.0) or 0.0)
            except Exception:
                delay_after_ms = 0.0

            effective_sleep_ms = max(0.0, prev_delay_after_ms) + max(0.0, delay_before_ms)
            if effective_sleep_ms > 0:
                time.sleep(effective_sleep_ms / 1000.0)
            prev_delay_after_ms = max(0.0, delay_after_ms)

            # --- КЛЮЧЕВОЕ ИСПРАВЛЕНИЕ ---
            # Вычисляем новый Sequence Number для КАЖДОГО сегмента
            # на основе его смещения (seq_offset) из "рецепта"
            new_sequence_number = (
                base_seq + seq_offset
            ) & 0xFFFFFFFF  # & 0xFFFFFFFF для обработки переполнения

            opts = options or {}
            # Flags precedence: explicit -> tcp_flags/flags -> engine default
            explicit_flags = opts.get("new_flags", None)
            if explicit_flags is None:
                explicit_flags = opts.get("tcp_flags", opts.get("flags", None))
            if explicit_flags is None:
                flags_str = "A" if i < len(segments) - 1 else "PA"
            elif isinstance(explicit_flags, str):
                flags_str = explicit_flags
            else:
                flags_str = self._tcp_flags_int_to_str(explicit_flags)

            # "delay-only" markers (do not send empty payload packets unless explicitly requested)
            if (not data) and (opts.get("is_session_gap") or opts.get("delay_only")):
                continue

            packet_params = {
                "new_payload": data,
                "new_seq": new_sequence_number,  # <--- ИСПОЛЬЗУЕМ ВЫЧИСЛЕННЫЙ SEQ
                "new_flags": flags_str,
            }

            # Only pass-through keys that are likely to be supported by EnhancedPacketBuilder.
            # Everything else stays in metadata/options for observability.
            tcp_options = opts.get("tcp_options")
            if isinstance(tcp_options, (bytes, bytearray, memoryview)):
                packet_params["tcp_options"] = bytes(tcp_options)

            try:
                new_packet_raw = EnhancedPacketBuilder.assemble_tcp_packet(
                    bytes(original_packet.raw), **packet_params
                )
            except TypeError as e:
                # If builder signature differs, retry with minimal known kwargs
                log.debug(f"assemble_tcp_packet TypeError, retry minimal kwargs: {e}")
                new_packet_raw = EnhancedPacketBuilder.assemble_tcp_packet(
                    bytes(original_packet.raw),
                    new_payload=data,
                    new_seq=new_sequence_number,
                    new_flags=flags_str,
                )

            # Apply post-build low-level modifications (independent of builder kwargs support)
            ttl = opts.get("ttl", None)
            if ttl is not None:
                new_packet_raw = self._apply_ipv4_ttl(new_packet_raw, ttl)
            win = opts.get("window_size_override", opts.get("window_size", None))
            if win is not None:
                new_packet_raw = self._apply_tcp_window_size(new_packet_raw, win)
            if opts.get("corrupt_tcp_checksum") or opts.get("bad_checksum"):
                new_packet_raw = self._apply_bad_checksum(new_packet_raw, 0xDEAD)

            if self._send_raw_packet(w, new_packet_raw, original_packet):
                packets_sent += 1
                # ... (остальная часть метода для валидации остается без изменений) ...
                expected_seq = packet_params.get("new_seq")
                new_seq = expected_seq
                report = self.mod_validator.validate_segment(
                    original_payload,
                    data,
                    expected_seq=expected_seq,
                    new_seq=new_seq,
                    is_last=i == len(segments) - 1,
                )
                if report.success:
                    try:
                        self.metrics.increment_counter("packets_modified")
                    except Exception:
                        pass
                else:
                    log.debug(
                        f"Modification validation failed: {report.reason} {report.details or ''}"
                    )
        return packets_sent

    def _send_modified_payload(
        self,
        w: pydivert.WinDivert,
        original_packet: pydivert.Packet,
        modified_payload: bytes,
    ) -> bool:
        """Отправляет пакет с модифицированным payload."""
        original_payload = bytes(original_packet.payload)
        new_packet_raw = EnhancedPacketBuilder.assemble_tcp_packet(
            bytes(original_packet.raw), new_payload=modified_payload
        )
        sent = self._send_raw_packet(w, new_packet_raw, original_packet)
        if sent:
            report = self.mod_validator.validate_segment(
                original_payload,
                modified_payload,
                expected_seq=None,
                new_seq=None,
                is_last=True,
            )
            if report.success:
                try:
                    self.metrics.increment_counter("packets_modified")
                except Exception:
                    pass
            else:
                LOG.debug(
                    f"Modification validation failed (modified_payload): {report.reason} {report.details or ''}"
                )
        return sent

    def _send_raw_packet(
        self,
        w: pydivert.WinDivert,
        packet_data: bytes,
        template_packet: pydivert.Packet,
    ) -> bool:
        """Отправляет сырые данные пакета."""
        try:
            packet = pydivert.Packet(
                packet_data, template_packet.interface, template_packet.direction
            )
        except Exception:
            try:
                direction = getattr(pydivert, "Direction").OUTBOUND
            except Exception:
                direction = 0
            packet = pydivert.Packet(packet_data, (0, 0), direction)
        return self._safe_send_packet(w, packet)

    def _safe_send_packet(self, w: pydivert.WinDivert, packet: pydivert.Packet) -> bool:
        """Безопасная отправка пакета."""
        try:
            if self.packet_processor.validate_packet(packet):
                w.send(packet)
                self.metrics.increment_counter("packets_sent")
                return True
            else:
                reconstructed = self.packet_processor.reconstruct_packet(packet)
                if reconstructed:
                    w.send(reconstructed)
                    self.metrics.increment_counter("packets_reconstructed_sent")
                    return True
                else:
                    self.metrics.increment_counter("packets_dropped")
                    return False
        except OSError as e:
            if e.winerror == 87:
                self.metrics.increment_counter("windivert_error_87")
            return False
        except Exception:
            return False

    def _is_target_ip(self, ip_str: str, target_ips: Set[str]) -> bool:
        """Проверяет, является ли IP целевым."""
        if ip_str in target_ips:
            return True
        if ip_str.startswith(self.cloudflare_prefixes):
            self.logger.debug(f"IP {ip_str} соответствует префиксу Cloudflare")
            return True
        return False

    def _is_relevant_port(self, port: int, protocol: int) -> bool:
        """Определяет, является ли порт релевантным для обхода DPI."""
        all_relevant_ports = self.standard_web_ports | self.custom_ports
        if protocol == socket.IPPROTO_TCP:
            return port in all_relevant_ports
        elif protocol == socket.IPPROTO_UDP:
            return port in {443} | self.custom_ports
        return False

    def _get_packet_port(self, packet: pydivert.Packet) -> int:
        """Получает порт назначения из пакета."""
        if packet.protocol == socket.IPPROTO_TCP and hasattr(packet, "tcp") and packet.tcp:
            return packet.tcp.dport
        elif packet.protocol == socket.IPPROTO_UDP and hasattr(packet, "udp") and packet.udp:
            return packet.udp.dport
        return 0

    def _get_packet_src_port(self, packet: pydivert.Packet) -> int:
        """Получает порт источника из пакета."""
        if packet.protocol == socket.IPPROTO_TCP and hasattr(packet, "tcp") and packet.tcp:
            return packet.tcp.sport
        elif packet.protocol == socket.IPPROTO_UDP and hasattr(packet, "udp") and packet.udp:
            return packet.udp.sport
        return 0

    def _get_tcp_seq(self, packet: pydivert.Packet) -> int:
        """Получает TCP sequence number из пакета."""
        if packet.protocol == socket.IPPROTO_TCP and hasattr(packet, "tcp") and packet.tcp:
            return packet.tcp.seq
        try:
            raw = bytes(packet.raw)
            ip_hlen = (raw[0] & 15) * 4
            if len(raw) >= ip_hlen + 8:
                return struct.unpack("!I", raw[ip_hlen + 4 : ip_hlen + 8])[0]
        except:
            pass
        return 0

    def _get_tcp_flags_string(self, tcp) -> str:
        """Получает строковое представление TCP флагов."""
        flags = ""
        if hasattr(tcp.flags, "fin") and tcp.flags.fin:
            flags += "F"
        if hasattr(tcp.flags, "syn") and tcp.flags.syn:
            flags += "S"
        if hasattr(tcp.flags, "rst") and tcp.flags.rst:
            flags += "R"
        if hasattr(tcp.flags, "psh") and tcp.flags.psh:
            flags += "P"
        if hasattr(tcp.flags, "ack") and tcp.flags.ack:
            flags += "A"
        if hasattr(tcp.flags, "urg") and tcp.flags.urg:
            flags += "U"
        return flags

    def _get_strategy_for_packet(self, packet: pydivert.Packet) -> Optional[Dict]:
        """Получает стратегию для пакета с учетом кэширования."""
        tcp = getattr(packet, "tcp", None)
        dport = getattr(tcp, "dst_port", getattr(tcp, "dport", 0)) if tcp else 0
        cache_key = f"{packet.dst_addr}:{dport}"
        cached = self.strategy_cache.get(cache_key)
        if cached and time.time() - cached[1] < self.cache_ttl:
            self.metrics.increment_counter("strategy_cache_hits")
            return cached[0]
        strategy = self.strategy_map.get(packet.dst_addr) or self.strategy_map.get("default")
        if strategy:
            self.strategy_cache[cache_key] = (strategy, time.time())
            self.metrics.increment_counter("strategy_cache_misses")
        return strategy

    def _parse_segment_info(
        self, segment_info: Union[tuple, bytes]
    ) -> Tuple[bytes, int, float, Dict[str, Any]]:
        """Парсит информацию о сегменте в унифицированный формат."""
        # bytes-like segment
        if isinstance(segment_info, (bytes, bytearray, memoryview)):
            return (bytes(segment_info), 0, 0.0, {})

        if not isinstance(segment_info, tuple) or len(segment_info) == 0:
            return (b"", 0, 0.0, {})

        data = segment_info[0]
        if not isinstance(data, (bytes, bytearray, memoryview)):
            return (b"", 0, 0.0, {})
        data_b = bytes(data)

        # Defaults
        seq_offset = 0
        delay_ms: float = 0.0
        options: Dict[str, Any] = {}

        def _get_delay_from_options(opts: Dict[str, Any]) -> float:
            try:
                v = opts.get("delay_ms", opts.get("delay_ms_before", 0.0))
                if v is None:
                    v = 0.0
                return float(v)
            except Exception:
                return 0.0

        # 2-tuple:
        #   (data, seq_offset)  [canonical-short]
        #   (data, options_dict) [accepted convenience]
        if len(segment_info) == 2:
            second = segment_info[1]
            if isinstance(second, dict):
                options = second
                delay_ms = _get_delay_from_options(options)
                seq_offset = (
                    int(options.get("seq_offset", 0) or 0) if isinstance(options, dict) else 0
                )
            else:
                try:
                    seq_offset = int(second or 0)
                except Exception:
                    seq_offset = 0
            return (data_b, seq_offset, max(0.0, delay_ms), options)

        # 3+ tuple:
        # canonical: (data, seq_offset, options_dict)
        # legacy:    (data, seq_offset, delay_ms)
        # opt-in legacy: (data, delay_ms, options_dict) when options["_interpret_second_as_delay"]=True
        second = segment_info[1] if len(segment_info) >= 2 else 0
        third = segment_info[2] if len(segment_info) >= 3 else {}

        if isinstance(third, dict):
            options = third
            if options.get("_interpret_second_as_delay"):
                # explicit opt-in to avoid guessing
                seq_offset = 0
                try:
                    delay_ms = float(second or 0.0)
                except Exception:
                    delay_ms = 0.0
            else:
                try:
                    seq_offset = int(second or 0)
                except Exception:
                    seq_offset = 0
                delay_ms = _get_delay_from_options(options)
        else:
            # tolerate (data, seq_offset, delay_ms)
            try:
                seq_offset = int(second or 0)
            except Exception:
                seq_offset = 0
            try:
                delay_ms = float(third or 0.0)
            except Exception:
                delay_ms = 0.0

        # tolerate extended: (data, seq_offset, delay_ms, options_dict)
        if len(segment_info) >= 4 and isinstance(segment_info[3], dict):
            options = segment_info[3]
            # if dict provides delay_ms, it wins
            delay_ms = _get_delay_from_options(options) or delay_ms

        return (data_b, seq_offset, max(0.0, delay_ms), options)

    def _get_or_create_fingerprint(self, domain: str, target_ips: List[str]) -> Any:
        """Получает или создает fingerprint для домена."""
        cache_key = f"{domain}:{','.join(sorted(target_ips))}"
        if cache_key in self.fingerprint_cache:
            cached_fingerprint, cache_time = self.fingerprint_cache[cache_key]
            if time.time() - cache_time < self.cache_ttl:
                return cached_fingerprint
        fp = self.fingerprint_engine.create_comprehensive_fingerprint(domain, target_ips)
        fingerprint = self._run_coro_sync(fp, timeout=60.0)
        if fingerprint:
            self.fingerprint_cache[cache_key] = (fingerprint, time.time())
        return fingerprint

    def _context_to_legacy_params(self, context: AttackContext) -> Dict[str, Any]:
        """Конвертирует AttackContext в legacy параметры."""
        legacy_params = {
            "target_ip": context.dst_ip,
            "target_port": context.dst_port,
            "src_ip": context.src_ip,
            "src_port": context.src_port,
            "payload": context.payload,
            "protocol": context.protocol,
        }
        if context.domain:
            legacy_params["domain"] = context.domain
        if context.seq is not None:
            legacy_params["seq"] = context.seq
        if context.ack is not None:
            legacy_params["ack"] = context.ack
        legacy_params.update(context.params)
        return legacy_params

    def _legacy_result_to_attack_result(self, legacy_result: Dict[str, Any]) -> AttackResult:
        """Конвертирует legacy результат в AttackResult."""
        if legacy_result.get("success", False):
            status = AttackStatus.SUCCESS
        elif legacy_result.get("timeout", False):
            status = AttackStatus.TIMEOUT
        else:
            status = AttackStatus.ERROR
        return AttackResult(
            status=status,
            error_message=legacy_result.get("error_message", ""),
            latency_ms=legacy_result.get("execution_time_ms", 0),
            metadata=legacy_result,
        )

    def _apply_bad_checksum(self, packet_raw: bytes, checksum_value: int) -> bytes:
        """Применяет плохую контрольную сумму к пакету."""
        packet_bytes = bytearray(packet_raw)
        ip_hlen = (packet_bytes[0] & 15) * 4
        tcp_checksum_pos = ip_hlen + 16
        if len(packet_bytes) > tcp_checksum_pos + 1:
            packet_bytes[tcp_checksum_pos : tcp_checksum_pos + 2] = struct.pack(
                "!H", checksum_value
            )
        return bytes(packet_bytes)

    def _log_processing_result(
        self, packet: pydivert.Packet, strategy: Dict, result: PacketProcessingResult
    ) -> None:
        """Логирует результат обработки пакета через DiagnosticSystem."""
        try:
            if result.success:
                self.metrics.increment_counter("strategy_success")
            else:
                self.metrics.increment_counter("strategy_failed")
            # Do NOT increment packets_sent here: it is already counted in _safe_send_packet()
            # Otherwise packets_sent becomes double-counted.
            self.metrics.increment_counter("packets_sent_reported", result.packets_sent)
        except Exception:
            pass
        self.diagnostic_system.log_packet_processing(
            packet=packet,
            action="bypassed" if result.success else "failed",
            technique_used=result.attack_used or strategy.get("type", "unknown"),
            strategy_type=strategy.get("type", "unknown"),
            processing_time_ms=result.execution_time_ms,
            success=result.success,
            error_message=result.error_message,
            byte_level_info=result.metadata,
        )

    def _cleanup(self) -> None:
        """Очистка ресурсов."""
        self.strategy_cache.clear()
        self.attack_adapter.clear_cache()
        EnhancedPacketBuilder.clear_cache()

    def get_combined_stats(self) -> Dict[str, Any]:
        """Получить объединенную статистику всех компонентов."""
        stats = {
            "engine_metrics": self.metrics.get_all_metrics(),
            "packet_processor_stats": self.packet_processor.get_stats(),
            "diagnostic_stats": self.diagnostic_system.get_stats(),
            "fingerprint_stats": self.fingerprint_engine.get_stats(),
            "packet_builder_stats": EnhancedPacketBuilder.get_performance_stats(),
            "attack_adapter_stats": self.attack_adapter.get_execution_stats(),
        }
        if self.performance_optimizer:
            stats["performance_stats"] = self.performance_optimizer.get_comprehensive_stats()
        if self.combo_attacker:
            stats["combo_stats"] = self.combo_attacker.get_stats()
        return stats

    def create_domain_fingerprint(self, domain: str, target_ips: List[str] = None):
        """Создать отпечаток DPI для домена."""
        fp = self.fingerprint_engine.create_comprehensive_fingerprint(domain, target_ips)
        return self._run_coro_sync(fp, timeout=60.0)

    def analyze_domain_behavior(self, domain: str):
        """Анализ поведения DPI для домена."""
        coro = self.fingerprint_engine.analyze_dpi_behavior(domain)
        return self._run_coro_sync(coro, timeout=120.0)

    def get_performance_recommendations(self) -> Dict[str, Any]:
        """Получить рекомендации по оптимизации производительности."""
        if not self.performance_optimizer:
            return {"recommendations": [], "optimization_available": False}
        return self.performance_optimizer.get_optimization_recommendations()

    def get_available_attacks(
        self, category: Optional[str] = None, protocol: Optional[str] = None
    ) -> List[str]:
        """Получить список доступных атак."""
        return self.attack_adapter.get_available_attacks(category, protocol)

    def get_attack_info(self, attack_name: str) -> Optional[Dict[str, Any]]:
        """Получить информацию о конкретной атаке."""
        return self.attack_adapter.get_attack_info(attack_name)

    # ---- DI helpers (were previously unreachable due to indentation after a return) ----
    def set_performance_optimizer(self, optimizer) -> None:
        """
        Set performance optimizer via dependency injection.
        """
        self._performance_optimizer = optimizer
        # Keep main field consistent (engine code uses self.performance_optimizer)
        self.performance_optimizer = optimizer
        self.logger.debug("Performance optimizer injected via DI")

    def set_effectiveness_validator(self, validator) -> None:
        """
        Set effectiveness validator via dependency injection.
        """
        self._effectiveness_validator = validator
        self.logger.debug("Effectiveness validator injected via DI")

    def get_injected_performance_optimizer(self):
        """Get injected performance optimizer."""
        return self._performance_optimizer

    def get_injected_effectiveness_validator(self):
        """Get injected effectiveness validator."""
        return self._effectiveness_validator

    def has_di_dependencies(self) -> bool:
        """Check if DI dependencies are available."""
        return self._performance_optimizer is not None or self._effectiveness_validator is not None

    def get_di_status(self) -> Dict[str, Any]:
        """Get status of DI dependencies."""
        return {
            "performance_optimizer_injected": self._performance_optimizer is not None,
            "effectiveness_validator_injected": self._effectiveness_validator is not None,
            "di_enabled": self.has_di_dependencies(),
        }


def create_packet_processing_engine(
    config: Optional[EngineConfig] = None,
) -> PacketProcessingEngine:
    """Фабричная функция для создания движка."""
    raise EngineError(
        "PacketProcessingEngine must be created via dependency injection "
        "(attack_adapter, fingerprint_engine, diagnostic_system are required)."
    )
