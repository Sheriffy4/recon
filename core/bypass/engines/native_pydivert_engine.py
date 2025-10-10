import threading
import time
import logging
import asyncio
import struct
from typing import Dict, Any, Set, Optional, List, Union
from dataclasses import dataclass
from core.bypass.engines.base import BaseBypassEngine, EngineConfig, EngineStats
from core.bypass.attacks.base import (
    AttackResult,
    AttackStatus,
    AttackContext,
    SegmentTuple,
)
from core.bypass.attacks.segment_packet_builder import (
    SegmentPacketBuilder,
    SegmentPacketInfo,
    validate_segments_for_building,
)
from core.bypass.attacks.timing_controller import get_timing_controller
from core.bypass.diagnostics.segment_diagnostics import get_segment_diagnostic_logger
from core.bypass.monitoring.segment_execution_stats import (
    get_segment_stats_collector,
    ExecutionPhase,
    ExecutionStatus,
)
from core.integration.attack_adapter import AttackAdapter
from core.packet_builder import EnhancedPacketBuilder
from core.windivert_filter import WinDivertFilterGenerator
from core.integration.strategy_prediction_integration import get_strategy_integrator
from core.integration.performance_integration import get_performance_integrator

try:
    import pydivert

    HAS_PYDIVERT = True
except ImportError:
    HAS_PYDIVERT = False
    pydivert = None
LOG = logging.getLogger("NativePydivertEngine")


@dataclass
class InterceptionConfig:
    """Configuration for packet interception."""

    target_ips: Set[str]
    target_ports: Set[int]
    filter_string: Optional[str] = None


class NativePydivertEngine(BaseBypassEngine):
    """
    Engine that uses WinDivert for native packet interception.
    Now correctly integrates with AttackAdapter to apply real strategies.
    """

    _global_handle = None
    _global_lock = threading.Lock()
    _active_count = 0

    def __init__(self, config: EngineConfig):
        super().__init__(config)
        if not HAS_PYDIVERT:
            raise RuntimeError("pydivert not available")
        self.intercept_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.windivert_handle = None
        self.interception_config: Optional[InterceptionConfig] = None
        self.attack_adapter = AttackAdapter()
        self.packet_builder = EnhancedPacketBuilder()
        self.segment_builder = SegmentPacketBuilder(self.packet_builder)
        self.strategy_map: Dict[str, Dict[str, Any]] = {}
        self.strategy_integrator = get_strategy_integrator()
        LOG.info("Strategy prediction integrator initialized")
        self.performance_integrator = get_performance_integrator()
        LOG.info("Performance monitoring integrator initialized")
        self._loop = asyncio.new_event_loop()
        self._loop_thread = threading.Thread(target=self._run_async_loop, daemon=True)
        self._loop_thread.start()
        self._filter_gen = WinDivertFilterGenerator()
        self.recipe_mode = False
        self.segments_recipe: Optional[List[SegmentTuple]] = None
        self._recipe_consumed = False
        self.static_segments_map: Dict[str, List[SegmentTuple]] = {}
        self._recipe_consumed_ips: Set[str] = set()
        self._consumed_recipes: Set[str] = set()
        self.segments_recipe = None

    def _run_async_loop(self):
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def start(
        self, target_ips: Set[str], strategy_map: Dict[str, Dict[str, Any]]
    ) -> bool:
        if self.is_running:
            self.logger.warning("Engine already running")
            return False
        if not isinstance(target_ips, set):
            self.logger.warning(
                f"target_ips is not a set ({type(target_ips)}), converting."
            )
            target_ips = set(target_ips)
        ports = {s.get("target_port", 443) for s in strategy_map.values()}
        if not ports:
            ports = {80, 443}
        self.interception_config = InterceptionConfig(
            target_ips=target_ips, target_ports=ports
        )
        self.logger.info(f"Engine starting for {len(target_ips)} target IPs.")
        self.logger.info(f"Filter target IPs: {target_ips}")
        self.logger.info(f"Filter target ports: {ports}")
        self.strategy_map = strategy_map
        self.stop_event.clear()
        self.intercept_thread = threading.Thread(
            target=self._intercept_loop, daemon=True
        )
        self.intercept_thread.start()
        time.sleep(0.5)
        self.is_running = True
        self.stats.start_time = time.time()
        self.logger.info("Native pydivert engine started")
        return True

    def _extract_sni(self, payload: bytes) -> Optional[str]:
        """Надежно извлекает Server Name Indication (SNI) из TLS ClientHello."""
        try:
            if len(payload) < 42 or payload[0] != 22 or payload[5] != 1:
                return None
            cursor = 43
            session_id_len = payload[cursor]
            cursor += 1 + session_id_len
            cipher_suites_len = struct.unpack("!H", payload[cursor : cursor + 2])[0]
            cursor += 2 + cipher_suites_len
            compression_len = payload[cursor]
            cursor += 1 + compression_len
            if cursor + 2 > len(payload):
                return None
            extensions_len = struct.unpack("!H", payload[cursor : cursor + 2])[0]
            cursor += 2
            extensions_end = cursor + extensions_len
            while cursor + 4 <= extensions_end:
                ext_type = struct.unpack("!H", payload[cursor : cursor + 2])[0]
                ext_len = struct.unpack("!H", payload[cursor + 2 : cursor + 4])[0]
                cursor += 4
                if ext_type == 0:
                    sni_data_start = cursor
                    if ext_len < 5:
                        break
                    server_name_list_len = struct.unpack(
                        "!H", payload[sni_data_start : sni_data_start + 2]
                    )[0]
                    server_name_type = payload[sni_data_start + 2]
                    if server_name_type == 0:
                        name_len_start = sni_data_start + 3
                        server_name_len = struct.unpack(
                            "!H", payload[name_len_start : name_len_start + 2]
                        )[0]
                        name_start = name_len_start + 2
                        if name_start + server_name_len <= sni_data_start + ext_len:
                            domain_bytes = payload[
                                name_start : name_start + server_name_len
                            ]
                            return domain_bytes.decode("utf-8", errors="ignore")
                cursor += ext_len
            return None
        except (struct.error, IndexError) as e:
            self.logger.debug(f"Error parsing TLS ClientHello for SNI: {e}")
            return None
        except Exception as e:
            self.logger.error(
                f"Unexpected error in _extract_sni: {e}", exc_info=self.config.debug
            )
            return None

    def _build_filter(self) -> str:
        """Создает надежный фильтр для WinDivert, используя переданные целевые IP."""
        if not self.interception_config or not self.interception_config.target_ips:
            self.logger.warning(
                "Нет целевых IP для создания фильтра, используется общий фильтр."
            )
            return "outbound and tcp and tcp.DstPort == 443"
        from core.windivert_filter import WinDivertFilterGenerator

        filter_gen = WinDivertFilterGenerator()
        try:
            return filter_gen.generate(
                target_ips=self.interception_config.target_ips,
                target_ports=self.interception_config.target_ports,
                direction="outbound",
                protocols=("tcp",),
            )
        except Exception as e:
            self.logger.error(f"Ошибка генерации фильтра: {e}. Используется fallback.")
            return "outbound and tcp"

    def _intercept_loop(self):
        try:
            with self._global_lock:
                if self._global_handle is None:
                    target_ips = (
                        self.interception_config.target_ips
                        if self.interception_config
                        else set()
                    )
                    target_ports = (
                        self.interception_config.target_ports
                        if self.interception_config
                        else {443}
                    )
                    filter_candidates = self._filter_gen.progressive_candidates(
                        target_ips,
                        target_ports,
                        direction="outbound",
                        protocols=("tcp",),
                    )
                    created = False
                    last_error = None
                    for filter_str in filter_candidates:
                        self.logger.debug(
                            f"Попытка создать хендл WinDivert с фильтром: {filter_str}"
                        )
                        try:
                            self._global_handle = pydivert.WinDivert(filter_str)
                            self._global_handle.open()
                            self.logger.info(
                                f"Успешно создан глобальный хендл с фильтром: {filter_str}"
                            )
                            created = True
                            break
                        except Exception as e:
                            last_error = e
                            self.logger.warning(
                                f"Не удалось создать хендл с фильтром '{filter_str}': {e}"
                            )
                            self._global_handle = None
                    if not created:
                        self.logger.critical(
                            f"КРИТИЧЕСКАЯ ОШИБКА: Не удалось создать ни один хендл WinDivert. Последняя ошибка: {last_error}"
                        )
                        self._cleanup_handle()
                        return
                self._active_count += 1
                self.windivert_handle = self._global_handle
            self.logger.debug("Starting packet interception loop")
            while not self.stop_event.is_set():
                try:
                    packet = self.windivert_handle.recv()
                    if not packet:
                        continue
                    self.stats.packets_processed += 1
                    was_handled = False
                    if self.recipe_mode:
                        if not self._recipe_consumed and self._should_process_packet(
                            packet
                        ):
                            self._recipe_consumed = True
                            was_handled = self._process_packet_with_recipe(packet)
                    elif self._should_process_packet(packet):
                        was_handled = self._process_packet_with_attack(packet)
                    if not was_handled:
                        self.windivert_handle.send(packet)
                except Exception as e:
                    if not self.stop_event.is_set():
                        self.logger.debug(f"Ошибка обработки пакета в цикле: {e}")
                        self.stats.errors += 1
        except Exception as e:
            self.logger.error(
                f"Критическая ошибка в цикле перехвата: {e}", exc_info=self.config.debug
            )
        finally:
            self.logger.debug("Завершение цикла перехвата, очистка ресурсов...")
            self._cleanup_handle()

    def _should_process_packet(self, packet: pydivert.Packet) -> bool:
        """
        Быстро определяет, является ли пакет кандидатом для сложной обработки.
        Основная цель - отфильтровать пакеты без payload и не-TLS/HTTP трафик.
        """
        if not packet.is_outbound or not packet.tcp or (not packet.tcp.payload):
            return False
        payload = bytes(packet.tcp.payload)
        if packet.tcp.dst_port == 443:
            return len(payload) > 5 and payload[0] == 22 and (payload[5] == 1)
        if packet.tcp.dst_port == 80:
            return payload.startswith((b"GET", b"POST", b"PUT", b"DELETE", b"HEAD"))
        return False

    def start_with_strategy_or_segments(
        self,
        target_ips: Set[str],
        strategy_or_segments: Union[Dict[str, Dict[str, Any]], List[SegmentTuple]],
    ) -> bool:
        """
        Start engine with either strategy map (old way) or segments recipe (new way).
        Provides backward compatibility.

        Args:
            target_ips: Set of target IPs
            strategy_or_segments: Either strategy map or segments list

        Returns:
            True if started successfully
        """
        if isinstance(strategy_or_segments, dict):
            return self.start(target_ips, strategy_or_segments)
        elif isinstance(strategy_or_segments, list):
            self.segments_recipe = strategy_or_segments
            self.recipe_mode = True
            return self.start(target_ips, {})
        else:
            self.logger.error(f"Invalid input type: {type(strategy_or_segments)}")
            return False

    def _process_packet_with_recipe(self, packet: pydivert.Packet) -> bool:
        """
        Обрабатывает пакет, применяя заранее заданный рецепт сегментов.
        """
        self.logger.debug(f"Applying segments recipe to packet for {packet.dst_addr}")
        context = self._create_enhanced_attack_context(packet)
        if not context or not self.segments_recipe:
            return False
        from core.bypass.attacks.base import AttackResult, AttackStatus

        recipe_result = AttackResult(
            status=AttackStatus.SUCCESS, segments=self.segments_recipe
        )
        return self._execute_segments_orchestration(recipe_result, context, packet)

    def _process_packet_with_attack(self, packet: pydivert.Packet) -> bool:
        """Enhanced to support both modes."""
        strategy = self.strategy_map.get(packet.dst_addr)
        if strategy and strategy.get("type") == "segments_recipe":
            self.logger.debug(f"Executing segments recipe for {packet.dst_addr}")
            context = self._create_enhanced_attack_context(packet)
            if not context:
                return False
            from core.bypass.attacks.base import AttackResult, AttackStatus

            recipe_result = AttackResult(
                status=AttackStatus.SUCCESS, segments=strategy.get("segments")
            )
            return self._execute_segments_orchestration(recipe_result, context, packet)
        if not strategy:
            try:
                domain = self._get_domain_for_ip(packet.dst_addr)
                recommendation = self.strategy_integrator.predict_best_strategy(
                    packet.dst_addr, domain=domain
                )
                strategy = {
                    "type": recommendation.primary_strategy,
                    "name": recommendation.primary_strategy,
                    "params": {},
                    "ml_predicted": True,
                    "confidence": recommendation.confidence,
                    "fallbacks": recommendation.fallback_strategies,
                    "domain": domain,
                }
                LOG.info(
                    f"ML predicted strategy for {packet.dst_addr} ({domain}): {recommendation.primary_strategy} (confidence: {recommendation.confidence:.2f})"
                )
            except Exception as e:
                LOG.error(f"ML strategy prediction failed for {packet.dst_addr}: {e}")
                return False
        if not strategy:
            return False
        context = self._create_enhanced_attack_context(packet)
        if not context:
            self.logger.warning(
                "Failed to create enhanced AttackContext. Sending original."
            )
            return False
        context.params = strategy.get("params", {})
        attack_name = strategy.get("type") or strategy.get("name")
        try:
            attack_start_time = time.time()
            future = asyncio.run_coroutine_threadsafe(
                self.attack_adapter.execute_attack_by_name(
                    attack_name, context, strategy_params=strategy
                ),
                self._loop,
            )
            attack_result = future.result(timeout=5.0)
            if attack_result.status == AttackStatus.SUCCESS:
                if attack_result.has_segments():
                    return self._execute_segments_orchestration(
                        attack_result, context, packet
                    )
                elif attack_result.modified_payload:
                    return self._send_modified_packet(
                        packet, attack_result.modified_payload
                    )
                else:
                    self.logger.warning(
                        f"Attack '{attack_name}' succeeded but produced no packets."
                    )
                    return False
            else:
                self.logger.error(
                    f"Attack '{attack_name}' failed: {attack_result.error_message}"
                )
                return False
        except Exception as e:
            self.logger.error(
                f"Attack execution for '{attack_name}' raised an exception: {e}",
                exc_info=self.config.debug,
            )
            return False
            attack_latency_ms = (time.time() - attack_start_time) * 1000
            if attack_result.status == AttackStatus.SUCCESS:
                if attack_result.has_segments():
                    return self._execute_segments_orchestration(
                        attack_result, context, packet
                    )
                elif attack_result.modified_payload:
                    return self._send_modified_packet(
                        packet, attack_result.modified_payload
                    )
            success = attack_result.status == AttackStatus.SUCCESS
            self.performance_integrator.record_attack_executed(
                attack_latency_ms, success
            )
            if strategy.get("ml_predicted", False):
                try:
                    feedback_latency = attack_result.metadata.get(
                        "latency_ms", attack_latency_ms
                    )
                    self.strategy_integrator.update_strategy_effectiveness(
                        packet.dst_addr, attack_name, success, feedback_latency
                    )
                except Exception as e:
                    LOG.debug(f"Failed to update ML feedback: {e}")
            if success:
                if hasattr(attack_result, "segments") and attack_result.segments:
                    self._execute_segments_orchestration(attack_result, context, packet)
                self.stats.packets_modified += 1
                return True
            else:
                error_msg = (
                    attack_result.error_message
                    if hasattr(attack_result, "error_message")
                    else "No error message"
                )
                self.logger.debug(
                    f"Attack '{attack_name}' failed: {attack_result.status.value}. Error: {error_msg}"
                )
                if hasattr(attack_result, "metadata"):
                    self.logger.debug(f"Attack metadata: {attack_result.metadata}")
                return False
        except Exception as e:
            self.logger.error(f"Attack execution failed for {attack_name}: {e}")
            self.performance_integrator.record_attack_executed(0, False)
            if strategy.get("ml_predicted", False):
                try:
                    self.strategy_integrator.update_strategy_effectiveness(
                        packet.dst_addr, attack_name, False, 0
                    )
                except Exception as e:
                    LOG.debug(f"Failed to update ML feedback for failure: {e}")
            return False

    def start_with_segments_recipe(
        self, target_ips: Set[str], segments_recipe: List[SegmentTuple]
    ) -> bool:
        """
        Запускает движок в специальном "Режиме Рецепта" для тестирования.
        Движок применит этот рецепт к первому подходящему пакету.
        """
        if self.is_running:
            self.logger.warning("Engine already running")
            return False
        self.recipe_mode = True
        self.segments_recipe = segments_recipe
        self._recipe_consumed = False
        target_port = 443
        self.interception_config = InterceptionConfig(
            target_ips=target_ips, target_ports={target_port}
        )
        self.strategy_map = {}
        self.stop_event.clear()
        self.intercept_thread = threading.Thread(
            target=self._intercept_loop, daemon=True, name="PydivertRecipeThread"
        )
        self.intercept_thread.start()
        time.sleep(0.5)
        self.is_running = True
        self.stats.start_time = time.time()
        self.logger.info(
            f"Native pydivert engine started in RECIPE MODE for IPs {target_ips}"
        )
        return True

    def _create_enhanced_attack_context(
        self, packet: pydivert.Packet
    ) -> Optional[AttackContext]:
        """
        Create enhanced AttackContext with complete TCP session information.

        Args:
            packet: PyDivert packet

        Returns:
            Enhanced AttackContext or None if creation fails
        """
        try:
            payload = packet.tcp.payload if packet.tcp and packet.tcp.payload else b""
            context = AttackContext(
                dst_ip=packet.dst_addr,
                dst_port=packet.dst_port,
                src_ip=packet.src_addr,
                src_port=packet.src_port,
                domain=self._get_domain_for_ip(packet.dst_addr),
                payload=payload,
                raw_packet=packet.raw,
                ttl=packet.ipv4.ttl if packet.ipv4 else 64,
                tcp_seq=packet.tcp.seq_num if packet.tcp else 0,
                tcp_ack=packet.tcp.ack_num if packet.tcp else 0,
                tcp_flags=self._get_tcp_flags_int(packet),
                tcp_window_size=packet.tcp.window_size if packet.tcp else 65535,
                tcp_urgent_pointer=packet.tcp.urg_ptr if packet.tcp else 0,
                connection_id=f"{packet.src_addr}:{packet.src_port}->{packet.dst_addr}:{packet.dst_port}",
                packet_id=1,
                session_established=True,
                initial_seq=packet.tcp.seq_num if packet.tcp else 0,
            )
            return context
        except Exception as e:
            self.logger.error(f"Failed to create enhanced AttackContext: {e}")
            return None

    def _get_tcp_flags_int(self, packet: pydivert.Packet) -> int:
        """
        Convert PyDivert TCP flags to integer representation.

        Args:
            packet: PyDivert packet

        Returns:
            TCP flags as integer
        """
        if not packet.tcp:
            return 24
        flags = 0
        if hasattr(packet.tcp, "fin") and packet.tcp.fin:
            flags |= 1
        if hasattr(packet.tcp, "syn") and packet.tcp.syn:
            flags |= 2
        if hasattr(packet.tcp, "rst") and packet.tcp.rst:
            flags |= 4
        if hasattr(packet.tcp, "psh") and packet.tcp.psh:
            flags |= 8
        if hasattr(packet.tcp, "ack") and packet.tcp.ack:
            flags |= 16
        if hasattr(packet.tcp, "urg") and packet.tcp.urg:
            flags |= 32
        if hasattr(packet.tcp, "ece") and packet.tcp.ece:
            flags |= 64
        if hasattr(packet.tcp, "cwr") and packet.tcp.cwr:
            flags |= 128
        return flags

    def _execute_segments_orchestration(
        self,
        attack_result: AttackResult,
        context: AttackContext,
        original_packet: pydivert.Packet,
    ) -> bool:
        """Исполняет отправку сегментов с полным контролем над параметрами пакетов."""
        try:
            segments = attack_result.get_metadata("segments") or getattr(
                attack_result, "segments", None
            )
            if not segments:
                self.logger.warning(
                    "No segments found in attack result for orchestration"
                )
                return False
            self.logger.info(
                f"Orchestrating {len(segments)} segments for connection {context.connection_id}"
            )
            timing_controller = get_timing_controller()
            for i, segment_info in enumerate(segments):
                payload_data, seq_offset, options = segment_info
                delay_ms = options.get("delay_ms", 0)
                if delay_ms > 0:
                    timing_controller.delay(delay_ms)
                packet_info = self.segment_builder.build_segment(
                    payload=payload_data,
                    seq_offset=seq_offset,
                    options=options,
                    context=context,
                )
                pydivert_packet = pydivert.Packet(
                    packet_info.packet_bytes,
                    original_packet.interface,
                    original_packet.direction,
                )
                self.windivert_handle.send(pydivert_packet)
                self.stats.packets_sent += 1
            self.logger.debug(
                f"Successfully sent {len(segments)} orchestrated segments."
            )
            return True
        except Exception as e:
            self.logger.error(
                f"Segments orchestration failed: {e}", exc_info=self.debug
            )
            return False

    def _validate_segments_for_execution(
        self, segments: list, context: AttackContext
    ) -> tuple[bool, Optional[str]]:
        """
        Validate segments before execution.

        Args:
            segments: List of segment tuples
            context: Attack context

        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            return validate_segments_for_building(segments, context)
        except Exception as e:
            return (False, f"Validation error: {e}")

    def _execute_segments_with_timing(
        self, segments: list, context: AttackContext, original_packet: pydivert.Packet
    ) -> bool:
        """
        Execute segments with precise timing control and comprehensive diagnostic logging.

        Args:
            segments: List of segment tuples
            context: Attack context
            original_packet: Original PyDivert packet for interface/direction info

        Returns:
            True if all segments were sent successfully
        """
        successful_segments = 0
        total_segments = len(segments)
        timing_controller = get_timing_controller()
        diagnostic_logger = get_segment_diagnostic_logger()
        stats_collector = get_segment_stats_collector()
        session_id = f"{context.connection_id}_{int(time.time() * 1000)}"
        diagnostic_logger.start_session(session_id, context.connection_id)
        session_stats = stats_collector.start_session(session_id, context.connection_id)
        try:
            for i, segment in enumerate(segments):
                segment_start_time = time.time()
                segment_data = None
                try:
                    payload_data, seq_offset, options_dict = segment
                    segment_data = diagnostic_logger.log_segment_start(
                        session_id, i + 1, len(payload_data), seq_offset, options_dict
                    )
                    segment_metrics = stats_collector.start_segment_execution(
                        i + 1, session_id, len(payload_data), seq_offset, options_dict
                    )
                    validation_start = time.time()
                    is_valid, error_msg = self._validate_single_segment(
                        segment, context
                    )
                    validation_time = (time.time() - validation_start) * 1000
                    diagnostic_logger.log_validation_phase(
                        segment_data, validation_time, is_valid, error_msg
                    )
                    stats_collector.update_segment_phase(
                        segment_metrics, ExecutionPhase.VALIDATION, validation_time
                    )
                    if not is_valid:
                        self.logger.warning(
                            f"Segment {i + 1} validation failed: {error_msg}"
                        )
                        stats_collector.complete_segment_execution(
                            segment_metrics, ExecutionStatus.FAILED, error_msg
                        )
                        continue
                    construction_start = time.time()
                    packet_info = self.segment_builder.build_segment(
                        payload_data, seq_offset, options_dict, context
                    )
                    construction_time = (time.time() - construction_start) * 1000
                    diagnostic_logger.log_construction_phase(segment_data, packet_info)
                    stats_collector.update_segment_phase(
                        segment_metrics, ExecutionPhase.CONSTRUCTION, construction_time
                    )
                    if "ttl" in options_dict:
                        self._apply_ttl_modification(packet_info, options_dict["ttl"])
                    if options_dict.get("bad_checksum", False):
                        self._apply_checksum_corruption(packet_info)
                    self._apply_sequence_adjustment(packet_info, seq_offset, context)
                    timing_result = None
                    delay_ms = options_dict.get("delay_ms", 0)
                    if delay_ms > 0:
                        timing_start = time.time()
                        timing_result = timing_controller.delay(delay_ms)
                        timing_phase_time = (time.time() - timing_start) * 1000
                        diagnostic_logger.log_timing_phase(segment_data, timing_result)
                        stats_collector.update_segment_phase(
                            segment_metrics, ExecutionPhase.TIMING, timing_phase_time
                        )
                    transmission_start = time.time()
                    success = self._send_segment_packet(
                        packet_info, i + 1, original_packet
                    )
                    transmission_time = (time.time() - transmission_start) * 1000
                    diagnostic_logger.log_transmission_phase(
                        segment_data,
                        transmission_time,
                        success,
                        None if success else "Transmission failed",
                    )
                    stats_collector.update_segment_phase(
                        segment_metrics, ExecutionPhase.TRANSMISSION, transmission_time
                    )
                    if success:
                        successful_segments += 1
                        self.stats.packets_sent += 1
                        self.stats.modified_packets += 1
                        stats_collector.complete_segment_execution(
                            segment_metrics,
                            ExecutionStatus.SUCCESS,
                            None,
                            packet_info.packet_size,
                            packet_info.ttl != 64,
                            packet_info.checksum_corrupted,
                            packet_info.tcp_flags != context.tcp_flags,
                            packet_info.tcp_window != context.tcp_window_size,
                            timing_result.accuracy_error_ms if timing_result else 0.0,
                        )
                        segment_time = (time.time() - segment_start_time) * 1000
                        self._log_segment_execution(
                            i + 1, packet_info, options_dict, segment_time
                        )
                    else:
                        self.logger.warning(f"Failed to send segment {i + 1}")
                        stats_collector.complete_segment_execution(
                            segment_metrics,
                            ExecutionStatus.FAILED,
                            "Transmission failed",
                        )
                except Exception as e:
                    error_msg = str(e)
                    self.logger.error(f"Failed to execute segment {i + 1}: {error_msg}")
                    if segment_data:
                        diagnostic_logger.log_transmission_phase(
                            segment_data, 0.0, False, error_msg
                        )
                    if "segment_metrics" in locals():
                        stats_collector.complete_segment_execution(
                            segment_metrics, ExecutionStatus.ERROR, error_msg
                        )
                    continue
            summary = diagnostic_logger.end_session(session_id)
            session_stats = stats_collector.complete_session(session_id)
            diagnostic_logger.log_execution_summary(summary)
            if session_stats:
                self.logger.info(
                    f"Session statistics: {session_stats.success_rate_percent:.1f}% success rate, {session_stats.avg_segment_time_ms:.2f}ms avg time, {session_stats.throughput_segments_per_sec:.1f} segments/sec"
                )
            success_rate = (
                successful_segments / total_segments * 100 if total_segments > 0 else 0
            )
            self.logger.info(
                f"Segments execution completed: {successful_segments}/{total_segments} successful ({success_rate:.1f}%)"
            )
            return successful_segments > 0
        except Exception as e:
            self.logger.error(f"Segments execution failed: {e}")
            try:
                diagnostic_logger.end_session(session_id)
                stats_collector.complete_session(session_id)
            except:
                pass
            return False

    def _validate_single_segment(
        self, segment: tuple, context: AttackContext
    ) -> tuple[bool, Optional[str]]:
        """
        Validate a single segment.

        Args:
            segment: Segment tuple to validate
            context: Attack context

        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            if len(segment) != 3:
                return (False, "Invalid segment format")
            payload_data, seq_offset, options_dict = segment
            if not isinstance(payload_data, bytes):
                return (False, "payload_data must be bytes")
            if not isinstance(seq_offset, int):
                return (False, "seq_offset must be int")
            if not isinstance(options_dict, dict):
                return (False, "options_dict must be dict")
            if not self.segment_builder.validate_segment_options(options_dict):
                return (False, "Invalid segment options")
            return (True, None)
        except Exception as e:
            return (False, f"Validation error: {e}")

    def _apply_ttl_modification(
        self, packet_info: "SegmentPacketInfo", ttl: int
    ) -> None:
        """
        Apply TTL modification to packet.

        Args:
            packet_info: Packet information object
            ttl: TTL value to apply
        """
        try:
            if packet_info.ttl != ttl:
                self.logger.warning(
                    f"TTL mismatch: expected {ttl}, got {packet_info.ttl}"
                )
            else:
                self.logger.debug(f"TTL modification applied: {ttl}")
        except Exception as e:
            self.logger.error(f"TTL modification failed: {e}")

    def _apply_checksum_corruption(self, packet_info: "SegmentPacketInfo") -> None:
        """
        Apply TCP checksum corruption to packet.

        Args:
            packet_info: Packet information object
        """
        try:
            if packet_info.checksum_corrupted:
                self.logger.debug("TCP checksum corruption applied")
            else:
                self.logger.warning("Checksum corruption was requested but not applied")
        except Exception as e:
            self.logger.error(f"Checksum corruption validation failed: {e}")

    def _apply_sequence_adjustment(
        self, packet_info: "SegmentPacketInfo", seq_offset: int, context: AttackContext
    ) -> None:
        """
        Apply and validate sequence number adjustment.

        Args:
            packet_info: Packet information object
            seq_offset: Sequence offset applied
            context: Attack context
        """
        try:
            expected_seq = context.tcp_seq + seq_offset
            if packet_info.tcp_seq != expected_seq:
                self.logger.warning(
                    f"Sequence number mismatch: expected {expected_seq}, got {packet_info.tcp_seq}"
                )
            else:
                self.logger.debug(
                    f"Sequence adjustment applied: base={context.tcp_seq}, offset={seq_offset}, final={packet_info.tcp_seq}"
                )
        except Exception as e:
            self.logger.error(f"Sequence adjustment validation failed: {e}")

    def _send_segment_packet(
        self,
        packet_info: "SegmentPacketInfo",
        segment_num: int,
        original_packet: pydivert.Packet,
    ) -> bool:
        """
        Send segment packet via PyDivert with error handling.
        """
        try:
            packet_obj = pydivert.Packet(
                packet_info.packet_bytes,
                original_packet.interface,
                original_packet.direction,
            )
            self.windivert_handle.send(packet_obj)
            self.logger.debug(
                f"Segment {segment_num} sent successfully ({packet_info.packet_size} bytes)"
            )
            return True
        except Exception as e:
            self.logger.error(f"Failed to send segment {segment_num}: {e}")
            return False

    def _log_timing_execution(self, segment_num: int, timing_result) -> None:
        """
        Log timing execution details.

        Args:
            segment_num: Segment number
            timing_result: TimingMeasurement from timing controller
        """
        self.logger.debug(
            f"Segment {segment_num} timing: requested={timing_result.requested_delay_ms:.3f}ms, actual={timing_result.actual_delay_ms:.3f}ms, error={timing_result.accuracy_error_ms:.3f}ms, strategy={timing_result.strategy_used.value}"
        )

    def _log_segment_execution(
        self,
        segment_num: int,
        packet_info: "SegmentPacketInfo",
        options: dict,
        execution_time_ms: float,
    ):
        """
        Log detailed information about segment execution.

        Args:
            segment_num: Segment number
            packet_info: Built packet information
            options: Segment options
            execution_time_ms: Total execution time for this segment
        """
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(
                f"Segment {segment_num}: {packet_info.packet_size} bytes, seq={packet_info.tcp_seq}, ack={packet_info.tcp_ack}, flags=0x{packet_info.tcp_flags:02x}, window={packet_info.tcp_window}"
            )
            modifications = []
            if packet_info.ttl != 64:
                modifications.append(f"ttl={packet_info.ttl}")
            if packet_info.checksum_corrupted:
                modifications.append("bad_checksum")
            if options.get("delay_ms", 0) > 0:
                modifications.append(f"delay={options['delay_ms']}ms")
            if modifications:
                self.logger.debug(
                    f"Segment {segment_num} modifications: {', '.join(modifications)}"
                )
            self.logger.debug(
                f"Segment {segment_num} performance: build_time={packet_info.construction_time_ms:.3f}ms, total_time={execution_time_ms:.3f}ms"
            )
        if self.logger.isEnabledFor(logging.INFO):
            payload_size = (
                len(options.get("payload_data", b""))
                if "payload_data" in options
                else 0
            )
            self.logger.info(
                f"Segment {segment_num} executed: {payload_size} bytes payload, {packet_info.packet_size} bytes total"
            )

    def _send_modified_packet(
        self, original_packet: pydivert.Packet, modified_payload: bytes
    ) -> bool:
        """
        Send packet with modified payload (legacy support).

        Args:
            original_packet: Original PyDivert packet
            modified_payload: Modified payload bytes

        Returns:
            True if packet was sent successfully
        """
        try:
            modified_packet = pydivert.Packet(
                original_packet.raw,
                original_packet.interface,
                original_packet.direction,
            )
            modified_packet.tcp.payload = modified_payload
            self.windivert_handle.send(modified_packet)
            self.stats.packets_sent += 1
            self.stats.modified_packets += 1
            self.logger.debug(
                f"Sent modified packet with {len(modified_payload)} bytes payload"
            )
            return True
        except Exception as e:
            self.logger.error(f"Failed to send modified packet: {e}")
            return False

    def _cleanup_handle(self):
        """
        Потокобезопасно уменьшает счетчик пользователей глобального хендла
        и закрывает его, если пользователей не осталось.
        """
        with self._global_lock:
            self._active_count -= 1
            if self._active_count <= 0 and self._global_handle:
                try:
                    self._global_handle.close()
                    self._global_handle = None
                    self.logger.info("Закрыт глобальный хендл WinDivert.")
                except Exception as e:
                    self.logger.warning(f"Ошибка при закрытии глобального хендла: {e}")
        self.windivert_handle = None

    def stop(self) -> bool:
        if not self.is_running:
            return True
        self.logger.debug("Stopping native pydivert engine")
        self.stop_event.set()
        self._cleanup_handle()
        if self.intercept_thread:
            self.intercept_thread.join(timeout=3.0)
            if self.intercept_thread.is_alive():
                self.logger.warning("Intercept thread did not stop cleanly")
        self.is_running = False
        self.stats.stop_time = time.time()
        self.logger.info("Native pydivert engine stopped")
        return True

    def is_healthy(self) -> bool:
        if (
            not self.is_running
            or not self.intercept_thread
            or (not self.intercept_thread.is_alive())
        ):
            return False
        if not self.windivert_handle:
            return False
        if self.stats.packets_processed > 0:
            error_rate = self.stats.errors / self.stats.packets_processed
            if error_rate > 0.1:
                return False
        return True

    def get_stats(self) -> EngineStats:
        """Get engine statistics including segment builder and timing stats."""
        if hasattr(self, "segment_builder"):
            segment_stats = self.segment_builder.get_stats()
            if not hasattr(self.stats, "metadata"):
                self.stats.metadata = {}
            self.stats.metadata.update(
                {
                    "segment_packets_built": segment_stats.get("packets_built", 0),
                    "segment_build_time_ms": segment_stats.get(
                        "total_build_time_ms", 0.0
                    ),
                    "segment_avg_build_time_ms": segment_stats.get(
                        "avg_build_time_ms", 0.0
                    ),
                    "segment_ttl_modifications": segment_stats.get(
                        "ttl_modifications", 0
                    ),
                    "segment_checksum_corruptions": segment_stats.get(
                        "checksum_corruptions", 0
                    ),
                    "segment_flag_modifications": segment_stats.get(
                        "flag_modifications", 0
                    ),
                }
            )
        try:
            timing_controller = get_timing_controller()
            timing_data = None
            for m in ("get_stats", "get_statistics", "get_performance_report"):
                fn = getattr(timing_controller, m, None)
                if callable(fn):
                    timing_data = fn()
                    break
            if not hasattr(self.stats, "metadata") or self.stats.metadata is None:
                self.stats.metadata = {}
            if timing_data is not None:
                if isinstance(timing_data, dict):
                    self.stats.metadata["timing_performance"] = timing_data
                    self.stats.metadata.update(
                        {
                            "timing_total_delays": timing_data.get(
                                "total_delays", timing_data.get("delays_total", 0)
                            ),
                            "timing_average_accuracy": timing_data.get(
                                "average_accuracy_percent",
                                timing_data.get("avg_accuracy_percent", 0.0),
                            ),
                            "timing_errors": timing_data.get(
                                "timing_errors", timing_data.get("errors", 0)
                            ),
                            "timing_total_requested_ms": timing_data.get(
                                "total_requested_time_ms", 0.0
                            ),
                            "timing_total_actual_ms": timing_data.get(
                                "total_actual_time_ms", 0.0
                            ),
                        }
                    )
                else:
                    self.stats.metadata.update(
                        {
                            "timing_total_delays": getattr(
                                timing_data, "total_delays", 0
                            ),
                            "timing_average_accuracy": getattr(
                                timing_data,
                                "average_accuracy_percent",
                                getattr(timing_data, "avg_accuracy_percent", 0.0),
                            ),
                            "timing_errors": getattr(
                                timing_data,
                                "timing_errors",
                                getattr(timing_data, "errors", 0),
                            ),
                            "timing_total_requested_ms": getattr(
                                timing_data, "total_requested_time_ms", 0.0
                            ),
                            "timing_total_actual_ms": getattr(
                                timing_data, "total_actual_time_ms", 0.0
                            ),
                        }
                    )
        except Exception as e:
            self.logger.debug(f"Failed to get timing stats: {e!r}")
        return self.stats

    def get_segment_execution_report(self) -> Dict[str, Any]:
        """
        Get comprehensive segment execution report.

        Returns:
            Detailed report of segment execution performance
        """
        report = {
            "engine_stats": {
                "packets_processed": self.stats.packets_processed,
                "packets_sent": self.stats.packets_sent,
                "modified_packets": getattr(self.stats, "modified_packets", 0),
                "errors": self.stats.errors,
            }
        }
        if hasattr(self, "segment_builder"):
            segment_stats = self.segment_builder.get_stats()
            report["segment_builder"] = segment_stats
        try:
            timing_controller = get_timing_controller()
            report["timing_performance"] = timing_controller.get_performance_report()
        except Exception as e:
            report["timing_performance"] = {"error": str(e)}
        try:
            stats_collector = get_segment_stats_collector()
            report["segment_execution_stats"] = (
                stats_collector.get_performance_summary()
            )
        except Exception as e:
            report["segment_execution_stats"] = {"error": str(e)}
        return report

    async def execute_dry_run_test(
        self, attack_name: str, context: AttackContext
    ) -> AttackResult:
        """
        Execute attack in dry run mode for testing without network transmission.

        Args:
            attack_name: Name of attack to test
            context: Attack context

        Returns:
            AttackResult with dry run simulation details
        """
        try:
            self.logger.info(f"Starting dry run test for attack '{attack_name}'")
            result = await self.attack_adapter.execute_attack_by_name(
                attack_name, context, dry_run=True
            )
            result.metadata = result.metadata or {}
            result.metadata.update(
                {
                    "engine_dry_run": True,
                    "engine_type": "native_pydivert",
                    "engine_stats": self.get_stats().to_dict(),
                }
            )
            self._log_dry_run_results(result, attack_name, context)
            self.logger.info(
                f"Dry run test completed for '{attack_name}': {result.status.value}"
            )
            return result
        except Exception as e:
            self.logger.error(f"Dry run test failed for '{attack_name}': {e}")
            from core.bypass.attacks.base import AttackResult, AttackStatus

            return AttackResult(
                status=AttackStatus.FAILED,
                technique_used=attack_name,
                error_message=f"Dry run test failed: {e}",
                metadata={
                    "engine_dry_run": True,
                    "engine_type": "native_pydivert",
                    "dry_run_error": str(e),
                },
            )

    def _log_dry_run_results(
        self, result: AttackResult, attack_name: str, context: AttackContext
    ):
        """
        Log dry run test results with engine-specific details.

        Args:
            result: Dry run result
            attack_name: Name of attack
            context: Attack context
        """
        self.logger.info("=" * 60)
        self.logger.info(f"ENGINE DRY RUN TEST - Attack: {attack_name}")
        self.logger.info("=" * 60)
        self.logger.info("Engine: NativePyDivertEngine")
        self.logger.info(f"Status: {result.status.value}")
        self.logger.info(f"Target: {context.dst_ip}:{context.dst_port}")
        if result.error_message:
            self.logger.info(f"Error: {result.error_message}")
        if "segment_analysis" in result.metadata:
            analysis = result.metadata["segment_analysis"]
            self.logger.info("Segments Analysis:")
            self.logger.info(f"  - Total segments: {analysis.get('total_segments', 0)}")
            self.logger.info(
                f"  - TTL modifications: {analysis.get('ttl_modifications', 0)}"
            )
            self.logger.info(
                f"  - Checksum corruptions: {analysis.get('checksum_corruptions', 0)}"
            )
            self.logger.info(f"  - Timing delays: {analysis.get('timing_delays', 0)}")
        if "segments_valid" in result.metadata:
            validation_status = (
                "✓ PASSED" if result.metadata["segments_valid"] else "✗ FAILED"
            )
            self.logger.info(f"Validation: {validation_status}")
            if not result.metadata["segments_valid"]:
                errors = result.metadata.get("validation_errors", [])
                for error in errors:
                    self.logger.info(f"  - {error}")
        if "simulation_time_ms" in result.metadata:
            self.logger.info(
                f"Simulation time: {result.metadata['simulation_time_ms']:.3f}ms"
            )
        self.logger.info("=" * 60)

    def test_attack_scenarios(self, attack_scenarios: list) -> dict:
        """
        Test multiple attack scenarios in dry run mode.

        Args:
            attack_scenarios: List of (attack_name, context) tuples

        Returns:
            Dictionary with test results for each scenario
        """
        results = {}
        self.logger.info(
            f"Testing {len(attack_scenarios)} attack scenarios in dry run mode"
        )
        for i, (attack_name, context) in enumerate(attack_scenarios):
            try:
                self.logger.info(
                    f"Testing scenario {i + 1}/{len(attack_scenarios)}: {attack_name}"
                )
                future = asyncio.run_coroutine_threadsafe(
                    self.execute_dry_run_test(attack_name, context), self._loop
                )
                result = future.result(timeout=30.0)
                results[f"{attack_name}_{i}"] = {
                    "attack_name": attack_name,
                    "status": result.status.value,
                    "success": result.status == AttackStatus.SUCCESS,
                    "simulation_time_ms": result.metadata.get("simulation_time_ms", 0),
                    "segments_valid": result.metadata.get("segments_valid", True),
                    "validation_errors": result.metadata.get("validation_errors", []),
                    "error_message": result.error_message,
                }
            except Exception as e:
                self.logger.error(f"Scenario test failed for {attack_name}: {e}")
                results[f"{attack_name}_{i}"] = {
                    "attack_name": attack_name,
                    "status": "ERROR",
                    "success": False,
                    "error_message": str(e),
                }
        total_scenarios = len(attack_scenarios)
        successful_scenarios = sum(
            (1 for r in results.values() if r.get("success", False))
        )
        summary = {
            "total_scenarios": total_scenarios,
            "successful_scenarios": successful_scenarios,
            "failed_scenarios": total_scenarios - successful_scenarios,
            "success_rate": (
                successful_scenarios / total_scenarios * 100
                if total_scenarios > 0
                else 0
            ),
            "results": results,
        }
        self.logger.info(
            f"Attack scenario testing completed: {successful_scenarios}/{total_scenarios} successful ({summary['success_rate']:.1f}%)"
        )
        return summary

    def get_diagnostic_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive diagnostic statistics.

        Returns:
            Diagnostic statistics including segment execution details
        """
        try:
            diagnostic_logger = get_segment_diagnostic_logger()
            global_stats = diagnostic_logger.get_global_statistics()
            stats_collector = get_segment_stats_collector()
            segment_stats = stats_collector.get_global_stats()
            return {
                "diagnostic_system": global_stats,
                "segment_execution_stats": {
                    "total_sessions": segment_stats.total_sessions,
                    "active_sessions": segment_stats.active_sessions,
                    "completed_sessions": segment_stats.completed_sessions,
                    "total_segments_processed": segment_stats.total_segments_processed,
                    "successful_segments": segment_stats.total_successful_segments,
                    "failed_segments": segment_stats.total_failed_segments,
                    "global_success_rate_percent": segment_stats.global_success_rate_percent,
                    "global_throughput_segments_per_sec": segment_stats.global_throughput_segments_per_sec,
                    "global_avg_timing_accuracy_percent": segment_stats.global_avg_timing_accuracy_percent,
                },
                "engine_integration": {
                    "diagnostic_sessions_active": global_stats.get(
                        "active_sessions", 0
                    ),
                    "total_diagnostic_sessions": global_stats.get("total_sessions", 0),
                    "segments_diagnosed": global_stats.get(
                        "total_segments_processed", 0
                    ),
                },
            }
        except Exception as e:
            self.logger.error(f"Failed to get diagnostic statistics: {e}")
            return {"error": str(e)}

    def get_segment_execution_statistics(self) -> Dict[str, Any]:
        """
        Get detailed segment execution statistics.

        Returns:
            Comprehensive segment execution statistics
        """
        try:
            stats_collector = get_segment_stats_collector()
            return stats_collector.get_performance_summary()
        except Exception as e:
            self.logger.error(f"Failed to get segment execution statistics: {e}")
            return {"error": str(e)}

    def get_recent_session_stats(self, count: int = 10) -> List[Dict[str, Any]]:
        """
        Get recent session statistics.

        Args:
            count: Number of recent sessions to return

        Returns:
            List of recent session statistics
        """
        try:
            stats_collector = get_segment_stats_collector()
            recent_sessions = stats_collector.get_recent_sessions(count)
            return [
                {
                    "session_id": session.session_id,
                    "connection_id": session.connection_id,
                    "total_segments": session.total_segments,
                    "successful_segments": session.successful_segments,
                    "success_rate_percent": session.success_rate_percent,
                    "avg_segment_time_ms": session.avg_segment_time_ms,
                    "throughput_segments_per_sec": session.throughput_segments_per_sec,
                    "timing_accuracy_percent": session.timing_accuracy_percent,
                    "total_execution_time_ms": session.total_execution_time_ms,
                }
                for session in recent_sessions
            ]
        except Exception as e:
            self.logger.error(f"Failed to get recent session stats: {e}")
            return []

    def get_performance_metrics(self) -> Dict[str, Any]:
        """
        Get comprehensive performance metrics.

        Returns:
            Performance metrics including timing, throughput, and accuracy
        """
        try:
            stats_collector = get_segment_stats_collector()
            global_stats = stats_collector.get_global_stats()
            performance_summary = stats_collector.get_performance_summary()
            return {
                "throughput": {
                    "segments_per_sec": global_stats.global_throughput_segments_per_sec,
                    "bytes_per_sec": global_stats.global_throughput_bytes_per_sec,
                    "avg_segments_per_session": global_stats.avg_segments_per_session,
                },
                "timing": {
                    "avg_accuracy_percent": global_stats.global_avg_timing_accuracy_percent,
                    "avg_construction_time_ms": global_stats.global_avg_construction_time_ms,
                    "avg_transmission_time_ms": global_stats.global_avg_transmission_time_ms,
                },
                "reliability": {
                    "success_rate_percent": global_stats.global_success_rate_percent,
                    "error_rate_percent": global_stats.error_rate_percent,
                    "total_sessions": global_stats.total_sessions,
                    "completed_sessions": global_stats.completed_sessions,
                },
                "modifications": {
                    "ttl_modifications": global_stats.total_ttl_modifications,
                    "checksum_corruptions": global_stats.total_checksum_corruptions,
                    "tcp_flags_modifications": global_stats.total_tcp_flags_modifications,
                    "window_size_modifications": global_stats.total_window_size_modifications,
                },
                "recent_performance": performance_summary.get("recent_performance", {}),
                "timing_analysis": performance_summary.get("timing_analysis", {}),
                "modification_analysis": performance_summary.get(
                    "modification_analysis", {}
                ),
                "error_analysis": performance_summary.get("error_analysis", {}),
            }
        except Exception as e:
            self.logger.error(f"Failed to get performance metrics: {e}")
            return {"error": str(e)}

    def _get_domain_for_ip(self, ip_address: str) -> Optional[str]:
        """
        Try to get domain name for IP address.
        Uses reverse mapping from strategy_map or simple heuristics.
        """
        for ip, strategy in self.strategy_map.items():
            if ip == ip_address and "domain" in strategy:
                return strategy["domain"]
        ip_to_domain = {
            "104.21.32.39": "rutracker.org",
            "185.60.216.35": "nnmclub.to",
            "31.13.24.36": "instagram.com",
            "217.69.139.200": "mail.ru",
        }
        if ip_address in ip_to_domain:
            return ip_to_domain[ip_address]
        return None

    def _apply_attack_strategy(
        self, packet_data: bytes, packet_info: dict, strategy: dict
    ) -> Optional[bytes]:
        """
        Применяет стратегию атаки к пакету.

        Args:
            packet_data: Данные пакета
            packet_info: Информация о пакете
            strategy: Стратегия для применения

        Returns:
            Модифицированные данные пакета или None
        """
        try:
            from core.bypass.attacks.base import AttackContext, AttackStatus

            context = AttackContext(
                dst_ip=packet_info.get("dst_ip", ""),
                dst_port=packet_info.get("dst_port", 0),
                src_ip=packet_info.get("src_ip", ""),
                src_port=packet_info.get("src_port", 0),
                payload=packet_data,
                protocol=packet_info.get("protocol", "tcp"),
            )
            from scapy.all import IP

            try:
                scapy_packet = IP(packet_data)
            except Exception as e:
                self.logger.debug(f"Could not parse packet as Scapy: {e}")
                return None
            if hasattr(self, "attack_adapter") and self.attack_adapter:
                attack_name = strategy.get("method", "unknown")
                import asyncio

                try:
                    future = asyncio.run_coroutine_threadsafe(
                        self.attack_adapter.execute_attack_by_name(
                            attack_name, context, strategy_params=strategy
                        ),
                        self._loop,
                    )
                    result = future.result(timeout=2.0)
                    if result and result.status == AttackStatus.SUCCESS:
                        modified_packets = result.metadata.get("modified_packets", [])
                        segments = result.metadata.get("segments", [])
                        if modified_packets:
                            modified_packet = modified_packets[0]
                            if hasattr(modified_packet, "raw"):
                                self.logger.debug(
                                    f"Applied strategy {strategy.get('method', 'unknown')}: packet modified"
                                )
                                return bytes(modified_packet.raw)
                            else:
                                return modified_packet
                        elif segments:
                            self.logger.debug(
                                f"Applied strategy {strategy.get('method', 'unknown')}: generated {len(segments)} segments"
                            )
                            return None
                        else:
                            self.logger.debug(
                                f"Strategy {strategy.get('method', 'unknown')} did not modify packet"
                            )
                            return None
                    else:
                        self.logger.debug(
                            f"Strategy {strategy.get('method', 'unknown')} execution failed"
                        )
                        return None
                except asyncio.TimeoutError:
                    self.logger.warning(
                        f"Strategy {strategy.get('method', 'unknown')} execution timed out"
                    )
                    return None
                except Exception as e:
                    self.logger.error(
                        f"Strategy {strategy.get('method', 'unknown')} execution error: {e}"
                    )
                    return None
            else:
                self.logger.warning(
                    "AttackAdapter not available for strategy execution"
                )
                return None
        except Exception as e:
            self.logger.error(f"Error applying attack strategy: {e}")
            import traceback

            self.logger.debug(traceback.format_exc())
            return None
