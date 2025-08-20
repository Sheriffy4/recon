# recon/core/integration/attack_adapter.py
"""
Attack Adapter
...
"""

import time
import logging
import asyncio
import copy
import inspect
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

from ..bypass.attacks.registry import AttackRegistry
from ..bypass.attacks.base import AttackContext, AttackResult, AttackStatus
from ..async_utils import ensure_attack_execution_context
from .strategy_mapper import StrategyMapper
from .result_processor import ResultProcessor
from .integration_config import (
    IntegrationConfig,
    AttackExecutionError,
    CompatibilityError,
)
from ..bypass.engines.packet_executor import IntelligentPacketExecutor


LOG = logging.getLogger("AttackAdapter")


class AttackAdapter:
    # --- НАЧАЛО ИЗМЕНЕНИЯ ---
    def __init__(
        self,
        attack_registry: Optional[AttackRegistry] = None,
        integration_config: Optional[IntegrationConfig] = None,
    ):
        """
        Инициализирует адаптер с опциональной зависимостью AttackRegistry.
        """
        self.attack_registry = (
            attack_registry or AttackRegistry()
        )  # Создаем если не передан
        self.config = integration_config or IntegrationConfig()
        self.logger = logging.getLogger("AttackAdapter")
        self.registry = self.attack_registry  # Используем переданный или созданный

        # Принудительно запускаем автообнаружение
        if hasattr(self.registry, "_ensure_initialized"):
            self.registry._ensure_initialized()

        # Ensure attack imports are available
        self._ensure_attack_imports()

    def _cache_attack_imports(self):
        """Cache attack imports for safe access."""
        try:
            from ..bypass.attacks.base import AttackResult, AttackStatus

            self._cached_attack_result = AttackResult
            self._cached_attack_status = AttackStatus
        except Exception as e:
            self.logger.warning(f"Failed to cache attack imports: {e}")
            self._cached_attack_result = None
            self._cached_attack_status = None

    def _safe_create_attack_result(
        self,
        status_name: str,
        error_message: str = "",
        technique_used: str = "",
        **kwargs,
    ):
        """Safely create AttackResult with proper error handling."""
        try:
            # Try using cached imports first
            if self._cached_attack_result and self._cached_attack_status:
                status = getattr(self._cached_attack_status, status_name)
                return self._cached_attack_result(
                    status=status,
                    error_message=error_message,
                    technique_used=technique_used,
                    **kwargs,
                )
        except Exception:
            pass

        try:
            # Fallback to direct import
            from ..bypass.attacks.base import AttackResult, AttackStatus

            status = getattr(AttackStatus, status_name)
            return AttackResult(
                status=status,
                error_message=error_message,
                technique_used=technique_used,
                **kwargs,
            )
        except Exception as e:
            self.logger.critical(f"Critical error creating AttackResult: {e}")
            return None

        self.strategy_mapper = StrategyMapper()
        self.result_processor = ResultProcessor()

        # Cache imports for safe access
        self._cached_attack_result = None
        self._cached_attack_status = None
        self._cache_attack_imports()

        # --- ДОБАВИТЬ ЭТИ 2 СТРОКИ ---

        if self.config.debug_mode:
            self.logger.setLevel(logging.DEBUG)

        # Initialize IntelligentPacketExecutor for raw packet attacks
        self.packet_executor = IntelligentPacketExecutor(debug=self.config.debug_mode)

        # Thread pool for parallel execution
        self.executor = ThreadPoolExecutor(
            max_workers=self.config.parallel_execution_limit
        )

        # Performance tracking
        self.execution_stats = {
            "total_executions": 0,
            "successful_executions": 0,
            "failed_executions": 0,
            "total_execution_time": 0.0,
            "cache_hits": 0,
            "cache_misses": 0,
            "raw_packet_executions": 0,
            "packet_executor_successes": 0,
        }
        self.stats_lock = Lock()

        # Result cache
        self.result_cache: Dict[str, Dict] = {}
        self.cache_timestamps: Dict[str, float] = {}

        LOG.info("AttackAdapter initialized with unified attack system integration")
        LOG.info("AttackAdapter serves as bridge between testing and production modes")
        LOG.info("IntelligentPacketExecutor integrated for raw packet attacks")

        # Dry run statistics
        self.dry_run_stats = {
            "total_dry_runs": 0,
            "segments_simulated": 0,
            "validation_errors": 0,
            "simulation_time": 0.0,
        }

    _PARAM_ALIASES = {
        "tcp_multisplit": {
            # вход -> (целевой ключ, преобразование)
            "split_count": ("positions", lambda v: list(range(1, int(v) * 2, 2))),
            "split_positions": (
                "positions",
                lambda v: (
                    [int(x) for x in v] if isinstance(v, (list, tuple)) else [int(v)]
                ),
            ),
            "split_pos": ("positions", lambda v: [int(v)]),
            "seq_overlap": ("overlap_size", int),
            "overlap": ("overlap_size", int),
        },
        "tcp_multidisorder": {
            "split_count": ("positions", lambda v: list(range(1, int(v) * 2, 2))),
            "split_positions": (
                "positions",
                lambda v: (
                    [int(x) for x in v] if isinstance(v, (list, tuple)) else [int(v)]
                ),
            ),
            "split_pos": ("positions", lambda v: [int(v)]),
        },
        "tcp_seqovl": {
            "seq_overlap": ("overlap_size", int),
            "split_pos": ("split_pos", int),
        },
        "tcp_fakeddisorder": {
            "split_positions": (
                "split_pos",
                lambda v: int(v[0]) if isinstance(v, (list, tuple)) and v else int(v),
            ),
            "split_pos": ("split_pos", int),
        },
        "badsum_race": {
            "race_delay_ms": ("delay_ms", int),
            "ttl": ("ttl", int),
        },
    }

    def _normalize_attack_params_for_name(
        self,
        attack_name: str,
        provided: Dict[str, Any],
        expected_keys: Optional[set] = None,
    ) -> Dict[str, Any]:
        """
        Приводит параметры к ожидаемым ключам атаки:
        - применяет StrategyMapper.convert_parameters (если есть правила),
        - затем alias-таблицу для известных атак,
        - строит производные значения (positions из split_count и т.д.),
        - чистит лишние ключи, если задан expected_keys.
        """
        normalized = dict(provided or {})

        # 1) Попробовать конвертацию через StrategyMapper (если есть правила)
        try:
            mapped = self.strategy_mapper.convert_parameters(normalized, attack_name)
            if isinstance(mapped, dict) and mapped:
                normalized = mapped
        except Exception:
            pass

        # 2) Применить alias-таблицу для конкретной атаки
        aliases = self._PARAM_ALIASES.get(attack_name, {})
        out: Dict[str, Any] = {}
        consumed_keys = set()

        for src_key, value in normalized.items():
            if src_key in aliases:
                dst_key, converter = aliases[src_key]
                try:
                    out[dst_key] = converter(value)
                    consumed_keys.add(src_key)
                except Exception:
                    # если конверсия не удалась — оставим исходное
                    out[src_key] = value
            else:
                out[src_key] = value

        # 3) Построить производные значения (если указаны только high-level ключи)
        # tcp_multisplit / tcp_multidisorder: split_count -> positions
        if attack_name in ("tcp_multisplit", "tcp_multidisorder"):
            if "positions" not in out:
                if "split_count" in normalized:
                    try:
                        sc = int(normalized["split_count"])
                        out["positions"] = list(range(1, sc * 2, 2))
                    except Exception:
                        pass
            # нормализуем positions к списку int
            if "positions" in out:
                val = out["positions"]
                if isinstance(val, (int, str)):
                    out["positions"] = [int(val)]
                elif isinstance(val, (list, tuple)):
                    out["positions"] = [int(x) for x in val]

        # tcp_seqovl: seq_overlap -> overlap_size
        if attack_name == "tcp_seqovl":
            if "overlap_size" not in out and "seq_overlap" in normalized:
                try:
                    out["overlap_size"] = int(normalized["seq_overlap"])
                except Exception:
                    pass

        # tcp_fakeddisorder: берем первый split_positions или split_pos
        if attack_name == "tcp_fakeddisorder":
            if "split_pos" not in out and "split_positions" in normalized:
                sp = normalized["split_positions"]
                if isinstance(sp, (list, tuple)) and sp:
                    out["split_pos"] = int(sp[0])
                else:
                    try:
                        out["split_pos"] = int(sp)
                    except Exception:
                        pass

        # 4) Очистить лишнее, если есть список ожидаемых ключей
        if expected_keys:
            out = {k: v for k, v in out.items() if k in expected_keys}

        return out

    def is_bridge_component(self) -> bool:
        """
        Confirms that this adapter bridges testing and production modes.

        Returns:
            True - this adapter works with both RealEffectivenessTester and PacketProcessingEngine
        """
        return True

    def supports_testing_mode(self) -> bool:
        """Check if adapter supports testing mode (RealEffectivenessTester)."""
        return True

    def supports_production_mode(self) -> bool:
        """Check if adapter supports production mode (PacketProcessingEngine)."""
        return True

    def execute_legacy_technique(
        self, technique_name: str, params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Convert legacy technique call to new attack execution.

        Args:
            technique_name: Legacy technique name
            params: Legacy parameters

        Returns:
            Result dictionary in legacy format

        Raises:
            CompatibilityError: If technique cannot be mapped
        """
        try:
            LOG.debug(f"Executing legacy technique: {technique_name}")

            # Create legacy strategy format for mapping
            legacy_strategy = {
                "name": technique_name,
                "type": technique_name,
                "params": params,
            }

            # Map to new attacks
            parsed_strategy = self.strategy_mapper.parser.parse(
                strategy_string_from_legacy
            )  # Нужно передать строку
            attack_names = parsed_strategy.attack_types
            if not mappings:
                raise CompatibilityError(
                    f"No mapping found for legacy technique: {technique_name}"
                )

            # Use the first (best) mapping
            mapping = mappings[0]
            attack_name = mapping.attack_names[0]

            # Convert parameters
            converted_params = self.strategy_mapper.convert_parameters(
                params, attack_name
            )

            # Create attack context
            context = self._create_attack_context_from_legacy(params, converted_params)

            # Execute attack
            result = self.execute_attack_by_name(attack_name, context)

            # Process result for legacy compatibility
            legacy_result = self.result_processor.process_attack_result(
                result, attack_name
            )

            # Add mapping information
            legacy_result["mapped_from"] = technique_name
            legacy_result["mapping_confidence"] = mapping.confidence

            LOG.info(
                f"Legacy technique {technique_name} mapped to {attack_name} with {mapping.confidence:.2%} confidence"
            )
            return legacy_result

        except Exception as e:
            LOG.error(f"Failed to execute legacy technique {technique_name}: {e}")
            raise CompatibilityError(f"Legacy technique execution failed: {e}")

    async def execute_attack_by_name(
        self,
        attack_name: str,
        context: "AttackContext",
        strategy_params: Optional[Dict[str, Any]] = None,
    ) -> "AttackResult":
        """
        Находит, создает и выполняет атаку по ее имени, передавая параметры
        через обновленный контекст.
        """
        self.logger.debug(
            f"Executing attack '{attack_name}' for {context.dst_ip}:{context.dst_port}"
        )

        attack_instance = self.attack_registry.create(attack_name)
        if not attack_instance:
            error_msg = f"Attack '{attack_name}' not found in registry."
            self.logger.error(error_msg)
            return AttackResult(status=AttackStatus.NOT_FOUND, error_message=error_msg)

        try:
            # Создаем копию контекста, чтобы не изменять оригинальный объект,
            # который может использоваться в других частях программы.
            execution_context = context.copy()

            # **ИСПРАВЛЕНИЕ:** Извлекаем только словарь 'params' и обновляем контекст.
            if strategy_params:
                params_to_update = strategy_params.get("params", {})
                if params_to_update:
                    execution_context.params.update(params_to_update)

            self.logger.debug(
                f"Final parameters for '{attack_name}': {execution_context.params}"
            )

            # Выполняем атаку, передавая только контекст.
            if inspect.iscoroutinefunction(attack_instance.execute):
                result = await attack_instance.execute(execution_context)
            else:
                loop = asyncio.get_running_loop()
                result = await loop.run_in_executor(
                    None, attack_instance.execute, execution_context
                )

            return result

        except Exception as e:
            self.logger.error(
                f"Exception during execution of attack '{attack_name}': {e}",
                exc_info=True,
            )
            # Возвращаем стандартизированный результат ошибки.
            # Предполагается, что циклические импорты устранены.
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"Exception during execution: {e}",
                technique_used=attack_name,
            )

    async def execute_attack_sequence(
        self, stages: List[Dict[str, Any]], initial_context: AttackContext
    ) -> AttackResult:
        """
        Выполняет последовательность атак (комбо).
        """
        self.logger.info(f"Executing dynamic combo with {len(stages)} stages.")

        current_context = copy.deepcopy(initial_context)
        all_results: List[AttackResult] = []
        successful_stages = []

        for i, stage_task in enumerate(stages):
            stage_name = stage_task.get("name") or stage_task.get("type")
            if not stage_name:
                self.logger.warning(f"Stage {i+1} has no name, skipping.")
                continue

            self.logger.debug(f"  Stage {i+1}/{len(stages)}: Executing '{stage_name}'")

            # --- НОРМАЛИЗАЦИЯ ПАРАМЕТРОВ ДЛЯ СТАДИИ ---
            stage_params_raw = stage_task.get("params", {}) or {}
            # Если схема у конкретной атаки недоступна — expected_keys=None (не фильтруем лишнее)
            stage_params = self._normalize_attack_params_for_name(
                stage_name, stage_params_raw, expected_keys=None
            )
            current_context.params = stage_params
            # --- КОНЕЦ НОРМАЛИЗАЦИИ ---

            stage_result = await self.execute_attack_by_name(
                stage_name, current_context
            )
            all_results.append(stage_result)

            # Безопасная проверка статуса
            try:
                is_success = stage_result.status == AttackStatus.SUCCESS
            except NameError:
                from ..bypass.attacks.base import AttackStatus as AS

                is_success = stage_result.status == AS.SUCCESS

            if is_success:
                successful_stages.append(stage_name)
                current_context = self._update_context_from_result(
                    current_context, stage_result
                )
            else:
                self.logger.warning(
                    f"  Stage '{stage_name}' failed. Stopping combo execution."
                )
                break

        return self._aggregate_combo_results(all_results, successful_stages, stages)

    def _aggregate_combo_results(
        self,
        results: List[AttackResult],
        successful_stages: List[str],
        all_stages: List[Dict],
    ) -> AttackResult:
        """Агрегирует результаты комбо-атаки."""
        if not results:
            return self._safe_create_attack_result(
                status_name="ERROR", error_message="No stages were executed."
            )

        final_result = results[-1]

        if len(successful_stages) < len(all_stages):
            try:
                final_result.status = AttackStatus.ERROR
            except NameError:
                from ..bypass.attacks.base import AttackStatus as AS

                final_result.status = AS.ERROR
            failed_stage_info = all_stages[len(successful_stages)]
            failed_stage_name = failed_stage_info.get("name") or failed_stage_info.get(
                "type", "unknown_stage"
            )
            final_result.error_message = (
                f"Combo failed at stage '{failed_stage_name}'. "
                + (final_result.error_message or "")
            )

        # Суммируем метрики
        final_result.latency_ms = sum(r.latency_ms for r in results)
        final_result.packets_sent = sum(r.packets_sent for r in results)
        final_result.bytes_sent = sum(r.bytes_sent for r in results)
        final_result.technique_used = "dynamic_combo"
        final_result.set_metadata(
            "combo_stages_executed", [r.technique_used for r in results]
        )
        final_result.set_metadata("combo_successful_stages", successful_stages)

        return final_result

    def execute_attack_parallel(
        self, attacks: List[str], context: AttackContext
    ) -> List[AttackResult]:
        """
        Execute multiple attacks in parallel.

        Args:
            attacks: List of attack names to execute
            context: Attack execution context

        Returns:
            List of AttackResult objects
        """
        try:
            LOG.info(f"Executing {len(attacks)} attacks in parallel")

            if len(attacks) > self.config.parallel_execution_limit:
                raise AttackExecutionError(
                    f"Too many parallel attacks: {len(attacks)} > {self.config.parallel_execution_limit}"
                )

            # Submit all attacks to thread pool
            future_to_attack = {}
            for attack_name in attacks:
                future = self.executor.submit(
                    self.execute_attack_by_name, attack_name, context
                )
                future_to_attack[future] = attack_name

            # Collect results as they complete
            results = []
            for future in as_completed(
                future_to_attack, timeout=self.config.attack_timeout_seconds
            ):
                attack_name = future_to_attack[future]
                try:
                    result = future.result()
                    results.append(result)
                    LOG.debug(
                        f"Parallel attack {attack_name} completed: {result.status.value}"
                    )
                except Exception as e:
                    LOG.error(f"Parallel attack {attack_name} failed: {e}")
                    error_result = self._safe_create_attack_result(
                        status_name="ERROR", error_message=str(e), latency_ms=0
                    )
                    results.append(error_result)

            LOG.info(f"Parallel execution completed: {len(results)} results")
            return results

        except Exception as e:
            LOG.error(f"Failed to execute attacks in parallel: {e}")
            raise AttackExecutionError(f"Parallel attack execution failed: {e}")

    def get_available_attacks(
        self, category: Optional[str] = None, protocol: Optional[str] = None
    ) -> List[str]:
        """
        Get list of available attacks, optionally filtered by category or protocol.

        Args:
            category: Filter by attack category (optional)
            protocol: Filter by supported protocol (optional)

        Returns:
            List of attack names
        """
        try:
            if category:
                attacks = self.registry.get_by_category(category)
                attack_names = list(attacks.keys())
            else:
                attacks = self.registry.get_all()
                attack_names = list(attacks.keys())

            # Filter by protocol if specified
            if protocol:
                filtered_names = []
                for name in attack_names:
                    attack = self.registry.create(name)
                    if attack and protocol in attack.supported_protocols:
                        filtered_names.append(name)
                attack_names = filtered_names

            LOG.debug(
                f"Found {len(attack_names)} attacks (category: {category}, protocol: {protocol})"
            )
            return attack_names

        except Exception as e:
            LOG.error(f"Failed to get available attacks: {e}")
            return []

    def get_attack_info(self, attack_name: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a specific attack.

        Args:
            attack_name: Name of the attack

        Returns:
            Dictionary with attack information or None if not found
        """
        try:
            attack = self.registry.create(attack_name)
            if not attack:
                return None

            return {
                "name": attack.name,
                "category": attack.category,
                "description": attack.description,
                "supported_protocols": attack.supported_protocols,
                "class_name": attack.__class__.__name__,
            }

        except Exception as e:
            LOG.error(f"Failed to get attack info for {attack_name}: {e}")
            return None

    def get_execution_stats(self) -> Dict[str, Any]:
        """
        Get execution statistics.

        Returns:
            Dictionary with execution statistics
        """
        with self.stats_lock:
            stats = self.execution_stats.copy()

        # Calculate derived statistics
        if stats["total_executions"] > 0:
            stats["success_rate"] = (
                stats["successful_executions"] / stats["total_executions"]
            )
            stats["average_execution_time"] = (
                stats["total_execution_time"] / stats["total_executions"]
            )
        else:
            stats["success_rate"] = 0.0
            stats["average_execution_time"] = 0.0

        # Add cache statistics
        total_cache_requests = stats["cache_hits"] + stats["cache_misses"]
        if total_cache_requests > 0:
            stats["cache_hit_rate"] = stats["cache_hits"] / total_cache_requests
        else:
            stats["cache_hit_rate"] = 0.0

        stats["cache_size"] = len(self.result_cache)

        return stats

    def clear_cache(self):
        """Clear the result cache."""
        self.result_cache.clear()
        self.cache_timestamps.clear()
        LOG.info("Attack result cache cleared")

    def _create_attack_context_from_legacy(
        self, legacy_params: Dict[str, Any], converted_params: Dict[str, Any]
    ) -> AttackContext:
        """Create AttackContext from legacy parameters."""

        # Extract common parameters
        dst_ip = legacy_params.get(
            "target_ip", legacy_params.get("dst_ip", "127.0.0.1")
        )
        dst_port = legacy_params.get("target_port", legacy_params.get("dst_port", 80))
        payload = legacy_params.get("payload", b"")
        protocol = legacy_params.get("protocol", "tcp")

        # Create context
        context = AttackContext(
            dst_ip=dst_ip,
            dst_port=dst_port,
            payload=payload,
            protocol=protocol,
            params=converted_params,
        )

        # Add optional parameters if present
        if "src_ip" in legacy_params:
            context.src_ip = legacy_params["src_ip"]

        if "src_port" in legacy_params:
            context.src_port = legacy_params["src_port"]

        if "domain" in legacy_params:
            context.domain = legacy_params["domain"]

        if "timeout" in legacy_params:
            context.timeout = float(legacy_params["timeout"])

        return context

    def _validate_attack_context(self, attack, context: AttackContext):
        """Validate attack context for the given attack."""

        # Check if protocol is supported
        if context.protocol not in attack.supported_protocols:
            raise AttackExecutionError(
                f"Attack {attack.name} does not support protocol {context.protocol}. "
                f"Supported: {attack.supported_protocols}"
            )

        # Check payload size limits
        if len(context.payload) > 65535:  # Max packet size
            raise AttackExecutionError(
                f"Payload too large: {len(context.payload)} bytes"
            )

        # Validate IP address format (basic check)
        if not context.dst_ip or context.dst_ip == "0.0.0.0":
            raise AttackExecutionError("Invalid destination IP address")

        # Validate port range (skip for ICMP)
        if context.protocol != "icmp" and not 1 <= context.dst_port <= 65535:
            raise AttackExecutionError(f"Invalid destination port: {context.dst_port}")

    def _execute_with_timeout(self, attack, context: AttackContext) -> AttackResult:
        """Execute attack with timeout protection."""

        # Submit to thread pool with timeout
        future = self.executor.submit(attack.execute, context)

        try:
            result = future.result(timeout=self.config.attack_timeout_seconds)
            return result
        except TimeoutError:
            future.cancel()
            return self._safe_create_attack_result(
                status_name="TIMEOUT",
                error_message=f"Attack timed out after {self.config.attack_timeout_seconds}s",
                latency_ms=self.config.attack_timeout_seconds * 1000,
            )

    def _generate_cache_key(self, attack_name: str, context: AttackContext) -> str:
        """Generate a more robust cache key for attack result."""
        try:
            # Преобразуем нехэшируемые типы в params в строки
            hashable_params = {}
            for k, v in context.params.items():
                if isinstance(v, (list, dict)):
                    hashable_params[k] = str(v)
                else:
                    hashable_params[k] = v

            context_str = (
                f"{context.dst_ip}:{context.dst_port}:{context.protocol}:"
                f"{len(context.payload)}:{hash(frozenset(hashable_params.items()))}"
            )
            return f"{attack_name}:{hash(context_str)}"
        except Exception as e:
            LOG.debug(f"Failed to generate complex cache key: {e}")
            # Fallback на более простой, но менее точный ключ
            return f"{attack_name}:{context.dst_ip}:{context.dst_port}:{len(context.payload)}"

    def _get_cached_result(self, cache_key: str) -> Optional[AttackResult]:
        """Get cached result if still valid."""

        if cache_key not in self.result_cache:
            with self.stats_lock:
                self.execution_stats["cache_misses"] += 1
            return None

        # Check if cache entry is still valid
        timestamp = self.cache_timestamps.get(cache_key, 0)
        if time.time() - timestamp > self.config.cache_ttl_seconds:
            # Cache expired
            del self.result_cache[cache_key]
            del self.cache_timestamps[cache_key]
            with self.stats_lock:
                self.execution_stats["cache_misses"] += 1
            return None

        return self.result_cache[cache_key]

    def _cache_result(self, cache_key: str, result: AttackResult):
        """Cache attack result."""

        # Check cache size limit
        if len(self.result_cache) >= self.config.max_cache_size:
            # Remove oldest entry
            oldest_key = min(
                self.cache_timestamps.keys(), key=lambda k: self.cache_timestamps[k]
            )
            del self.result_cache[oldest_key]
            del self.cache_timestamps[oldest_key]

        # Cache result
        self.result_cache[cache_key] = result
        self.cache_timestamps[cache_key] = time.time()

    def _update_context_from_result(
        self, context: AttackContext, result: AttackResult
    ) -> AttackContext:
        """Обновляет контекст на основе результата предыдущей стадии."""
        new_context = copy.deepcopy(context)
        if result.metadata and "modified_payload" in result.metadata:
            new_context.payload = result.metadata["modified_payload"]
        if result.metadata and "next_params" in result.metadata:
            new_context.params.update(result.metadata["next_params"])
        return new_context

    def _update_execution_stats(self, success: bool, execution_time: float):
        """Update execution statistics."""

        with self.stats_lock:
            self.execution_stats["total_executions"] += 1
            self.execution_stats["total_execution_time"] += execution_time

            if success:
                self.execution_stats["successful_executions"] += 1
            else:
                self.execution_stats["failed_executions"] += 1

    def _ensure_attack_imports(self):
        """Ensure all necessary imports are available for attack execution."""
        try:
            # Get attack execution context and inject into current globals
            context = ensure_attack_execution_context()

            # Inject imports into the current module's globals
            current_globals = globals()
            for name, value in context.items():
                if value is not None and name not in current_globals:
                    current_globals[name] = value

            LOG.debug("Attack imports ensured successfully")

        except Exception as e:
            LOG.warning(f"Failed to ensure attack imports: {e}")

    def _should_execute_raw_packets(self, result: AttackResult) -> bool:
        """
        Determine if attack result contains raw packets that should be executed.

        Args:
            result: Attack result to check

        Returns:
            True if raw packets should be executed
        """
        # Check if result has 'is_raw' metadata indicating raw packet attack
        if result.metadata.get("is_raw", False):
            return True

        # Check if result has modified_packets (from stateful/race attacks)
        if hasattr(result, "modified_packets") and result.modified_packets:
            return True

        # Check if result has segments for packet execution
        if result.metadata.get("segments"):
            return True

        return False

    async def _execute_raw_packets(
        self, context: AttackContext, result: AttackResult
    ) -> bool:
        """
        Execute raw packets using IntelligentPacketExecutor.

        Args:
            context: Attack context
            result: Attack result containing raw packet data

        Returns:
            True if raw packet execution succeeded
        """
        try:
            with self.stats_lock:
                self.execution_stats["raw_packet_executions"] += 1

            LOG.debug(f"Executing raw packets for attack {result.technique_used}")

            # Handle different types of raw packet data
            if result.metadata.get("segments"):
                # Attack result has segments (from packet builder attacks)
                success = await asyncio.to_thread(
                    self.packet_executor.execute_attack_session, context, result
                )

            elif hasattr(result, "modified_packets") and result.modified_packets:
                # Attack result has modified packets (from Scapy-based attacks)
                success = await self._execute_scapy_packets(
                    context, result.modified_packets
                )

            else:
                LOG.warning("Raw packet execution requested but no packet data found")
                return False

            if success:
                LOG.debug(f"Raw packet execution succeeded for {result.technique_used}")
            else:
                LOG.warning(f"Raw packet execution failed for {result.technique_used}")

            return success

        except Exception as e:
            LOG.error(f"Error executing raw packets: {e}")
            return False

    async def _execute_scapy_packets(
        self, context: AttackContext, packets: List[Any]
    ) -> bool:
        """
        Execute Scapy packets by converting them to segments for IntelligentPacketExecutor.

        Args:
            context: Attack context
            packets: List of Scapy packets

        Returns:
            True if execution succeeded
        """
        try:
            # Convert Scapy packets to segments format
            segments = []

            for i, packet in enumerate(packets):
                try:
                    # Extract payload from Scapy packet
                    if hasattr(packet, "load"):
                        payload = packet.load
                    elif hasattr(packet, "payload") and hasattr(packet.payload, "load"):
                        payload = packet.payload.load
                    else:
                        payload = bytes(packet)

                    # Create segment info
                    segment_info = (payload, i * len(payload), {})
                    segments.append(segment_info)

                except Exception as e:
                    LOG.warning(f"Failed to convert Scapy packet {i}: {e}")
                    continue

            if not segments:
                LOG.warning("No valid segments extracted from Scapy packets")
                return False

            # Create a mock AttackResult with segments
            mock_result = self._safe_create_attack_result(
                status_name="SUCCESS",
                technique_used="scapy_conversion",
                metadata={"segments": segments},
            )
            if mock_result:
                mock_result.success = True

            # Execute using packet executor
            success = await asyncio.to_thread(
                self.packet_executor.execute_attack_session, context, mock_result
            )

            return success

        except Exception as e:
            LOG.error(f"Error executing Scapy packets: {e}")
            return False

    def get_execution_stats(self) -> Dict[str, Any]:
        """
        Get comprehensive execution statistics including raw packet execution.

        Returns:
            Dictionary with execution statistics
        """
        with self.stats_lock:
            stats = self.execution_stats.copy()

        # Calculate derived statistics
        if stats["total_executions"] > 0:
            stats["success_rate"] = (
                stats["successful_executions"] / stats["total_executions"]
            )
            stats["average_execution_time"] = (
                stats["total_execution_time"] / stats["total_executions"]
            )
        else:
            stats["success_rate"] = 0.0
            stats["average_execution_time"] = 0.0

        if stats["raw_packet_executions"] > 0:
            stats["raw_packet_success_rate"] = (
                stats["packet_executor_successes"] / stats["raw_packet_executions"]
            )
        else:
            stats["raw_packet_success_rate"] = 0.0

        # Add cache statistics
        total_cache_requests = stats["cache_hits"] + stats["cache_misses"]
        if total_cache_requests > 0:
            stats["cache_hit_rate"] = stats["cache_hits"] / total_cache_requests
        else:
            stats["cache_hit_rate"] = 0.0

        return stats

    def supports_raw_packet_execution(self) -> bool:
        """
        Check if raw packet execution is supported.

        Returns:
            True if IntelligentPacketExecutor is available and functional
        """
        return self.packet_executor is not None

    async def _execute_dry_run(
        self, attack, context: AttackContext, attack_name: str
    ) -> AttackResult:
        """
        Execute attack in dry run mode - simulate execution without network transmission.

        Args:
            attack: Attack instance to simulate
            context: Attack context
            attack_name: Name of the attack

        Returns:
            AttackResult with simulation details
        """
        start_time = time.time()

        try:
            with self.stats_lock:
                self.dry_run_stats["total_dry_runs"] += 1

            LOG.info(f"Starting dry run simulation for attack '{attack_name}'")

            # Create dry run result
            result = self._safe_create_attack_result(
                status_name="SUCCESS",
                technique_used=attack_name,
                latency_ms=0.0,
                metadata={
                    "dry_run": True,
                    "simulation_mode": True,
                    "attack_name": attack_name,
                    "context_summary": self._create_context_summary(context),
                },
            )

            # Simulate attack execution by calling the attack's execute method
            # but intercept any network operations
            try:
                # Execute attack in simulation mode
                simulated_result = await self._simulate_attack_execution(
                    attack, context
                )

                # Merge simulation results
                if simulated_result:
                    result.status = simulated_result.status
                    result.technique_used = (
                        simulated_result.technique_used or attack_name
                    )
                    result.error_message = simulated_result.error_message

                    # Copy metadata from simulated result
                    if simulated_result.metadata:
                        result.metadata.update(simulated_result.metadata)

                    # Handle segments simulation
                    if (
                        hasattr(simulated_result, "_segments")
                        and simulated_result._segments
                    ):
                        segments = simulated_result._segments
                        result._segments = segments
                        result.metadata["segments"] = segments
                        result.metadata["segments_count"] = len(segments)

                        # Simulate segment validation and analysis
                        validation_result = self._simulate_segments_validation(
                            segments, context
                        )
                        result.metadata.update(validation_result)

                        with self.stats_lock:
                            self.dry_run_stats["segments_simulated"] += len(segments)

                    # Handle modified payload
                    if simulated_result.modified_payload:
                        result.modified_payload = simulated_result.modified_payload
                        result.metadata["payload_modified"] = True
                        result.metadata["original_payload_size"] = len(context.payload)
                        result.metadata["modified_payload_size"] = len(
                            simulated_result.modified_payload
                        )

            except Exception as e:
                LOG.warning(f"Dry run simulation encountered error: {e}")
                try:
                    result.status = AttackStatus.FAILED
                except NameError:
                    from ..bypass.attacks.base import AttackStatus as AS

                    result.status = AS.FAILED
                result.error_message = f"Simulation error: {e}"
                result.metadata["simulation_error"] = str(e)

                with self.stats_lock:
                    self.dry_run_stats["validation_errors"] += 1

            # Add dry run specific metadata
            simulation_time = (time.time() - start_time) * 1000
            result.latency_ms = simulation_time
            result.metadata["simulation_time_ms"] = simulation_time
            result.metadata["dry_run_timestamp"] = time.time()

            # Log dry run summary
            self._log_dry_run_summary(result, attack_name, context)

            with self.stats_lock:
                self.dry_run_stats["simulation_time"] += simulation_time

            LOG.info(
                f"Dry run simulation completed for '{attack_name}' in {simulation_time:.3f}ms"
            )

            return result

        except Exception as e:
            LOG.error(f"Dry run execution failed for '{attack_name}': {e}")

            # Return failed result
            return self._safe_create_attack_result(
                status_name="FAILED",
                technique_used=attack_name,
                error_message=f"Dry run failed: {e}",
                latency_ms=(time.time() - start_time) * 1000,
                metadata={
                    "dry_run": True,
                    "simulation_mode": True,
                    "dry_run_error": str(e),
                },
            )

    async def _simulate_attack_execution(self, attack, context: AttackContext):
        """
        Simulate attack execution by calling the attack but preventing network operations.

        Args:
            attack: Attack instance
            context: Attack context

        Returns:
            Simulated AttackResult
        """
        try:
            # Create a copy of context for simulation
            sim_context = copy.deepcopy(context)
            sim_context.params = sim_context.params or {}
            sim_context.params["dry_run"] = True
            sim_context.params["simulation_mode"] = True

            # Execute attack in thread to prevent blocking
            result = await asyncio.to_thread(attack.execute, sim_context)

            return result

        except Exception as e:
            LOG.debug(f"Attack simulation failed: {e}")
            return None

    def _simulate_segments_validation(
        self, segments: list, context: AttackContext
    ) -> dict:
        """
        Simulate validation of segments for dry run.

        Args:
            segments: List of segment tuples
            context: Attack context

        Returns:
            Dictionary with validation results
        """
        validation_result = {
            "segments_validated": True,
            "validation_errors": [],
            "segment_analysis": {},
        }

        try:
            # Import validation function
            from ..bypass.attacks.segment_packet_builder import (
                validate_segments_for_building,
            )

            is_valid, error_msg = validate_segments_for_building(segments, context)

            validation_result["segments_valid"] = is_valid
            if not is_valid:
                validation_result["validation_errors"].append(error_msg)

            # Analyze segments
            total_payload_size = 0
            ttl_modifications = 0
            checksum_corruptions = 0
            timing_delays = 0

            for i, segment in enumerate(segments):
                if len(segment) >= 3:
                    payload_data, seq_offset, options = segment[:3]

                    total_payload_size += (
                        len(payload_data) if isinstance(payload_data, bytes) else 0
                    )

                    if isinstance(options, dict):
                        if options.get("ttl") and options["ttl"] != 64:
                            ttl_modifications += 1
                        if options.get("bad_checksum"):
                            checksum_corruptions += 1
                        if options.get("delay_ms", 0) > 0:
                            timing_delays += 1

            validation_result["segment_analysis"] = {
                "total_segments": len(segments),
                "total_payload_size": total_payload_size,
                "ttl_modifications": ttl_modifications,
                "checksum_corruptions": checksum_corruptions,
                "timing_delays": timing_delays,
            }

        except Exception as e:
            validation_result["segments_validated"] = False
            validation_result["validation_errors"].append(f"Validation error: {e}")

        return validation_result

    def _create_context_summary(self, context: AttackContext) -> dict:
        """
        Create summary of attack context for dry run logging.

        Args:
            context: Attack context

        Returns:
            Dictionary with context summary
        """
        return {
            "dst_ip": context.dst_ip,
            "dst_port": context.dst_port,
            "protocol": context.protocol,
            "payload_size": len(context.payload) if context.payload else 0,
            "domain": context.domain,
            "params_count": len(context.params) if context.params else 0,
            "has_tcp_session": hasattr(context, "tcp_seq")
            and context.tcp_seq is not None,
        }

    def _log_dry_run_summary(
        self, result: AttackResult, attack_name: str, context: AttackContext
    ):
        """
        Log comprehensive dry run summary.

        Args:
            result: Dry run result
            attack_name: Name of attack
            context: Attack context
        """
        LOG.info("=" * 60)
        LOG.info(f"DRY RUN SUMMARY - Attack: {attack_name}")
        LOG.info("=" * 60)
        LOG.info(f"Status: {result.status.value}")
        LOG.info(
            f"Simulation time: {result.metadata.get('simulation_time_ms', 0):.3f}ms"
        )

        if result.error_message:
            LOG.info(f"Error: {result.error_message}")

        # Log context summary
        context_summary = result.metadata.get("context_summary", {})
        LOG.info(
            f"Target: {context_summary.get('dst_ip')}:{context_summary.get('dst_port')}"
        )
        LOG.info(f"Protocol: {context_summary.get('protocol')}")
        LOG.info(f"Payload size: {context_summary.get('payload_size')} bytes")

        # Log segments analysis if available
        if "segment_analysis" in result.metadata:
            analysis = result.metadata["segment_analysis"]
            LOG.info(f"Segments: {analysis.get('total_segments', 0)}")
            LOG.info(f"Total payload: {analysis.get('total_payload_size', 0)} bytes")
            LOG.info(f"TTL modifications: {analysis.get('ttl_modifications', 0)}")
            LOG.info(f"Checksum corruptions: {analysis.get('checksum_corruptions', 0)}")
            LOG.info(f"Timing delays: {analysis.get('timing_delays', 0)}")

        # Log validation results
        if "validation_errors" in result.metadata:
            errors = result.metadata["validation_errors"]
            if errors:
                LOG.info(f"Validation errors: {len(errors)}")
                for error in errors:
                    LOG.info(f"  - {error}")
            else:
                LOG.info("Validation: PASSED")

        LOG.info("=" * 60)

    def get_dry_run_stats(self) -> dict:
        """
        Get dry run execution statistics.

        Returns:
            Dictionary with dry run statistics
        """
        with self.stats_lock:
            stats = self.dry_run_stats.copy()

        # Calculate derived statistics
        if stats["total_dry_runs"] > 0:
            stats["average_simulation_time_ms"] = (
                stats["simulation_time"] / stats["total_dry_runs"]
            )
            stats["average_segments_per_run"] = (
                stats["segments_simulated"] / stats["total_dry_runs"]
            )
            stats["validation_error_rate"] = (
                stats["validation_errors"] / stats["total_dry_runs"]
            )
        else:
            stats["average_simulation_time_ms"] = 0.0
            stats["average_segments_per_run"] = 0.0
            stats["validation_error_rate"] = 0.0

        return stats
