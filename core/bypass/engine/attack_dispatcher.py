#!/usr/bin/env python3
"""
Диспетчер атак DPI обхода.

Основные функции:
- Маршрутизация каждого типа атаки к соответствующему обработчику
- Нормализация и валидация параметров атак
- Разрешение специальных значений параметров (cipher, sni, midsld)
- Приоритетная интеграция продвинутых атак (advanced) с fallback на примитивы
- Поддержка zapret-style стратегий и комбинированных атак
- Логирование операций для оффлайн-валидации (operation_logger) и PCAP-метаданных
"""

from __future__ import annotations

import logging
import random
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, TypeAlias

# Local imports
from ..attacks.metadata import ValidationResult
from ..attacks.unified_registry import UnifiedAttackRegistry, get_unified_registry
from ..filtering.custom_sni import CustomSNIHandler
from ..techniques.primitives import BypassTechniques
from .dispatcher_observability import DispatcherObservability
from .tls_field_locator import TLSFieldLocator

# Backward compatibility type alias
AttackRegistry = UnifiedAttackRegistry

logger = logging.getLogger(__name__)

# Type aliases
SegmentTuple: TypeAlias = Tuple[bytes, int, Dict[str, Any]]
AttackRecipe: TypeAlias = List[SegmentTuple]
AttackSequence: TypeAlias = List[Tuple[str, Dict[str, Any]]]


# ============================================================================
# Disorder constants
# ============================================================================


class DisorderMethod(str, Enum):
    """Методы переупорядочивания сегментов."""

    REVERSE = "reverse"
    RANDOM = "random"
    SWAP = "swap"


# ============================================================================
# Исключения диспетчера
# ============================================================================


class DispatcherError(Exception):
    """Базовое исключение для ошибок диспетчера."""

    pass


class AttackNotFoundError(DispatcherError):
    """Атака не найдена в реестре."""

    pass


class ParameterValidationError(DispatcherError):
    """Ошибка валидации параметров."""

    pass


class AttackExecutionError(DispatcherError):
    """Ошибка выполнения атаки."""

    pass


# ============================================================================
# Fallback-классы, когда advanced-атаки недоступны
# ============================================================================


@dataclass
class FallbackAttackContext:
    """Fallback AttackContext для совместимости."""

    dst_ip: str = "127.0.0.1"
    dst_port: int = 443
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    payload: bytes = b""
    protocol: str = "tcp"
    connection_id: str = ""
    params: Dict[str, Any] = field(default_factory=dict)
    packet_info: Optional[Dict[str, Any]] = None


@dataclass
class FallbackAttackResult:
    """Fallback AttackResult для совместимости."""

    status: str = "unknown"
    segments: List[SegmentTuple] = field(default_factory=list)
    error_message: Optional[str] = None


class FallbackAttackStatus:
    """Константы статуса выполнения атаки (fallback)."""

    SUCCESS = "success"
    FAILURE = "failure"
    ERROR = "error"


# Попытка импортировать advanced-атаки
try:
    from ..attacks.tcp.fakeddisorder_attack import (
        FakedDisorderAttack as FixedFakeDisorderAttack,  # noqa: F401
        FakedDisorderConfig,  # noqa: F401
    )
    from ..attacks.tcp.manipulation import TCPMultiSplitAttack  # noqa: F401
    from ..attacks.base import AttackContext, AttackResult, AttackStatus

    ADVANCED_ATTACKS_AVAILABLE = True
    logger.debug("Advanced attacks imported successfully")
except ImportError as e:
    logger.warning("Advanced attacks not available: %s", e)
    ADVANCED_ATTACKS_AVAILABLE = False
    AttackContext = FallbackAttackContext
    AttackResult = FallbackAttackResult
    AttackStatus = FallbackAttackStatus


# ============================================================================
# Конфигурация диспетчера
# ============================================================================


@dataclass
class DispatcherConfig:
    """Конфигурация AttackDispatcher."""

    enable_advanced_attacks: bool = True
    default_split_position_ratio: float = 0.5
    max_recursion_depth: int = 10
    log_segment_preview_bytes: int = 16

    # Маппинг параметров вида key=value → тип атаки + базовые параметры
    param_to_attack_map: Dict[str, Tuple[str, Dict[str, Any]]] = field(
        default_factory=lambda: {
            "hostspell": ("http_host_header", {"manipulation_type": "replace"}),
            "hostdot": ("http_host_header", {"manipulation_type": "replace"}),
            "hosttab": ("http_host_header", {"manipulation_type": "replace"}),
            "hostcase": ("http_header_case", {"case_strategy": "random"}),
        }
    )

    # Параметры, специфичные для каждого типа атаки
    attack_param_sets: Dict[str, set] = field(
        default_factory=lambda: {
            "multisplit": {
                # legacy aliases (keep for backward compatibility)
                "split_position",
                "split_cnt",
                "split_cnt_min",
                "split_position_ratio",
                "split_pos",
                "split_count",
                "positions",
                "fragment_size",
                "fragment_delay",
                "fooling",
                "fooling_methods",
                "fake_ttl",
                "ttl",
            },
            "multidisorder": {
                # legacy aliases (keep for backward compatibility)
                "split_position",
                "split_cnt",
                "split_cnt_min",
                "split_position_ratio",
                "split_pos",
                "split_count",
                "positions",
                "fragment_size",
                "fragment_delay",
                "fooling",
                "fooling_methods",
                "fake_ttl",
                "ttl",
                "disorder_method",
                "disorder_count",
                "fragmentation_method",
            },
            "disorder": {
                "disorder_method",
                "split_pos",
                # legacy alias
                "split_position",
                "disorder_count",
                "fragmentation_method",
                "fragment_size",
            },
            "fake": {
                "ttl",
                "fake_ttl",
                "fake_count",
                "fooling",
                "fooling_methods",
                "custom_sni",
                "fake_sni",
                # CRITICAL: dynamic recipes map split_pos for fake_..._splX
                "split_pos",
                # legacy alias
                "split_position",
                # some handlers accept fake_data/custom_sni etc
                "fake_data",
                "fake_payload",
            },
            "fakeddisorder": {
                "ttl",
                "fake_ttl",
                "fake_count",
                "fooling",
                "fooling_methods",
                "custom_sni",
                "fake_sni",
                "disorder_method",
                "split_pos",
                # legacy alias
                "split_position",
                "fake_payload",
            },
            "split": {
                "split_pos",
                # legacy aliases
                "split_position",
                "split_position_ratio",
                "fragment_size",
                "fragment_delay",
            },
            # If registry contains a 'ttl' attack, allow ttl/fake_ttl to pass for combos/recipes
            "ttl": {"ttl", "fake_ttl"},
            # CRITICAL: seqovl dynamic recipes carry split_pos and fake_ttl
            "seqovl": {
                "split_pos",
                # legacy alias
                "split_position",
                "overlap_size",
                "fake_ttl",
                "ttl",
                "fooling",
                "fooling_methods",
            },
            "passthrough": {"domain", "front_domain", "real_domain"},
        }
    )

    # Общие параметры, которые передаются во все атаки
    common_params: set = field(
        # include 'domain' because StrategyGenerator/RecipeResolver commonly provide it,
        # and dropping it in combination-mode silently changes semantics downstream.
        default_factory=lambda: {"no_fallbacks", "forced", "resolved_custom_sni", "domain"}
    )


# ============================================================================
# AttackDispatcher
# ============================================================================


class AttackDispatcher:
    """
    Центральный диспетчер для маршрутизации атак обхода DPI.

    Приоритет:
    1. Advanced-реализации из attacks/ (если доступны и приоритет HIGH/CORE)
    2. Fallback на примитивные реализации через AttackRegistry
    """

    # Keep these sets centralized to avoid semantic drift across methods.
    _BASIC_ATTACKS: frozenset = frozenset(
        {
            "split",
            "disorder",
            "fake",
            "ttl",
            "multisplit",
            "seqovl",
            "multidisorder",
            "fakeddisorder",
            "passthrough",
        }
    )

    _SPLIT_REQUIRED_ATTACKS: frozenset = frozenset(
        {"split", "multisplit", "fake", "fakeddisorder", "disorder", "seqovl", "multidisorder"}
    )

    def __init__(
        self,
        techniques: BypassTechniques,
        attack_registry: Optional[UnifiedAttackRegistry] = None,
        config: Optional[DispatcherConfig] = None,
    ) -> None:
        self.techniques = techniques
        self.registry = attack_registry or get_unified_registry()
        self.config = config or DispatcherConfig()

        from .parameter_normalizer import ParameterNormalizer
        from .strategy_resolver import StrategyResolver
        from .recipe_resolver import RecipeResolver

        self.parameter_normalizer = ParameterNormalizer()

        # StrategyResolver с доступом к config и normalize функции
        self.strategy_resolver = StrategyResolver(
            param_to_attack_map=self.config.param_to_attack_map,
            normalize_attack_type_fn=self._normalize_attack_type,
        )

        # RecipeResolver для разрешения recipe имён
        self.recipe_resolver = RecipeResolver(registry=self.registry)

        self.custom_sni_handler = CustomSNIHandler()

        # recursion depth must be per-thread to avoid cross-thread contamination
        self._tls = threading.local()
        self._tls.recursion_depth = 0

        # Cache SNI extractor (avoid re-creating it on every split_pos="sni" resolution)
        self._sni_extractor = None
        try:
            from ..filtering.sni_extractor import SNIExtractor  # type: ignore

            self._sni_extractor = SNIExtractor()
        except Exception:
            self._sni_extractor = None

        # TLSFieldLocator for split position resolution (reuses SNIExtractor)
        self.tls_field_locator = TLSFieldLocator(
            sni_extractor=self._sni_extractor,
            default_split_ratio=self.config.default_split_position_ratio,
        )

        # DispatcherObservability for logging and metadata
        self.observability = DispatcherObservability(
            log_segment_preview_bytes=self.config.log_segment_preview_bytes,
        )

        # Lazy cached integrated-combo dispatcher/builder (avoid re-import and re-init each packet).
        self._integrated_combo_builder = None
        self._integrated_combo_dispatcher = None

        self._validate_critical_attacks()
        logger.info(
            f"AttackDispatcher initialized with {len(self.registry.list_attacks())} "
            f"registered attacks"
        )

    # ======================================================================
    # Валидация реестра атак
    # ======================================================================

    def _validate_critical_attacks(self) -> None:
        critical = ["fakeddisorder", "multisplit", "multidisorder", "seqovl"]
        missing: List[str] = []
        available: List[str] = []

        for name in critical:
            if self.registry.get_attack_handler(name):
                available.append(name)
            else:
                missing.append(name)

        if missing:
            logger.warning(f"Critical attacks not registered: {missing}")
        if available:
            logger.debug(f"Critical attacks available: {available}")

    # ======================================================================
    # Разбор zapret-стратегий (делегирует в StrategyResolver)
    # ======================================================================

    def resolve_strategy(self, strategy: str) -> AttackSequence:
        """
        Разбирает zapret-style стратегию в список атак.

        Делегирует в StrategyResolver для централизованной логики.

        Поддерживаемые форматы:
        - "fake"
        - "fake,disorder"
        - "fake:ttl=3"
        - "disorder:split_pos=sni"
        - "smart_combo_split_fake"
        - "hostspell=go-ogle.com"
        """
        return self.strategy_resolver.resolve(strategy)

    # ======================================================================
    # Основной публичный метод
    # ======================================================================

    def dispatch_attack(
        self,
        task_type: str,
        params: Dict[str, Any],
        payload: bytes,
        packet_info: Dict[str, Any],
    ) -> AttackRecipe:
        """
        Главная точка входа.

        - Определяет, что именно нужно делать: стратегия, комбинация или одиночная атака.
        - Поддерживает интегрированные combo-режимы.
        - Обеспечивает защиту от рекурсии и централизованную обработку ошибок.
        """
        start_time = time.time()  # wall-clock timestamp for observability/metadata
        correlation_id = self._generate_correlation_id()
        params = params or {}
        packet_info = packet_info or {}
        original_params = dict(params)

        self._log_dispatch_start(correlation_id, task_type, payload, packet_info, params)

        try:
            depth = getattr(self._tls, "recursion_depth", 0) + 1
            self._tls.recursion_depth = depth
            if depth > self.config.max_recursion_depth:
                raise AttackExecutionError(
                    f"Maximum recursion depth ({self.config.max_recursion_depth}) exceeded"
                )

            result = self._dispatch_internal(
                task_type,
                params,
                payload,
                packet_info,
                correlation_id,
                original_params,
                start_time,
            )
            return result

        except DispatcherError:
            raise
        except Exception as e:
            self._log_dispatch_error(
                correlation_id,
                task_type,
                e,
                params,
                payload,
                packet_info,
                start_time,
            )
            raise AttackExecutionError(f"Attack dispatch failed: {e}") from e
        finally:
            depth = getattr(self._tls, "recursion_depth", 1) - 1
            self._tls.recursion_depth = max(0, depth)

    def _dispatch_internal(
        self,
        task_type: str,
        params: Dict[str, Any],
        payload: bytes,
        packet_info: Dict[str, Any],
        correlation_id: str,
        original_params: Dict[str, Any],
        start_time: float,
    ) -> AttackRecipe:
        # интегрированная комбо-атака
        if (
            task_type == "fake_multisplit_disorder_combo"
            or task_type == "integrated_combo"
            or params.get("_use_unified_dispatcher")
            or params.get("_combo_attacks")
        ):
            return self._dispatch_integrated_combo(params, payload, packet_info, correlation_id)

        # zapret-style стратегия
        if self._is_strategy_string(task_type):
            return self._dispatch_strategy(
                task_type,
                params,
                payload,
                packet_info,
                correlation_id,
                original_params,
                start_time,
            )

        # комбинация через params['attacks']
        if self._is_combination_attack(params):
            return self._dispatch_combination_wrapper(params, payload, packet_info, correlation_id)

        # одиночная атака
        return self._dispatch_single_attack(
            task_type,
            params,
            payload,
            packet_info,
            correlation_id,
            start_time,
        )

    def _is_strategy_string(self, task_type: str) -> bool:
        if task_type.startswith("smart_combo_"):
            return True
        if "," in task_type or ":" in task_type:
            return True
        if "=" in task_type:
            name = task_type.split("=", 1)[0].strip().lower()
            return name in self.config.param_to_attack_map
        return False

    def _is_combination_attack(self, params: Dict[str, Any]) -> bool:
        attacks = params.get("attacks")
        return isinstance(attacks, list) and len(attacks) > 1

    # ======================================================================
    # Запуск zapret-стратегии
    # ======================================================================

    def _dispatch_strategy(
        self,
        task_type: str,
        params: Dict[str, Any],
        payload: bytes,
        packet_info: Dict[str, Any],
        correlation_id: str,
        original_params: Dict[str, Any],
        start_time: float,
    ) -> AttackRecipe:
        logger.info("[CID:%s] Detected zapret-style strategy: %r", correlation_id, task_type)

        resolved = self.resolve_strategy(task_type)
        all_segments: AttackRecipe = []

        for i, (attack_name, strategy_params) in enumerate(resolved, start=1):
            logger.info(
                "[CID:%s] Executing strategy attack %d/%d: %r",
                correlation_id,
                i,
                len(resolved),
                attack_name,
            )
            # IMPORTANT: Merge order semantics
            # Current: {**strategy_params, **params} means runtime params override strategy params
            # This allows external callers to override strategy-specific parameters
            # Alternative: {**params, **strategy_params} would make strategy params stronger
            # TODO: Add test to verify this behavior is intentional
            merged_params = {**strategy_params, **params}
            attack_start = time.monotonic()

            segments = self.dispatch_attack(attack_name, merged_params, payload, packet_info)

            logger.info(
                "[CID:%s] Attack %r completed in %.3fs, segments=%d",
                correlation_id,
                attack_name,
                (time.monotonic() - attack_start),
                len(segments),
            )
            all_segments.extend(segments)

        self._log_dispatch_success(
            correlation_id,
            task_type,
            all_segments,
            start_time,
            attack_mode="strategy",
        )
        self._log_segment_details(all_segments, correlation_id)

        # Operation logger: логируем все сегменты этой стратегии
        strategy_id = packet_info.get("strategy_id")
        if strategy_id:
            self._log_operations_for_validation(
                strategy_id=strategy_id,
                operation_type="strategy",
                parameters={
                    "strategy": task_type,
                    "attacks": [a[0] for a in resolved],
                },
                segments=all_segments,
                correlation_id=correlation_id,
            )

        # Сохранение PCAP-метаданных (если доступно)
        self._save_metadata_if_needed(
            packet_info,
            correlation_id,
            task_type,
            resolved,
            original_params,
            all_segments,
            start_time,
        )

        return all_segments

    # ======================================================================
    # Комбинация атак (через params['attacks'])
    # ======================================================================

    def _dispatch_combination_wrapper(
        self,
        params: Dict[str, Any],
        payload: bytes,
        packet_info: Dict[str, Any],
        correlation_id: str,
    ) -> AttackRecipe:
        attacks = params["attacks"]
        logger.info("[CID:%s] Detected combination attack: %s", correlation_id, attacks)

        start = time.monotonic()
        segments = self._dispatch_combination(attacks, params, payload, packet_info, correlation_id)
        logger.info(
            "[CID:%s] Combination completed in %.3fs, segments=%d",
            correlation_id,
            (time.monotonic() - start),
            len(segments),
        )
        self._log_segment_details(segments, correlation_id)

        # Operation logger
        strategy_id = packet_info.get("strategy_id")
        if strategy_id:
            self._log_operations_for_validation(
                strategy_id=strategy_id,
                operation_type="combination",
                parameters={"attacks": attacks},
                segments=segments,
                correlation_id=correlation_id,
            )

        return segments

    def _dispatch_combination(
        self,
        attacks: List[str],
        params: Dict[str, Any],
        payload: bytes,
        packet_info: Dict[str, Any],
        correlation_id: str,
    ) -> AttackRecipe:
        if not attacks:
            raise AttackExecutionError("Empty attacks list in combination")

        logger.info(
            "[CID:%s] Executing combination of %d attacks: %s",
            correlation_id,
            len(attacks),
            attacks,
        )
        all_segments: AttackRecipe = []

        for i, attack_name in enumerate(attacks, start=1):
            logger.info("[CID:%s] Attack %d/%d: %r", correlation_id, i, len(attacks), attack_name)
            attack_params = self._filter_params_for_attack(attack_name, params)
            attack_params.pop("attacks", None)  # защита от рекурсии

            attack_start = time.monotonic()
            try:
                segments = self.dispatch_attack(attack_name, attack_params, payload, packet_info)
            except Exception as e:
                raise AttackExecutionError(
                    f"Attack '{attack_name}' failed in combination: {e}"
                ) from e

            logger.info(
                "[CID:%s] %r -> %d segments in %.3fs",
                correlation_id,
                attack_name,
                len(segments),
                (time.monotonic() - attack_start),
            )
            all_segments.extend(segments)

        # Применяем disorder-переупорядочивание, если требуется
        if "disorder" in attacks and "disorder_method" in params:
            all_segments = self._apply_disorder_reordering(
                all_segments, params["disorder_method"], correlation_id
            )

        return all_segments

    def _filter_params_for_attack(
        self,
        attack_name: str,
        all_params: Dict[str, Any],
    ) -> Dict[str, Any]:
        normalized = self._normalize_attack_type(attack_name)

        # If recipe marker is present, classify based on underlying recipe name.
        n = normalized.lower()
        if n.startswith("__recipe__"):
            n = n[len("__recipe__") :]

        # Robustness: dynamic recipe names often include prefixes (fake_..., disorder_..., seqovl_...).
        # Filtering by exact name would drop essential params, changing semantics.
        specific: set
        if normalized in self.config.attack_param_sets:
            specific = self.config.attack_param_sets[normalized]
        else:
            base = None
            if n.startswith("fake"):
                base = "fake"
            elif n.startswith("disorder"):
                base = "disorder"
            elif n.startswith("multisplit"):
                base = "multisplit"
            elif n.startswith("multidisorder"):
                base = "multidisorder"
            elif n.startswith("seqovl"):
                base = "seqovl"
            elif n.startswith("split"):
                base = "split"
            if base and base in self.config.attack_param_sets:
                specific = self.config.attack_param_sets[base]
            else:
                specific = set()

        common = self.config.common_params

        return {k: v for k, v in all_params.items() if k in common or k in specific}

    def _apply_disorder_reordering(
        self,
        segments: AttackRecipe,
        disorder_method: str,
        correlation_id: str,
    ) -> AttackRecipe:
        if not segments:
            return segments

        original_count = len(segments)
        logger.info(
            f"[CID:{correlation_id}] Applying disorder '{disorder_method}' "
            f"to {original_count} segments"
        )

        try:
            method = DisorderMethod(disorder_method)
        except ValueError:
            logger.warning(
                f"[CID:{correlation_id}] Unknown disorder method '{disorder_method}', "
                f"skipping reordering"
            )
            return segments

        if method == DisorderMethod.REVERSE:
            result = list(reversed(segments))
        elif method == DisorderMethod.RANDOM:
            result = segments.copy()
            random.shuffle(result)
        elif method == DisorderMethod.SWAP:
            if len(segments) >= 2:
                result = segments.copy()
                result[0], result[-1] = result[-1], result[0]
            else:
                result = segments
        else:
            result = segments

        if len(result) != original_count:
            raise AttackExecutionError(
                f"Disorder reordering changed segment count: " f"{original_count} -> {len(result)}"
            )

        return result

    # ======================================================================
    # Интегрированная combo-атака через UnifiedAttackDispatcher
    # ======================================================================

    def _dispatch_integrated_combo(
        self,
        params: Dict[str, Any],
        payload: bytes,
        packet_info: Dict[str, Any],
        correlation_id: str,
    ) -> AttackRecipe:
        logger.info(
            f"[CID:{correlation_id}] Starting integrated combo attack "
            f"(fake + split/multisplit + disorder)"
        )

        try:
            if self._integrated_combo_dispatcher is None or self._integrated_combo_builder is None:
                from .unified_attack_dispatcher import UnifiedAttackDispatcher
                from ...strategy.combo_builder import ComboAttackBuilder

                self._integrated_combo_builder = ComboAttackBuilder()
                self._integrated_combo_dispatcher = UnifiedAttackDispatcher(
                    self._integrated_combo_builder
                )

            combo_builder = self._integrated_combo_builder
            dispatcher = self._integrated_combo_dispatcher

            combo_attacks = params.get("_combo_attacks", ["fake", "multisplit", "disorder"])
            clean_params = {k: v for k, v in params.items() if not k.startswith("_")}

            recipe = combo_builder.build_recipe(combo_attacks, clean_params)
            segments = dispatcher.apply_recipe(recipe, payload, packet_info)

            fake_count = sum(1 for s in segments if s[2].get("is_fake"))
            logger.info(
                f"[CID:{correlation_id}] Integrated combo produced "
                f"{len(segments)} segments (fake={fake_count}, "
                f"real={len(segments) - fake_count})"
            )
            return segments

        except ImportError as e:
            logger.warning(
                "[CID:%s] UnifiedAttackDispatcher unavailable: %s, falling back to sequential combination",
                correlation_id,
                e,
            )
            combo_attacks = params.get("_combo_attacks", ["fake", "multisplit", "disorder"])
            return self._dispatch_combination(
                combo_attacks, params, payload, packet_info, correlation_id
            )

    # ======================================================================
    # Одиночная атака: advanced + fallback на примитив
    # ======================================================================

    def _dispatch_single_attack(
        self,
        task_type: str,
        params: Dict[str, Any],
        payload: bytes,
        packet_info: Dict[str, Any],
        correlation_id: str,
        start_time: float,
    ) -> AttackRecipe:
        normalized_type = self._normalize_attack_type(task_type)
        logger.info(
            "[CID:%s] Normalized attack type: %r -> %r", correlation_id, task_type, normalized_type
        )

        # Check if this is a recipe that needs to be resolved to component attacks
        if normalized_type.startswith("__RECIPE__"):
            recipe_name = normalized_type[10:]  # Remove "__RECIPE__" prefix
            component_attacks = self._resolve_recipe_name(recipe_name)
            if component_attacks:
                logger.info(
                    f"[CID:{correlation_id}] Dispatching recipe '{recipe_name}' "
                    f"as combination: {component_attacks}"
                )
                # Map recipe parameters to component attack parameters
                mapped_params = self._map_recipe_parameters(recipe_name, params)
                logger.debug(f"[CID:{correlation_id}] Mapped parameters: {mapped_params}")

                # Dispatch as combination attack
                return self._dispatch_combination(
                    component_attacks, mapped_params, payload, packet_info, correlation_id
                )
            else:
                raise AttackNotFoundError(f"Recipe '{recipe_name}' could not be resolved")

        # нормализация параметров
        normalized_params = self._normalize_parameters(normalized_type, params, len(payload))
        normalized_params = self._apply_registry_defaults(normalized_type, normalized_params)

        # сначала пытаемся использовать advanced
        if self.config.enable_advanced_attacks:
            adv_segments, adv_used = self._use_advanced_attack(
                normalized_type, normalized_params, payload, packet_info
            )
            if adv_segments is not None:
                self._log_dispatch_success(
                    correlation_id,
                    task_type,
                    adv_segments,
                    start_time,
                    attack_mode="advanced",
                )
                self._log_segment_details(adv_segments, correlation_id)

                # operation logger
                strategy_id = packet_info.get("strategy_id")
                if strategy_id:
                    self._log_operations_for_validation(
                        strategy_id=strategy_id,
                        operation_type=normalized_type,
                        parameters=normalized_params,
                        segments=adv_segments,
                        correlation_id=correlation_id,
                    )

                return adv_segments

            # advanced был, но не дал валидного результата
            # Разрешаем fallback на primitive для базовых атак (split, disorder, fake, ttl)
            # которые могут быть зарегистрированы с высоким приоритетом но иметь
            # несовместимый интерфейс с advanced handler
            if adv_used:
                # Расширенный список базовых атак включая возможные алиасы
                basic_attacks = {
                    "split",
                    "disorder",
                    "fake",
                    "ttl",
                    "multisplit",
                    "seqovl",
                    "multidisorder",
                    "fakeddisorder",
                    "passthrough",
                }

                logger.debug(
                    f"[CID:{correlation_id}] Checking if '{normalized_type}' is basic attack. "
                    f"Basic attacks: {basic_attacks}"
                )

                if normalized_type in basic_attacks:
                    logger.warning(
                        f"[CID:{correlation_id}] Advanced attack '{normalized_type}' "
                        f"failed, attempting primitive fallback for basic attack"
                    )
                    # Продолжаем к fallback на primitive
                else:
                    elapsed = time.time() - start_time
                    logger.error(
                        f"[CID:{correlation_id}] Advanced attack '{normalized_type}' "
                        f"failed, no primitive fallback will be attempted "
                        f"(elapsed {elapsed:.3f}s)"
                    )
                    raise AttackExecutionError(f"Advanced attack '{normalized_type}' failed")

        # fallback на примитивную реализацию
        logger.info(
            f"[CID:{correlation_id}] Falling back to primitive attack " f"for '{normalized_type}'"
        )

        recipe = self._execute_primitive_attack(
            normalized_type, normalized_params, payload, packet_info
        )

        self._log_dispatch_success(
            correlation_id,
            task_type,
            recipe,
            start_time,
            attack_mode="primitive",
        )
        self._log_segment_details(recipe, correlation_id)

        # operation logger
        strategy_id = packet_info.get("strategy_id")
        if strategy_id:
            self._log_operations_for_validation(
                strategy_id=strategy_id,
                operation_type=normalized_type,
                parameters=normalized_params,
                segments=recipe,
                correlation_id=correlation_id,
            )

        return recipe

    def _normalize_parameters(
        self,
        attack_type: str,
        params: Dict[str, Any],
        payload_length: int,
    ) -> Dict[str, Any]:
        try:
            # CRITICAL FIX: Better error handling for parameter normalization
            res = self.parameter_normalizer.normalize(attack_type, params, payload_length)
            if not res.is_valid:
                raise ParameterValidationError(
                    f"Parameter normalization failed: {res.error_message}"
                )

            # Safe iteration over warnings
            if hasattr(res, "warnings") and res.warnings:
                for w in res.warnings:
                    logger.warning(w)

            return res.normalized_params

        except Exception as e:
            # Log the full error for debugging
            logger.error("Parameter normalization error: %s", e)
            logger.error("Attack type: %s, Params: %s", attack_type, params)

            # Re-raise with more context
            raise ParameterValidationError(f"Parameter normalization failed: {str(e)}") from e

    def _apply_registry_defaults(self, attack_type: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply registry-provided optional/default params in a fail-safe way.
        Priority: caller params override defaults.
        """
        try:
            md = None
            try:
                md = self.registry.get_attack_metadata(attack_type)
            except Exception:
                md = None

            default_params = None
            # support both dataclass-like and dict-like metadata
            if md is None:
                return params
            if isinstance(md, dict):
                default_params = md.get("optional_params") or md.get("default_params")
            else:
                default_params = getattr(md, "optional_params", None) or getattr(md, "default_params", None)

            if not isinstance(default_params, dict) or not default_params:
                return params

            # defaults first, then params overwrite
            merged = dict(default_params)
            merged.update(params)
            return merged
        except Exception:
            return params

    def _execute_primitive_attack(
        self,
        attack_type: str,
        params: Dict[str, Any],
        payload: bytes,
        packet_info: Dict[str, Any],
    ) -> AttackRecipe:
        """
        Execute primitive attack with fail-safe for invalid split positions.

        CRITICAL: If split_pos=0 (payload too short), attacks requiring split
        will fail. We provide a safe fallback to passthrough.
        """
        handler = self.registry.get_attack_handler(attack_type)
        if not handler:
            available = self.registry.list_attacks()
            raise AttackNotFoundError(
                f"No handler found for '{attack_type}'. " f"Available: {available[:5]}..."
            )

        validation = self.registry.validate_parameters(attack_type, params)
        if not validation.is_valid:
            raise ParameterValidationError(
                f"Parameter validation failed: {validation.error_message}"
            )

        resolved_params = self._resolve_parameters(params, payload, packet_info)

        # CRITICAL GUARD: split_pos=0 means payload too short to split
        # Attacks requiring split will fail, so provide safe fallback
        split_pos = resolved_params.get("split_pos")
        if split_pos == 0:
            # Attacks that require split position
            split_attacks = {
                "split",
                "multisplit",
                "fake",
                "fakeddisorder",
                "disorder",
                "seqovl",
                "multidisorder",
            }
            if attack_type in split_attacks:
                logger.warning(
                    f"Attack '{attack_type}' requires split but payload too short "
                    f"(split_pos=0), returning passthrough"
                )
                # Return passthrough: single segment with original payload
                return [(payload, 0, {})]

        context = self._create_attack_context(resolved_params, payload, packet_info)

        recipe = handler(context)
        if not recipe or not isinstance(recipe, list):
            raise AttackExecutionError(
                f"Handler for '{attack_type}' returned invalid result " f"of type {type(recipe)}"
            )
        return recipe

    def _create_attack_context(
        self,
        params: Dict[str, Any],
        payload: bytes,
        packet_info: Dict[str, Any],
    ) -> AttackContext:
        connection_id = (
            f"{packet_info.get('src_addr', 'unknown')}:"
            f"{packet_info.get('src_port', 0)}->"
            f"{packet_info.get('dst_addr', 'unknown')}:"
            f"{packet_info.get('dst_port', 0)}"
        )
        return AttackContext(
            dst_ip=packet_info.get("dst_addr", "127.0.0.1"),
            dst_port=packet_info.get("dst_port", 443),
            src_ip=packet_info.get("src_addr"),
            src_port=packet_info.get("src_port"),
            payload=payload,
            protocol="tcp",
            connection_id=connection_id,
            params=params,
        )

    # ======================================================================
    # Advanced-атаки (с исправленной логикой)
    # ======================================================================

    def _is_advanced_priority(self, entry: Any) -> bool:
        """
        Проверяет, является ли атака advanced (высокий приоритет).

        Поддерживает обе шкалы приоритетов:
        - Старая: NORMAL=1, HIGH=2, CORE=3
        - Новая (UAR): DYNAMIC=10, EXTERNAL=50, CORE=100

        CRITICAL: DYNAMIC=10 должен быть primitive, иначе при сбое не будет fallback!

        Args:
            entry: AttackEntry с полем priority

        Returns:
            True если атака имеет высокий приоритет (advanced)
        """
        pr = getattr(entry, "priority", None)
        if pr is None:
            return False

        # 1) Проверка по имени (самое надёжное)
        name = getattr(pr, "name", None)
        if name in {"CORE", "HIGH"}:
            return True
        if name in {"NORMAL", "LOW", "DYNAMIC"}:
            return False
        if name == "EXTERNAL":
            return True

        # 2) Fallback по числовым значениям (устойчиво к обеим шкалам)
        value = getattr(pr, "value", None)
        if isinstance(value, int):
            # Старая шкала 1..3
            if 1 <= value <= 3:
                return value >= 2  # HIGH=2, CORE=3 → advanced

            # Новая шкала: явная проверка
            if value == 10:  # DYNAMIC
                return False
            if value in (50, 100):  # EXTERNAL, CORE
                return True

            # Неизвестное значение — fail-safe primitive
            logger.warning("Unknown priority value %r, treating as primitive (fail-safe)", value)
            return False

        # Если не смогли определить — fail-safe primitive
        return False

    def _use_advanced_attack(
        self,
        task_type: str,
        params: Dict[str, Any],
        payload: bytes,
        packet_info: Dict[str, Any],
    ) -> Tuple[Optional[AttackRecipe], bool]:
        """
        Пытается запустить продвинутую реализацию атаки.

        Возвращает (segments, used_advanced):
        - (list, True)  — advanced-обработчик найден, успешно отработал и
                          вернул сегменты.
        - (None, True)  — advanced-обработчик найден и вызывался, но:
                          * вернул ошибку / пусто / неожиданный тип
                          * либо выбросил исключение.
        - (None, False) — advanced-обработчик не найден или имеет низкий
                          приоритет (рассматриваем как "примитив").
        """
        if not ADVANCED_ATTACKS_AVAILABLE:
            logger.debug(f"Advanced attacks not available, skipping advanced for '{task_type}'")
            return None, False

        normalized_type = task_type  # сюда уже передают нормализованное имя
        handler = self.registry.get_attack_handler(normalized_type)
        if not handler:
            logger.debug(
                f"No handler found in registry for '{normalized_type}' " f"(advanced not used)"
            )
            return None, False

        # Проверяем приоритет: HIGH/CORE → advanced, LOW/NORMAL → примитив
        entry = getattr(self.registry, "attacks", {}).get(normalized_type)
        if entry and not self._is_advanced_priority(entry):
            logger.debug(
                f"Attack '{normalized_type}' has low priority ({entry.priority.name}), "
                f"treating as primitive"
            )
            return None, False

        logger.info(
            f"Using advanced attack handler for '{normalized_type}' "
            f"(priority {entry.priority.name if entry else 'UNKNOWN'})"
        )

        try:
            # BUGFIX: Resolve parameters (e.g., "random" -> int) before creating context
            resolved_params = self._resolve_parameters(params, payload, packet_info)
            context = self._create_attack_context(resolved_params, payload, packet_info)
            # добавляем packet_info для advanced-реализаций
            setattr(context, "packet_info", packet_info)

            result = handler(context)
            logger.info(
                f"Advanced handler for '{normalized_type}' returned "
                f"type={type(result)}, is_list={isinstance(result, list)}"
            )

            # primitive-style: сразу список сегментов
            if isinstance(result, list):
                return result, True

            # advanced-style: AttackResult
            if hasattr(result, "status") and hasattr(result, "segments"):
                if result.status == AttackStatus.SUCCESS and getattr(result, "segments", None):
                    return list(result.segments), True
                logger.warning(
                    f"Advanced attack '{normalized_type}' failed "
                    f"with status={getattr(result, 'status', None)} "
                    f"error={getattr(result, 'error_message', None)}"
                )
                return None, True

            logger.warning(
                f"Advanced attack '{normalized_type}' returned unexpected result "
                f"type={type(result)}"
            )
            return None, True

        except Exception as e:
            logger.error("Advanced attack %r execution error: %s", normalized_type, e)
            logger.debug("Advanced attack error details: %s: %s", type(e).__name__, str(e))
            return None, True

    # ======================================================================
    # Разрешение типов атак и параметров
    # ======================================================================

    def _normalize_attack_type(self, task_type: str) -> str:
        normalized = task_type.lower().strip()
        if normalized.startswith("attack="):
            normalized = normalized[7:]

        # PRIORITY 1: Check if this is a recipe name FIRST (before registry lookup)
        # This handles dynamic recipe names like tls_fragmentation, http_fragmentation, tcp_frag_*, etc.
        recipe_attacks = self._resolve_recipe_name(normalized)
        if recipe_attacks:
            logger.debug(f"Resolved recipe '{normalized}' to attacks: {recipe_attacks}")
            # For recipes, we'll return a special marker that indicates this is a recipe
            # The caller should handle this by dispatching the component attacks
            return f"__RECIPE__{normalized}"

        # Compatibility alias: many parts of recon generate 'ttl_manipulation' as strategy type
        if normalized == "ttl_manipulation":
            try:
                if self.registry.get_attack_handler("ttl"):
                    return "ttl"
            except Exception:
                pass
            # If there's no dedicated 'ttl' handler, treat as a recipe -> will fallback later
            return "__RECIPE__ttl_manipulation"

        # PRIORITY 2: Try to resolve as a registered attack
        resolved = self.registry.get_canonical_name(normalized)

        if not self.registry.get_attack_handler(resolved):
            available = self.registry.list_attacks()
            similar = [a for a in available if normalized in a or a in normalized]
            msg = f"Unknown attack type '{task_type}'"
            if similar:
                msg += f". Did you mean: {', '.join(similar[:3])}?"
            raise AttackNotFoundError(msg)

        return resolved

    def _resolve_recipe_name(self, recipe_name: str) -> Optional[List[str]]:
        """
        Resolve a recipe name to its component attacks.

        Wrapper for RecipeResolver.resolve_name() for backward compatibility.

        Args:
            recipe_name: The recipe name to resolve

        Returns:
            List of component attack names, or None if not a known recipe
        """
        return self.recipe_resolver.resolve_name(recipe_name)

    def _map_recipe_parameters(self, recipe_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Map recipe parameters to component attack parameters.

        Wrapper for RecipeResolver.map_parameters() for backward compatibility.

        Args:
            recipe_name: The recipe name
            params: Original parameters

        Returns:
            Mapped parameters for component attacks
        """
        return self.recipe_resolver.map_parameters(recipe_name, params)

    def _resolve_parameters(
        self,
        params: Dict[str, Any],
        payload: bytes,
        packet_info: Dict[str, Any],
    ) -> Dict[str, Any]:
        resolved = params.copy()

        # split_pos
        if "split_pos" in resolved:
            resolved["split_pos"] = self._resolve_split_position(
                resolved["split_pos"], payload, packet_info
            )

        # positions для multisplit/multidisorder
        if "positions" in resolved:
            resolved["positions"] = [
                self._resolve_split_position(p, payload, packet_info) for p in resolved["positions"]
            ]

        # custom SNI
        sni = self._resolve_custom_sni(resolved)
        if sni:
            resolved["resolved_custom_sni"] = sni

        # TTL
        if "fake_ttl" not in resolved and "ttl" in resolved:
            resolved["fake_ttl"] = resolved["ttl"]
        elif "ttl" not in resolved and "fake_ttl" in resolved:
            resolved["ttl"] = resolved["fake_ttl"]

        # Canonical parameter is 'fooling' (may be str or list[str]).
        # Ensure 'fooling_methods' exists as a compatibility mirror (list[str]).
        def _as_list(v: Any) -> List[str]:
            if v is None:
                return []
            if isinstance(v, str):
                s = v.strip()
                return [s] if s else []
            if isinstance(v, (list, tuple)):
                out: List[str] = []
                for x in v:
                    if x is None:
                        continue
                    sx = str(x).strip()
                    if sx:
                        out.append(sx)
                return out
            sx = str(v).strip()
            return [sx] if sx else []

        fooling = resolved.get("fooling")
        fooling_methods = resolved.get("fooling_methods")

        if fooling is None and fooling_methods is not None:
            # prefer canonical key
            resolved["fooling"] = fooling_methods
        if "fooling_methods" not in resolved and "fooling" in resolved:
            resolved["fooling_methods"] = _as_list(resolved.get("fooling"))
        else:
            resolved["fooling_methods"] = _as_list(resolved.get("fooling_methods"))

        # If fooling is list with exactly 1 element, allow keeping it as list (canonical),
        # do not force to string here (get_fake_params() will pick first).

        return resolved

    def _resolve_split_position(
        self,
        split_pos: Any,
        payload: bytes,
        packet_info: Dict[str, Any],
    ) -> int:
        """
        Wrapper for TLSFieldLocator.resolve_position().

        Delegates to TLSFieldLocator for actual position resolution.
        """
        return self.tls_field_locator.resolve_position(split_pos, payload, packet_info)

    def _find_cipher_position(self, payload: bytes) -> int:
        """Wrapper for TLSFieldLocator.find_cipher_position()."""
        return self.tls_field_locator.find_cipher_position(payload)

    def _find_sni_position(self, payload: bytes) -> int:
        """Wrapper for TLSFieldLocator.find_sni_position()."""
        return self.tls_field_locator.find_sni_position(payload)

    def _find_midsld_position(
        self,
        payload: bytes,
        packet_info: Dict[str, Any],
    ) -> int:
        """Wrapper for TLSFieldLocator.find_midsld_position()."""
        return self.tls_field_locator.find_midsld_position(payload, packet_info)

    def _extract_domain_from_sni(self, payload: bytes) -> Optional[str]:
        """Wrapper for TLSFieldLocator.extract_domain_from_sni()."""
        return self.tls_field_locator.extract_domain_from_sni(payload)

    def _resolve_custom_sni(self, params: Dict[str, Any]) -> Optional[str]:
        custom_sni = params.get("custom_sni") or params.get("fake_sni")
        if not custom_sni:
            return None

        try:
            strategy = {"custom_sni": custom_sni}
            return self.custom_sni_handler.get_sni_for_strategy(strategy)
        except Exception as e:
            logger.warning("Failed to resolve custom SNI: %s", e)
            return None

    # ======================================================================
    # Публичные вспомогательные методы
    # ======================================================================

    def get_attack_info(self, attack_type: str) -> Dict[str, Any]:
        try:
            canonical = self.registry.get_canonical_name(attack_type)
            metadata = self.registry.get_attack_metadata(canonical)
            if not metadata:
                raise AttackNotFoundError(f"No metadata for '{attack_type}'")

            return {
                "canonical_name": canonical,
                "aliases": self.registry.get_attack_aliases(canonical),
                "metadata": metadata,
                "is_available": self.registry.get_attack_handler(canonical) is not None,
                "is_alias": self.registry.is_alias(attack_type),
                "all_names": self.registry.get_all_names_for_attack(canonical),
            }
        except Exception as e:
            raise AttackNotFoundError(f"Attack '{attack_type}' not found in registry") from e

    def list_available_attacks(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        attacks = self.registry.list_attacks(category=category, enabled_only=True)
        result: List[Dict[str, Any]] = []
        for name in attacks:
            try:
                result.append(self.get_attack_info(name))
            except Exception as e:
                logger.warning("Failed to get info for %r: %s", name, e)
        return result

    def validate_attack_parameters(
        self, attack_type: str, params: Dict[str, Any]
    ) -> ValidationResult:
        try:
            canonical = self.registry.get_canonical_name(attack_type)
            return self.registry.validate_parameters(canonical, params)
        except Exception as e:
            return ValidationResult(is_valid=False, error_message=str(e))

    # ======================================================================
    # Логирование / метаданные / operation logger
    # ======================================================================

    @staticmethod
    def _generate_correlation_id() -> str:
        """Wrapper for DispatcherObservability.generate_correlation_id()."""
        return DispatcherObservability.generate_correlation_id()

    def _log_dispatch_start(
        self,
        correlation_id: str,
        task_type: str,
        payload: bytes,
        packet_info: Dict[str, Any],
        params: Dict[str, Any],
    ) -> None:
        """Wrapper for DispatcherObservability.log_dispatch_start()."""
        self.observability.log_dispatch_start(
            correlation_id, task_type, payload, packet_info, params
        )

    def _log_dispatch_success(
        self,
        correlation_id: str,
        task_type: str,
        segments: AttackRecipe,
        start_time: float,
        attack_mode: str = "",
    ) -> None:
        """Wrapper for DispatcherObservability.log_dispatch_success()."""
        self.observability.log_dispatch_success(
            correlation_id, task_type, segments, start_time, attack_mode
        )

    def _log_dispatch_error(
        self,
        correlation_id: str,
        task_type: str,
        error: Exception,
        params: Dict[str, Any],
        payload: bytes,
        packet_info: Dict[str, Any],
        start_time: float,
    ) -> None:
        """Wrapper for DispatcherObservability.log_dispatch_error()."""
        self.observability.log_dispatch_error(
            correlation_id, task_type, error, params, payload, packet_info, start_time
        )

    def _log_segment_details(
        self,
        segments: AttackRecipe,
        correlation_id: str,
    ) -> None:
        """Wrapper for DispatcherObservability.log_segment_details()."""
        self.observability.log_segment_details(segments, correlation_id)

    def _log_operations_for_validation(
        self,
        strategy_id: Optional[str],
        operation_type: str,
        parameters: Dict[str, Any],
        segments: AttackRecipe,
        correlation_id: Optional[str] = None,
    ) -> None:
        """Wrapper for DispatcherObservability.log_operations_for_validation()."""
        self.observability.log_operations_for_validation(
            strategy_id, operation_type, parameters, segments, correlation_id
        )

    def _save_metadata_if_needed(
        self,
        packet_info: Dict[str, Any],
        correlation_id: str,
        task_type: str,
        resolved_attacks: AttackSequence,
        original_params: Dict[str, Any],
        segments: AttackRecipe,
        start_time: float,
    ) -> None:
        """Wrapper for DispatcherObservability.save_metadata_if_needed()."""
        self.observability.save_metadata_if_needed(
            packet_info,
            correlation_id,
            task_type,
            resolved_attacks,
            original_params,
            segments,
            start_time,
        )


# ============================================================================
# Фабрика
# ============================================================================


def create_attack_dispatcher(
    techniques: BypassTechniques,
    config: Optional[DispatcherConfig] = None,
) -> AttackDispatcher:
    return AttackDispatcher(techniques, config=config)
