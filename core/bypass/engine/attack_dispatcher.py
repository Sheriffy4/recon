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
import time
import traceback
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import (
    Any,
    Dict,
    List,
    Optional,
    Sequence,
    Tuple,
    TypeAlias,
)

# Local imports
from ..attacks.attack_registry import AttackRegistry, get_attack_registry
from ..attacks.metadata import SpecialParameterValues, ValidationResult
from ..techniques.primitives import BypassTechniques
from ..filtering.custom_sni import CustomSNIHandler

logger = logging.getLogger(__name__)

# Type aliases
SegmentTuple: TypeAlias = Tuple[bytes, int, Dict[str, Any]]
AttackRecipe: TypeAlias = List[SegmentTuple]
AttackSequence: TypeAlias = List[Tuple[str, Dict[str, Any]]]


# ============================================================================
# TLS / Disorder constants
# ============================================================================

class TLSConstants:
    """Константы для парсинга TLS ClientHello."""
    RECORD_HEADER_SIZE = 5
    HANDSHAKE_HEADER_SIZE = 4
    VERSION_SIZE = 2
    RANDOM_SIZE = 32
    MIN_CLIENT_HELLO_SIZE = 43  # до Session ID
    CONTENT_TYPE_HANDSHAKE = 0x16
    SNI_EXTENSION_TYPE = b"\x00\x00"  # extension_type = 0x0000 (SNI)


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
    logger.info("Advanced attacks imported successfully")
except ImportError as e:
    logger.warning(f"Advanced attacks not available: {e}")
    ADVANCED_ATTACKS_AVAILABLE = False
    AttackContext = FallbackAttackContext
    AttackResult = FallbackAttackResult
    AttackStatus = FallbackAttackStatus


# Operation logger (опционально)
try:
    from core.operation_logger import get_operation_logger
    OPERATION_LOGGER_AVAILABLE = True
except ImportError:
    OPERATION_LOGGER_AVAILABLE = False
    get_operation_logger = None  # type: ignore[assignment]


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
                "split_pos", "split_count", "positions", "fooling",
                "fooling_methods", "fake_ttl", "ttl",
            },
            "multidisorder": {
                "split_pos", "split_count", "positions", "fooling",
                "fooling_methods", "fake_ttl", "ttl", "disorder_method",
            },
            "disorder": {"disorder_method", "split_pos"},
            "fake": {
                "ttl", "fake_ttl", "fooling", "fooling_methods",
                "custom_sni", "fake_sni",
            },
            "fakeddisorder": {
                "ttl", "fake_ttl", "fooling", "fooling_methods",
                "custom_sni", "fake_sni", "disorder_method", "split_pos",
            },
            "split": {"split_pos"},
            "seqovl": {"overlap_size", "fooling", "fooling_methods"},
        }
    )

    # Общие параметры, которые передаются во все атаки
    common_params: set = field(
        default_factory=lambda: {"no_fallbacks", "forced", "resolved_custom_sni"}
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

    def __init__(
        self,
        techniques: BypassTechniques,
        attack_registry: Optional[AttackRegistry] = None,
        config: Optional[DispatcherConfig] = None,
    ) -> None:
        self.techniques = techniques
        self.registry = attack_registry or get_attack_registry()
        self.config = config or DispatcherConfig()

        from .parameter_normalizer import ParameterNormalizer
        self.parameter_normalizer = ParameterNormalizer()

        self.custom_sni_handler = CustomSNIHandler()

        self._recursion_depth = 0  # защита от бесконечной рекурсии

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
    # Разбор zapret-стратегий
    # ======================================================================

    def resolve_strategy(self, strategy: str) -> AttackSequence:
        """
        Разбирает zapret-style стратегию в список атак.

        Поддерживаемые форматы:
        - "fake"
        - "fake,disorder"
        - "fake:ttl=3"
        - "disorder:split_pos=sni"
        - "smart_combo_split_fake"
        - "hostspell=go-ogle.com"
        """
        if not strategy or not strategy.strip():
            raise ValueError("Strategy cannot be empty")

        s = strategy.strip().lower()
        logger.info(f"Resolving zapret-style strategy: '{s}'")

        # smart_combo_...
        if s.startswith("smart_combo_"):
            return self._resolve_smart_combo_strategy(s)

        # param-style, например hostspell=...
        if self._is_parameter_style_strategy(s):
            return self._resolve_parameter_strategy(s)

        # обычная стратегия через запятую
        return self._parse_standard_strategy(s)

    def _resolve_smart_combo_strategy(self, strategy: str) -> AttackSequence:
        parts = strategy.replace("smart_combo_", "").split("_")
        attacks: AttackSequence = []
        for p in parts:
            p = p.strip()
            if p:
                attacks.append((self._normalize_attack_type(p), {}))
        return self._resolve_attack_combinations(attacks)

    def _is_parameter_style_strategy(self, strategy: str) -> bool:
        if "=" not in strategy or ":" in strategy or "," in strategy:
            return False
        param_name = strategy.split("=", 1)[0].strip().lower()
        return param_name in self.config.param_to_attack_map

    def _resolve_parameter_strategy(self, strategy: str) -> AttackSequence:
        param_name, param_value = strategy.split("=", 1)
        param_name = param_name.strip().lower()
        param_value = param_value.strip()

        attack_info = self.config.param_to_attack_map.get(param_name)
        if not attack_info:
            raise ValueError(f"Unknown parameter-style strategy: '{strategy}'")

        attack_name, base_params = attack_info
        params = dict(base_params)
        # Для http_host_header добавляем fake_host
        if attack_name == "http_host_header":
            params["fake_host"] = param_value
        logger.info(f"Inferred attack '{attack_name}' from parameter '{param_name}'")
        return [(attack_name, params)]

    def _parse_standard_strategy(self, strategy: str) -> AttackSequence:
        components = [c.strip() for c in strategy.split(",") if c.strip()]
        attacks: AttackSequence = []

        for comp in components:
            if ":" in comp:
                attack_name, params_str = comp.split(":", 1)
                attack_name = attack_name.strip()
                params = self._parse_strategy_params(params_str)
            else:
                attack_name = comp
                params = {}

            normalized = self._normalize_attack_type(attack_name)
            attacks.append((normalized, params))

        resolved = self._resolve_attack_combinations(attacks)
        logger.info(
            f"Strategy '{strategy}' resolved to {len(resolved)} attacks: "
            f"{[a[0] for a in resolved]}"
        )
        return resolved

    def _parse_strategy_params(self, params_str: str) -> Dict[str, Any]:
        """
        Парсит параметры из строки стратегии:
        - ttl=3
        - split_pos=sni
        - fooling=badsum+badseq
        """
        params: Dict[str, Any] = {}

        for part in params_str.split(","):
            part = part.strip()
            if not part or "=" not in part:
                continue

            key, value = part.split("=", 1)
            key = key.strip()
            value = value.strip()
            if not key:
                continue

            # список значений: "badsum+badseq"
            if "+" in value:
                vals = [v for v in value.split("+") if v]
                params[key] = vals
                continue

            lower = value.lower()
            # bool
            if lower in ("true", "false"):
                params[key] = (lower == "true")
                continue

            # число (в т.ч. отрицательное)
            try:
                iv = int(value)
            except ValueError:
                params[key] = value  # строка (в т.ч. спец. split_pos="sni" и т.п.)
            else:
                params[key] = iv

        return params

    def _resolve_attack_combinations(self, attacks: AttackSequence) -> AttackSequence:
        """
        Оптимизация комбинаций:
        - fake + disorder -> fakeddisorder
        - fake + split/multisplit + disorder -> integrated combo
        """
        if len(attacks) <= 1:
            return attacks

        names = [name for name, _ in attacks]
        name_set = set(names)

        # Собираем общие параметры
        combined_params: Dict[str, Any] = {}
        for _, p in attacks:
            combined_params.update(p)

        # чистая пара fake + disorder
        if name_set == {"fake", "disorder"}:
            logger.debug("Combining 'fake' + 'disorder' -> 'fakeddisorder'")
            return [("fakeddisorder", combined_params)]

        # fake + split/multisplit + disorder -> интегрированная комбо
        has_fake = "fake" in name_set
        has_disorder = "disorder" in name_set
        has_split = bool(name_set & {"split", "multisplit"})

        if has_fake and has_disorder and has_split:
            logger.debug("Found integrated combo: fake + split/multisplit + disorder")
            combined_params["_combo_attacks"] = names
            combined_params["_use_unified_dispatcher"] = True
            return [("fake_multisplit_disorder_combo", combined_params)]

        # общий случай fake+disorder среди других атак → заменяем их на fakeddisorder
        if has_fake and has_disorder:
            remaining = [
                (n, p) for (n, p) in attacks if n not in {"fake", "disorder"}
            ]
            return [("fakeddisorder", combined_params)] + remaining

        return attacks

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
        start_time = time.time()
        correlation_id = self._generate_correlation_id()
        original_params = params.copy()

        self._log_dispatch_start(
            correlation_id, task_type, payload, packet_info, params
        )

        try:
            self._recursion_depth += 1
            if self._recursion_depth > self.config.max_recursion_depth:
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
            self._recursion_depth -= 1

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
            return self._dispatch_integrated_combo(
                params, payload, packet_info, correlation_id
            )

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
            return self._dispatch_combination_wrapper(
                params, payload, packet_info, correlation_id
            )

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
        logger.info(
            f"[CID:{correlation_id}] Detected zapret-style strategy: '{task_type}'"
        )

        resolved = self.resolve_strategy(task_type)
        all_segments: AttackRecipe = []

        for i, (attack_name, strategy_params) in enumerate(resolved, start=1):
            logger.info(
                f"[CID:{correlation_id}] Executing strategy attack "
                f"{i}/{len(resolved)}: '{attack_name}'"
            )
            merged_params = {**strategy_params, **params}
            attack_start = time.time()

            segments = self.dispatch_attack(
                attack_name, merged_params, payload, packet_info
            )

            logger.info(
                f"[CID:{correlation_id}] Attack '{attack_name}' completed in "
                f"{time.time() - attack_start:.3f}s, segments={len(segments)}"
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
        logger.info(
            f"[CID:{correlation_id}] Detected combination attack: {attacks}"
        )

        start = time.time()
        segments = self._dispatch_combination(
            attacks, params, payload, packet_info, correlation_id
        )
        logger.info(
            f"[CID:{correlation_id}] Combination completed in "
            f"{time.time() - start:.3f}s, segments={len(segments)}"
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
            raise ValueError("Empty attacks list in combination")

        logger.info(
            f"[CID:{correlation_id}] Executing combination of {len(attacks)} "
            f"attacks: {attacks}"
        )
        all_segments: AttackRecipe = []

        for i, attack_name in enumerate(attacks, start=1):
            logger.info(
                f"[CID:{correlation_id}] Attack {i}/{len(attacks)}: '{attack_name}'"
            )
            attack_params = self._filter_params_for_attack(attack_name, params)
            attack_params.pop("attacks", None)  # защита от рекурсии

            attack_start = time.time()
            try:
                segments = self.dispatch_attack(
                    attack_name, attack_params, payload, packet_info
                )
            except Exception as e:
                raise AttackExecutionError(
                    f"Attack '{attack_name}' failed in combination: {e}"
                ) from e

            logger.info(
                f"[CID:{correlation_id}] '{attack_name}' -> {len(segments)} segments "
                f"in {time.time() - attack_start:.3f}s"
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
        specific = self.config.attack_param_sets.get(normalized, set())
        common = self.config.common_params

        return {
            k: v
            for k, v in all_params.items()
            if k in common or k in specific
        }

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
                f"Disorder reordering changed segment count: "
                f"{original_count} -> {len(result)}"
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
            from ..unified_attack_dispatcher import UnifiedAttackDispatcher
            from ...strategy.combo_builder import ComboAttackBuilder

            combo_builder = ComboAttackBuilder()
            dispatcher = UnifiedAttackDispatcher(combo_builder)

            combo_attacks = params.get(
                "_combo_attacks", ["fake", "multisplit", "disorder"]
            )
            clean_params = {
                k: v for k, v in params.items() if not k.startswith("_")
            }

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
                f"[CID:{correlation_id}] UnifiedAttackDispatcher unavailable: {e}, "
                f"falling back to sequential combination"
            )
            combo_attacks = params.get(
                "_combo_attacks", ["fake", "multisplit", "disorder"]
            )
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
            f"[CID:{correlation_id}] Normalized attack type: "
            f"'{task_type}' -> '{normalized_type}'"
        )

        # нормализация параметров
        normalized_params = self._normalize_parameters(
            normalized_type, params, len(payload)
        )

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

            # advanced был, но не дал валидного результата — не запускаем fallback
            if adv_used:
                elapsed = time.time() - start_time
                logger.error(
                    f"[CID:{correlation_id}] Advanced attack '{normalized_type}' "
                    f"failed, no primitive fallback will be attempted "
                    f"(elapsed {elapsed:.3f}s)"
                )
                raise AttackExecutionError(
                    f"Advanced attack '{normalized_type}' failed"
                )

        # fallback на примитивную реализацию
        logger.info(
            f"[CID:{correlation_id}] Falling back to primitive attack "
            f"for '{normalized_type}'"
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
        res = self.parameter_normalizer.normalize(
            attack_type, params, payload_length
        )
        if not res.is_valid:
            raise ParameterValidationError(
                f"Parameter normalization failed: {res.error_message}"
            )
        for w in res.warnings:
            logger.warning(w)
        return res.normalized_params

    def _execute_primitive_attack(
        self,
        attack_type: str,
        params: Dict[str, Any],
        payload: bytes,
        packet_info: Dict[str, Any],
    ) -> AttackRecipe:
        handler = self.registry.get_attack_handler(attack_type)
        if not handler:
            available = self.registry.list_attacks()
            raise AttackNotFoundError(
                f"No handler found for '{attack_type}'. "
                f"Available: {available[:5]}..."
            )

        validation = self.registry.validate_parameters(attack_type, params)
        if not validation.is_valid:
            raise ParameterValidationError(
                f"Parameter validation failed: {validation.error_message}"
            )

        resolved_params = self._resolve_parameters(params, payload, packet_info)
        context = self._create_attack_context(resolved_params, payload, packet_info)

        recipe = handler(context)
        if not recipe or not isinstance(recipe, list):
            raise AttackExecutionError(
                f"Handler for '{attack_type}' returned invalid result "
                f"of type {type(recipe)}"
            )
        return recipe

    def _create_attack_context(
        self,
        params: Dict[str, Any],
        payload: bytes,
        packet_info: Dict[str, Any],
    ) -> AttackContext:
        connection_id = (
            f"{packet_info.get('src_addr', '0.0.0.0')}:"
            f"{packet_info.get('src_port', 0)}->"
            f"{packet_info.get('dst_addr', '0.0.0.0')}:"
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
            logger.debug(
                f"Advanced attacks not available, skipping advanced for '{task_type}'"
            )
            return None, False

        normalized_type = task_type  # сюда уже передают нормализованное имя
        handler = self.registry.get_attack_handler(normalized_type)
        if not handler:
            logger.debug(
                f"No handler found in registry for '{normalized_type}' "
                f"(advanced not used)"
            )
            return None, False

        # Проверяем приоритет: HIGH/CORE → advanced, LOW/NORMAL → примитив
        entry = getattr(self.registry, "attacks", {}).get(normalized_type)
        if entry and entry.priority.value < 2:  # NORMAL=1, HIGH=2, CORE=3
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
            context = self._create_attack_context(params, payload, packet_info)
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
                if (
                    result.status == AttackStatus.SUCCESS
                    and getattr(result, "segments", None)
                ):
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
            logger.error(f"Advanced attack '{normalized_type}' execution error: {e}")
            logger.debug(traceback.format_exc())
            return None, True

    # ======================================================================
    # Разрешение типов атак и параметров
    # ======================================================================

    def _normalize_attack_type(self, task_type: str) -> str:
        normalized = task_type.lower().strip()
        if normalized.startswith("attack="):
            normalized = normalized[7:]

        resolved = self.registry.get_canonical_name(normalized)

        if not self.registry.get_attack_handler(resolved):
            available = self.registry.list_attacks()
            similar = [a for a in available if normalized in a or a in normalized]
            msg = f"Unknown attack type '{task_type}'"
            if similar:
                msg += f". Did you mean: {', '.join(similar[:3])}?"
            raise AttackNotFoundError(msg)

        return resolved

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
                self._resolve_split_position(p, payload, packet_info)
                for p in resolved["positions"]
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

        # fooling -> fooling_methods
        if "fooling_methods" not in resolved and "fooling" in resolved:
            resolved["fooling_methods"] = resolved["fooling"]

        return resolved

    def _resolve_split_position(
        self,
        split_pos: Any,
        payload: bytes,
        packet_info: Dict[str, Any],
    ) -> int:
        payload_len = len(payload)
        default_pos = int(payload_len * self.config.default_split_position_ratio) or 1

        if split_pos is None:
            return default_pos

        if isinstance(split_pos, int):
            return max(1, min(split_pos, payload_len - 1))

        if isinstance(split_pos, str):
            if split_pos == SpecialParameterValues.CIPHER:
                return self._find_cipher_position(payload)
            if split_pos == SpecialParameterValues.SNI:
                return self._find_sni_position(payload)
            if split_pos == SpecialParameterValues.MIDSLD:
                return self._find_midsld_position(payload, packet_info)
            if split_pos in (SpecialParameterValues.RANDOM, "random"):
                return random.randint(1, max(1, payload_len - 1))
            try:
                iv = int(split_pos)
            except ValueError:
                logger.warning(
                    f"Invalid split_pos '{split_pos}', using default position"
                )
                return default_pos
            else:
                return max(1, min(iv, payload_len - 1))

        logger.warning(
            f"Unknown split_pos type {type(split_pos)}, using default position"
        )
        return default_pos

    def _find_cipher_position(self, payload: bytes) -> int:
        try:
            if (
                len(payload) < TLSConstants.MIN_CLIENT_HELLO_SIZE
                or payload[0] != TLSConstants.CONTENT_TYPE_HANDSHAKE
            ):
                return len(payload) // 2

            pos = TLSConstants.MIN_CLIENT_HELLO_SIZE
            if pos < len(payload):
                session_id_len = payload[pos]
                pos += 1 + session_id_len

            if pos + 2 <= len(payload):
                return pos
        except Exception as e:
            logger.debug(f"Failed to find cipher position: {e}")

        return len(payload) // 2

    # ---------- корректный парсер SNI ----------

    def _parse_sni_extension(self, payload: bytes) -> Optional[Tuple[int, str]]:
        """
        Парсит SNI-расширение в TLS ClientHello.

        Возвращает (hostname_offset, hostname) или None.
        hostname_offset — смещение первого байта имени хоста.
        """
        try:
            data = payload
            max_i = len(data) - 9
            if max_i <= 0:
                return None

            for i in range(max_i):
                # extension_type == 0x0000 (SNI)
                if data[i : i + 2] != TLSConstants.SNI_EXTENSION_TYPE:
                    continue
                if i + 9 > len(data):
                    continue

                # структура:
                # i+0..1  extension_type (0x0000)
                # i+2..3  extension_length
                # i+4..5  list_length
                # i+6     name_type (0=host_name)
                # i+7..8  name_length
                # i+9..   hostname
                name_type = data[i + 6]
                if name_type != 0:
                    continue

                name_len = int.from_bytes(data[i + 7 : i + 9], "big")
                host_start = i + 9
                host_end = host_start + name_len

                if name_len <= 0 or host_end > len(data):
                    continue

                host_bytes = data[host_start:host_end]
                try:
                    hostname = host_bytes.decode("ascii")
                except UnicodeDecodeError:
                    hostname = host_bytes.decode("ascii", "ignore")

                if not hostname:
                    continue

                return host_start, hostname

        except Exception as e:
            logger.debug(f"Failed to parse SNI extension: {e}")

        return None

    def _find_sni_position(self, payload: bytes) -> int:
        """
        Возвращает позицию начала hostname в SNI, либо середину payload по умолчанию.
        """
        try:
            parsed = self._parse_sni_extension(payload)
            if parsed is not None:
                pos, _ = parsed
                logger.debug(f"Found SNI hostname position at {pos}")
                return pos
        except Exception as e:
            logger.warning(f"Failed to find SNI position: {e}")

        return len(payload) // 2

    def _find_midsld_position(
        self,
        payload: bytes,
        packet_info: Dict[str, Any],
    ) -> int:
        """
        Позиция середины второго уровня домена (SLD) внутри payload,
        если домен найден в SNI.
        """
        try:
            domain = self._extract_domain_from_sni(payload)
            if not domain:
                return len(payload) // 2

            parts = domain.split(".")
            if len(parts) < 2:
                return len(payload) // 2

            sld = parts[-2]
            mid = len(sld) // 2

            domain_bytes = domain.encode("utf-8")
            domain_pos = payload.find(domain_bytes)
            if domain_pos == -1:
                return len(payload) // 2

            sld_start = domain_pos + domain.rfind(sld)
            return sld_start + mid

        except Exception as e:
            logger.debug(f"Failed to find midsld position: {e}")

        return len(payload) // 2

    def _extract_domain_from_sni(self, payload: bytes) -> Optional[str]:
        """
        Извлекает hostname из SNI-расширения.
        """
        try:
            parsed = self._parse_sni_extension(payload)
            if parsed is None:
                return None
            _, hostname = parsed
            return hostname
        except Exception as e:
            logger.debug(f"Failed to extract domain from SNI: {e}")
            return None

    def _resolve_custom_sni(self, params: Dict[str, Any]) -> Optional[str]:
        custom_sni = params.get("custom_sni") or params.get("fake_sni")
        if not custom_sni:
            return None

        try:
            strategy = {"custom_sni": custom_sni}
            return self.custom_sni_handler.get_sni_for_strategy(strategy)
        except Exception as e:
            logger.warning(f"Failed to resolve custom SNI: {e}")
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
            raise AttackNotFoundError(
                f"Attack '{attack_type}' not found in registry"
            ) from e

    def list_available_attacks(
        self, category: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        attacks = self.registry.list_attacks(category=category, enabled_only=True)
        result: List[Dict[str, Any]] = []
        for name in attacks:
            try:
                result.append(self.get_attack_info(name))
            except Exception as e:
                logger.warning(f"Failed to get info for '{name}': {e}")
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
        return str(uuid.uuid4())[:8]

    def _log_dispatch_start(
        self,
        correlation_id: str,
        task_type: str,
        payload: bytes,
        packet_info: Dict[str, Any],
        params: Dict[str, Any],
    ) -> None:
        src = f"{packet_info.get('src_addr', 'unknown')}:{packet_info.get('src_port', 'unknown')}"
        dst = f"{packet_info.get('dst_addr', 'unknown')}:{packet_info.get('dst_port', 'unknown')}"
        logger.info(
            f"[CID:{correlation_id}] Dispatch: type='{task_type}', "
            f"payload={len(payload)} bytes, {src} -> {dst}"
        )
        logger.info(f"[CID:{correlation_id}] Parameters: {params}")

    def _log_dispatch_success(
        self,
        correlation_id: str,
        task_type: str,
        segments: AttackRecipe,
        start_time: float,
        attack_mode: str = "",
    ) -> None:
        elapsed = time.time() - start_time
        mode = f" ({attack_mode})" if attack_mode else ""
        logger.info(
            f"[CID:{correlation_id}] Attack '{task_type}'{mode} completed: "
            f"{len(segments)} segments in {elapsed:.3f}s"
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
        elapsed = time.time() - start_time
        logger.error(
            f"[CID:{correlation_id}] Attack '{task_type}' failed after "
            f"{elapsed:.3f}s: {type(error).__name__}: {error}"
        )
        logger.debug(f"[CID:{correlation_id}] Parameters: {params}")
        logger.debug(f"[CID:{correlation_id}] Payload size: {len(payload)}")
        logger.debug(f"[CID:{correlation_id}] Packet info: {packet_info}")
        logger.debug(traceback.format_exc())

    def _log_segment_details(
        self,
        segments: AttackRecipe,
        correlation_id: str,
    ) -> None:
        if not segments:
            return

        logger.info(
            f"[CID:{correlation_id}] Segment details ({len(segments)} total):"
        )
        for i, (data, offset, options) in enumerate(segments, start=1):
            flags = options.get("flags", "N/A")
            seq = options.get("tcp_seq", "N/A")
            ack = options.get("tcp_ack", "N/A")
            logger.info(
                f"   Segment {i}/{len(segments)}: len={len(data)}, "
                f"offset={offset}, seq={seq}, ack={ack}, flags={flags}"
            )

            if logger.isEnabledFor(logging.DEBUG) and data:
                preview_len = min(self.config.log_segment_preview_bytes, len(data))
                hex_preview = " ".join(f"{b:02x}" for b in data[:preview_len])
                if len(data) > preview_len:
                    hex_preview += "..."
                logger.debug(f"      Data preview: {hex_preview}")

    def _log_operations_for_validation(
        self,
        strategy_id: Optional[str],
        operation_type: str,
        parameters: Dict[str, Any],
        segments: AttackRecipe,
        correlation_id: Optional[str] = None,
    ) -> None:
        """
        Логирует операции для оффлайн-валидации PCAP (operation_logger).
        Логируется по одному событию на каждый сгенерированный сегмент.
        """
        if not OPERATION_LOGGER_AVAILABLE or not strategy_id:
            return

        try:
            operation_logger = get_operation_logger()
            for i, (data, offset, options) in enumerate(segments, start=1):
                op_params = {
                    "operation_type": operation_type,
                    "offset": offset,
                    "data_length": len(data),
                    **parameters,
                    **options,
                }
                operation_logger.log_operation(
                    strategy_id=strategy_id,
                    operation_type=operation_type,
                    parameters=op_params,
                    segment_number=i,
                    correlation_id=correlation_id,
                )
        except Exception as e:
            logger.warning(
                f"[CID:{correlation_id}] Failed to log operations for validation: {e}"
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
        strategy_id = packet_info.get("strategy_id")
        if not strategy_id:
            return

        try:
            from core.pcap.metadata_saver import save_pcap_metadata

            save_pcap_metadata(
                strategy_id=strategy_id,
                domain=packet_info.get("domain"),
                executed_attacks=task_type,
                strategy_name=packet_info.get("strategy_name"),
                additional_data={
                    "correlation_id": correlation_id,
                    "attacks": [a[0] for a in resolved_attacks],
                    "parameters": original_params,
                    "segment_count": len(segments),
                    "execution_time": time.time() - start_time,
                },
            )
        except Exception as e:
            logger.debug(f"Failed to save PCAP metadata: {e}")


# ============================================================================
# Фабрика
# ============================================================================

def create_attack_dispatcher(
    techniques: BypassTechniques,
    config: Optional[DispatcherConfig] = None,
) -> AttackDispatcher:
    return AttackDispatcher(techniques, config=config)