#!/usr/bin/env python3
"""
Strategy Resolver - Парсинг и разрешение zapret-style стратегий.

Этот модуль отвечает за:
- Парсинг zapret-style стратегий (fake, fake,disorder, smart_combo_*, etc.)
- Разрешение parameter-style стратегий (hostspell=..., etc.)
- Оптимизацию комбинаций атак (fake + disorder -> fakeddisorder)

Extracted from AttackDispatcher as part of refactoring (Step 3).
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Type alias для последовательности атак
AttackSequence = List[Tuple[str, Dict[str, Any]]]


class StrategyResolver:
    """
    Разрешает zapret-style стратегии в последовательность атак.

    Поддерживаемые форматы:
    - Простые: "fake", "disorder", "split"
    - Комбинации: "fake,disorder", "fake,split,disorder"
    - С параметрами: "fake:ttl=3", "disorder:split_pos=sni"
    - Smart combo: "smart_combo_split_fake"
    - Parameter-style: "hostspell=go-ogle.com"

    Оптимизации:
    - fake + disorder → fakeddisorder
    - fake + split + disorder → integrated combo
    """

    def __init__(
        self,
        param_to_attack_map: Optional[Dict[str, Tuple[str, Dict[str, Any]]]] = None,
        normalize_attack_type_fn: Optional[callable] = None,
    ):
        """
        Инициализация StrategyResolver.

        Args:
            param_to_attack_map: Маппинг параметров вида key=value → (attack_type, params)
            normalize_attack_type_fn: Функция для нормализации типа атаки
        """
        self.param_to_attack_map = param_to_attack_map or self._default_param_map()
        self.normalize_attack_type_fn = normalize_attack_type_fn or self._default_normalize

    @staticmethod
    def _default_param_map() -> Dict[str, Tuple[str, Dict[str, Any]]]:
        """Маппинг по умолчанию для parameter-style стратегий."""
        return {
            "hostspell": ("http_host_header", {"manipulation_type": "replace"}),
            "hostdot": ("http_host_header", {"manipulation_type": "replace"}),
            "hosttab": ("http_host_header", {"manipulation_type": "replace"}),
            "hostcase": ("http_header_case", {"case_strategy": "random"}),
        }

    @staticmethod
    def _default_normalize(attack_type: str) -> str:
        """Нормализация по умолчанию - просто lowercase."""
        return attack_type.lower().strip()

    def resolve(self, strategy: str) -> AttackSequence:
        """
        Разбирает zapret-style стратегию в список атак.

        Args:
            strategy: Строка стратегии

        Returns:
            Список кортежей (attack_name, params)

        Raises:
            ValueError: Если стратегия пустая или невалидная
        """
        if not strategy or not strategy.strip():
            raise ValueError("Strategy cannot be empty")

        s = strategy.strip().lower()
        logger.debug("Resolving zapret-style strategy: %r", s)

        # smart_combo_...
        if s.startswith("smart_combo_"):
            return self._resolve_smart_combo_strategy(s)

        # param-style, например hostspell=...
        if self._is_parameter_style_strategy(s):
            return self._resolve_parameter_strategy(s)

        # обычная стратегия через запятую
        return self._parse_standard_strategy(s)

    def _resolve_smart_combo_strategy(self, strategy: str) -> AttackSequence:
        """
        Разрешает smart_combo_* стратегии.

        Example: smart_combo_split_fake → [("split", {}), ("fake", {})]
        """
        parts = strategy.replace("smart_combo_", "").split("_")
        attacks: AttackSequence = []

        for p in parts:
            p = p.strip()
            if p:
                normalized = self.normalize_attack_type_fn(p)
                attacks.append((normalized, {}))

        return self._resolve_attack_combinations(attacks)

    def _is_parameter_style_strategy(self, strategy: str) -> bool:
        """
        Проверяет, является ли стратегия parameter-style.

        Example: hostspell=go-ogle.com → True
        """
        if "=" not in strategy or ":" in strategy or "," in strategy:
            return False

        param_name = strategy.split("=", 1)[0].strip().lower()
        return param_name in self.param_to_attack_map

    def _resolve_parameter_strategy(self, strategy: str) -> AttackSequence:
        """
        Разрешает parameter-style стратегии.

        Example: hostspell=go-ogle.com → [("http_host_header", {"fake_host": "go-ogle.com"})]
        """
        param_name, param_value = strategy.split("=", 1)
        param_name = param_name.strip().lower()
        param_value = param_value.strip()

        attack_info = self.param_to_attack_map.get(param_name)
        if not attack_info:
            raise ValueError(f"Unknown parameter-style strategy: '{strategy}'")

        attack_name, base_params = attack_info
        params = dict(base_params)

        # Для http_host_header добавляем fake_host
        if attack_name == "http_host_header":
            params["fake_host"] = param_value

        logger.info("Inferred attack %r from parameter %r", attack_name, param_name)
        return [(attack_name, params)]

    def _parse_standard_strategy(self, strategy: str) -> AttackSequence:
        """
        Парсит стандартную стратегию через запятую.

        Example: fake:ttl=3,disorder:split_pos=sni
        """
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

            normalized = self.normalize_attack_type_fn(attack_name)
            attacks.append((normalized, params))

        resolved = self._resolve_attack_combinations(attacks)
        logger.info(
            f"Strategy '{strategy}' resolved to {len(resolved)} attacks: "
            f"{[a[0] for a in resolved]}"
        )
        return resolved

    def _parse_strategy_params(self, params_str: str) -> Dict[str, Any]:
        """
        Парсит параметры из строки стратегии.

        Examples:
        - ttl=3 → {"ttl": 3}
        - split_pos=sni → {"split_pos": "sni"}
        - fooling=badsum+badseq → {"fooling": ["badsum", "badseq"]}
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
                params[key] = lower == "true"
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
        Оптимизация комбинаций атак.

        Правила:
        - fake + disorder → fakeddisorder
        - fake + split/multisplit + disorder → integrated combo
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

        # fake + split/multisplit + disorder → интегрированная комбо
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
            remaining = [(n, p) for (n, p) in attacks if n not in {"fake", "disorder"}]
            return [("fakeddisorder", combined_params)] + remaining

        return attacks


def create_strategy_resolver(
    param_to_attack_map: Optional[Dict[str, Tuple[str, Dict[str, Any]]]] = None,
    normalize_attack_type_fn: Optional[callable] = None,
) -> StrategyResolver:
    """
    Фабрика для создания StrategyResolver.

    Args:
        param_to_attack_map: Маппинг параметров
        normalize_attack_type_fn: Функция нормализации

    Returns:
        Экземпляр StrategyResolver
    """
    return StrategyResolver(param_to_attack_map, normalize_attack_type_fn)
