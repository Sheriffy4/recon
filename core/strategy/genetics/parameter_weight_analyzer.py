"""
Parameter weight analysis for strategy optimization.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Any, Tuple, Set

LOG = logging.getLogger("ParameterWeightAnalyzer")


class ParameterWeightAnalyzer:
    """Анализатор весов параметров стратегий."""

    def __init__(self):
        self.success_weight_multiplier = 1.1
        self.success_categorical_multiplier = 1.2
        self.failure_weight_multiplier = 0.9

    def extract_all_parameters(
        self, strategy_results: List[Tuple[Dict[str, Any], bool, float]]
    ) -> Set[str]:
        """
        Извлечение всех уникальных параметров из результатов.

        Args:
            strategy_results: Результаты тестирования стратегий

        Returns:
            Множество названий параметров
        """
        all_parameters = set()
        for strategy, _, _ in strategy_results:
            if "parameters" in strategy:
                all_parameters.update(strategy["parameters"].keys())
        return all_parameters

    def split_by_success(
        self, strategy_results: List[Tuple[Dict[str, Any], bool, float]]
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Разделение стратегий на успешные и неуспешные.

        Args:
            strategy_results: Результаты тестирования стратегий

        Returns:
            Кортеж (успешные_стратегии, неуспешные_стратегии)
        """
        successful = [s for s, success, _ in strategy_results if success]
        failed = [s for s, success, _ in strategy_results if not success]
        return successful, failed

    def collect_parameter_values(
        self, strategies: List[Dict[str, Any]], param_name: str
    ) -> List[Any]:
        """
        Сбор значений параметра из списка стратегий.

        Args:
            strategies: Список стратегий
            param_name: Название параметра

        Returns:
            Список значений параметра
        """
        values = []
        for strategy in strategies:
            if param_name in strategy.get("parameters", {}):
                values.append(strategy["parameters"][param_name])
        return values

    def update_weights_for_parameter(
        self,
        domain_weights: Dict[str, Dict[str, float]],
        param_name: str,
        successful_values: List[Any],
        failed_values: List[Any],
    ):
        """
        Обновление весов для конкретного параметра.

        Args:
            domain_weights: Словарь весов домена
            param_name: Название параметра
            successful_values: Успешные значения параметра
            failed_values: Неуспешные значения параметра
        """
        if param_name not in domain_weights:
            domain_weights[param_name] = {}

        # Обновление весов для успешных значений
        if successful_values:
            if self._is_numeric_parameter(successful_values):
                self._update_numeric_weights(
                    domain_weights[param_name], successful_values, self.success_weight_multiplier
                )
            else:
                self._update_categorical_weights(
                    domain_weights[param_name],
                    successful_values,
                    self.success_categorical_multiplier,
                )

        # Уменьшение весов для неуспешных значений
        if failed_values:
            self._update_categorical_weights(
                domain_weights[param_name], failed_values, self.failure_weight_multiplier
            )

    def _is_numeric_parameter(self, values: List[Any]) -> bool:
        """Проверка, является ли параметр числовым."""
        # bool is a subclass of int -> treat it as categorical
        return all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in values)

    def _update_numeric_weights(
        self, param_weights: Dict[str, float], values: List[Any], multiplier: float
    ):
        """Обновление весов для числовых параметров."""
        for value in values:
            value_key = str(value)
            if value_key not in param_weights:
                param_weights[value_key] = 1.0
            param_weights[value_key] *= multiplier

    def _update_categorical_weights(
        self, param_weights: Dict[str, float], values: List[Any], multiplier: float
    ):
        """Обновление весов для категориальных параметров."""
        for value in values:
            value_key = str(value)
            if value_key not in param_weights:
                param_weights[value_key] = 1.0
            param_weights[value_key] *= multiplier
