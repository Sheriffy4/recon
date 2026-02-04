"""
Strategy Integration Fix - Compatibility Layer
Обеспечивает совместимость между различными компонентами системы стратегий.

Этот модуль решает проблемы интеграции между:
- AttackCombinator и существующими модулями
- Различными форматами стратегий
- Legacy и новыми компонентами системы
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime

LOG = logging.getLogger("strategy_integration_fix")


@dataclass
class IntegrationResult:
    """Результат интеграционного исправления"""

    success: bool
    original_data: Any
    fixed_data: Any
    applied_fixes: List[str]
    warnings: List[str]
    error_message: Optional[str] = None


class StrategyIntegrationFix:
    """
    Класс для исправления проблем интеграции стратегий.

    Обеспечивает совместимость между различными компонентами
    системы и форматами данных.
    """

    def __init__(self, debug: bool = False):
        """
        Инициализация StrategyIntegrationFix.

        Args:
            debug: Включить отладочное логирование
        """
        self.debug = debug
        self.logger = logging.getLogger(__name__)
        if debug and self.logger.level == logging.NOTSET:
            self.logger.setLevel(logging.DEBUG)

        # Счетчики исправлений
        self.fixes_applied = 0
        self.warnings_generated = 0

        self.logger.info("StrategyIntegrationFix инициализирован")

    def fix_strategy_format(self, strategy_data: Any) -> IntegrationResult:
        """
        Исправление формата стратегии для совместимости.

        Args:
            strategy_data: Данные стратегии в любом формате

        Returns:
            IntegrationResult с исправленными данными
        """
        applied_fixes = []
        warnings = []

        try:
            # Если это строка, пытаемся интерпретировать как zapret-стиль
            if isinstance(strategy_data, str):
                fixed_data = self._fix_string_strategy(strategy_data)
                applied_fixes.append("string_format_normalization")

            # Если это словарь, проверяем структуру
            elif isinstance(strategy_data, dict):
                fixed_data = self._fix_dict_strategy(strategy_data)
                applied_fixes.append("dict_structure_normalization")

            # Если это список, обрабатываем каждый элемент
            elif isinstance(strategy_data, list):
                fixed_data = [self.fix_strategy_format(item).fixed_data for item in strategy_data]
                applied_fixes.append("list_processing")

            else:
                # Неизвестный формат, возвращаем как есть с предупреждением
                fixed_data = strategy_data
                warnings.append(f"Unknown strategy format: {type(strategy_data)}")

            self.fixes_applied += len(applied_fixes)
            self.warnings_generated += len(warnings)

            return IntegrationResult(
                success=True,
                original_data=strategy_data,
                fixed_data=fixed_data,
                applied_fixes=applied_fixes,
                warnings=warnings,
            )

        except Exception as e:
            self.logger.error(f"Ошибка при исправлении стратегии: {e}")
            return IntegrationResult(
                success=False,
                original_data=strategy_data,
                fixed_data=strategy_data,
                applied_fixes=applied_fixes,
                warnings=warnings,
                error_message=str(e),
            )

    def _fix_string_strategy(self, strategy_str: str) -> str:
        """Исправление строковых стратегий"""
        # Нормализация пробелов
        fixed = " ".join(strategy_str.split())

        # Исправление распространенных опечаток
        fixes = {
            "--dpi-desync-fooling=badsum,badseq": "--dpi-desync-fooling=badsum,badseq",
            "fakeddisorder": "fake,disorder",
            "multidisorder": "multidisorder",
        }

        for old, new in fixes.items():
            if old in fixed and old != new:
                fixed = fixed.replace(old, new)
                self.logger.debug(f"Исправлено: {old} -> {new}")

        return fixed

    def _fix_dict_strategy(self, strategy_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Исправление словарных стратегий"""
        fixed = strategy_dict.copy()

        # Стандартизация ключей
        key_mappings = {
            "attack_type": "type",
            "strategy_type": "type",
            "method": "type",
            "parameters": "params",
            "options": "params",
        }

        for old_key, new_key in key_mappings.items():
            if old_key in fixed and new_key not in fixed:
                fixed[new_key] = fixed.pop(old_key)
                self.logger.debug(f"Переименован ключ: {old_key} -> {new_key}")

        # Исправление параметров
        if "params" in fixed and isinstance(fixed["params"], dict):
            fixed["params"] = self._fix_parameters(fixed["params"])

        return fixed

    def _fix_parameters(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Исправление параметров стратегии"""
        fixed = params.copy()

        # Исправление типов данных
        type_fixes = {
            "ttl": int,
            "autottl": int,
            "split_pos": int,
            "split_count": int,
            "overlap_size": int,
            "repeats": int,
            "window_div": int,
        }

        for param, expected_type in type_fixes.items():
            if param in fixed:
                try:
                    if not isinstance(fixed[param], expected_type):
                        fixed[param] = expected_type(fixed[param])
                        self.logger.debug(
                            f"Исправлен тип {param}: {type(params[param])} -> {expected_type}"
                        )
                except (ValueError, TypeError) as e:
                    self.logger.warning(f"Не удалось исправить тип {param}: {e}")

        # Исправление списков fooling
        if "fooling" in fixed:
            if isinstance(fixed["fooling"], str):
                fixed["fooling"] = [fixed["fooling"]]
            elif not isinstance(fixed["fooling"], list):
                fixed["fooling"] = []

        return fixed

    def fix_attack_result(self, result_data: Any) -> IntegrationResult:
        """
        Исправление результатов атак для совместимости.

        Args:
            result_data: Данные результата атаки

        Returns:
            IntegrationResult с исправленными данными
        """
        applied_fixes = []
        warnings = []

        try:
            if isinstance(result_data, dict):
                fixed_data = result_data.copy()

                # Стандартизация полей результата
                field_mappings = {
                    "successful": "success",
                    "succeeded": "success",
                    "latency": "latency_ms",
                    "response_time": "latency_ms",
                    "error": "error_message",
                    "message": "error_message",
                }

                for old_field, new_field in field_mappings.items():
                    if old_field in fixed_data and new_field not in fixed_data:
                        fixed_data[new_field] = fixed_data.pop(old_field)
                        applied_fixes.append(f"field_rename_{old_field}")

                # Обеспечение обязательных полей
                required_fields = {
                    "success": False,
                    "latency_ms": 0.0,
                    "rst_packets": 0,
                    "connection_established": False,
                }

                for field, default_value in required_fields.items():
                    if field not in fixed_data:
                        fixed_data[field] = default_value
                        applied_fixes.append(f"add_missing_field_{field}")

                # Добавление timestamp если отсутствует
                if "timestamp" not in fixed_data:
                    fixed_data["timestamp"] = datetime.now()
                    applied_fixes.append("add_timestamp")

            else:
                fixed_data = result_data
                warnings.append(f"Unexpected result format: {type(result_data)}")

            return IntegrationResult(
                success=True,
                original_data=result_data,
                fixed_data=fixed_data,
                applied_fixes=applied_fixes,
                warnings=warnings,
            )

        except Exception as e:
            self.logger.error(f"Ошибка при исправлении результата: {e}")
            return IntegrationResult(
                success=False,
                original_data=result_data,
                fixed_data=result_data,
                applied_fixes=applied_fixes,
                warnings=warnings,
                error_message=str(e),
            )

    def normalize_attack_name(self, attack_name: str) -> str:
        """
        Нормализация названий атак для совместимости.

        Args:
            attack_name: Название атаки

        Returns:
            Нормализованное название
        """
        # Словарь нормализации
        normalizations = {
            "fake_disorder": "fakeddisorder",
            "fake+disorder": "fakeddisorder",
            "multi_split": "multisplit",
            "multi-split": "multisplit",
            "multi_disorder": "multidisorder",
            "multi-disorder": "multidisorder",
            "seq_ovl": "seqovl",
            "seq-ovl": "seqovl",
            "badsum_race": "badsum",
            "md5sig_race": "md5sig",
            "badseq_race": "badseq",
        }

        # Приведение к нижнему регистру
        normalized = attack_name.lower().strip()

        # Применение нормализации
        if normalized in normalizations:
            result = normalizations[normalized]
            self.logger.debug(f"Нормализовано название атаки: {attack_name} -> {result}")
            return result

        return normalized

    def get_statistics(self) -> Dict[str, Any]:
        """Получение статистики исправлений"""
        return {
            "fixes_applied": self.fixes_applied,
            "warnings_generated": self.warnings_generated,
            "integration_active": True,
            "debug_mode": self.debug,
        }

    def reset_statistics(self):
        """Сброс статистики"""
        self.fixes_applied = 0
        self.warnings_generated = 0
        self.logger.info("Статистика исправлений сброшена")


# Глобальный экземпляр для удобства использования
_global_integration_fix = None


def get_integration_fix(debug: bool = False) -> StrategyIntegrationFix:
    """Получение глобального экземпляра StrategyIntegrationFix"""
    global _global_integration_fix
    if _global_integration_fix is None:
        _global_integration_fix = StrategyIntegrationFix(debug=debug)
    return _global_integration_fix


# Удобные функции для быстрого использования
def fix_strategy(strategy_data: Any) -> Any:
    """Быстрое исправление стратегии"""
    result = get_integration_fix().fix_strategy_format(strategy_data)
    return result.fixed_data if result.success else strategy_data


def fix_result(result_data: Any) -> Any:
    """Быстрое исправление результата"""
    result = get_integration_fix().fix_attack_result(result_data)
    return result.fixed_data if result.success else result_data


def normalize_attack(attack_name: str) -> str:
    """Быстрая нормализация названия атаки"""
    return get_integration_fix().normalize_attack_name(attack_name)
