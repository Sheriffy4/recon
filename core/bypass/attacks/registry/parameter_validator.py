"""
Parameter validation component for the Attack Registry system.

This module provides AttackParameterValidator - a specialized component
responsible for validating attack parameters according to their metadata
specifications.
"""

import logging
from typing import Any, Callable, Dict, List

from .config import RegistryConfig
from .models import ValidationResult, AttackMetadata
from .interfaces import BaseRegistryComponent


logger = logging.getLogger(__name__)


class AttackParameterValidator(BaseRegistryComponent):
    """
    Валидатор параметров атак.

    Ответственность:
    - Валидация параметров атак согласно их метаданным
    - Проверка типов и значений параметров
    - Проверка специальных ограничений (диапазоны, списки значений)
    - Поддержка пользовательских правил валидации

    Валидируемые параметры:
    - split_pos: int, str или list (позиции разделения)
    - positions: List[int/str] (для multisplit/multidisorder)
    - overlap_size: int >= 0 (для seqovl)
    - ttl/fake_ttl: int 1-255 (время жизни пакетов)
    - fooling: List[str] (методы обмана DPI)
    - custom_sni/fake_sni: str (SNI значения)

    Специальные значения split_pos:
    - "cipher", "sni", "midsld", "random" - автоматически разрешаются
    - Числовые строки - конвертируются в int
    - Списки - берется первый элемент
    """

    def __init__(self, config: RegistryConfig):
        """
        Инициализирует валидатор с конфигурацией.

        Args:
            config: Конфигурация реестра
        """
        super().__init__(config, __name__)
        self._validation_rules: Dict[str, Callable] = {}
        self._setup_default_rules()

    def initialize(self) -> bool:
        """
        Инициализирует компонент валидатора.

        Returns:
            True если инициализация успешна
        """
        try:
            self._clear_errors()
            self._setup_default_rules()
            self._set_status("ready")
            self.logger.info("AttackParameterValidator initialized successfully")
            return True
        except Exception as e:
            self._add_error(f"Failed to initialize validator: {e}")
            return False

    def validate_parameters(
        self, attack_metadata: AttackMetadata, params: Dict[str, Any]
    ) -> ValidationResult:
        """
        Валидирует параметры атаки согласно метаданным.

        Процесс валидации:
        1. Проверка существования всех обязательных параметров
        2. Валидация типов и значений параметров
        3. Проверка специальных ограничений
        4. Применение пользовательских правил валидации

        Args:
            attack_metadata: Метаданные атаки с описанием параметров
            params: Словарь параметров для проверки

        Returns:
            ValidationResult с результатом проверки, ошибками и предупреждениями
        """
        if not self.config.validation_enabled:
            return ValidationResult(is_valid=True, error_message=None)

        # Проверяем обязательные параметры
        missing_params = self._validate_required_params(attack_metadata, params)
        if missing_params:
            return ValidationResult(
                is_valid=False,
                error_message=f"Missing required parameters: {', '.join(missing_params)}",
            )

        # Проверяем типы параметров
        if self.config.validate_param_types:
            type_errors = self._validate_param_types(attack_metadata, params)
            if type_errors:
                return ValidationResult(
                    is_valid=False, error_message=f"Parameter type errors: {'; '.join(type_errors)}"
                )

        # Проверяем значения параметров
        if self.config.validate_param_ranges:
            value_errors = self._validate_param_values(attack_metadata, params)
            if value_errors:
                return ValidationResult(
                    is_valid=False,
                    error_message=f"Parameter value errors: {'; '.join(value_errors)}",
                )

        # Применяем пользовательские правила
        custom_errors = self._apply_custom_rules(params)
        if custom_errors:
            return ValidationResult(
                is_valid=False,
                error_message=f"Custom validation errors: {'; '.join(custom_errors)}",
            )

        return ValidationResult(is_valid=True, error_message=None)

    def register_validation_rule(self, param_name: str, validator: Callable[[Any], bool]) -> None:
        """
        Регистрирует пользовательское правило валидации.

        Args:
            param_name: Имя параметра для валидации
            validator: Функция валидации, возвращающая True если значение валидно
        """
        self._validation_rules[param_name] = validator
        self.logger.debug(f"Registered custom validation rule for parameter '{param_name}'")

    def _validate_required_params(
        self, metadata: AttackMetadata, params: Dict[str, Any]
    ) -> List[str]:
        """
        Проверяет наличие всех обязательных параметров.

        Args:
            metadata: Метаданные атаки
            params: Параметры для проверки

        Returns:
            Список отсутствующих обязательных параметров
        """
        missing = []
        for required_param in metadata.required_params:
            if required_param not in params:
                missing.append(required_param)
        return missing

    def _validate_param_types(self, metadata: AttackMetadata, params: Dict[str, Any]) -> List[str]:
        """
        Проверяет типы параметров.

        Args:
            metadata: Метаданные атаки
            params: Параметры для проверки

        Returns:
            Список ошибок типов
        """
        errors = []

        # Проверяем типы для известных параметров
        for param_name, param_value in params.items():
            if param_value is None:
                continue

            # Специальная обработка для известных параметров
            if param_name == "split_pos":
                if not isinstance(param_value, (int, str, list)):
                    errors.append(f"split_pos must be int, str, or list, got {type(param_value)}")
            elif param_name == "positions":
                if not isinstance(param_value, (list, type(None))):
                    errors.append(f"positions must be a list or None, got {type(param_value)}")
            elif param_name == "overlap_size":
                if not isinstance(param_value, int):
                    errors.append(f"overlap_size must be int, got {type(param_value)}")
            elif param_name in ["ttl", "fake_ttl"]:
                if not isinstance(param_value, int):
                    errors.append(f"{param_name} must be int, got {type(param_value)}")
            elif param_name == "fooling":
                if not isinstance(param_value, list):
                    errors.append(f"fooling must be a list, got {type(param_value)}")
            elif param_name in ["custom_sni", "fake_sni"]:
                if not isinstance(param_value, str):
                    errors.append(f"{param_name} must be a string, got {type(param_value)}")

        return errors

    def _validate_param_values(self, metadata: AttackMetadata, params: Dict[str, Any]) -> List[str]:
        """
        Проверяет значения параметров.

        Это основная логика валидации, извлеченная из AttackRegistry._validate_parameter_values().

        Args:
            metadata: Метаданные атаки
            params: Параметры для проверки

        Returns:
            Список ошибок значений
        """
        errors = []

        # Валидация split_pos (только если он присутствует и не None)
        if "split_pos" in params and params["split_pos"] is not None:
            split_pos = params["split_pos"]

            # Если split_pos это список, берем первый элемент
            if isinstance(split_pos, list):
                if len(split_pos) == 0:
                    errors.append("split_pos list cannot be empty")
                    return errors
                split_pos = split_pos[0]
                # Обновляем параметры для дальнейшего использования
                params["split_pos"] = split_pos
                self.logger.debug(f"Converted split_pos list to single value: {split_pos}")

            # Проверяем специальные значения
            if isinstance(split_pos, str) and split_pos not in [
                "cipher",
                "sni",
                "midsld",
                "random",
            ]:
                try:
                    int(split_pos)
                except ValueError:
                    errors.append(f"Invalid split_pos value: {split_pos}")

        # Валидация positions для multisplit/multidisorder
        if "positions" in params:
            positions = params["positions"]
            if positions is None:
                # None is acceptable for positions - the attack handler will convert it
                # from split_pos or use defaults
                pass
            elif not isinstance(positions, list):
                errors.append(f"positions must be a list, got {type(positions)}")
            else:
                # Only validate if positions is not None and is a list
                special_values = ["cipher", "sni", "midsld"]
                for pos in positions:
                    if isinstance(pos, int):
                        if pos < 1:
                            errors.append(f"Position values must be >= 1, got {pos}")
                    elif isinstance(pos, str):
                        if pos not in special_values:
                            try:
                                int(pos)  # Try to convert to int
                            except ValueError:
                                errors.append(
                                    f"Invalid position value: {pos}. Must be int or one of {special_values}"
                                )
                    else:
                        errors.append(f"All positions must be int or str, got {type(pos)}")

        # Валидация overlap_size для seqovl
        if "overlap_size" in params:
            overlap_size = params["overlap_size"]
            if not isinstance(overlap_size, int) or overlap_size < 0:
                errors.append(f"overlap_size must be non-negative int, got {overlap_size}")

        # Валидация ttl
        if "ttl" in params:
            ttl = params["ttl"]
            if not isinstance(ttl, int) or not (1 <= ttl <= 255):
                errors.append(f"ttl must be int between 1 and 255, got {ttl}")

        # Note: fake_ttl is NOT validated in the original implementation
        # It's used in the attack handlers but not validated in validate_parameters

        # Валидация fooling методов
        if "fooling" in params and params["fooling"] is not None:
            fooling = params["fooling"]
            if not isinstance(fooling, list):
                errors.append(f"fooling must be a list, got {type(fooling)}")
            else:
                valid_fooling_methods = [
                    "badsum",
                    "badseq",
                    "badack",
                    "datanoack",
                    "hopbyhop",
                    "md5sig",
                    "fakesni",  # Add fakesni to valid methods
                ]
                for method in fooling:
                    if method not in valid_fooling_methods:
                        errors.append(
                            f"Invalid fooling method '{method}'. Valid methods: {valid_fooling_methods}"
                        )

        # Валидация custom_sni и fake_sni параметров (backward compatibility)
        sni_params = ["custom_sni", "fake_sni"]
        for param_name in sni_params:
            if param_name in params and params[param_name] is not None:
                sni_value = params[param_name]
                if not isinstance(sni_value, str):
                    errors.append(f"{param_name} must be a string, got {type(sni_value)}")
                else:
                    # Validate SNI format - basic domain name validation
                    if not self._validate_sni_format(sni_value):
                        errors.append(
                            f"Invalid {param_name} format: '{sni_value}'. Must be a valid domain name."
                        )

        return errors

    def _apply_custom_rules(self, params: Dict[str, Any]) -> List[str]:
        """
        Применяет пользовательские правила валидации.

        Args:
            params: Параметры для проверки

        Returns:
            Список ошибок пользовательской валидации
        """
        errors = []

        for param_name, validator in self._validation_rules.items():
            if param_name in params:
                try:
                    if not validator(params[param_name]):
                        errors.append(f"Custom validation failed for parameter '{param_name}'")
                except Exception as e:
                    errors.append(f"Custom validation error for parameter '{param_name}': {e}")

        return errors

    def _setup_default_rules(self) -> None:
        """Настраивает правила валидации по умолчанию."""
        # Можно добавить дополнительные правила валидации по умолчанию
        pass

    def _validate_sni_format(self, sni_value: str) -> bool:
        """
        Валидирует формат SNI (Server Name Indication).

        Uses the same validation logic as the original AttackRegistry
        by importing and using CustomSNIHandler.

        Args:
            sni_value: Значение SNI для проверки

        Returns:
            True если формат валиден
        """
        if not sni_value or not isinstance(sni_value, str):
            return False

        try:
            # Use the same validation as the original AttackRegistry
            from ..filtering.custom_sni import CustomSNIHandler

            sni_handler = CustomSNIHandler()
            return sni_handler.validate_sni(sni_value)
        except ImportError:
            # Fallback to basic validation if CustomSNIHandler is not available
            return self._basic_sni_validation(sni_value)

    def _basic_sni_validation(self, sni_value: str) -> bool:
        """
        Basic SNI validation fallback.

        Args:
            sni_value: Значение SNI для проверки

        Returns:
            True если формат валиден
        """
        if not sni_value or not isinstance(sni_value, str):
            return False

        # Базовая проверка доменного имени
        # Домен не должен быть пустым, начинаться/заканчиваться точкой или дефисом
        if not sni_value or sni_value.startswith(".") or sni_value.endswith("."):
            return False

        if sni_value.startswith("-") or sni_value.endswith("-"):
            return False

        # Проверяем каждую часть домена
        parts = sni_value.split(".")
        if len(parts) < 2:  # Домен должен содержать хотя бы две части
            return False

        for part in parts:
            if not part:  # Пустые части недопустимы
                return False

            # Каждая часть должна содержать только буквы, цифры и дефисы
            if not all(c.isalnum() or c == "-" for c in part):
                return False

            # Часть не должна начинаться или заканчиваться дефисом
            if part.startswith("-") or part.endswith("-"):
                return False

        return True
