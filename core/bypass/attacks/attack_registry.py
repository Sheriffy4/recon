from __future__ import annotations

"""
Централизованный реестр всех атак DPI обхода.

Этот модуль предоставляет AttackRegistry - центральный компонент для:
- Регистрации всех доступных атак
- Валидации параметров атак
- Управления метаданными атак
- Автоматического обнаружения внешних модулей атак
"""

# Standard library imports

import importlib
import inspect
import logging
import re
import builtins
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


# Local imports
from .base import AttackContext
from .metadata import (
    AttackCategories,
    AttackMetadata,
    ValidationResult,
    RegistrationPriority,
    AttackEntry,
    RegistrationResult,
)


logger = logging.getLogger(__name__)

# Cross-module singleton key (survives "double import" under different package prefixes)
_REGISTRY_BUILTIN_KEY = "__BYPASS_ATTACK_REGISTRY_SINGLETON__"

_ATTACKS_DIR = Path(__file__).parent

_EXCLUDED_ATTACK_FILES = {
    "attack_registry.py",
    "metadata.py",
    "base.py",
    "__init__.py",
    "real_effectiveness_tester.py",
    "simple_attack_executor.py",
    "alias_map.py",
    "attack_classifier.py",
    "attack_definition.py",
    "learning_memory.py",
    "multisplit_segment_fix.py",
    "proper_testing_methodology.py",
    "safe_result_utils.py",
    "segment_packet_builder.py",
    "timing_controller.py",
    "engine.py",
    "http_manipulation.py",  # Temporarily excluded due to syntax issues / instability
}

_ATTACK_SUBDIRS = ["tcp", "udp", "tls", "http2", "payload", "tunneling", "combo"]

_global_registry: Optional["AttackRegistry"] = None
_lazy_loading_config: Optional[bool] = None


class AttackRegistry:
    """
    Централизованный реестр всех атак DPI обхода.

    Основные функции:
    - Регистрация встроенных и внешних атак
    - Управление метаданными атак (параметры, алиасы, категории)
    - Валидация параметров атак
    - Разрешение алиасов в канонические имена
    - Автоматическое обнаружение внешних модулей атак

    Архитектура:
    - Встроенные атаки: Регистрируются из primitives.py при инициализации
    - Внешние атаки: Автоматически обнаруживаются в core/bypass/attacks/
    - Алиасы: Поддержка альтернативных имен для атак
    - Валидация: Проверка типов и значений параметров

    Поддерживаемые типы атак:
    - fakeddisorder: Фейковый пакет + реальные части в обратном порядке
    - seqovl: Sequence overlap с перекрытием
    - multidisorder: Множественное разделение с disorder
    - multisplit: Множественное разделение пакетов
    - disorder: Простое изменение порядка без фейкового пакета
    - split: Простое разделение на две части
    - fake: Race condition с фейковым пакетом
    """

    def __init__(self, lazy_loading: bool = False):
        """
        Инициализирует реестр и регистрирует все доступные атаки.

        Args:
            lazy_loading: Если True, внешние атаки загружаются по требованию
        """
        self.attacks: Dict[str, AttackEntry] = {}
        self._registration_order: List[str] = []
        self._lazy_loading = lazy_loading
        self._unloaded_modules: Dict[str, str] = {}
        self._loaded_modules: set = set()

        # Publish this instance early to break re-entrant registry creation during imports
        # (prevents recursion storms / deadlocks when external modules call get_attack_registry()).
        try:
            if getattr(builtins, _REGISTRY_BUILTIN_KEY, None) is None:
                setattr(builtins, _REGISTRY_BUILTIN_KEY, self)
        except Exception:
            pass

        # Initialize handler factory for creating attack handlers
        from .registry.handler_factory import AttackHandlerFactory
        from .registry.alias_manager import AttackAliasManager
        from .registry.registration_manager import RegistrationManager

        self.handler_factory = AttackHandlerFactory()
        self.alias_manager = AttackAliasManager()
        self.registration_manager = RegistrationManager()

        # Validator import: keep compatibility with either old "validator.py" or new "parameter_validator.py"
        # NOTE: AttackParameterValidator requires RegistryConfig and has different API.
        try:
            from .registry.validator import AttackValidator

            self.validator = AttackValidator()
        except Exception:  # pragma: no cover
            from .registry.config import RegistryConfig
            from .registry.parameter_validator import AttackParameterValidator

            self.validator = AttackParameterValidator(RegistryConfig())

        # Ensure registry and manager share the same lazy-loading state containers
        # (otherwise stats/loading can diverge).
        if hasattr(self.registration_manager, "set_lazy_loading_state"):
            self.registration_manager.set_lazy_loading_state(
                self._unloaded_modules, self._loaded_modules
            )

        # Регистрируем встроенные атаки (всегда eager)
        self._register_builtin_attacks()

        # Автоматически обнаруживаем внешние атаки
        if lazy_loading:
            self._discover_external_attacks()
        else:
            self._register_external_attacks()
        # else:
        #     self._register_external_attacks()

        logger.info(
            f"AttackRegistry initialized with {len(self.attacks)} attacks (lazy_loading={lazy_loading})"
        )

    def _normalize_attack_lookup_key(self, name: str) -> str:
        """
        Normalize an attack name for lookup in lazy-loading tables.

        Normalization goals:
        - tolerate "attack=" prefixes
        - tolerate underscores/hyphens/spaces and other separators
        - case-insensitive matching
        """
        if not isinstance(name, str):
            return ""
        name = name.strip()
        if name.startswith("attack="):
            name = name[7:]
        name = name.lower()
        # keep only alnum to make matches more forgiving (tls_fragmentation vs tls-fragmentation etc.)
        return re.sub(r"[^a-z0-9]+", "", name)

    def register_attack(
        self,
        attack_type: str,
        handler: Callable,
        metadata: AttackMetadata,
        priority: RegistrationPriority = RegistrationPriority.NORMAL,
    ) -> RegistrationResult:
        """
        Регистрирует новую атаку в реестре с поддержкой приоритетов и дедупликации.

        Процесс регистрации:
        1. Проверка существования атаки и обработка дубликатов
        2. Создание записи AttackEntry с приоритетом
        3. Регистрация всех алиасов атаки
        4. Логирование результата регистрации

        Обработчик атаки должен иметь сигнатуру:
        handler(techniques: BypassTechniques, payload: bytes, **params) -> List[Tuple]

        Где возвращаемый список содержит кортежи (данные, смещение, опции)
        для каждого TCP сегмента, который нужно отправить.

        Args:
            attack_type: Уникальный идентификатор (канонический тип атаки)
            handler: Функция-обработчик для выполнения атаки
            metadata: Полные метаданные атаки (параметры, описание, алиасы)
            priority: Приоритет регистрации для разрешения конфликтов

        Returns:
            RegistrationResult с информацией о результате регистрации
        """
        import inspect

        # Определяем модуль-источник
        frame = inspect.currentframe()
        source_module = "unknown"
        try:
            if frame and frame.f_back:
                source_module = frame.f_back.f_globals.get("__name__", "unknown")
        finally:
            del frame

        # Проверяем на дубликаты
        if attack_type in self.attacks:
            existing_entry = self.attacks[attack_type]
            return self.registration_manager.handle_duplicate_registration(
                attack_type,
                handler,
                metadata,
                priority,
                source_module,
                existing_entry,
                self.attacks,
                self.alias_manager,
            )

        # Создаем новую запись
        entry = AttackEntry(
            attack_type=attack_type,
            handler=handler,
            metadata=metadata,
            priority=priority,
            source_module=source_module,
            registration_time=datetime.now(),
            is_canonical=True,
            performance_data={},
        )

        self.attacks[attack_type] = entry
        self._registration_order.append(attack_type)

        # Регистрируем алиасы через alias_manager
        conflicts = []
        for alias in metadata.aliases:
            # Check if alias already exists
            existing_canonical = self.alias_manager.resolve_name(alias)
            if existing_canonical != alias and existing_canonical != attack_type:
                conflicts.append(f"Alias '{alias}' already exists for '{existing_canonical}'")
                logger.warning(
                    f"Alias '{alias}' already exists for '{existing_canonical}', overwriting with '{attack_type}'"
                )

            # Register the alias
            self.alias_manager.register_alias(alias, attack_type)

        # Too noisy for production/testing loops; keep per-attack logs at DEBUG.
        logger.debug(
            f"Registered attack '{attack_type}' with priority {priority.name} from {source_module}"
        )
        if len(metadata.aliases) > 0:
            logger.debug(
                f"Registered {len(metadata.aliases)} aliases for '{attack_type}': {metadata.aliases}"
            )

        return RegistrationResult(
            success=True,
            action="registered",
            message=f"Successfully registered attack '{attack_type}' with priority {priority.name}",
            attack_type=attack_type,
            conflicts=conflicts,
            new_priority=priority,
        )

    def get_attack_handler(self, attack_type: str) -> Optional[Callable]:
        """
        Возвращает обработчик для указанного типа атаки с поддержкой lazy loading.

        Args:
            attack_type: Тип атаки или алиас

        Returns:
            Функция-обработчик или None если атака не найдена
        """
        # Разрешаем алиас в основной тип
        resolved_type = self._resolve_attack_type(attack_type)

        # Проверяем, загружена ли атака
        if resolved_type not in self.attacks:
            # Пытаемся загрузить через lazy loading
            if not self._ensure_attack_loaded(attack_type):
                logger.error(f"Attack type '{attack_type}' not found in registry")
                return None

            # Повторно разрешаем после загрузки
            resolved_type = self._resolve_attack_type(attack_type)
            if resolved_type not in self.attacks:
                logger.error(f"Attack type '{attack_type}' not found after lazy loading")
                return None

        return self.attacks[resolved_type].handler

    def get(self, attack_type: str) -> Optional[Callable]:
        """
        Возвращает обработчик атаки (алиас для get_attack_handler для совместимости).

        Этот метод добавлен для совместимости с кодом, который вызывает AttackRegistry.get().

        Args:
            attack_type: Тип атаки или алиас

        Returns:
            Функция-обработчик или None если атака не найдена
        """
        return self.get_attack_handler(attack_type)

    def get_attack_metadata(self, attack_type: str) -> Optional[AttackMetadata]:
        """
        Возвращает метаданные для указанного типа атаки с поддержкой lazy loading.

        Args:
            attack_type: Тип атаки или алиас

        Returns:
            Метаданные атаки или None если атака не найдена
        """
        resolved_type = self._resolve_attack_type(attack_type)

        if resolved_type not in self.attacks:
            # Пытаемся загрузить через lazy loading
            if not self._ensure_attack_loaded(attack_type):
                return None

            # Повторно разрешаем после загрузки
            resolved_type = self._resolve_attack_type(attack_type)
            if resolved_type not in self.attacks:
                return None

        return self.attacks[resolved_type].metadata

    def get_attack_definition(self, attack_type: str) -> Optional[AttackMetadata]:
        """
        Возвращает определение атаки (алиас для get_attack_metadata для совместимости).

        Args:
            attack_type: Тип атаки или алиас

        Returns:
            Метаданные атаки или None если атака не найдена
        """
        return self.get_attack_metadata(attack_type)

    def validate_parameters(self, attack_type: str, params: Dict[str, Any]) -> ValidationResult:
        """
        Валидирует параметры для указанного типа атаки с подробной проверкой.

        Процесс валидации:
        1. Проверка существования типа атаки
        2. Проверка наличия всех обязательных параметров
        3. Валидация типов и значений параметров
        4. Проверка специальных ограничений (диапазоны, списки значений)
        5. Генерация предупреждений для потенциальных проблем

        Валидируемые параметры:
        - split_pos: int, str или list (позиции разделения)
        - positions: List[int/str] (для multisplit/multidisorder)
        - overlap_size: int >= 0 (для seqovl)
        - ttl/fake_ttl: int 1-255 (время жизни пакетов)
        - fooling: List[str] (методы обмана DPI)

        Специальные значения split_pos:
        - "cipher", "sni", "midsld" - автоматически разрешаются
        - Числовые строки - конвертируются в int
        - Списки - берется первый элемент

        Args:
            attack_type: Тип атаки или алиас для валидации
            params: Словарь параметров для проверки

        Returns:
            ValidationResult с результатом проверки, ошибками и предупреждениями
        """
        metadata = self.get_attack_metadata(attack_type)
        if not metadata:
            return ValidationResult(
                is_valid=False, error_message=f"Unknown attack type: {attack_type}"
            )

        # Support both validator APIs:
        # - AttackValidator.validate_parameters(attack_type, params, metadata)
        # - AttackParameterValidator.validate_parameters(attack_metadata, params)
        import inspect as _inspect

        validate_fn = getattr(self.validator, "validate_parameters", None)
        if validate_fn is None:
            return ValidationResult(
                is_valid=False,
                error_message="Validator does not provide validate_parameters()",
            )

        sig = _inspect.signature(validate_fn)
        params_list = list(sig.parameters.values())
        effective_count = len(params_list)
        # Account for 'self' or 'cls' in bound methods
        if params_list and params_list[0].name in ("self", "cls"):
            effective_count -= 1

        if effective_count == 3:
            return validate_fn(attack_type, params, metadata)
        if effective_count == 2:
            return validate_fn(metadata, params)

        return ValidationResult(
            is_valid=False,
            error_message=f"Unsupported validator signature: {len(params_list)} params",
        )

    def list_attacks(self, category: Optional[str] = None, enabled_only: bool = False) -> List[str]:
        """
        Возвращает список всех зарегистрированных атак.

        Args:
            category: Опциональная фильтрация по категории
            enabled_only: Фильтровать только включенные атаки (для совместимости)

        Returns:
            Список типов атак
        """
        attacks = list(self.attacks.keys())

        if category is not None:
            attacks = [
                attack_type
                for attack_type in attacks
                if self.attacks[attack_type].metadata.category == category
            ]

        # enabled_only параметр для совместимости - все атаки считаются
        # включенными
        return attacks

    def get_attack_aliases(self, attack_type: str) -> List[str]:
        """
        Возвращает все алиасы для указанного типа атаки.

        Args:
            attack_type: Тип атаки

        Returns:
            Список алиасов
        """
        resolved_type = self._resolve_attack_type(attack_type)

        if resolved_type not in self.attacks:
            return []

        return self.attacks[resolved_type].metadata.aliases

    def _resolve_attack_type(self, attack_type: str) -> str:
        """Разрешает алиас в основной тип атаки."""
        # Handle attack= prefix if present (for compatibility with --attack= format)
        normalized_type = attack_type
        if normalized_type.startswith("attack="):
            normalized_type = normalized_type[7:]  # Remove "attack=" prefix

        return self.alias_manager.resolve_name(normalized_type)

    # Alias management wrapper methods for backward compatibility
    def register_alias(
        self, alias: str, canonical_attack: str, metadata: Optional[AttackMetadata] = None
    ) -> bool:
        """
        Register an alias for a canonical attack name.

        Args:
            alias: The alias name to register
            canonical_attack: The canonical attack name
            metadata: Optional metadata (for compatibility, not used)

        Returns:
            True if registration was successful
        """
        return self.alias_manager.register_alias(alias, canonical_attack)

    def get_canonical_name(self, attack_type: str) -> str:
        """
        Get the canonical name for an attack type or alias.

        Args:
            attack_type: Attack type or alias

        Returns:
            Canonical attack name
        """
        return self.alias_manager.resolve_name(attack_type)

    def is_alias(self, name: str) -> bool:
        """
        Check if a name is an alias (not a canonical name).

        Args:
            name: Name to check

        Returns:
            True if name is an alias
        """
        resolved = self.alias_manager.resolve_name(name)
        return resolved != name

    def get_all_names_for_attack(self, attack_type: str) -> List[str]:
        """
        Get all names (canonical + aliases) for an attack.

        Args:
            attack_type: Attack type or alias

        Returns:
            List of all names including canonical and aliases
        """
        canonical = self.alias_manager.resolve_name(attack_type)
        if canonical not in self.attacks:
            return []

        aliases = self.attacks[canonical].metadata.aliases
        return [canonical] + aliases

    def get_alias_mapping(self) -> Dict[str, str]:
        """
        Get complete alias mapping.

        Returns:
            Dictionary mapping aliases to canonical names
        """
        return self.alias_manager.get_alias_mapping()

    def _register_builtin_attacks(self) -> None:
        """
        Регистрирует все встроенные атаки из primitives.py с полными метаданными.

        Регистрируемые атаки:

        1. fakeddisorder - Основная атака с фейковым пакетом
           - Отправляет фейковый пакет с низким TTL
           - Затем реальные части в обратном порядке
           - Параметры: split_pos (обязательный), ttl, fooling

        2. seqovl - Sequence overlap атака
           - Фейковый пакет с перекрытием последовательности
           - Затем полный реальный пакет
           - Параметры: split_pos, overlap_size (обязательные)

        3. multidisorder - Множественное разделение с disorder
           - Разделение на несколько частей
           - Отправка в обратном порядке с фейковым пакетом
           - Параметры: positions или split_pos

        4. disorder/disorder2 - Простое изменение порядка
           - Без фейкового пакета
           - disorder2 использует ACK флаг первым

        5. multisplit/split - Разделение пакетов
           - multisplit: множественные позиции
           - split: одна позиция (алиас для multisplit)

        6. fake - Race condition атака
           - Фейковый пакет перед реальным
           - Параметры: ttl (обязательный)

        Каждая атака регистрируется с:
        - Специализированным обработчиком
        - Полными метаданными (описание, параметры)
        - Алиасами для совместимости
        - Категорией для классификации
        """

        # fakeddisorder - основная атака с фейковым пакетом
        self.register_attack(
            "fakeddisorder",
            self.handler_factory.create_handler(
                "fakeddisorder",
                AttackMetadata(
                    name="Fake Disorder",
                    description="Отправляет фейковый пакет с низким TTL, затем реальные части в обратном порядке",
                    required_params=[],
                    optional_params={
                        "split_pos": 3,
                        "ttl": 3,
                        "fake_ttl": 3,
                        "disorder_method": "reverse",
                        "fooling": ["badsum"],
                        "fake_sni": None,
                        "fake_data": None,
                        "custom_sni": None,
                    },
                    aliases=[
                        "fake_disorder",
                        "fakedisorder",
                        "force_tcp",
                        "filter-udp",
                        "filter_udv",
                    ],
                    category=AttackCategories.FAKE,
                ),
            ),
            AttackMetadata(
                name="Fake Disorder",
                description="Отправляет фейковый пакет с низким TTL, затем реальные части в обратном порядке",
                required_params=[],
                optional_params={
                    "split_pos": 3,
                    "ttl": 3,
                    "fake_ttl": 3,
                    "disorder_method": "reverse",  # Add default disorder_method
                    "fooling": ["badsum"],
                    # Не добавляем fooling_methods по умолчанию - это дубликат fooling
                    "fake_sni": None,
                    "fake_data": None,
                    "custom_sni": None,  # Add custom_sni parameter support
                },
                aliases=["fake_disorder", "fakedisorder", "force_tcp", "filter-udp", "filter_udv"],
                category=AttackCategories.FAKE,
            ),
            priority=RegistrationPriority.CORE,
        )

        # seqovl - sequence overlap атака
        self.register_attack(
            "seqovl",
            self.handler_factory.create_handler(
                "seqovl",
                AttackMetadata(
                    name="Sequence Overlap",
                    description="Отправляет фейковый пакет с перекрытием, затем полный реальный пакет",
                    required_params=[],
                    optional_params={
                        "split_pos": 3,
                        "overlap_size": 10,
                        "fake_ttl": 3,
                        "fooling": ["badsum"],
                        "custom_sni": None,
                    },
                    aliases=["seq_overlap", "overlap"],
                    category=AttackCategories.OVERLAP,
                ),
            ),
            AttackMetadata(
                name="Sequence Overlap",
                description="Отправляет фейковый пакет с перекрытием, затем полный реальный пакет",
                required_params=[],  # Fixed: match actual attack class
                optional_params={
                    "split_pos": 3,
                    "overlap_size": 10,
                    "fake_ttl": 3,
                    "fooling": ["badsum"],  # Используем fooling вместо fooling_methods
                    "custom_sni": None,  # Add custom_sni parameter support
                },
                aliases=["seq_overlap", "overlap"],
                category=AttackCategories.OVERLAP,
            ),
            priority=RegistrationPriority.CORE,
        )

        # multidisorder - множественное разделение с disorder
        self.register_attack(
            "multidisorder",
            self.handler_factory.create_handler(
                "multidisorder",
                AttackMetadata(
                    name="Multi Disorder",
                    description="Разделяет пакет на несколько частей и отправляет в обратном порядке с фейковым пакетом",
                    required_params=[],
                    optional_params={
                        "positions": [1, 5, 10],
                        "split_pos": 3,
                        "fake_ttl": 3,
                        "fooling": ["badsum"],
                        "custom_sni": None,
                    },
                    aliases=["multi_disorder"],
                    category=AttackCategories.DISORDER,
                ),
            ),
            AttackMetadata(
                name="Multi Disorder",
                description="Разделяет пакет на несколько частей и отправляет в обратном порядке с фейковым пакетом",
                required_params=[],  # Не требуем обязательных параметров, обработчик сам разберется
                optional_params={
                    "positions": [1, 5, 10],
                    "split_pos": 3,
                    "fake_ttl": 3,
                    "fooling": ["badsum"],
                    "custom_sni": None,  # Add custom_sni parameter support
                },
                aliases=["multi_disorder"],
                category=AttackCategories.DISORDER,
            ),
            priority=RegistrationPriority.CORE,
        )

        # disorder - простое разделение без фейкового пакета
        self.register_attack(
            "disorder",
            self.handler_factory.create_handler(
                "disorder",
                AttackMetadata(
                    name="Simple Disorder",
                    description="Разделяет пакет на две части и отправляет в обратном порядке",
                    required_params=[],
                    optional_params={
                        "split_pos": 3,
                        "ack_first": False,
                        "disorder_method": "reverse",
                    },
                    aliases=["simple_disorder"],
                    category=AttackCategories.DISORDER,
                ),
            ),
            AttackMetadata(
                name="Simple Disorder",
                description="Разделяет пакет на две части и отправляет в обратном порядке",
                required_params=[],  # Make split_pos optional with default
                optional_params={
                    "split_pos": 3,
                    "ack_first": False,
                    "disorder_method": "reverse",  # Add default disorder_method
                },
                aliases=["simple_disorder"],
                category=AttackCategories.DISORDER,
            ),
            priority=RegistrationPriority.CORE,
        )

        # disorder2 - disorder с ack_first=True
        self.register_attack(
            "disorder2",
            self.handler_factory.create_handler(
                "disorder2",
                AttackMetadata(
                    name="Disorder with ACK First",
                    description="Разделяет пакет на две части и отправляет в обратном порядке с ACK флагом первым",
                    required_params=["split_pos"],
                    optional_params={},
                    aliases=["disorder_ack"],
                    category=AttackCategories.DISORDER,
                ),
            ),
            AttackMetadata(
                name="Disorder with ACK First",
                description="Разделяет пакет на две части и отправляет в обратном порядке с ACK флагом первым",
                required_params=["split_pos"],
                optional_params={},
                aliases=["disorder_ack"],
                category=AttackCategories.DISORDER,
            ),
            priority=RegistrationPriority.CORE,
        )

        # multisplit - множественное разделение
        self.register_attack(
            "multisplit",
            self.handler_factory.create_handler(
                "multisplit",
                AttackMetadata(
                    name="Multi Split",
                    description="Разделяет пакет на несколько частей по указанным позициям",
                    required_params=[],
                    optional_params={
                        "positions": [3, 9, 15, 21, 27, 33, 39, 45],
                        "split_pos": 3,
                        "split_count": 8,
                        "fooling": ["badsum"],
                    },
                    aliases=["multi_split"],
                    category=AttackCategories.SPLIT,
                ),
            ),
            AttackMetadata(
                name="Multi Split",
                description="Разделяет пакет на несколько частей по указанным позициям",
                required_params=[],  # Не требуем обязательных параметров, обработчик сам разберется
                optional_params={
                    "positions": [3, 9, 15, 21, 27, 33, 39, 45],  # Default 8 positions
                    "split_pos": 3,  # Default split position
                    "split_count": 8,  # Default split count
                    "fooling": ["badsum"],
                },
                aliases=["multi_split"],
                category=AttackCategories.SPLIT,
            ),
            priority=RegistrationPriority.CORE,
        )

        # split - простое разделение (алиас для multisplit с одной позицией)
        self.register_attack(
            "split",
            self.handler_factory.create_handler(
                "split",
                AttackMetadata(
                    name="Simple Split",
                    description="Разделяет пакет на две части по указанной позиции",
                    required_params=["split_pos"],
                    optional_params={"fooling": ["badsum"]},
                    aliases=["simple_split"],
                    category=AttackCategories.SPLIT,
                ),
            ),
            AttackMetadata(
                name="Simple Split",
                description="Разделяет пакет на две части по указанной позиции",
                required_params=["split_pos"],
                optional_params={"fooling": ["badsum"]},
                aliases=["simple_split"],
                category=AttackCategories.SPLIT,
            ),
            priority=RegistrationPriority.CORE,
        )

        # fake - фейковый пакет race condition
        self.register_attack(
            "fake",
            self.handler_factory.create_handler(
                "fake",
                AttackMetadata(
                    name="Fake Packet Race",
                    description="Отправляет фейковый пакет с низким TTL перед реальным",
                    required_params=[],
                    optional_params={
                        "ttl": 3,
                        "fake_ttl": 3,
                        "split_pos": 3,
                        "fooling": ["badsum"],
                        "fake_data": None,
                        "custom_sni": None,
                    },
                    aliases=["fake_race", "race"],
                    category=AttackCategories.RACE,
                ),
            ),
            AttackMetadata(
                name="Fake Packet Race",
                description="Отправляет фейковый пакет с низким TTL перед реальным",
                required_params=[],
                optional_params={
                    "ttl": 3,
                    "fake_ttl": 3,
                    "split_pos": 3,
                    "fooling": ["badsum"],
                    "fake_data": None,
                    "custom_sni": None,  # Add custom_sni parameter support
                },
                aliases=["fake_race", "race", "fake_syn", "connection_recovery_fake_syn"],
                category=AttackCategories.RACE,
            ),
            priority=RegistrationPriority.CORE,
        )

        # TCP window manipulation - migrated from tcp_fragmentation.py
        self.register_attack(
            "window_manipulation",
            self.handler_factory.create_handler(
                "window_manipulation",
                AttackMetadata(
                    name="TCP Window Manipulation",
                    description="Manipulates TCP window size to force small segments and control flow",
                    required_params=[],
                    optional_params={
                        "window_size": 1,
                        "delay_ms": 50.0,
                        "fragment_count": 5,
                        "fooling": ["badsum"],
                    },
                    aliases=["tcp_window_manipulation", "window_control"],
                    category=AttackCategories.FRAGMENT,
                ),
            ),
            AttackMetadata(
                name="TCP Window Manipulation",
                description="Manipulates TCP window size to force small segments and control flow",
                required_params=[],
                optional_params={
                    "window_size": 1,
                    "delay_ms": 50.0,
                    "fragment_count": 5,
                    "fooling": ["badsum"],
                },
                aliases=["tcp_window_manipulation", "window_control"],
                category=AttackCategories.FRAGMENT,
            ),
            priority=RegistrationPriority.CORE,
        )

        # TCP options modification - migrated from tcp_fragmentation.py
        self.register_attack(
            "tcp_options_modification",
            self.handler_factory.create_handler(
                "tcp_options_modification",
                AttackMetadata(
                    name="TCP Options Modification",
                    description="Modifies TCP options to evade DPI detection while fragmenting",
                    required_params=[],
                    optional_params={
                        "split_pos": 5,
                        "options_type": "mss",
                        "bad_checksum": False,
                        "fooling": ["badsum"],
                    },
                    aliases=["tcp_options", "options_modification"],
                    category=AttackCategories.FRAGMENT,
                ),
            ),
            AttackMetadata(
                name="TCP Options Modification",
                description="Modifies TCP options to evade DPI detection while fragmenting",
                required_params=[],
                optional_params={
                    "split_pos": 5,
                    "options_type": "mss",
                    "bad_checksum": False,
                    "fooling": ["badsum"],
                },
                aliases=["tcp_options", "options_modification"],
                category=AttackCategories.FRAGMENT,
            ),
            priority=RegistrationPriority.CORE,
        )

        # Advanced timing control - migrated from tcp_fragmentation.py
        self.register_attack(
            "advanced_timing",
            self.handler_factory.create_handler(
                "advanced_timing",
                AttackMetadata(
                    name="Advanced Timing Control",
                    description="Provides precise control over timing between segments to evade temporal analysis",
                    required_params=[],
                    optional_params={
                        "split_pos": 3,
                        "delays": [1.0, 2.0],
                        "jitter": False,
                        "fooling": ["badsum"],
                    },
                    aliases=["timing_control", "temporal_evasion"],
                    category=AttackCategories.TIMING,
                ),
            ),
            AttackMetadata(
                name="Advanced Timing Control",
                description="Provides precise control over timing between segments to evade temporal analysis",
                required_params=[],
                optional_params={
                    "split_pos": 3,
                    "delays": [1.0, 2.0],
                    "jitter": False,
                    "fooling": ["badsum"],
                },
                aliases=["timing_control", "temporal_evasion"],
                category=AttackCategories.TIMING,
            ),
            priority=RegistrationPriority.CORE,
        )

        # disorder_split - combination of disorder and split attacks
        self.register_attack(
            "disorder_split",
            self.handler_factory.create_handler(
                "disorder_split",
                AttackMetadata(
                    name="Disorder Split",
                    description="Combines disorder and split attacks: splits packet and sends parts in reverse order",
                    required_params=[],
                    optional_params={
                        "split_pos": 3,
                        "positions": None,
                        "split_count": None,
                        "ack_first": False,
                        "fooling": ["badsum"],
                    },
                    aliases=["split_disorder"],
                    category=AttackCategories.DISORDER,
                ),
            ),
            AttackMetadata(
                name="Disorder Split",
                description="Combines disorder and split attacks: splits packet and sends parts in reverse order",
                required_params=[],
                optional_params={
                    "split_pos": 3,
                    "positions": None,
                    "split_count": None,
                    "ack_first": False,
                    "fooling": ["badsum"],
                },
                aliases=["split_disorder"],
                category=AttackCategories.DISORDER,
            ),
            priority=RegistrationPriority.CORE,
        )

        # Register missing fooling attacks that are referenced but not registered
        self.register_attack(
            "badsum",
            self.handler_factory.create_handler(
                "badsum",
                AttackMetadata(
                    name="Bad Checksum Fooling",
                    description="Sends fake packet with invalid TCP checksum to fool DPI",
                    required_params=[],
                    optional_params={"ttl": 3, "fake_ttl": 3},
                    aliases=["bad_checksum", "badsum_fooling"],
                    category=AttackCategories.FAKE,
                ),
            ),
            AttackMetadata(
                name="Bad Checksum Fooling",
                description="Sends fake packet with invalid TCP checksum to fool DPI",
                required_params=[],
                optional_params={"ttl": 3, "fake_ttl": 3},
                aliases=["bad_checksum", "badsum_fooling"],
                category=AttackCategories.FAKE,
            ),
            priority=RegistrationPriority.CORE,
        )

        self.register_attack(
            "badseq",
            self.handler_factory.create_handler(
                "badseq",
                AttackMetadata(
                    name="Bad Sequence Fooling",
                    description="Sends fake packet with invalid TCP sequence number to fool DPI",
                    required_params=[],
                    optional_params={"ttl": 3, "fake_ttl": 3},
                    aliases=["bad_sequence", "badseq_fooling"],
                    category=AttackCategories.FAKE,
                ),
            ),
            AttackMetadata(
                name="Bad Sequence Fooling",
                description="Sends fake packet with invalid TCP sequence number to fool DPI",
                required_params=[],
                optional_params={"ttl": 3, "fake_ttl": 3},
                aliases=["bad_sequence", "badseq_fooling"],
                category=AttackCategories.FAKE,
            ),
            priority=RegistrationPriority.CORE,
        )

        self.register_attack(
            "md5sig",
            self.handler_factory.create_handler(
                "md5sig",
                AttackMetadata(
                    name="MD5 Signature Fooling",
                    description="Sends fake packet with invalid MD5 signature to fool DPI",
                    required_params=[],
                    optional_params={"ttl": 3, "fake_ttl": 3},
                    aliases=["md5_signature", "md5sig_fooling"],
                    category=AttackCategories.FAKE,
                ),
            ),
            AttackMetadata(
                name="MD5 Signature Fooling",
                description="Sends fake packet with invalid MD5 signature to fool DPI",
                required_params=[],
                optional_params={"ttl": 3, "fake_ttl": 3},
                aliases=["md5_signature", "md5sig_fooling"],
                category=AttackCategories.FAKE,
            ),
            priority=RegistrationPriority.CORE,
        )

        self.register_attack(
            "passthrough",
            self.handler_factory.create_handler(
                "passthrough",
                AttackMetadata(
                    name="Passthrough (No-Op)",
                    description="Passes packet through without any modification (baseline test)",
                    required_params=[],
                    optional_params={},
                    aliases=["noop", "no_op", "baseline"],
                    category=AttackCategories.FAKE,
                ),
            ),
            AttackMetadata(
                name="Passthrough (No-Op)",
                description="Passes packet through without any modification (baseline test)",
                required_params=[],
                optional_params={},
                aliases=["noop", "no_op", "baseline"],
                category=AttackCategories.FAKE,
            ),
            priority=RegistrationPriority.CORE,
        )

        self.register_attack(
            "ttl",
            self.handler_factory.create_handler(
                "ttl",
                AttackMetadata(
                    name="TTL Manipulation",
                    description="Manipulates packet TTL to expire before reaching DPI",
                    required_params=[],
                    optional_params={"ttl": 3, "fooling": ["badsum"]},
                    aliases=["ttl_manipulation", "ttl_attack"],
                    category=AttackCategories.FAKE,
                ),
            ),
            AttackMetadata(
                name="TTL Manipulation",
                description="Manipulates packet TTL to expire before reaching DPI",
                required_params=[],
                optional_params={"ttl": 3, "fooling": ["badsum"]},
                aliases=["ttl_manipulation", "ttl_attack"],
                category=AttackCategories.FAKE,
            ),
            priority=RegistrationPriority.CORE,
        )

        logger.info("Registered all builtin attacks")

        # Register aliases for common attack variations
        self.register_alias(
            alias="multisplit_conceal_sni",
            canonical_attack="multisplit",
            metadata=AttackMetadata(
                name="multisplit_conceal_sni",
                description="Alias for multisplit attack with SNI concealment",
                required_params=[],
                optional_params={},
                aliases=[],
                category=AttackCategories.SPLIT,
            ),
        )

        # Register custom strategy aliases for backward compatibility
        self.register_alias(
            alias="disorder_short_ttl_decoy",
            canonical_attack="disorder",
            metadata=AttackMetadata(
                name="disorder_short_ttl_decoy",
                description="Disorder attack with short TTL and decoy packets",
                required_params=[],
                optional_params={"ttl": 3, "split_pos": "sni", "fooling": ["badseq"]},
                aliases=[],
                category=AttackCategories.DISORDER,
            ),
        )

        self.register_alias(
            alias="disorder_short_ttl_decoy_optimized",
            canonical_attack="disorder",
            metadata=AttackMetadata(
                name="disorder_short_ttl_decoy_optimized",
                description="Optimized disorder attack with short TTL",
                required_params=[],
                optional_params={"ttl": 1, "split_pos": "sni", "fooling": ["badseq"]},
                aliases=[],
                category=AttackCategories.DISORDER,
            ),
        )

        # Register aliases for fragmentation-based attacks from adaptive knowledge
        self.register_alias(
            alias="split_basic_fragmentation_optimized",
            canonical_attack="split",
            metadata=AttackMetadata(
                name="split_basic_fragmentation_optimized",
                description="Optimized split attack with basic fragmentation",
                required_params=[],
                optional_params={
                    "split_pos": 3,
                    "ttl": 3,
                    "split_count": 4,
                    "fooling": ["badsum"],
                    "repeats": 1,
                },
                aliases=[],
                category=AttackCategories.SPLIT,
            ),
        )

        # CRITICAL FIX: Register tls_fragmentation as alias for tls_fragmentation_combo
        # This fixes the AttackNotFoundError where domain rules use tls_fragmentation
        # but the actual registered attack is tls_fragmentation_combo
        self.register_alias(
            alias="tls_fragmentation",
            canonical_attack="tls_fragmentation_combo",
            metadata=AttackMetadata(
                name="tls_fragmentation",
                description="TLS fragmentation attack (alias for tls_fragmentation_combo)",
                required_params=[],
                optional_params={"fragment_size": 64, "tls_record_split": True},
                aliases=[],
                category=AttackCategories.FRAGMENT,
            ),
        )

        self.register_alias(
            alias="multisplit_basic_fragmentation_optimized",
            canonical_attack="multisplit",
            metadata=AttackMetadata(
                name="multisplit_basic_fragmentation_optimized",
                description="Optimized multisplit attack with basic fragmentation",
                required_params=[],
                optional_params={
                    "split_count": 4,
                    "ttl": 3,
                    "split_pos": 3,
                    "fooling": ["badsum"],
                    "repeats": 1,
                },
                aliases=[],
                category=AttackCategories.SPLIT,
            ),
        )

        # Register other fragmentation aliases that might be used
        self.register_alias(
            alias="split_basic_fragmentation",
            canonical_attack="split",
            metadata=AttackMetadata(
                name="split_basic_fragmentation",
                description="Basic split attack with fragmentation",
                required_params=[],
                optional_params={"split_pos": 2},
                aliases=[],
                category=AttackCategories.SPLIT,
            ),
        )

        self.register_alias(
            alias="multisplit_basic_fragmentation",
            canonical_attack="multisplit",
            metadata=AttackMetadata(
                name="multisplit_basic_fragmentation",
                description="Basic multisplit attack with fragmentation",
                required_params=[],
                optional_params={"split_count": 4},
                aliases=[],
                category=AttackCategories.SPLIT,
            ),
        )

        # Register disorder aliases
        self.register_alias(
            alias="disorder_simple_reordering",
            canonical_attack="disorder",
            metadata=AttackMetadata(
                name="disorder_simple_reordering",
                description="Simple disorder attack with packet reordering",
                required_params=[],
                optional_params={"split_pos": 2},
                aliases=[],
                category=AttackCategories.DISORDER,
            ),
        )

        # CRITICAL FIX: Register tls_fragmentation as alias for tls_fragmentation_combo
        # This fixes the AttackNotFoundError where domain rules use tls_fragmentation
        # but the actual registered attack is tls_fragmentation_combo
        self.register_alias(
            alias="tls_fragmentation",
            canonical_attack="tls_fragmentation_combo",
            metadata=AttackMetadata(
                name="tls_fragmentation",
                description="TLS fragmentation attack (alias for tls_fragmentation_combo)",
                required_params=[],
                optional_params={"fragment_size": 64, "tls_record_split": True},
                aliases=[],
                category=AttackCategories.FRAGMENT,
            ),
        )
        logger.info("✅ Pre-registered tls_fragmentation alias for tls_fragmentation_combo")

        logger.info("Registered attack aliases")

    def _register_external_attacks_legacy(self) -> None:
        """LEGACY: автоматически обнаруживает и регистрирует внешние атаки (старый путь)."""
        attacks_dir = _ATTACKS_DIR

        if not attacks_dir.exists():
            logger.warning(f"Attacks directory {attacks_dir} does not exist")
            return

        # Only process .py files in the main attacks directory, not
        # subdirectories
        for module_file in attacks_dir.glob("*.py"):
            # Skip system files and non-attack modules
            excluded_files = [
                "attack_registry.py",
                "metadata.py",
                "base.py",
                "__init__.py",
                "real_effectiveness_tester.py",
                "simple_attack_executor.py",
                "alias_map.py",
                "attack_classifier.py",
                "attack_definition.py",
                "learning_memory.py",
                "multisplit_segment_fix.py",
                "proper_testing_methodology.py",
                "safe_result_utils.py",
                "segment_packet_builder.py",
                "timing_controller.py",
                "engine.py",
                "http_manipulation.py",  # Temporarily excluded due to syntax issues
            ]

            # Skip files that start with _ or are in the excluded list
            if module_file.name.startswith("_") or module_file.name in excluded_files:
                continue

            # Skip if it's actually a directory (shouldn't happen with *.py
            # glob, but just in case)
            if module_file.is_dir():
                continue

            try:
                module_name = f"core.bypass.attacks.{module_file.stem}"
                module = importlib.import_module(module_name)

                # Поиск классов атак
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if self._is_attack_class(obj):
                        self._register_attack_class(obj)

            except Exception as e:
                logger.warning(f"Failed to load attack module {module_file}: {e}")

        logger.info("Finished registering external attacks")

        # CRITICAL FIX: Register tls_fragmentation alias after external attacks are loaded
        # This ensures tls_fragmentation_combo is available before creating the alias
        if "tls_fragmentation_combo" in self.attacks and "tls_fragmentation" not in self.attacks:
            self.register_alias(
                alias="tls_fragmentation",
                canonical_attack="tls_fragmentation_combo",
                metadata=AttackMetadata(
                    name="tls_fragmentation",
                    description="TLS fragmentation attack (alias for tls_fragmentation_combo)",
                    required_params=[],
                    optional_params={"fragment_size": 64, "tls_record_split": True},
                    aliases=[],
                    category=AttackCategories.FRAGMENT,
                ),
            )
            logger.info("✅ Registered tls_fragmentation alias for tls_fragmentation_combo")

    def _is_attack_class(self, cls) -> bool:
        """Проверяет, является ли класс классом атаки."""
        return (
            hasattr(cls, "attack_type") and hasattr(cls, "execute") and hasattr(cls, "get_metadata")
        )

    def _register_attack_class(self, attack_class) -> None:
        """Регистрирует класс атаки."""
        try:
            instance = attack_class()
            attack_type = instance.attack_type
            metadata = instance.get_metadata()

            def handler(
                context: AttackContext,
            ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
                return instance.execute(context.payload, **context.params)

            result = self.register_attack(
                attack_type, handler, metadata, priority=RegistrationPriority.NORMAL
            )
            if result.success:
                logger.debug(f"Registered external attack class: {attack_class.__name__}")
            else:
                logger.debug(
                    f"Skipped external attack class {attack_class.__name__}: {result.message}"
                )

        except Exception as e:
            logger.error(f"Failed to register attack class {attack_class.__name__}: {e}")

    def validate_registry_integrity(self) -> Dict[str, Any]:
        """
        Проверяет целостность реестра и выявляет потенциальные конфликты.

        Проверки:
        1. Все алиасы указывают на существующие атаки
        2. Нет циклических ссылок в алиасах
        3. Все обработчики являются вызываемыми объектами
        4. Метаданные корректны
        5. Приоритеты соответствуют источникам

        Returns:
            Словарь с результатами проверки и найденными проблемами
        """
        validate_integrity = getattr(self.validator, "validate_registry_integrity", None)
        if callable(validate_integrity):
            return validate_integrity(self.attacks, self.alias_manager.get_alias_mapping())

        # Fallback integrity check if validator doesn't support it (e.g. AttackParameterValidator)
        issues: List[str] = []
        warnings: List[str] = []

        alias_mapping = self.alias_manager.get_alias_mapping()
        for alias, target in alias_mapping.items():
            if target not in self.attacks:
                issues.append(f"Alias '{alias}' points to non-existent attack '{target}'")
            elif alias == target:
                warnings.append(f"Alias '{alias}' points to itself")

        for attack_type, entry in self.attacks.items():
            if not callable(getattr(entry, "handler", None)):
                issues.append(f"Attack '{attack_type}' has non-callable handler")

        return {
            "is_valid": len(issues) == 0,
            "issues": issues,
            "warnings": warnings,
            "stats": {
                "total_attacks": len(self.attacks),
                "total_aliases": len(alias_mapping),
            },
            "timestamp": datetime.now().isoformat(),
        }

    def get_registration_conflicts(self) -> List[Dict[str, Any]]:
        """
        Возвращает список всех конфликтов регистрации из истории.

        Returns:
            Список конфликтов с подробной информацией
        """
        return self.registration_manager.get_registration_conflicts(self.attacks)

    def get_priority_statistics(self) -> Dict[str, Any]:
        """
        Возвращает статистику по приоритетам атак.

        Returns:
            Словарь со статистикой приоритетов
        """
        return self.registration_manager.get_priority_statistics(self.attacks)

    def promote_implementation(
        self,
        attack_type: str,
        new_handler: Callable,
        new_metadata: AttackMetadata,
        reason: str,
        performance_data: Optional[Dict[str, Any]] = None,
        require_confirmation: bool = True,
    ) -> RegistrationResult:
        """
        Продвигает новую реализацию атаки, заменяя существующую.

        Механизм продвижения позволяет заменить существующую реализацию атаки
        более эффективной версией с сохранением истории изменений.

        Args:
            attack_type: Тип атаки для продвижения
            new_handler: Новый обработчик атаки
            new_metadata: Новые метаданные
            reason: Обоснование продвижения
            performance_data: Данные о производительности, подтверждающие улучшение
            require_confirmation: Требовать подтверждения для CORE атак

        Returns:
            RegistrationResult с результатом продвижения
        """
        # Проверяем существование атаки
        if attack_type not in self.attacks:
            return RegistrationResult(
                success=False,
                action="failed",
                message=f"Cannot promote '{attack_type}': attack not found",
                attack_type=attack_type,
                conflicts=[f"Attack '{attack_type}' does not exist"],
            )

        existing_entry = self.attacks[attack_type]

        # Проверяем права на продвижение CORE атак
        if existing_entry.priority == RegistrationPriority.CORE and require_confirmation:
            logger.warning(
                f"Attempted promotion of CORE attack '{attack_type}' requires explicit confirmation"
            )
            return RegistrationResult(
                success=False,
                action="confirmation_required",
                message=(
                    f"Promotion of CORE attack '{attack_type}' requires explicit confirmation "
                    f"(set require_confirmation=False)"
                ),
                attack_type=attack_type,
                conflicts=["CORE attack promotion requires confirmation"],
            )

        # Валидируем новый обработчик
        if not callable(new_handler):
            return RegistrationResult(
                success=False,
                action="failed",
                message=f"Cannot promote '{attack_type}': new handler is not callable",
                attack_type=attack_type,
                conflicts=["New handler is not callable"],
            )

        # Создаем запись о продвижении
        promotion_info = {
            "timestamp": datetime.now().isoformat(),
            "action": "promoted",
            "old_priority": existing_entry.priority.name,
            "new_priority": existing_entry.priority.name,  # Приоритет остается тем же
            "old_source": existing_entry.source_module,
            "new_source": "promoted_implementation",
            "reason": reason,
            "performance_data": performance_data,
            "old_handler_name": getattr(existing_entry.handler, "__name__", "unknown"),
            "new_handler_name": getattr(new_handler, "__name__", "unknown"),
        }

        # Создаем новую запись с сохранением истории
        new_entry = AttackEntry(
            attack_type=attack_type,
            handler=new_handler,
            metadata=new_metadata,
            priority=existing_entry.priority,  # Сохраняем приоритет
            source_module="promoted_implementation",
            registration_time=datetime.now(),
            is_canonical=existing_entry.is_canonical,
            is_alias_of=existing_entry.is_alias_of,
            promotion_history=existing_entry.promotion_history + [promotion_info],
            performance_data=performance_data or existing_entry.performance_data,
        )

        # Заменяем запись
        self.attacks[attack_type] = new_entry

        logger.info(f"Promoted implementation of attack '{attack_type}': {reason}")
        if performance_data:
            logger.info(f"Performance data for '{attack_type}': {performance_data}")

        return RegistrationResult(
            success=True,
            action="promoted",
            message=f"Successfully promoted implementation of attack '{attack_type}': {reason}",
            attack_type=attack_type,
            conflicts=[],
            previous_priority=existing_entry.priority,
            new_priority=existing_entry.priority,
        )

    def get_promotion_history(self, attack_type: str) -> List[Dict[str, Any]]:
        """
        Возвращает историю продвижений для атаки.

        Args:
            attack_type: Тип атаки

        Returns:
            Список записей о продвижениях
        """
        resolved_type = self._resolve_attack_type(attack_type)

        if resolved_type not in self.attacks:
            return []

        return self.attacks[resolved_type].promotion_history.copy()

    def validate_promotion_request(
        self,
        attack_type: str,
        new_handler: Callable,
        performance_data: Optional[Dict[str, Any]] = None,
    ) -> ValidationResult:
        """
        Валидирует запрос на продвижение реализации.

        Args:
            attack_type: Тип атаки
            new_handler: Предлагаемый новый обработчик
            performance_data: Данные о производительности

        Returns:
            ValidationResult с результатом валидации
        """
        warnings = []

        # Проверяем существование атаки
        if attack_type not in self.attacks:
            return ValidationResult(
                is_valid=False, error_message=f"Attack '{attack_type}' not found"
            )

        existing_entry = self.attacks[attack_type]

        # Проверяем обработчик
        if not callable(new_handler):
            return ValidationResult(is_valid=False, error_message="New handler is not callable")

        # Предупреждения для CORE атак
        if existing_entry.priority == RegistrationPriority.CORE:
            warnings.append("Promoting CORE attack requires careful consideration")

        # Проверяем данные о производительности
        if not performance_data:
            warnings.append("No performance data provided to justify promotion")
        elif isinstance(performance_data, dict):
            required_metrics = ["improvement_percent", "test_cases", "success_rate"]
            missing_metrics = [m for m in required_metrics if m not in performance_data]
            if missing_metrics:
                warnings.append(f"Missing recommended performance metrics: {missing_metrics}")

        # Проверяем частоту продвижений
        if len(existing_entry.promotion_history) > 3:
            warnings.append("Attack has been promoted multiple times - consider stability")

        return ValidationResult(is_valid=True, warnings=warnings)

    def _discover_external_attacks(self) -> None:
        """
        Обнаруживает внешние атаки без их загрузки (для lazy loading).

        Быстро сканирует директории атак и сохраняет пути к модулям для последующей загрузки.
        Оптимизирован для минимального времени инициализации.
        """
        attacks_dir = _ATTACKS_DIR

        if not attacks_dir.exists():
            logger.warning(f"Attacks directory {attacks_dir} does not exist")
            return

        discovered_count = 0

        # Быстрое сканирование только имен файлов (без чтения содержимого)
        for module_file in attacks_dir.glob("*.py"):
            if module_file.name.startswith("_") or module_file.name in _EXCLUDED_ATTACK_FILES:
                continue

            if module_file.is_dir():
                continue

            # Предполагаем, что все остальные .py файлы могут содержать атаки
            # Это быстрее, чем читать каждый файл
            module_path = f"core.bypass.attacks.{module_file.stem}"
            module_key = self._normalize_attack_lookup_key(module_file.stem)
            self._unloaded_modules[module_key] = module_path
            discovered_count += 1

            logger.debug(f"Discovered potential attack module: {module_path}")

        logger.info(f"Discovered {discovered_count} potential attack modules for lazy loading")

    def _register_external_attacks(self) -> None:
        """
        Регистрирует внешние атаки из модулей (eager loading).

        Загружает все внешние модули атак и регистрирует найденные атаки.
        Используется когда lazy loading отключен.
        """
        from .registry.decorator import process_pending_registrations

        attacks_dir = _ATTACKS_DIR

        if not attacks_dir.exists():
            logger.warning(f"Attacks directory {attacks_dir} does not exist")
            return

        registered_count = 0

        # Scan subdirectories for attack modules
        for subdir in _ATTACK_SUBDIRS:
            subdir_path = attacks_dir / subdir
            if not subdir_path.exists() or not subdir_path.is_dir():
                continue

            logger.debug(f"Scanning {subdir} directory for attacks")

            for module_file in subdir_path.glob("*.py"):
                if module_file.name.startswith("_") or module_file.name in _EXCLUDED_ATTACK_FILES:
                    continue

                module_path = f"core.bypass.attacks.{subdir}.{module_file.stem}"

                try:
                    # Import the module - this will trigger @register_attack decorators
                    importlib.import_module(module_path)
                    self._loaded_modules.add(module_path)
                    logger.debug(f"Loaded external attack module: {module_path}")

                except Exception as e:
                    logger.warning(f"Failed to load attack module {module_path}: {e}")

        # Process any pending registrations from decorators
        registered_count = process_pending_registrations(self)

        if registered_count > 0:
            logger.info(f"Registered {registered_count} external attacks")

    def _load_module_on_demand(self, module_path: str) -> bool:
        """
        Загружает модуль по требованию и регистрирует найденные атаки.

        Args:
            module_path: Путь к модулю для загрузки

        Returns:
            True если модуль успешно загружен, False иначе
        """
        if module_path in self._loaded_modules:
            return True  # Уже загружен

        try:
            module = importlib.import_module(module_path)
            self._loaded_modules.add(module_path)

            # Ищем классы атак в загруженном модуле
            loaded_attacks = 0
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if self._is_attack_class(obj):
                    self._register_attack_class(obj)
                    loaded_attacks += 1

            # IMPORTANT: also process queued decorator registrations if module used
            # core.bypass.attacks.registry.decorator.register_attack
            try:
                from .registry.decorator import process_pending_registrations

                loaded_attacks += process_pending_registrations(self)
            except Exception as e:
                logger.debug(f"Skipping pending decorator registrations for {module_path}: {e}")

            logger.debug(f"Loaded module {module_path} with {loaded_attacks} attacks")
            return True

        except Exception as e:
            logger.warning(f"Failed to load attack module {module_path}: {e}")
            return False

    def _ensure_attack_loaded(self, attack_type: str) -> bool:
        """
        Гарантирует, что атака загружена (для lazy loading).

        Args:
            attack_type: Тип атаки для загрузки

        Returns:
            True если атака доступна, False иначе
        """
        # Если атака уже загружена, возвращаем True
        resolved_type = self._resolve_attack_type(attack_type)
        if resolved_type in self.attacks:
            return True

        # Если lazy loading отключен, атака недоступна
        if not self._lazy_loading:
            return False

        # Ищем модуль для загрузки с более эффективным поиском
        # Try both raw name and resolved canonical name for matching.
        normalized_raw = self._normalize_attack_lookup_key(attack_type)
        normalized_resolved = self._normalize_attack_lookup_key(
            self._resolve_attack_type(attack_type)
        )
        normalized_candidates = [k for k in {normalized_raw, normalized_resolved} if k]

        # Сначала пытаемся найти точное соответствие
        for key in normalized_candidates:
            module_path = self._unloaded_modules.get(key)
            if module_path:
                logger.debug(
                    f"Found exact match, loading module {module_path} for attack '{attack_type}'"
                )
                if (
                    self._load_module_on_demand(module_path)
                    and self._resolve_attack_type(attack_type) in self.attacks
                ):
                    return True

        # Затем пытаемся найти частичное соответствие
        for unloaded_key, module_path in self._unloaded_modules.items():
            for key in normalized_candidates:
                if key in unloaded_key or unloaded_key in key:
                    logger.debug(
                        f"Found partial match, loading module {module_path} for attack '{attack_type}'"
                    )
                    if (
                        self._load_module_on_demand(module_path)
                        and self._resolve_attack_type(attack_type) in self.attacks
                    ):
                        return True

        # Только в крайнем случае загружаем все модули (ограничиваем количество)
        remaining_modules = [
            path for path in self._unloaded_modules.values() if path not in self._loaded_modules
        ]

        # Ограничиваем количество модулей для загрузки в крайнем случае
        max_fallback_modules = min(5, len(remaining_modules))

        for module_path in remaining_modules[:max_fallback_modules]:
            logger.debug(f"Fallback loading module {module_path} for attack '{attack_type}'")
            if self._load_module_on_demand(module_path):
                if self._resolve_attack_type(attack_type) in self.attacks:
                    return True

        return False

    def get_lazy_loading_stats(self) -> Dict[str, Any]:
        """
        Возвращает статистику lazy loading.

        Returns:
            Словарь со статистикой загрузки модулей
        """
        return self.registration_manager.get_lazy_loading_stats(self.attacks)


# Глобальный экземпляр реестра (singleton pattern)
_global_registry = None
_lazy_loading_config = None  # Глобальная конфигурация lazy loading


def configure_lazy_loading(enabled: bool) -> None:
    """
    Конфигурирует глобальную настройку lazy loading для реестра атак.

    Эта функция должна быть вызвана до первого обращения к get_attack_registry()
    для применения настройки. Если реестр уже создан, настройка не применится.

    Args:
        enabled: True для включения lazy loading, False для eager loading

    Raises:
        RuntimeWarning: Если реестр уже инициализирован
    """
    global _lazy_loading_config

    if _global_registry is not None:
        logger.warning(
            "Attack registry already initialized. Lazy loading configuration will not take effect."
        )
        logger.warning(
            "Call configure_lazy_loading() before first use of get_attack_registry() or clear_registry() first."
        )
        return

    _lazy_loading_config = enabled
    logger.info(f"Configured lazy loading: {'enabled' if enabled else 'disabled'}")


def get_lazy_loading_config() -> Optional[bool]:
    """
    Возвращает текущую конфигурацию lazy loading.

    Returns:
        True если lazy loading включен, False если отключен, None если не настроен
    """
    return _lazy_loading_config


def get_attack_registry(lazy_loading: Optional[bool] = None) -> AttackRegistry:
    """
    Возвращает глобальный экземпляр AttackRegistry.

    Args:
        lazy_loading: Опциональная настройка lazy loading (только при первом создании).
                     Если не указано, используется глобальная конфигурация или False по умолчанию.

    Returns:
        Глобальный экземпляр AttackRegistry
    """
    global _global_registry, _lazy_loading_config

    # 1) builtins singleton first (handles double-import path issue)
    reg = getattr(builtins, _REGISTRY_BUILTIN_KEY, None)
    if reg is not None:
        _global_registry = reg
        return reg

    if _global_registry is None:
        # Определяем настройку lazy loading по приоритету:
        # 1. Параметр функции
        # 2. Глобальная конфигурация
        # 3. False по умолчанию
        if lazy_loading is not None:
            use_lazy_loading = lazy_loading
        elif _lazy_loading_config is not None:
            use_lazy_loading = _lazy_loading_config
        else:
            use_lazy_loading = False

        logger.debug(f"Creating attack registry with lazy_loading={use_lazy_loading}")
        _global_registry = AttackRegistry(lazy_loading=use_lazy_loading)
        try:
            setattr(builtins, _REGISTRY_BUILTIN_KEY, _global_registry)
        except Exception:
            pass

    return _global_registry


def register_attack(
    name: str = None,
    *,
    category: str = None,
    priority: RegistrationPriority = RegistrationPriority.NORMAL,
    required_params: List[str] = None,
    optional_params: Dict[str, Any] = None,
    aliases: List[str] = None,
    description: str = None,
    handler: Callable = None,
    metadata: AttackMetadata = None,
):
    """
    Enhanced attack registration decorator with full metadata support.

    Can be used as:
    1. Function: register_attack(name, handler=handler, metadata=metadata)
    2. Decorator with full metadata: @register_attack(name="attack_name", category=AttackCategories.TCP, ...)
    3. Simple decorator: @register_attack("attack_name")
    4. Parameterless decorator: @register_attack (uses class name)

    Args:
        name: Attack name (if None, uses class name or method name)
        category: Attack category from AttackCategories
        priority: Registration priority for conflict resolution
        required_params: List of required parameter names
        optional_params: Dict of optional parameters with default values
        aliases: List of alternative names for the attack
        description: Human-readable description (if None, uses docstring)
        handler: Attack handler function (for functional usage)
        metadata: Complete AttackMetadata object (for functional usage)

    Examples:
        @register_attack(
            name="advanced_split",
            category=AttackCategories.SPLIT,
            priority=RegistrationPriority.HIGH,
            required_params=["split_pos"],
            optional_params={"ttl": 3, "fooling": ["badsum"]},
            aliases=["adv_split", "enhanced_split"]
        )
        class AdvancedSplitAttack(BaseAttack):
            pass

        @register_attack("simple_attack")
        class SimpleAttack(BaseAttack):
            pass

        @register_attack
        class AutoNamedAttack(BaseAttack):
            pass
    """

    def decorator(attack_class_or_func):
        """Enhanced decorator for registering attack classes or functions."""
        try:
            # Determine if this is a class or function
            is_class = inspect.isclass(attack_class_or_func)

            if is_class:
                # Handle class registration
                return _register_attack_class(
                    attack_class_or_func,
                    name,
                    category,
                    priority,
                    required_params,
                    optional_params,
                    aliases,
                    description,
                )
            else:
                # Handle function registration
                return _register_attack_function(
                    attack_class_or_func,
                    name,
                    category,
                    priority,
                    required_params,
                    optional_params,
                    aliases,
                    description,
                )

        except Exception as e:
            logger.error(f"Failed to register attack {attack_class_or_func}: {e}")
            return attack_class_or_func

    # Handle different usage patterns
    if handler is not None and metadata is not None:
        # Functional usage: register_attack(name, handler=handler, metadata=metadata)
        registry = get_attack_registry()
        return registry.register_attack(name, handler, metadata, priority)

    elif name is None:
        # Used as @register_attack (parameterless)
        return decorator

    elif callable(name):
        # Used as @register_attack without parentheses on a class/function
        attack_class_or_func = name
        name = None  # Will be auto-determined
        return decorator(attack_class_or_func)

    else:
        # Used as @register_attack("name") or @register_attack(name="name", ...)
        return decorator


def _register_attack_class(
    attack_class,
    name: str = None,
    category: str = None,
    priority: RegistrationPriority = RegistrationPriority.NORMAL,
    required_params: List[str] = None,
    optional_params: Dict[str, Any] = None,
    aliases: List[str] = None,
    description: str = None,
) -> type:
    """Register an attack class with enhanced metadata extraction."""

    # IMPORTANT: Do NOT call __init__ for metadata extraction.
    # Some attacks import heavy modules or create circular imports in __init__.
    # We'll try a shallow instance via __new__ (no __init__) only for lightweight property reads.
    instance = None
    try:
        instance = attack_class.__new__(attack_class)
    except Exception:
        instance = None

    # Determine attack name
    attack_name = name
    if not attack_name:
        # Try instance.name (property) without requiring __init__
        try:
            candidate = getattr(instance, "name", None) if instance is not None else None
        except Exception:
            candidate = None
        if candidate:
            attack_name = candidate
        else:
            # Convert class name to snake_case
            attack_name = _class_name_to_snake_case(attack_class.__name__)

    # Extract metadata from class and instance
    extracted_metadata = _extract_class_metadata(attack_class, instance)

    # Build final metadata, prioritizing decorator parameters
    final_metadata = AttackMetadata(
        name=attack_name.replace("_", " ").title(),
        description=description
        or extracted_metadata.get("description")
        or attack_class.__doc__
        or f"Attack: {attack_name}",
        required_params=required_params or extracted_metadata.get("required_params", []),
        optional_params=optional_params or extracted_metadata.get("optional_params", {}),
        aliases=aliases or extracted_metadata.get("aliases", []),
        category=category or extracted_metadata.get("category", AttackCategories.CUSTOM),
    )

    # Validate category
    if final_metadata.category not in AttackCategories.ALL:
        logger.warning(
            f"Invalid category '{final_metadata.category}' for {attack_name}, using CUSTOM"
        )
        final_metadata.category = AttackCategories.CUSTOM

    # Create attack handler
    def attack_handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Enhanced attack handler with proper context handling and async support."""
        try:
            attack_instance = attack_class()
            result = attack_instance.execute(context)

            # Check if result is a coroutine (async method)
            if inspect.iscoroutine(result):
                # Run async method synchronously
                import asyncio

                try:
                    # If we're already inside a running loop in this thread, we cannot safely block here.
                    try:
                        running_loop = asyncio.get_running_loop()
                    except RuntimeError:
                        running_loop = None
                    if running_loop is not None and running_loop.is_running():
                        logger.debug(
                            f"Async attack '{attack_name}' executed in a running event loop; "
                            f"cannot block synchronously. Falling back to original payload."
                        )
                        return [(context.payload, 0, {})]

                    # Prefer asyncio.run when available (creates/cleans loop reliably)
                    run_fn = getattr(asyncio, "run", None)
                    if callable(run_fn):
                        result = run_fn(result)
                    else:  # pragma: no cover (very old Python)
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        try:
                            result = loop.run_until_complete(result)
                        finally:
                            loop.close()

                except Exception as e:
                    logger.error(f"Attack handler execution failed for {attack_name}: {e}")
                    import traceback

                    logger.debug(f"Stack trace: {traceback.format_exc()}")
                    return [(context.payload, 0, {})]

            # Convert AttackResult to segments format if needed
            if hasattr(result, "segments") and result.segments:
                # ✅ Validate segments format before returning
                segments = result.segments
                if not isinstance(segments, list):
                    logger.error(
                        f"Attack {attack_name} returned segments that is not a list: {type(segments)}"
                    )
                    return [(context.payload, 0, {})]

                # Validate each segment
                valid_segments = []
                for i, segment in enumerate(segments):
                    if isinstance(segment, tuple) and len(segment) == 3:
                        payload_data, seq_offset, options_dict = segment
                        if (
                            isinstance(payload_data, bytes)
                            and isinstance(seq_offset, int)
                            and isinstance(options_dict, dict)
                        ):
                            valid_segments.append(segment)
                        else:
                            logger.warning(
                                f"Attack {attack_name} segment {i} has invalid types, skipping"
                            )
                    else:
                        logger.warning(
                            f"Attack {attack_name} segment {i} is not a valid tuple (payload, offset, options), skipping"
                        )

                if valid_segments:
                    return valid_segments
                else:
                    logger.error(f"Attack {attack_name} returned no valid segments, using fallback")
                    return [(context.payload, 0, {})]

            elif hasattr(result, "modified_payload") and result.modified_payload:
                return [(result.modified_payload, 0, {})]
            else:
                # Fallback: return original payload
                return [(context.payload, 0, {})]

        except Exception as e:
            logger.error(f"Attack handler execution failed for {attack_name}: {e}")
            import traceback

            logger.debug(f"Stack trace: {traceback.format_exc()}")
            return [(context.payload, 0, {})]

    # Register with registry
    registry = get_attack_registry()
    result = registry.register_attack(attack_name, attack_handler, final_metadata, priority)

    if result.success:
        logger.debug(
            f"Registered attack class: {attack_class.__name__} as '{attack_name}' with priority {priority.name}"
        )
    else:
        logger.debug(f"Skipped attack class {attack_class.__name__}: {result.message}")

    # Store registration info on class for introspection
    attack_class._attack_registry_info = {
        "name": attack_name,
        "metadata": final_metadata,
        "priority": priority,
        "registration_result": result,
    }

    return attack_class


def _register_attack_function(
    attack_func,
    name: str = None,
    category: str = None,
    priority: RegistrationPriority = RegistrationPriority.NORMAL,
    required_params: List[str] = None,
    optional_params: Dict[str, Any] = None,
    aliases: List[str] = None,
    description: str = None,
):
    """Register an attack function with metadata."""

    # Determine attack name
    attack_name = name or attack_func.__name__

    # Extract metadata from function
    extracted_metadata = _extract_function_metadata(attack_func)

    # Build final metadata
    final_metadata = AttackMetadata(
        name=attack_name.replace("_", " ").title(),
        description=description
        or extracted_metadata.get("description")
        or attack_func.__doc__
        or f"Attack: {attack_name}",
        required_params=required_params or extracted_metadata.get("required_params", []),
        optional_params=optional_params or extracted_metadata.get("optional_params", {}),
        aliases=aliases or extracted_metadata.get("aliases", []),
        category=category or extracted_metadata.get("category", AttackCategories.CUSTOM),
    )

    # Validate category
    if final_metadata.category not in AttackCategories.ALL:
        logger.warning(
            f"Invalid category '{final_metadata.category}' for {attack_name}, using CUSTOM"
        )
        final_metadata.category = AttackCategories.CUSTOM

    # Create wrapper handler
    def attack_handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Function-based attack handler."""
        try:
            # Call the function with appropriate parameters
            sig = inspect.signature(attack_func)
            if "context" in sig.parameters:
                result = attack_func(context)
            else:
                # Legacy function signature
                result = attack_func(context.payload, **context.params)

            # Handle different return types
            if isinstance(result, list) and all(
                isinstance(item, tuple) and len(item) == 3 for item in result
            ):
                return result  # Already in segments format
            elif isinstance(result, bytes):
                return [(result, 0, {})]
            else:
                return [(context.payload, 0, {})]

        except Exception as e:
            logger.error(f"Function attack handler execution failed for {attack_name}: {e}")
            return [(context.payload, 0, {})]

    # Register with registry
    registry = get_attack_registry()
    result = registry.register_attack(attack_name, attack_handler, final_metadata, priority)

    if result.success:
        logger.debug(
            f"Registered attack function: {attack_func.__name__} as '{attack_name}' with priority {priority.name}"
        )
    else:
        logger.debug(f"Skipped attack function {attack_func.__name__}: {result.message}")

    # Store registration info on function for introspection
    attack_func._attack_registry_info = {
        "name": attack_name,
        "metadata": final_metadata,
        "priority": priority,
        "registration_result": result,
    }

    return attack_func


def _extract_class_metadata(attack_class, instance=None) -> Dict[str, Any]:
    """Extract metadata from attack class and instance."""
    metadata = {}

    def _safe_get(source, attr, default=None):
        try:
            return getattr(source, attr)
        except Exception:
            return default

    # Try to get metadata from instance first, then class
    sources = [instance, attack_class] if instance else [attack_class]

    for source in sources:
        if source is None:
            continue

        # Extract required_params - handle both list and non-list formats
        if not metadata.get("required_params"):
            required_params = _safe_get(source, "required_params", [])
            # Ensure it's a list
            if not isinstance(required_params, list):
                required_params = []
            metadata["required_params"] = required_params

        # Extract optional_params - ensure it's a dict
        if not metadata.get("optional_params"):
            optional_params = _safe_get(source, "optional_params", {})
            # Ensure it's a dict
            if not isinstance(optional_params, dict):
                optional_params = {}
            metadata["optional_params"] = optional_params

        # Extract aliases - ensure it's a list
        if not metadata.get("aliases"):
            aliases = _safe_get(source, "aliases", [])
            # Ensure it's a list
            if not isinstance(aliases, list):
                aliases = []
            metadata["aliases"] = aliases

        # Extract category
        if not metadata.get("category"):
            category = _safe_get(source, "category", None)
            if isinstance(category, str) and category in AttackCategories.ALL:
                metadata["category"] = category

        # Extract description
        if not metadata.get("description"):
            description = _safe_get(source, "description", None)
            if isinstance(description, str):
                metadata["description"] = description
        # Fallback to docstring if still missing
        if not metadata.get("description") and hasattr(source, "__doc__") and source.__doc__:
            metadata["description"] = source.__doc__.strip()

    # Set defaults for missing metadata
    if "required_params" not in metadata:
        metadata["required_params"] = []
    if "optional_params" not in metadata:
        metadata["optional_params"] = {}
    if "aliases" not in metadata:
        metadata["aliases"] = []
    if "category" not in metadata:
        metadata["category"] = AttackCategories.CUSTOM

    return metadata


def _extract_function_metadata(attack_func) -> Dict[str, Any]:
    """Extract metadata from attack function."""
    metadata = {}

    # Extract from function attributes
    if hasattr(attack_func, "required_params"):
        metadata["required_params"] = attack_func.required_params

    if hasattr(attack_func, "optional_params"):
        metadata["optional_params"] = attack_func.optional_params

    if hasattr(attack_func, "aliases"):
        metadata["aliases"] = attack_func.aliases

    if hasattr(attack_func, "category"):
        category = attack_func.category
        if category in AttackCategories.ALL:
            metadata["category"] = category

    # Extract from docstring
    if attack_func.__doc__:
        metadata["description"] = attack_func.__doc__.strip()

    return metadata


def _class_name_to_snake_case(class_name: str) -> str:
    """Convert CamelCase class name to snake_case."""

    # Remove 'Attack' suffix if present
    if class_name.endswith("Attack"):
        class_name = class_name[:-6]

    # Convert CamelCase to snake_case
    s1 = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", class_name)
    return re.sub("([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


def get_attack_handler(attack_type: str) -> Optional[Callable]:
    """
    Удобная функция для получения обработчика атаки из глобального реестра.

    Args:
        attack_type: Тип атаки

    Returns:
        Обработчик атаки или None
    """
    registry = get_attack_registry()
    return registry.get_attack_handler(attack_type)


def validate_attack_parameters(attack_type: str, params: Dict[str, Any]) -> ValidationResult:
    """
    Удобная функция для валидации параметров атаки.

    Args:
        attack_type: Тип атаки
        params: Параметры для валидации

    Returns:
        Результат валидации
    """
    registry = get_attack_registry()
    return registry.validate_parameters(attack_type, params)


def list_attacks(category: Optional[str] = None, enabled_only: bool = False) -> List[str]:
    """
    Удобная функция для получения списка атак из глобального реестра.

    Args:
        category: Опциональная категория для фильтрации
        enabled_only: Фильтровать только включенные атаки (для совместимости)

    Returns:
        Список имен атак
    """
    registry = get_attack_registry()
    return registry.list_attacks(category, enabled_only)


def get_attack_metadata(attack_type: str) -> Optional[AttackMetadata]:
    """
    Удобная функция для получения метаданных атаки из глобального реестра.

    Args:
        attack_type: Тип атаки

    Returns:
        Метаданные атаки или None если не найдена
    """
    registry = get_attack_registry()
    return registry.get_attack_metadata(attack_type)


def clear_registry(clear_config: bool = False):
    """
    Очищает глобальный реестр атак.

    Args:
        clear_config: Если True, также очищает конфигурацию lazy loading

    Используется в основном для тестирования.
    """
    global _global_registry, _lazy_loading_config
    _global_registry = None
    try:
        if getattr(builtins, _REGISTRY_BUILTIN_KEY, None) is not None:
            delattr(builtins, _REGISTRY_BUILTIN_KEY)
    except Exception:
        pass

    if clear_config:
        _lazy_loading_config = None
        logger.debug("Cleared attack registry and lazy loading configuration")
