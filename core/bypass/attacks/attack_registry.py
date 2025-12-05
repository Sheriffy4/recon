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
        self._aliases: Dict[str, str] = {}
        self._registration_order: List[str] = []
        self._lazy_loading = lazy_loading
        # {attack_type: module_path}
        self._unloaded_modules: Dict[str, str] = {}
        self._loaded_modules: set = set()  # Кэш загруженных модулей

        # Регистрируем встроенные атаки (всегда eager)
        self._register_builtin_attacks()

        # Автоматически обнаруживаем внешние атаки
        if lazy_loading:
            self._discover_external_attacks()
        else:
            self._register_external_attacks()

        logger.info(
            f"AttackRegistry initialized with {len(self.attacks)} attacks (lazy_loading={lazy_loading})"
        )

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
            return self._handle_duplicate_registration(
                attack_type, handler, metadata, priority, source_module, existing_entry
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

        # Регистрируем алиасы
        conflicts = []
        for alias in metadata.aliases:
            if alias in self._aliases:
                conflicts.append(
                    f"Alias '{alias}' already exists for '{
                        self._aliases[alias]}'"
                )
                logger.warning(
                    f"Alias '{alias}' already exists for '{
                        self._aliases[alias]}', overwriting with '{attack_type}'"
                )
            self._aliases[alias] = attack_type

        logger.info(
            f"Registered attack '{attack_type}' with priority {
                priority.name} from {source_module}"
        )
        if len(metadata.aliases) > 0:
            logger.debug(
                f"Registered {len(metadata.aliases)} aliases for '{attack_type}': {metadata.aliases}"
            )

        return RegistrationResult(
            success=True,
            action="registered",
            message=f"Successfully registered attack '{attack_type}' with priority {
                priority.name}",
            attack_type=attack_type,
            conflicts=conflicts,
            new_priority=priority,
        )

    def _handle_duplicate_registration(
        self,
        attack_type: str,
        handler: Callable,
        metadata: AttackMetadata,
        priority: RegistrationPriority,
        source_module: str,
        existing_entry: AttackEntry,
    ) -> RegistrationResult:
        """
        Обрабатывает дублирующуюся регистрацию атаки на основе приоритетов.

        Логика разрешения конфликтов:
        1. Если новый приоритет выше - заменяем существующую атаку
        2. Если приоритеты равны - пропускаем с предупреждением
        3. Если новый приоритет ниже - пропускаем с информационным сообщением

        Args:
            attack_type: Тип атаки
            handler: Новый обработчик
            metadata: Новые метаданные
            priority: Новый приоритет
            source_module: Модуль-источник новой атаки
            existing_entry: Существующая запись в реестре

        Returns:
            RegistrationResult с результатом обработки дубликата
        """
        existing_priority = existing_entry.priority

        if priority.value > existing_priority.value:
            # Новый приоритет выше - заменяем
            logger.info(
                f"Replacing attack '{attack_type}' (priority {
                    existing_priority.name} -> {
                    priority.name}) from {source_module}"
            )

            # Сохраняем информацию о замене в истории
            promotion_info = {
                "timestamp": datetime.now().isoformat(),
                "action": "replaced_by_higher_priority",
                "old_priority": existing_priority.name,
                "new_priority": priority.name,
                "old_source": existing_entry.source_module,
                "new_source": source_module,
                "reason": f"Higher priority registration ({
                    priority.name} > {
                    existing_priority.name})",
            }

            # Создаем новую запись
            new_entry = AttackEntry(
                attack_type=attack_type,
                handler=handler,
                metadata=metadata,
                priority=priority,
                source_module=source_module,
                registration_time=datetime.now(),
                is_canonical=True,
                promotion_history=existing_entry.promotion_history + [promotion_info],
                performance_data=existing_entry.performance_data or {},
            )

            self.attacks[attack_type] = new_entry

            # Обновляем алиасы
            conflicts = []
            for alias in metadata.aliases:
                if alias in self._aliases and self._aliases[alias] != attack_type:
                    conflicts.append(
                        f"Alias '{alias}' reassigned from '{
                            self._aliases[alias]}' to '{attack_type}'"
                    )
                self._aliases[alias] = attack_type

            return RegistrationResult(
                success=True,
                action="replaced",
                message=f"Replaced attack '{attack_type}' with higher priority version ({
                    priority.name} > {
                    existing_priority.name})",
                attack_type=attack_type,
                conflicts=conflicts,
                previous_priority=existing_priority,
                new_priority=priority,
            )

        elif priority.value == existing_priority.value:
            # Одинаковый приоритет - пропускаем с предупреждением
            logger.warning(
                f"Skipping duplicate registration of '{attack_type}' with same priority {
                    priority.name} from {source_module}"
            )

            return RegistrationResult(
                success=False,
                action="skipped",
                message=f"Skipped duplicate attack '{attack_type}' (same priority {
                    priority.name})",
                attack_type=attack_type,
                conflicts=[
                    f"Attack already registered with same priority from {
                        existing_entry.source_module}"
                ],
                previous_priority=existing_priority,
                new_priority=priority,
            )

        else:
            # Новый приоритет ниже - пропускаем
            logger.debug(
                f"Skipping registration of '{attack_type}' with lower priority {
                    priority.name} from {source_module}"
            )

            return RegistrationResult(
                success=False,
                action="skipped",
                message=f"Skipped attack '{attack_type}' (lower priority {
                    priority.name} < {
                    existing_priority.name})",
                attack_type=attack_type,
                conflicts=[
                    f"Existing attack has higher priority ({
                        existing_priority.name})"
                ],
                previous_priority=existing_priority,
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
                logger.error(
                    f"Attack type '{attack_type}' not found after lazy loading"
                )
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

    def validate_parameters(
        self, attack_type: str, params: Dict[str, Any]
    ) -> ValidationResult:
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

        # Проверяем обязательные параметры
        for required_param in metadata.required_params:
            if required_param not in params:
                return ValidationResult(
                    is_valid=False,
                    error_message=f"Missing required parameter '{required_param}' for attack '{attack_type}'",
                )

        # Валидируем значения параметров
        return self._validate_parameter_values(attack_type, params, metadata)

    def list_attacks(
        self, category: Optional[str] = None, enabled_only: bool = False
    ) -> List[str]:
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
            
        return self._aliases.get(normalized_type, normalized_type)

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
            self._create_fakeddisorder_handler(),
            AttackMetadata(
                name="Fake Disorder",
                description="Отправляет фейковый пакет с низким TTL, затем реальные части в обратном порядке",
                required_params=[],
                optional_params={
                    "split_pos": 3,
                    "ttl": 3,
                    "fake_ttl": 3,
                    "fooling": ["badsum"],
                    # Не добавляем fooling_methods по умолчанию - это дубликат fooling
                    "fake_sni": None,
                    "fake_data": None,
                    "custom_sni": None,  # Add custom_sni parameter support
                },
                aliases=["fake_disorder", "fakedisorder", "force_tcp", "filter-udp", "filter_udp"],
                category=AttackCategories.FAKE,
            ),
            priority=RegistrationPriority.CORE,
        )

        # seqovl - sequence overlap атака
        self.register_attack(
            "seqovl",
            self._create_seqovl_handler(),
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
            self._create_multidisorder_handler(),
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
            self._create_primitives_handler("apply_disorder"),
            AttackMetadata(
                name="Simple Disorder",
                description="Разделяет пакет на две части и отправляет в обратном порядке",
                required_params=[],  # Make split_pos optional with default
                optional_params={"split_pos": 3, "ack_first": False},  # Default split_pos=3
                aliases=["simple_disorder"],
                category=AttackCategories.DISORDER,
            ),
            priority=RegistrationPriority.CORE,
        )

        # disorder2 - disorder с ack_first=True
        self.register_attack(
            "disorder2",
            self._create_disorder2_handler(),
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
            self._create_multisplit_handler(),
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
            self._create_split_handler(),
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
            self._create_fake_handler(),
            AttackMetadata(
                name="Fake Packet Race",
                description="Отправляет фейковый пакет с низким TTL перед реальным",
                required_params=[],
                optional_params={
                    "ttl": 3, 
                    "fooling": ["badsum"], 
                    "fake_data": None,
                    "custom_sni": None,  # Add custom_sni parameter support
                },
                aliases=["fake_race", "race"],
                category=AttackCategories.RACE,
            ),
            priority=RegistrationPriority.CORE,
        )

        # TCP window manipulation - migrated from tcp_fragmentation.py
        self.register_attack(
            "window_manipulation",
            self._create_window_manipulation_handler(),
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
            self._create_tcp_options_handler(),
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
            self._create_advanced_timing_handler(),
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
                category=AttackCategories.SPLIT
            )
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
                category=AttackCategories.DISORDER
            )
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
                category=AttackCategories.DISORDER
            )
        )
        
        logger.info("Registered attack aliases")

    def _create_primitives_handler(self, method_name: str) -> Callable:
        """Создает обработчик для метода из primitives.py."""

        def handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            from ..techniques.primitives import BypassTechniques

            techniques = BypassTechniques()
            method = getattr(techniques, method_name)

            # Фильтруем параметры в соответствии с сигнатурой метода
            import inspect

            sig = inspect.signature(method)
            filtered_params = {}

            for param_name, param in sig.parameters.items():
                if param_name in [
                    "payload"
                ]:  # Пропускаем payload, он передается отдельно
                    continue
                if param_name in context.params:
                    filtered_params[param_name] = context.params[param_name]
                elif param.default != inspect.Parameter.empty:
                    # Параметр имеет значение по умолчанию, не добавляем его
                    continue

            return method(context.payload, **filtered_params)

        return handler

    def _create_disorder2_handler(self) -> Callable:
        """Создает специальный обработчик для disorder2."""

        def handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            from ..techniques.primitives import BypassTechniques

            techniques = BypassTechniques()
            split_pos = context.params.get("split_pos", 3)
            return techniques.apply_disorder(context.payload, split_pos, ack_first=True)

        return handler

    def _create_split_handler(self) -> Callable:
        """Создает обработчик для простого split (конвертирует в multisplit)."""

        def handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            from ..techniques.primitives import BypassTechniques

            techniques = BypassTechniques()
            split_pos = context.params.get("split_pos", 3)

            # Фильтруем параметры для multisplit
            filtered_params = {}
            if "fooling" in context.params:
                filtered_params["fooling"] = context.params["fooling"]

            return techniques.apply_multisplit(
                context.payload, positions=[split_pos], **filtered_params
            )

        return handler

    def _create_seqovl_handler(self) -> Callable:
        """Создает специальный обработчик для seqovl с правильными параметрами."""

        def handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            from ..techniques.primitives import BypassTechniques

            techniques = BypassTechniques()

            split_pos = context.params.get("split_pos", 3)
            overlap_size = context.params.get("overlap_size", 1)

            # Конвертируем параметры в правильный формат
            fake_ttl = context.params.get("fake_ttl", context.params.get("ttl", 3))
            fooling_methods = context.params.get(
                "fooling_methods", context.params.get("fooling", ["badsum"])
            )

            # Pass resolved custom SNI to the primitives method
            kwargs = {}
            if "resolved_custom_sni" in context.params:
                kwargs["resolved_custom_sni"] = context.params["resolved_custom_sni"]
            
            return techniques.apply_seqovl(
                context.payload, split_pos, overlap_size, fake_ttl, fooling_methods, **kwargs
            )

        return handler

    def _create_fake_handler(self) -> Callable:
        """Создает специальный обработчик для fake с правильными параметрами."""

        def handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            from ..techniques.primitives import BypassTechniques

            techniques = BypassTechniques()

            # Конвертируем параметры в правильный формат
            ttl = context.params.get("ttl", context.params.get("fake_ttl", 3))
            fooling = context.params.get(
                "fooling", context.params.get("fooling_methods", ["badsum"])
            )
            
            # Pass through resolved_custom_sni if available
            kwargs = {}
            if "resolved_custom_sni" in context.params:
                kwargs["resolved_custom_sni"] = context.params["resolved_custom_sni"]

            return techniques.apply_fake_packet_race(context.payload, ttl, fooling, **kwargs)

        return handler

    def _generate_positions(
        self,
        split_pos: any,
        split_count: any,
        payload_len: int
    ) -> List[int]:
        """
        Standardized position generation for multisplit attacks.
        
        This method ensures consistent position generation between testing and production modes.
        
        Algorithm:
        1. If positions explicitly provided, use them
        2. If split_pos AND split_count provided, generate positions starting from split_pos
        3. If only split_pos provided, use single position
        4. If only split_count provided, distribute evenly across payload
        5. Default: middle of payload
        
        Position generation formula (when both split_pos and split_count are provided):
        - Start at split_pos
        - Generate split_count positions with fixed gap of 6 bytes
        - positions = [split_pos, split_pos+6, split_pos+12, ..., split_pos+(split_count-1)*6]
        
        Args:
            split_pos: Starting position for splits (int or str)
            split_count: Number of split positions to generate (int or str)
            payload_len: Length of payload for validation
            
        Returns:
            List of integer positions, validated to be within payload bounds
            
        Examples:
            >>> _generate_positions(3, 8, 100)
            [3, 9, 15, 21, 27, 33, 39, 45]
            
            >>> _generate_positions(5, None, 100)
            [5]
            
            >>> _generate_positions(None, 4, 100)
            [25, 50, 75]
        """
        # REQUIREMENT 5.1: Log position generation parameters
        logger.info(
            f"🔢 Generating positions: split_pos={split_pos}, split_count={split_count}, payload_len={payload_len}"
        )
        
        # Case 1: Both split_pos AND split_count provided
        if split_pos is not None and split_count is not None:
            # Convert split_pos to int if string
            if isinstance(split_pos, str):
                try:
                    split_pos = int(split_pos)
                except ValueError:
                    logger.warning(f"Invalid split_pos string '{split_pos}', using default 3")
                    split_pos = 3
            
            # Validate and clamp split_pos
            base_pos = max(1, min(int(split_pos), payload_len - 1))
            count = max(1, int(split_count))
            
            # Calculate step size to distribute positions evenly across payload
            # This creates equal-sized segments like Case 3
            remaining_payload = payload_len - base_pos
            step = max(1, remaining_payload // count)
            
            positions = []
            for i in range(count - 1):  # count-1 because we need count segments, not count positions
                pos = base_pos + (i * step)
                if pos < payload_len:
                    positions.append(pos)
            
            # Ensure we have at least one position
            if not positions:
                positions = [base_pos]
            
            # REQUIREMENT 5.4: Log generated positions for debugging
            logger.info(
                f"✅ Generated {len(positions)} positions from split_pos={split_pos}, "
                f"split_count={split_count}: {positions}"
            )
            
            return positions
        
        # Case 2: Only split_pos provided
        elif split_pos is not None:
            if isinstance(split_pos, str):
                try:
                    split_pos = int(split_pos)
                except ValueError:
                    logger.warning(f"Invalid split_pos string '{split_pos}', using middle")
                    split_pos = payload_len // 2
            
            base_pos = max(1, min(int(split_pos), payload_len - 1))
            positions = [base_pos]
            
            logger.info(f"✅ Single position from split_pos={split_pos}: {positions}")
            return positions
        
        # Case 3: Only split_count provided
        elif split_count is not None:
            count = max(1, int(split_count))
            
            if count == 1:
                positions = [payload_len // 2]
            else:
                # Distribute evenly across payload
                step = payload_len // count
                positions = [
                    i * step
                    for i in range(1, count)
                    if i * step < payload_len
                ]
                
                # Ensure we have at least one position
                if not positions:
                    positions = [payload_len // 2]
            
            logger.info(
                f"✅ Generated {len(positions)} positions from split_count={split_count}: {positions}"
            )
            return positions
        
        # Case 4: No parameters provided - use default
        else:
            positions = [payload_len // 2]
            logger.info(f"✅ Using default position (middle): {positions}")
            return positions

    def _create_multisplit_handler(self) -> Callable:
        """Создает специальный обработчик для multisplit с правильными параметрами."""

        def handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            from ..techniques.primitives import BypassTechniques

            techniques = BypassTechniques()

            # REQUIREMENT 5.1: Log complete strategy parameters
            logger.info(f"📋 Multisplit handler called with params: {context.params}")

            # CRITICAL FIX: Always use split_count if provided, even if positions exists
            # This fixes the issue where split_pos=2 is converted to positions=[2] and split_count is ignored
            split_pos = context.params.get("split_pos")
            split_count = context.params.get("split_count")
            
            # REQUIREMENT 5.2: Use standardized position generation
            if split_count is not None:
                # If split_count is provided, always generate positions from it
                # This takes priority over any pre-set positions parameter
                logger.info(f"🔧 Using split_count={split_count} to generate positions (ignoring pre-set positions if any)")
                positions = self._generate_positions(split_pos, split_count, len(context.payload))
            else:
                # No split_count, check if positions are explicitly provided
                positions = context.params.get("positions")
                
                if not positions:
                    # No positions and no split_count, generate from split_pos only
                    positions = self._generate_positions(split_pos, None, len(context.payload))
                else:
                    # REQUIREMENT 5.3: Validate explicitly provided positions
                    logger.info(f"📋 Using explicit positions: {positions}")
                    
                    # Validate positions are within bounds
                    valid_positions = [p for p in positions if isinstance(p, int) and 0 < p < len(context.payload)]
                    
                    if len(valid_positions) != len(positions):
                        logger.warning(
                            f"⚠️ Filtered invalid positions: {len(positions)} → {len(valid_positions)}"
                        )
                    
                    positions = valid_positions if valid_positions else [len(context.payload) // 2]

            # REQUIREMENT 5.3: Validate final positions
            if not positions:
                logger.error("❌ No valid positions generated, using default")
                positions = [len(context.payload) // 2]
            
            # REQUIREMENT 5.4: Log final positions being used
            logger.info(f"🎯 Final positions for multisplit: {positions}")

            # Get fooling parameter
            fooling = context.params.get("fooling")

            return techniques.apply_multisplit(context.payload, positions, fooling)

        return handler

    def _create_fakeddisorder_handler(self) -> Callable:
        """Создает специальный обработчик для fakeddisorder с правильными параметрами."""

        def handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            from ..techniques.primitives import BypassTechniques

            techniques = BypassTechniques()

            # Обрабатываем split_pos - может быть int, str или list
            split_pos = context.params.get("split_pos")
            if isinstance(split_pos, list):
                if len(split_pos) == 0:
                    split_pos = len(context.payload) // 2
                else:
                    split_pos = split_pos[0]
                logger.debug(f"Converted split_pos list to single value: {split_pos}")
            elif split_pos is None:
                split_pos = len(context.payload) // 2

            # Обрабатываем TTL параметры
            fake_ttl = context.params.get("fake_ttl", context.params.get("ttl", 3))

            # Обрабатываем fooling методы
            fooling_methods = context.params.get(
                "fooling_methods", context.params.get("fooling", ["badsum"])
            )

            # Фильтруем только поддерживаемые параметры для apply_fakeddisorder
            filtered_params = {
                "split_pos": split_pos,
                "fake_ttl": fake_ttl,
                "fooling_methods": fooling_methods,
            }

            # Pass resolved custom SNI to the primitives method
            if "resolved_custom_sni" in context.params:
                filtered_params["resolved_custom_sni"] = context.params["resolved_custom_sni"]
            
            return techniques.apply_fakeddisorder(context.payload, **filtered_params)

        return handler

    def _create_multidisorder_handler(self) -> Callable:
        """Создает специальный обработчик для multidisorder с правильными параметрами."""

        def handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            logger.info(f"🔍 multidisorder handler CALLED! payload_len={len(context.payload)}")
            from ..techniques.primitives import BypassTechniques

            techniques = BypassTechniques()

            # Конвертируем параметры в правильный формат
            positions = context.params.get("positions")
            
            # CRITICAL DEBUG: Log what positions we received
            logger.info(f"🔍 multidisorder handler: positions={positions}, payload_len={len(context.payload)}")

            # Если positions не указан, но есть split_pos, создаем positions из
            # split_pos
            if not positions and "split_pos" in context.params:
                split_pos = context.params["split_pos"]
                if isinstance(split_pos, (int, str)):
                    # Создаем несколько позиций на основе split_pos
                    if isinstance(split_pos, str):
                        try:
                            split_pos = int(split_pos)
                        except ValueError:
                            split_pos = len(context.payload) // 2

                    # Создаем разумные позиции на основе split_pos
                    base_pos = max(1, min(split_pos, len(context.payload) - 1))
                    positions = []

                    # Добавляем позиции до split_pos
                    if base_pos > 2:
                        positions.append(base_pos // 2)

                    # Добавляем сам split_pos
                    positions.append(base_pos)

                    # Добавляем позицию после split_pos
                    if base_pos < len(context.payload) - 2:
                        positions.append(
                            min(base_pos + (base_pos // 2), len(context.payload) - 1)
                        )

                    # Убираем дубликаты и сортируем
                    positions = sorted(list(set(positions)))

                    logger.debug(
                        f"Converted split_pos={split_pos} to positions={positions} for payload length {
                            len(
                                context.payload)}"
                    )
                else:
                    positions = [1, 5, 10]  # Значения по умолчанию
            elif not positions:
                positions = [1, 5, 10]  # Значения по умолчанию

            fake_ttl = context.params.get("fake_ttl", context.params.get("ttl", 3))
            fooling_raw = context.params.get("fooling", context.params.get("fooling_methods"))
            
            # CRITICAL DEBUG: Log what we got from params
            logger.info(f"🔧 multidisorder handler: fooling_raw={fooling_raw}, type={type(fooling_raw)}")
            
            # CRITICAL: Convert fooling="none" string to empty list (no fooling)
            if fooling_raw is None:
                fooling = ["badsum"]  # Default
                logger.info(f"🔧 multidisorder: fooling is None, using default ['badsum']")
            elif fooling_raw == "none" or fooling_raw == ["none"]:
                fooling = []
                logger.info(f"🔧 multidisorder: fooling='none' detected, disabling all fooling methods")
            elif isinstance(fooling_raw, str):
                fooling = [fooling_raw]
                logger.info(f"🔧 multidisorder: converted string to list: {fooling}")
            elif isinstance(fooling_raw, list):
                fooling = fooling_raw
                logger.info(f"🔧 multidisorder: using list as-is: {fooling}")
            else:
                fooling = ["badsum"]  # Fallback
                logger.warning(f"🔧 multidisorder: unexpected fooling type, using default")
            
            logger.info(f"🔧 multidisorder handler FINAL: fooling={fooling}, fake_ttl={fake_ttl}")

            return techniques.apply_multidisorder(
                context.payload, positions, fooling, fake_ttl
            )

        return handler

    def _create_window_manipulation_handler(self) -> Callable:
        """Создает обработчик для TCP window manipulation."""

        def handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            from ..techniques.primitives import BypassTechniques

            # Extract parameters with defaults
            window_size = context.params.get("window_size", 1)
            delay_ms = context.params.get("delay_ms", 50.0)
            fragment_count = context.params.get("fragment_count", 5)
            fooling_methods = context.params.get("fooling", ["badsum"])

            return BypassTechniques.apply_window_manipulation(
                context.payload, window_size, delay_ms, fragment_count, fooling_methods
            )

        return handler

    def _create_tcp_options_handler(self) -> Callable:
        """Создает обработчик для TCP options modification."""

        def handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            from ..techniques.primitives import BypassTechniques

            # Extract parameters with defaults
            split_pos = context.params.get("split_pos", 5)
            options_type = context.params.get("options_type", "mss")
            bad_checksum = context.params.get("bad_checksum", False)
            fooling_methods = context.params.get("fooling", ["badsum"])

            return BypassTechniques.apply_tcp_options_modification(
                context.payload, split_pos, options_type, bad_checksum, fooling_methods
            )

        return handler

    def _create_advanced_timing_handler(self) -> Callable:
        """Создает обработчик для advanced timing control."""

        def handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
            from ..techniques.primitives import BypassTechniques

            # Extract parameters with defaults
            split_pos = context.params.get("split_pos", 3)
            delays = context.params.get("delays", [1.0, 2.0])
            jitter = context.params.get("jitter", False)
            fooling_methods = context.params.get("fooling", ["badsum"])

            return BypassTechniques.apply_advanced_timing_control(
                context.payload, split_pos, delays, jitter, fooling_methods
            )

        return handler

    def _register_external_attacks(self) -> None:
        """Автоматически обнаруживает и регистрирует внешние атаки."""
        attacks_dir = Path("core/bypass/attacks")

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

    def _is_attack_class(self, cls) -> bool:
        """Проверяет, является ли класс классом атаки."""
        return (
            hasattr(cls, "attack_type")
            and hasattr(cls, "execute")
            and hasattr(cls, "get_metadata")
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
                logger.debug(
                    f"Registered external attack class: {
                        attack_class.__name__}"
                )
            else:
                logger.debug(
                    f"Skipped external attack class {
                        attack_class.__name__}: {
                        result.message}"
                )

        except Exception as e:
            logger.error(
                f"Failed to register attack class {
                    attack_class.__name__}: {e}"
            )

    def _validate_parameter_values(
        self, attack_type: str, params: Dict[str, Any], metadata: AttackMetadata
    ) -> ValidationResult:
        """Валидирует значения параметров для конкретного типа атаки."""

        # Валидация split_pos (только если он присутствует и не None)
        if "split_pos" in params and params["split_pos"] is not None:
            split_pos = params["split_pos"]

            # Если split_pos это список, берем первый элемент
            if isinstance(split_pos, list):
                if len(split_pos) == 0:
                    return ValidationResult(
                        is_valid=False, error_message="split_pos list cannot be empty"
                    )
                split_pos = split_pos[0]
                # Обновляем параметры для дальнейшего использования
                params["split_pos"] = split_pos
                logger.debug(f"Converted split_pos list to single value: {split_pos}")

            if not isinstance(split_pos, (int, str)):
                return ValidationResult(
                    is_valid=False,
                    error_message=f"split_pos must be int, str, or list, got {
                        type(split_pos)}",
                )

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
                    return ValidationResult(
                        is_valid=False,
                        error_message=f"Invalid split_pos value: {split_pos}",
                    )

        # Валидация positions для multisplit/multidisorder
        if "positions" in params:
            positions = params["positions"]
            if positions is None:
                # None is acceptable for positions - the attack handler will convert it
                # from split_pos or use defaults
                pass
            elif not isinstance(positions, list):
                return ValidationResult(
                    is_valid=False,
                    error_message=f"positions must be a list, got {
                        type(positions)}",
                )
            else:
                # Only validate if positions is not None and is a list
                special_values = ["cipher", "sni", "midsld"]
                for pos in positions:
                    if isinstance(pos, int):
                        if pos < 1:
                            return ValidationResult(
                                is_valid=False,
                                error_message=f"Position values must be >= 1, got {pos}",
                            )
                    elif isinstance(pos, str):
                        if pos not in special_values:
                            try:
                                int(pos)  # Try to convert to int
                            except ValueError:
                                return ValidationResult(
                                    is_valid=False,
                                    error_message=f"Invalid position value: {pos}. Must be int or one of {special_values}",
                                )
                    else:
                        return ValidationResult(
                            is_valid=False,
                            error_message=f"All positions must be int or str, got {
                                type(pos)}",
                        )

        # Валидация overlap_size для seqovl
        if "overlap_size" in params:
            overlap_size = params["overlap_size"]
            if not isinstance(overlap_size, int) or overlap_size < 0:
                return ValidationResult(
                    is_valid=False,
                    error_message=f"overlap_size must be non-negative int, got {overlap_size}",
                )

        # Валидация ttl
        if "ttl" in params:
            ttl = params["ttl"]
            if not isinstance(ttl, int) or not (1 <= ttl <= 255):
                return ValidationResult(
                    is_valid=False,
                    error_message=f"ttl must be int between 1 and 255, got {ttl}",
                )

        # Валидация fooling методов
        if "fooling" in params and params["fooling"] is not None:
            fooling = params["fooling"]
            if not isinstance(fooling, list):
                return ValidationResult(
                    is_valid=False,
                    error_message=f"fooling must be a list, got {
                        type(fooling)}",
                )

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
                    return ValidationResult(
                        is_valid=False,
                        error_message=f"Invalid fooling method '{method}'. Valid methods: {valid_fooling_methods}",
                    )

        # Валидация custom_sni и fake_sni параметров (backward compatibility)
        sni_params = ["custom_sni", "fake_sni"]
        for param_name in sni_params:
            if param_name in params and params[param_name] is not None:
                sni_value = params[param_name]
                if not isinstance(sni_value, str):
                    return ValidationResult(
                        is_valid=False,
                        error_message=f"{param_name} must be a string, got {type(sni_value)}",
                    )
                
                # Validate SNI format using CustomSNIHandler
                from ..filtering.custom_sni import CustomSNIHandler
                sni_handler = CustomSNIHandler()
                if not sni_handler.validate_sni(sni_value):
                    return ValidationResult(
                        is_valid=False,
                        error_message=f"Invalid {param_name} format: '{sni_value}'. Must be a valid domain name.",
                    )

        return ValidationResult(is_valid=True, error_message=None)

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
        issues = []
        warnings = []
        stats = {
            "total_attacks": len(self.attacks),
            "total_aliases": len(self._aliases),
            "priority_distribution": {},
            "source_modules": set(),
            "categories": set(),
        }

        # Подсчет статистики по приоритетам
        for entry in self.attacks.values():
            priority_name = entry.priority.name
            stats["priority_distribution"][priority_name] = (
                stats["priority_distribution"].get(priority_name, 0) + 1
            )
            stats["source_modules"].add(entry.source_module)
            stats["categories"].add(entry.metadata.category)

        # Проверка алиасов
        for alias, target in self._aliases.items():
            if target not in self.attacks:
                issues.append(
                    f"Alias '{alias}' points to non-existent attack '{target}'"
                )
            elif alias == target:
                warnings.append(f"Alias '{alias}' points to itself")

        # Проверка обработчиков
        for attack_type, entry in self.attacks.items():
            if not callable(entry.handler):
                issues.append(
                    f"Attack '{attack_type}' has non-callable handler: {type(entry.handler)}"
                )

            # Проверка соответствия приоритета и источника
            if (
                entry.priority == RegistrationPriority.CORE
                and "primitives" not in entry.source_module
            ):
                warnings.append(
                    f"Attack '{attack_type}' has CORE priority but not from primitives module: {
                        entry.source_module}"
                )

        # Проверка дубликатов алиасов в метаданных
        all_aliases = []
        for entry in self.attacks.values():
            all_aliases.extend(entry.metadata.aliases)

        duplicate_aliases = []
        seen_aliases = set()
        for alias in all_aliases:
            if alias in seen_aliases:
                duplicate_aliases.append(alias)
            seen_aliases.add(alias)

        if duplicate_aliases:
            warnings.append(f"Duplicate aliases found in metadata: {duplicate_aliases}")

        # Конвертируем множества в списки для JSON-сериализации
        stats["source_modules"] = list(stats["source_modules"])
        stats["categories"] = list(stats["categories"])

        return {
            "is_valid": len(issues) == 0,
            "issues": issues,
            "warnings": warnings,
            "stats": stats,
            "timestamp": datetime.now().isoformat(),
        }

    def get_registration_conflicts(self) -> List[Dict[str, Any]]:
        """
        Возвращает список всех конфликтов регистрации из истории.

        Returns:
            Список конфликтов с подробной информацией
        """
        conflicts = []

        for attack_type, entry in self.attacks.items():
            if entry.promotion_history:
                for promotion in entry.promotion_history:
                    if promotion.get("action") in [
                        "replaced_by_higher_priority",
                        "promoted",
                    ]:
                        conflicts.append(
                            {
                                "attack_type": attack_type,
                                "conflict_type": promotion.get("action"),
                                "timestamp": promotion.get("timestamp"),
                                "old_priority": promotion.get("old_priority"),
                                "new_priority": promotion.get("new_priority"),
                                "old_source": promotion.get("old_source"),
                                "new_source": promotion.get("new_source"),
                                "reason": promotion.get("reason"),
                            }
                        )

        return conflicts

    def get_priority_statistics(self) -> Dict[str, Any]:
        """
        Возвращает статистику по приоритетам атак.

        Returns:
            Словарь со статистикой приоритетов
        """
        stats = {
            "total_attacks": len(self.attacks),
            "by_priority": {},
            "by_source": {},
            "core_attacks": [],
            "external_attacks": [],
        }

        for attack_type, entry in self.attacks.items():
            priority_name = entry.priority.name
            source = entry.source_module

            # Статистика по приоритетам
            if priority_name not in stats["by_priority"]:
                stats["by_priority"][priority_name] = {"count": 0, "attacks": []}
            stats["by_priority"][priority_name]["count"] += 1
            stats["by_priority"][priority_name]["attacks"].append(attack_type)

            # Статистика по источникам
            if source not in stats["by_source"]:
                stats["by_source"][source] = {"count": 0, "attacks": []}
            stats["by_source"][source]["count"] += 1
            stats["by_source"][source]["attacks"].append(attack_type)

            # Разделение на core и external
            if entry.priority == RegistrationPriority.CORE:
                stats["core_attacks"].append(attack_type)
            else:
                stats["external_attacks"].append(attack_type)

        return stats

    def register_alias(
        self,
        alias: str,
        canonical_attack: str,
        metadata: Optional[AttackMetadata] = None,
    ) -> RegistrationResult:
        """
        Регистрирует алиас для существующей атаки.

        Args:
            alias: Имя алиаса
            canonical_attack: Каноническое имя атаки
            metadata: Опциональные метаданные для алиаса

        Returns:
            RegistrationResult с результатом регистрации алиаса
        """
        # Проверяем, что каноническая атака существует
        if canonical_attack not in self.attacks:
            return RegistrationResult(
                success=False,
                action="failed",
                message=f"Cannot create alias '{alias}': canonical attack '{canonical_attack}' not found",
                attack_type=alias,
                conflicts=[f"Target attack '{canonical_attack}' does not exist"],
            )

        # Проверяем, что алиас не конфликтует с существующими атаками
        if alias in self.attacks:
            return RegistrationResult(
                success=False,
                action="failed",
                message=f"Cannot create alias '{alias}': name conflicts with existing attack",
                attack_type=alias,
                conflicts=[f"Attack '{alias}' already exists"],
            )

        # Проверяем существующие алиасы
        conflicts = []
        if alias in self._aliases:
            old_target = self._aliases[alias]
            conflicts.append(f"Alias '{alias}' was pointing to '{old_target}'")
            logger.warning(
                f"Overwriting alias '{alias}': '{old_target}' -> '{canonical_attack}'"
            )

        # Регистрируем алиас
        self._aliases[alias] = canonical_attack

        # Логируем создание алиаса, если предоставлены метаданные
        if metadata is not None:
            logger.debug(f"Created alias entry for '{alias}' -> '{canonical_attack}'")

        logger.info(f"Registered alias '{alias}' -> '{canonical_attack}'")

        return RegistrationResult(
            success=True,
            action="alias_registered",
            message=f"Successfully registered alias '{alias}' for attack '{canonical_attack}'",
            attack_type=alias,
            conflicts=conflicts,
        )

    def get_canonical_name(self, attack_name: str) -> str:
        """
        Возвращает каноническое имя атаки, разрешая алиасы.

        Args:
            attack_name: Имя атаки или алиас

        Returns:
            Каноническое имя атаки
        """
        return self._resolve_attack_type(attack_name)

    def is_alias(self, attack_name: str) -> bool:
        """
        Проверяет, является ли имя алиасом.

        Args:
            attack_name: Имя для проверки

        Returns:
            True если это алиас, False если каноническое имя или не существует
        """
        return attack_name in self._aliases and attack_name not in self.attacks

    def get_all_names_for_attack(self, canonical_name: str) -> List[str]:
        """
        Возвращает все имена (каноническое + алиасы) для атаки.

        Args:
            canonical_name: Каноническое имя атаки

        Returns:
            Список всех имен для этой атаки
        """
        if canonical_name not in self.attacks:
            return []

        names = [canonical_name]  # Каноническое имя

        # Добавляем алиасы из метаданных
        entry = self.attacks[canonical_name]
        names.extend(entry.metadata.aliases)

        # Добавляем алиасы из реестра алиасов
        for alias, target in self._aliases.items():
            if target == canonical_name and alias not in names:
                names.append(alias)

        return names

    def get_alias_mapping(self) -> Dict[str, str]:
        """
        Возвращает полное отображение алиасов на канонические имена.

        Returns:
            Словарь {алиас: каноническое_имя}
        """
        return self._aliases.copy()

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
        if (
            existing_entry.priority == RegistrationPriority.CORE
            and require_confirmation
        ):
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
            return ValidationResult(
                is_valid=False, error_message="New handler is not callable"
            )

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
                warnings.append(
                    f"Missing recommended performance metrics: {missing_metrics}"
                )

        # Проверяем частоту продвижений
        if len(existing_entry.promotion_history) > 3:
            warnings.append(
                "Attack has been promoted multiple times - consider stability"
            )

        return ValidationResult(is_valid=True, warnings=warnings)

    def _discover_external_attacks(self) -> None:
        """
        Обнаруживает внешние атаки без их загрузки (для lazy loading).

        Быстро сканирует директории атак и сохраняет пути к модулям для последующей загрузки.
        Оптимизирован для минимального времени инициализации.
        """
        attacks_dir = Path("core/bypass/attacks")

        if not attacks_dir.exists():
            logger.warning(f"Attacks directory {attacks_dir} does not exist")
            return

        discovered_count = 0

        # Системные файлы для исключения
        excluded_files = {
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
            "http_manipulation.py",
        }

        # Быстрое сканирование только имен файлов (без чтения содержимого)
        for module_file in attacks_dir.glob("*.py"):
            if module_file.name.startswith("_") or module_file.name in excluded_files:
                continue

            if module_file.is_dir():
                continue

            # Предполагаем, что все остальные .py файлы могут содержать атаки
            # Это быстрее, чем читать каждый файл
            module_path = f"core.bypass.attacks.{module_file.stem}"
            attack_name = module_file.stem.replace("_", "")
            
            self._unloaded_modules[attack_name] = module_path
            discovered_count += 1

            logger.debug(f"Discovered potential attack module: {module_path}")

        logger.info(
            f"Discovered {discovered_count} potential attack modules for lazy loading"
        )

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
        attack_lower = attack_type.lower()
        
        # Сначала пытаемся найти точное соответствие
        for unloaded_attack, module_path in self._unloaded_modules.items():
            if unloaded_attack.lower() == attack_lower:
                logger.debug(
                    f"Found exact match, loading module {module_path} for attack '{attack_type}'"
                )
                if self._load_module_on_demand(module_path):
                    if self._resolve_attack_type(attack_type) in self.attacks:
                        return True
        
        # Затем пытаемся найти частичное соответствие
        for unloaded_attack, module_path in self._unloaded_modules.items():
            if (
                attack_lower in unloaded_attack.lower()
                or unloaded_attack.lower() in attack_lower
            ):
                logger.debug(
                    f"Found partial match, loading module {module_path} for attack '{attack_type}'"
                )
                if self._load_module_on_demand(module_path):
                    if self._resolve_attack_type(attack_type) in self.attacks:
                        return True

        # Только в крайнем случае загружаем все модули (ограничиваем количество)
        remaining_modules = [
            path for path in self._unloaded_modules.values() 
            if path not in self._loaded_modules
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
        return {
            "lazy_loading_enabled": self._lazy_loading,
            "total_discovered_modules": len(self._unloaded_modules),
            "loaded_modules": len(self._loaded_modules),
            "unloaded_modules": len(self._unloaded_modules) - len(self._loaded_modules),
            "loaded_attacks": len(self.attacks),
            "discovered_module_paths": list(self._unloaded_modules.values()),
            "loaded_module_paths": list(self._loaded_modules),
        }


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
    logger.info(
        f"Configured lazy loading: {
            'enabled' if enabled else 'disabled'}"
    )


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
                    attack_class_or_func, name, category, priority, 
                    required_params, optional_params, aliases, description
                )
            else:
                # Handle function registration
                return _register_attack_function(
                    attack_class_or_func, name, category, priority,
                    required_params, optional_params, aliases, description
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
    
    # Create instance to extract metadata
    try:
        instance = attack_class()
    except Exception as e:
        logger.warning(f"Could not instantiate {attack_class.__name__} for metadata extraction: {e}")
        instance = None

    # Determine attack name
    attack_name = name
    if not attack_name:
        if instance and hasattr(instance, 'name'):
            attack_name = instance.name
        else:
            # Convert class name to snake_case
            attack_name = _class_name_to_snake_case(attack_class.__name__)

    # Extract metadata from class and instance
    extracted_metadata = _extract_class_metadata(attack_class, instance)
    
    # Build final metadata, prioritizing decorator parameters
    final_metadata = AttackMetadata(
        name=description or extracted_metadata.get('description') or attack_name.replace('_', ' ').title(),
        description=description or extracted_metadata.get('description') or attack_class.__doc__ or f"Attack: {attack_name}",
        required_params=required_params or extracted_metadata.get('required_params', []),
        optional_params=optional_params or extracted_metadata.get('optional_params', {}),
        aliases=aliases or extracted_metadata.get('aliases', []),
        category=category or extracted_metadata.get('category', AttackCategories.CUSTOM),
    )

    # Validate category
    if final_metadata.category not in AttackCategories.ALL:
        logger.warning(f"Invalid category '{final_metadata.category}' for {attack_name}, using CUSTOM")
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
                    # Try to get existing event loop
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        # If loop is already running, create a new one
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        try:
                            result = loop.run_until_complete(result)
                        finally:
                            loop.close()
                    else:
                        result = loop.run_until_complete(result)
                except RuntimeError:
                    # No event loop, create a new one
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    try:
                        result = loop.run_until_complete(result)
                    finally:
                        loop.close()
            
            # Convert AttackResult to segments format if needed
            if hasattr(result, 'segments') and result.segments:
                # ✅ Validate segments format before returning
                segments = result.segments
                if not isinstance(segments, list):
                    logger.error(f"Attack {attack_name} returned segments that is not a list: {type(segments)}")
                    return [(context.payload, 0, {})]
                
                # Validate each segment
                valid_segments = []
                for i, segment in enumerate(segments):
                    if isinstance(segment, tuple) and len(segment) == 3:
                        payload_data, seq_offset, options_dict = segment
                        if isinstance(payload_data, bytes) and isinstance(seq_offset, int) and isinstance(options_dict, dict):
                            valid_segments.append(segment)
                        else:
                            logger.warning(f"Attack {attack_name} segment {i} has invalid types, skipping")
                    else:
                        logger.warning(f"Attack {attack_name} segment {i} is not a valid tuple (payload, offset, options), skipping")
                
                if valid_segments:
                    return valid_segments
                else:
                    logger.error(f"Attack {attack_name} returned no valid segments, using fallback")
                    return [(context.payload, 0, {})]
                    
            elif hasattr(result, 'modified_payload') and result.modified_payload:
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
    result = registry.register_attack(
        attack_name, attack_handler, final_metadata, priority
    )

    if result.success:
        logger.debug(f"Registered attack class: {attack_class.__name__} as '{attack_name}' with priority {priority.name}")
    else:
        logger.debug(f"Skipped attack class {attack_class.__name__}: {result.message}")

    # Store registration info on class for introspection
    attack_class._attack_registry_info = {
        'name': attack_name,
        'metadata': final_metadata,
        'priority': priority,
        'registration_result': result
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
        name=description or extracted_metadata.get('description') or attack_name.replace('_', ' ').title(),
        description=description or extracted_metadata.get('description') or attack_func.__doc__ or f"Attack: {attack_name}",
        required_params=required_params or extracted_metadata.get('required_params', []),
        optional_params=optional_params or extracted_metadata.get('optional_params', {}),
        aliases=aliases or extracted_metadata.get('aliases', []),
        category=category or extracted_metadata.get('category', AttackCategories.CUSTOM),
    )

    # Validate category
    if final_metadata.category not in AttackCategories.ALL:
        logger.warning(f"Invalid category '{final_metadata.category}' for {attack_name}, using CUSTOM")
        final_metadata.category = AttackCategories.CUSTOM

    # Create wrapper handler
    def attack_handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Function-based attack handler."""
        try:
            # Call the function with appropriate parameters
            sig = inspect.signature(attack_func)
            if 'context' in sig.parameters:
                result = attack_func(context)
            else:
                # Legacy function signature
                result = attack_func(context.payload, **context.params)
            
            # Handle different return types
            if isinstance(result, list) and all(isinstance(item, tuple) and len(item) == 3 for item in result):
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
    result = registry.register_attack(
        attack_name, attack_handler, final_metadata, priority
    )

    if result.success:
        logger.debug(f"Registered attack function: {attack_func.__name__} as '{attack_name}' with priority {priority.name}")
    else:
        logger.debug(f"Skipped attack function {attack_func.__name__}: {result.message}")

    # Store registration info on function for introspection
    attack_func._attack_registry_info = {
        'name': attack_name,
        'metadata': final_metadata,
        'priority': priority,
        'registration_result': result
    }

    return attack_func


def _extract_class_metadata(attack_class, instance=None) -> Dict[str, Any]:
    """Extract metadata from attack class and instance."""
    metadata = {}
    
    # Try to get metadata from instance first, then class
    sources = [instance, attack_class] if instance else [attack_class]
    
    for source in sources:
        if source is None:
            continue
            
        # Extract required_params - handle both list and non-list formats
        if hasattr(source, 'required_params') and not metadata.get('required_params'):
            required_params = getattr(source, 'required_params', [])
            # Ensure it's a list
            if not isinstance(required_params, list):
                required_params = []
            metadata['required_params'] = required_params
        
        # Extract optional_params - ensure it's a dict
        if hasattr(source, 'optional_params') and not metadata.get('optional_params'):
            optional_params = getattr(source, 'optional_params', {})
            # Ensure it's a dict
            if not isinstance(optional_params, dict):
                optional_params = {}
            metadata['optional_params'] = optional_params
        
        # Extract aliases - ensure it's a list
        if hasattr(source, 'aliases') and not metadata.get('aliases'):
            aliases = getattr(source, 'aliases', [])
            # Ensure it's a list
            if not isinstance(aliases, list):
                aliases = []
            metadata['aliases'] = aliases
        
        # Extract category
        if hasattr(source, 'category') and not metadata.get('category'):
            category = getattr(source, 'category')
            if isinstance(category, str) and category in AttackCategories.ALL:
                metadata['category'] = category
        
        # Extract description
        if hasattr(source, 'description') and not metadata.get('description'):
            description = getattr(source, 'description')
            if isinstance(description, str):
                metadata['description'] = description
        elif hasattr(source, '__doc__') and source.__doc__ and not metadata.get('description'):
            metadata['description'] = source.__doc__.strip()
    
    # Set defaults for missing metadata
    if 'required_params' not in metadata:
        metadata['required_params'] = []
    if 'optional_params' not in metadata:
        metadata['optional_params'] = {}
    if 'aliases' not in metadata:
        metadata['aliases'] = []
    if 'category' not in metadata:
        metadata['category'] = AttackCategories.CUSTOM
    
    return metadata


def _extract_function_metadata(attack_func) -> Dict[str, Any]:
    """Extract metadata from attack function."""
    metadata = {}
    
    # Extract from function attributes
    if hasattr(attack_func, 'required_params'):
        metadata['required_params'] = attack_func.required_params
    
    if hasattr(attack_func, 'optional_params'):
        metadata['optional_params'] = attack_func.optional_params
    
    if hasattr(attack_func, 'aliases'):
        metadata['aliases'] = attack_func.aliases
    
    if hasattr(attack_func, 'category'):
        category = attack_func.category
        if category in AttackCategories.ALL:
            metadata['category'] = category
    
    # Extract from docstring
    if attack_func.__doc__:
        metadata['description'] = attack_func.__doc__.strip()
    
    return metadata


def _class_name_to_snake_case(class_name: str) -> str:
    """Convert CamelCase class name to snake_case."""
    import re
    
    # Remove 'Attack' suffix if present
    if class_name.endswith('Attack'):
        class_name = class_name[:-6]
    
    # Convert CamelCase to snake_case
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', class_name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


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


def validate_attack_parameters(
    attack_type: str, params: Dict[str, Any]
) -> ValidationResult:
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


def list_attacks(
    category: Optional[str] = None, enabled_only: bool = False
) -> List[str]:
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

    if clear_config:
        _lazy_loading_config = None
        logger.debug("Cleared attack registry and lazy loading configuration")