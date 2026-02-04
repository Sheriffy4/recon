"""
Unified Attack Registry - единый источник правды для всех атак.

Этот модуль предоставляет централизованный реестр для всех DPI bypass атак
с унифицированным интерфейсом, приоритетами регистрации и автоматической
дедупликацией.

Архитектура:
- CORE атаки (приоритет 100): встроенные примитивы из BypassTechniques
- EXTERNAL атаки (приоритет 50): внешние модули через @register
- DYNAMIC атаки (приоритет 10): динамически созданные в runtime

Преимущества:
- Единый источник правды для всех атак
- Автоматическая дедупликация по приоритетам
- Унифицированная сигнатура вызова
- Валидация при регистрации
- Управление алиасами без конфликтов
"""

from __future__ import annotations

import builtins
import logging
from datetime import datetime
from enum import IntEnum
from typing import Any, Callable, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Ключ для singleton в builtins
_UAR_BUILTIN_KEY = "__UNIFIED_ATTACK_REGISTRY_SINGLETON__"


class RegistrationPriority(IntEnum):
    """Приоритеты регистрации атак."""

    CORE = 100  # Встроенные примитивы (BypassTechniques)
    EXTERNAL = 50  # Внешние модули (@register)
    DYNAMIC = 10  # Динамически созданные (runtime)


@dataclass
class AttackMetadata:
    """Метаданные атаки."""

    name: str
    description: str
    category: str
    required_params: List[str] = field(default_factory=list)
    optional_params: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)


@dataclass
class AttackEntry:
    """Запись об атаке в реестре."""

    canonical_name: str
    handler: Callable
    metadata: AttackMetadata
    priority: RegistrationPriority
    source_module: str
    registration_time: datetime
    aliases: List[str] = field(default_factory=list)
    usage_count: int = 0
    last_used: Optional[datetime] = None


@dataclass
class RegistrationResult:
    """Результат регистрации атаки."""

    success: bool
    canonical_name: str
    action: str  # "registered", "skipped", "replaced", "error"
    message: str
    conflicts: List[str] = field(default_factory=list)
    previous_priority: Optional[RegistrationPriority] = None


class UnifiedAttackRegistry:
    """
    Унифицированный реестр атак - единый источник правды.

    Основные функции:
    - Регистрация атак с приоритетами
    - Автоматическая дедупликация
    - Управление алиасами
    - Валидация метаданных
    - Унифицированный интерфейс вызова

    Пример использования:
        uar = get_unified_registry()

        # Регистрация атаки
        uar.register(
            canonical_name="my_attack",
            handler=my_handler_func,
            metadata=AttackMetadata(...),
            priority=RegistrationPriority.EXTERNAL,
            aliases=["my_alias"]
        )

        # Получение обработчика
        handler = uar.get("my_attack")

        # Выполнение атаки
        segments = uar.execute("my_attack", context)
    """

    def __init__(self):
        """Инициализация реестра."""
        self._attacks: Dict[str, AttackEntry] = {}
        self._aliases: Dict[str, str] = {}  # alias -> canonical_name
        self._registration_order: List[str] = []
        self._conflicts_log: List[Dict[str, Any]] = []

        # Публикуем singleton в builtins
        try:
            if getattr(builtins, _UAR_BUILTIN_KEY, None) is None:
                setattr(builtins, _UAR_BUILTIN_KEY, self)
        except Exception:
            pass

        # Регистрируем встроенные атаки
        self._register_core_primitives()

        logger.info("UnifiedAttackRegistry initialized")

    def register(
        self,
        canonical_name: str,
        handler: Callable,
        metadata: AttackMetadata,
        priority: RegistrationPriority = RegistrationPriority.EXTERNAL,
        aliases: Optional[List[str]] = None,
        source_module: str = "unknown",
    ) -> RegistrationResult:
        """
        Регистрирует атаку в реестре.

        Args:
            canonical_name: Каноническое имя атаки (без префиксов)
            handler: Функция-обработчик атаки
            metadata: Метаданные атаки
            priority: Приоритет регистрации
            aliases: Список алиасов для атаки
            source_module: Имя модуля-источника

        Returns:
            RegistrationResult с информацией о результате
        """
        aliases = aliases or []

        # Валидация
        validation_result = self._validate_registration(canonical_name, handler, metadata, aliases)
        if not validation_result["valid"]:
            return RegistrationResult(
                success=False,
                canonical_name=canonical_name,
                action="error",
                message=validation_result["error"],
                conflicts=validation_result.get("conflicts", []),
            )

        # Проверка на существование
        if canonical_name in self._attacks:
            return self._handle_duplicate_registration(
                canonical_name, handler, metadata, priority, aliases, source_module
            )

        # Создаем запись
        entry = AttackEntry(
            canonical_name=canonical_name,
            handler=handler,
            metadata=metadata,
            priority=priority,
            source_module=source_module,
            registration_time=datetime.now(),
            aliases=aliases,
        )

        # Регистрируем атаку
        self._attacks[canonical_name] = entry
        self._registration_order.append(canonical_name)

        # Регистрируем алиасы
        alias_conflicts = []
        for alias in aliases:
            if alias in self._aliases:
                existing_target = self._aliases[alias]
                alias_conflicts.append(f"Alias '{alias}' already points to '{existing_target}'")
                logger.warning(
                    f"Overwriting alias '{alias}': '{existing_target}' -> '{canonical_name}'"
                )
            self._aliases[alias] = canonical_name

        logger.info(
            f"Registered attack '{canonical_name}' "
            f"(priority={priority.name}, aliases={len(aliases)})"
        )

        return RegistrationResult(
            success=True,
            canonical_name=canonical_name,
            action="registered",
            message=f"Successfully registered '{canonical_name}'",
            conflicts=alias_conflicts,
        )

    def get(self, name: str) -> Optional[Callable]:
        """
        Получает обработчик атаки по имени или алиасу.

        Args:
            name: Имя атаки или алиас

        Returns:
            Функция-обработчик или None
        """
        canonical = self.resolve_alias(name)
        entry = self._attacks.get(canonical)

        if entry:
            # Обновляем статистику использования
            entry.usage_count += 1
            entry.last_used = datetime.now()
            return entry.handler

        return None

    def execute(
        self, attack_name: str, context: Any  # AttackContext
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """
        Выполняет атаку с унифицированным интерфейсом.

        Args:
            attack_name: Имя атаки или алиас
            context: Контекст выполнения атаки

        Returns:
            Список сегментов (data, offset, options)

        Raises:
            ValueError: Если атака не найдена
        """
        handler = self.get(attack_name)
        if not handler:
            canonical = self.resolve_alias(attack_name)
            raise ValueError(f"Attack '{attack_name}' not found " f"(resolved to '{canonical}')")

        # Вызываем обработчик
        try:
            result = handler(context)
            return result
        except Exception as e:
            logger.error(f"Error executing attack '{attack_name}': {e}")
            raise

    def resolve_alias(self, name: str) -> str:
        """
        Разрешает алиас в каноническое имя.

        Args:
            name: Имя атаки или алиас

        Returns:
            Каноническое имя атаки
        """
        # Если это уже каноническое имя
        if name in self._attacks:
            return name

        # Если это алиас
        if name in self._aliases:
            return self._aliases[name]

        # Не найдено - возвращаем как есть
        return name

    def list_all(
        self, category: Optional[str] = None, priority: Optional[RegistrationPriority] = None
    ) -> List[str]:
        """
        Возвращает список всех зарегистрированных атак.

        Args:
            category: Фильтр по категории (опционально)
            priority: Фильтр по приоритету (опционально)

        Returns:
            Список канонических имен атак
        """
        attacks = list(self._attacks.keys())

        if category:
            attacks = [
                name for name in attacks if self._attacks[name].metadata.category == category
            ]

        if priority:
            attacks = [name for name in attacks if self._attacks[name].priority == priority]

        return attacks

    def get_metadata(self, name: str) -> Optional[AttackMetadata]:
        """
        Получает метаданные атаки.

        Args:
            name: Имя атаки или алиас

        Returns:
            Метаданные атаки или None
        """
        canonical = self.resolve_alias(name)
        entry = self._attacks.get(canonical)
        return entry.metadata if entry else None

    def get_aliases(self, canonical_name: str) -> List[str]:
        """
        Получает все алиасы для атаки.

        Args:
            canonical_name: Каноническое имя атаки

        Returns:
            Список алиасов
        """
        entry = self._attacks.get(canonical_name)
        return entry.aliases if entry else []

    # ========================================================================
    # Backward compatibility methods (для совместимости со старым кодом)
    # ========================================================================

    def get_attack_handler(self, name: str) -> Optional[Callable]:
        """
        Backward compatibility: alias for get().

        Args:
            name: Имя атаки или алиас

        Returns:
            Функция-обработчик или None
        """
        return self.get(name)

    def get_canonical_name(self, name: str) -> str:
        """
        Backward compatibility: alias for resolve_alias().

        Args:
            name: Имя атаки или алиас

        Returns:
            Каноническое имя атаки
        """
        return self.resolve_alias(name)

    def list_attacks(
        self,
        category: Optional[str] = None,
        priority: Optional[RegistrationPriority] = None,
        enabled_only: bool = False,
    ) -> List[str]:
        """
        Backward compatibility: alias for list_all().

        Args:
            category: Фильтр по категории (опционально)
            priority: Фильтр по приоритету (опционально)
            enabled_only: Для совместимости (игнорируется)

        Returns:
            Список канонических имен атак
        """
        return self.list_all(category=category, priority=priority)

    def get_attack_metadata(self, name: str) -> Optional[AttackMetadata]:
        """
        Backward compatibility: alias for get_metadata().

        Args:
            name: Имя атаки или алиас

        Returns:
            Метаданные атаки или None
        """
        return self.get_metadata(name)

    def get_attack_definition(self, name: str) -> Optional[AttackMetadata]:
        """
        Backward compatibility: alias for get_metadata().

        Args:
            name: Имя атаки или алиас

        Returns:
            Метаданные атаки или None
        """
        return self.get_metadata(name)

    def get_attack_aliases(self, name: str) -> List[str]:
        """
        Backward compatibility: alias for get_aliases().

        Args:
            name: Каноническое имя атаки

        Returns:
            Список алиасов
        """
        canonical = self.resolve_alias(name)
        return self.get_aliases(canonical)

    def is_alias(self, name: str) -> bool:
        """
        Проверяет, является ли имя алиасом (не каноническим именем).

        Args:
            name: Имя для проверки

        Returns:
            True если это алиас, False если каноническое имя или не найдено
        """
        # Если это каноническое имя, вернёт само себя
        canonical = self.resolve_alias(name)
        return canonical != name and canonical in self._attacks

    def get_all_names_for_attack(self, name: str) -> List[str]:
        """
        Получает все имена (каноническое + алиасы) для атаки.

        Args:
            name: Имя атаки или алиас

        Returns:
            Список всех имён включая каноническое и алиасы
        """
        canonical = self.resolve_alias(name)
        if canonical not in self._attacks:
            return []

        aliases = self.get_aliases(canonical)
        return [canonical] + aliases

    def get_alias_mapping(self) -> Dict[str, str]:
        """
        Получает полный маппинг алиасов.

        Returns:
            Словарь {alias -> canonical_name}
        """
        return self._aliases.copy()

    def validate_parameters(
        self, attack_type: str, params: Dict[str, Any]
    ) -> Any:  # ValidationResult
        """
        Валидирует параметры для указанного типа атаки.

        Args:
            attack_type: Тип атаки или алиас
            params: Словарь параметров для проверки

        Returns:
            ValidationResult с результатом проверки
        """
        # Import here to avoid circular dependency
        try:
            from ..attacks.metadata import ValidationResult
        except ImportError:
            from .metadata import ValidationResult

        canonical = self.resolve_alias(attack_type)
        metadata = self.get_metadata(canonical)

        if not metadata:
            return ValidationResult(
                is_valid=False, error_message=f"Unknown attack type: {attack_type}"
            )

        # Basic validation: check required params
        missing_params = []
        for required_param in metadata.required_params:
            if required_param not in params:
                missing_params.append(required_param)

        if missing_params:
            return ValidationResult(
                is_valid=False,
                error_message=f"Missing required parameters: {', '.join(missing_params)}",
            )

        # All checks passed
        return ValidationResult(is_valid=True, error_message=None)

    @property
    def attacks(self) -> Dict[str, AttackEntry]:
        """
        Property для доступа к словарю атак (backward compatibility).

        Returns:
            Словарь {canonical_name -> AttackEntry}
        """
        return self._attacks

    # ========================================================================
    # End of backward compatibility methods
    # ========================================================================

    def get_stats(self) -> Dict[str, Any]:
        """
        Возвращает статистику реестра.

        Returns:
            Словарь со статистикой
        """
        priority_counts = {}
        for entry in self._attacks.values():
            priority_name = entry.priority.name
            priority_counts[priority_name] = priority_counts.get(priority_name, 0) + 1

        category_counts = {}
        for entry in self._attacks.values():
            category = entry.metadata.category
            category_counts[category] = category_counts.get(category, 0) + 1

        return {
            "total_attacks": len(self._attacks),
            "total_aliases": len(self._aliases),
            "by_priority": priority_counts,
            "by_category": category_counts,
            "conflicts_logged": len(self._conflicts_log),
            "registration_order": self._registration_order[:10],  # First 10
        }

    def _validate_registration(
        self, canonical_name: str, handler: Callable, metadata: AttackMetadata, aliases: List[str]
    ) -> Dict[str, Any]:
        """Валидирует параметры регистрации."""
        errors = []
        conflicts = []

        # Проверка имени
        if not canonical_name or not isinstance(canonical_name, str):
            errors.append("canonical_name must be a non-empty string")

        # Проверка handler
        if not callable(handler):
            errors.append("handler must be callable")

        # Проверка метаданных
        if not isinstance(metadata, AttackMetadata):
            errors.append("metadata must be AttackMetadata instance")

        # Проверка алиасов
        if canonical_name in aliases:
            conflicts.append(f"Canonical name '{canonical_name}' cannot be in aliases")

        # Проверка на циклические алиасы
        for alias in aliases:
            if alias in self._attacks:
                conflicts.append(f"Alias '{alias}' conflicts with existing attack name")

        if errors:
            return {"valid": False, "error": "; ".join(errors), "conflicts": conflicts}

        if conflicts:
            logger.warning(f"Registration conflicts for '{canonical_name}': {conflicts}")

        return {"valid": True, "conflicts": conflicts}

    def _handle_duplicate_registration(
        self,
        canonical_name: str,
        handler: Callable,
        metadata: AttackMetadata,
        priority: RegistrationPriority,
        aliases: List[str],
        source_module: str,
    ) -> RegistrationResult:
        """Обрабатывает дублирующую регистрацию."""
        existing_entry = self._attacks[canonical_name]

        # Логируем конфликт
        conflict_info = {
            "canonical_name": canonical_name,
            "existing_priority": existing_entry.priority.name,
            "new_priority": priority.name,
            "existing_source": existing_entry.source_module,
            "new_source": source_module,
            "timestamp": datetime.now().isoformat(),
        }
        self._conflicts_log.append(conflict_info)

        # Если новый приоритет выше - заменяем
        if priority > existing_entry.priority:
            logger.info(
                f"Replacing attack '{canonical_name}': "
                f"{existing_entry.priority.name} -> {priority.name}"
            )

            # Создаем новую запись
            new_entry = AttackEntry(
                canonical_name=canonical_name,
                handler=handler,
                metadata=metadata,
                priority=priority,
                source_module=source_module,
                registration_time=datetime.now(),
                aliases=aliases,
            )

            self._attacks[canonical_name] = new_entry

            # Обновляем алиасы
            for alias in aliases:
                self._aliases[alias] = canonical_name

            return RegistrationResult(
                success=True,
                canonical_name=canonical_name,
                action="replaced",
                message=f"Replaced '{canonical_name}' with higher priority",
                previous_priority=existing_entry.priority,
            )

        # Если приоритет ниже или равен - пропускаем
        logger.debug(
            f"Skipping duplicate registration of '{canonical_name}': "
            f"existing priority {existing_entry.priority.name} >= "
            f"new priority {priority.name}"
        )

        return RegistrationResult(
            success=False,
            canonical_name=canonical_name,
            action="skipped",
            message=f"Skipped '{canonical_name}': lower or equal priority",
            previous_priority=existing_entry.priority,
        )

    def _register_core_primitives(self):
        """Регистрирует встроенные примитивы с CORE приоритетом."""
        try:
            from core.bypass.techniques.primitives import BypassTechniques

            # Список примитивов для регистрации
            # CRITICAL: Должны быть все атаки, используемые в AttackDispatcher._resolve_recipe_name
            primitives = [
                (
                    "fakeddisorder",
                    BypassTechniques.apply_fakeddisorder,
                    [
                        "fake_disorder",
                        "fakedisorder",
                        "tcp_fakeddisorder",
                        "force_tcp",
                        "filter-udp",
                    ],
                ),
                ("seqovl", BypassTechniques.apply_seqovl, ["seq_overlap", "overlap", "tcp_seqovl"]),
                (
                    "multisplit",
                    BypassTechniques.apply_multisplit,
                    ["multi_split", "tcp_multisplit"],
                ),
                (
                    "multidisorder",
                    BypassTechniques.apply_multidisorder,
                    ["multi_disorder", "tcp_multidisorder"],
                ),
                (
                    "fake",
                    BypassTechniques.apply_fake_packet_race,
                    [
                        "fake_race",
                        "race",
                        "ttl_fake_race",
                        "fake_syn",
                        "connection_recovery_fake_syn",
                    ],
                ),
                # ADDED: Missing attacks needed by recipes
                ("disorder", BypassTechniques.apply_disorder, ["simple_disorder", "tcp_disorder"]),
                # split is an alias for multisplit with single position
                ("split", BypassTechniques.apply_multisplit, ["simple_split", "tcp_split"]),
            ]

            for canonical_name, handler, aliases in primitives:
                self.register(
                    canonical_name=canonical_name,
                    handler=self._wrap_primitive(handler),
                    metadata=AttackMetadata(
                        name=canonical_name,
                        description=f"Core primitive: {canonical_name}",
                        category="core",
                        required_params=[],
                        optional_params={},
                    ),
                    priority=RegistrationPriority.CORE,
                    aliases=aliases,
                    source_module="core.bypass.techniques.primitives",
                )

            # Register passthrough (no-op attack)
            self.register(
                canonical_name="passthrough",
                handler=self._wrap_primitive(lambda payload, **params: [(payload, 0, {})]),
                metadata=AttackMetadata(
                    name="passthrough",
                    description="No-op attack (passthrough)",
                    category="core",
                    required_params=[],
                    optional_params={},
                ),
                priority=RegistrationPriority.CORE,
                aliases=["noop", "bypass"],
                source_module="core.bypass.attacks.unified_registry",
            )

            # Register TTL manipulation (if not already registered by external modules)
            # This is a fallback - prefer external TTL attack if available
            try:
                if not self.get("ttl"):
                    self.register(
                        canonical_name="ttl",
                        handler=self._wrap_primitive(BypassTechniques.apply_fake_packet_race),
                        metadata=AttackMetadata(
                            name="ttl",
                            description="TTL manipulation (fallback to fake)",
                            category="core",
                            required_params=[],
                            optional_params={"ttl": 3, "fake_ttl": 3},
                        ),
                        priority=RegistrationPriority.CORE,
                        aliases=["ttl_manipulation"],
                        source_module="core.bypass.techniques.primitives",
                    )
            except Exception:
                pass  # TTL already registered by external module

            logger.info(
                f"Registered {len(primitives) + 2} core primitives (including passthrough and ttl)"
            )

        except ImportError as e:
            logger.warning(f"Could not import BypassTechniques: {e}")

    def _wrap_primitive(self, primitive_func: Callable) -> Callable:
        """
        Оборачивает примитив в унифицированный интерфейс.

        Преобразует старую сигнатуру:
            func(payload: bytes, **params) -> List[Tuple]

        В новую:
            func(context: AttackContext) -> List[Tuple]

        Также выполняет маппинг параметров между AttackDispatcher и BypassTechniques:
        - split_pos -> positions (для multisplit)
        - disorder_method -> method (для disorder)

        И фильтрует параметры по сигнатуре функции (удаляет неизвестные параметры).
        """
        import inspect

        # Get function signature to filter parameters
        try:
            sig = inspect.signature(primitive_func)
            accepted_params = set(sig.parameters.keys()) - {"payload"}
        except Exception:
            # If can't get signature, accept all parameters
            accepted_params = None

        def wrapper(context):
            # Извлекаем параметры из контекста
            payload = getattr(context, "payload", b"")
            params = getattr(context, "params", {}).copy()  # Copy to avoid modifying original

            # Parameter mapping: AttackDispatcher -> BypassTechniques
            # This is function-specific mapping based on what each function expects

            func_name = getattr(primitive_func, "__name__", "")

            # multisplit: split_pos -> positions (list)
            if func_name == "apply_multisplit":
                if "split_pos" in params and "positions" not in params:
                    split_pos = params.pop("split_pos")
                    if isinstance(split_pos, int):
                        params["positions"] = [split_pos]
                    elif isinstance(split_pos, list):
                        params["positions"] = split_pos

            # split_positions -> positions (alternative name for multisplit)
            if "split_positions" in params and "positions" not in params:
                params["positions"] = params.pop("split_positions")
                params.pop("split_pos", None)  # Remove split_pos if positions is set

            # Filter parameters: only pass parameters that function accepts
            if accepted_params is not None:
                filtered_params = {k: v for k, v in params.items() if k in accepted_params}
                if len(filtered_params) < len(params):
                    removed = set(params.keys()) - set(filtered_params.keys())
                    logger.debug(f"Filtered out unsupported parameters for {func_name}: {removed}")
                params = filtered_params

            # Вызываем примитив со старой сигнатурой
            return primitive_func(payload, **params)

        return wrapper


# Singleton instance
_unified_registry_instance: Optional[UnifiedAttackRegistry] = None


def get_unified_registry() -> UnifiedAttackRegistry:
    """
    Получает singleton instance UnifiedAttackRegistry.

    Returns:
        UnifiedAttackRegistry instance
    """
    global _unified_registry_instance

    # Проверяем builtins сначала (для cross-module singleton)
    try:
        existing = getattr(builtins, _UAR_BUILTIN_KEY, None)
        if existing is not None:
            return existing
    except Exception:
        pass

    # Создаем новый instance если нужно
    if _unified_registry_instance is None:
        _unified_registry_instance = UnifiedAttackRegistry()

    return _unified_registry_instance


def clear_registry():
    """Очищает реестр (для тестов)."""
    global _unified_registry_instance
    _unified_registry_instance = None

    try:
        if hasattr(builtins, _UAR_BUILTIN_KEY):
            delattr(builtins, _UAR_BUILTIN_KEY)
    except Exception:
        pass


# Экспорт основных компонентов
__all__ = [
    "UnifiedAttackRegistry",
    "get_unified_registry",
    "clear_registry",
    "RegistrationPriority",
    "AttackMetadata",
    "AttackEntry",
    "RegistrationResult",
]
