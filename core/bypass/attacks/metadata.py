"""
Метаданные и вспомогательные классы для системы атак DPI обхода.

Этот модуль содержит:
- AttackMetadata: класс для описания метаданных атак
- AttackCategories: константы категорий атак
- ValidationResult: результат валидации параметров
- RegistrationPriority: приоритеты регистрации атак
- AttackEntry: полная запись атаки в реестре
- RegistrationResult: результат регистрации атаки
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable
from enum import Enum
from datetime import datetime


@dataclass
class AttackMetadata:
    """
    Полные метаданные атаки DPI обхода для системы регистрации и валидации.

    Содержит всю необходимую информацию для:
    - Регистрации атаки в AttackRegistry
    - Валидации параметров перед выполнением
    - Генерации документации и справки
    - Автоматического обнаружения внешних атак

    Структура метаданных:
    - Описательная информация (name, description)
    - Спецификация параметров (required_params, optional_params)
    - Альтернативные имена (aliases)
    - Классификация (category)

    Используется AttackRegistry для:
    - Проверки обязательных параметров
    - Валидации типов и значений
    - Разрешения алиасов в канонические имена
    - Группировки атак по категориям
    """

    name: str
    """Человекочитаемое название атаки"""

    description: str
    """Подробное описание того, как работает атака"""

    required_params: List[str]
    """Список обязательных параметров"""

    optional_params: Dict[str, Any]
    """Словарь опциональных параметров с их значениями по умолчанию"""

    aliases: List[str]
    """Список альтернативных названий для этой атаки"""

    category: str
    """Категория атаки (из AttackCategories)"""

    def __post_init__(self):
        """Валидация после инициализации."""
        if not self.name:
            raise ValueError("Attack name cannot be empty")

        if not self.description:
            raise ValueError("Attack description cannot be empty")

        if not isinstance(self.required_params, list):
            raise ValueError("required_params must be a list")

        if not isinstance(self.optional_params, dict):
            raise ValueError("optional_params must be a dict")

        if not isinstance(self.aliases, list):
            raise ValueError("aliases must be a list")

        if self.category not in AttackCategories.ALL:
            raise ValueError(
                f"Invalid category '{self.category}'. Must be one of: {AttackCategories.ALL}"
            )


class AttackCategories:
    """
    Константы для категорий атак DPI обхода с подробной классификацией.

    Категории помогают:
    - Организовать атаки по принципу действия
    - Выбрать подходящую стратегию для конкретного DPI
    - Генерировать документацию и справочные материалы
    - Анализировать эффективность различных подходов

    Основные принципы классификации:
    - TCP: TCP-уровневые атаки (разделение, изменение порядка, манипуляции)
    - IP: IP-уровневые атаки (фрагментация, TTL манипуляции)
    - TLS: TLS-специфичные атаки (SNI, record manipulation)
    - HTTP: HTTP-уровневые атаки (header manipulation, chunking)
    - PAYLOAD: Атаки на уровне полезной нагрузки (шифрование, обфускация)
    - TUNNELING: Туннелирование через другие протоколы
    - COMBO: Комбинированные атаки
    - TIMING: Временные атаки
    - CUSTOM: Специализированные пользовательские атаки
    """

    # Primary categories for new standardized format
    TCP = "tcp"
    """TCP-level attacks (splitting, reordering, window manipulation, etc.)"""

    IP = "ip"
    """IP-level attacks (fragmentation, TTL manipulation, options)"""

    TLS = "tls"
    """TLS-specific attacks (SNI manipulation, record fragmentation)"""

    HTTP = "http"
    """HTTP-level attacks (header manipulation, chunking, method changes)"""

    PAYLOAD = "payload"
    """Payload-level attacks (encryption, obfuscation, steganography)"""

    TUNNELING = "tunneling"
    """Protocol tunneling attacks (DNS, HTTP, WebSocket tunnels)"""

    COMBO = "combo"
    """Combination attacks using multiple techniques"""

    TIMING = "timing"
    """Timing-based attacks (delays, burst patterns, jitter)"""

    # Legacy categories (maintained for backward compatibility)
    SPLIT = "split"
    """Атаки, основанные на разделении пакетов (legacy, use TCP instead)"""

    DISORDER = "disorder"
    """Атаки, основанные на изменении порядка частей пакета (legacy, use TCP instead)"""

    FAKE = "fake"
    """Атаки с использованием фейковых пакетов (legacy, use TCP instead)"""

    RACE = "race"
    """Атаки типа race condition (legacy, use TCP instead)"""

    OVERLAP = "overlap"
    """Атаки с перекрытием последовательностей (legacy, use TCP instead)"""

    FRAGMENT = "fragment"
    """Атаки на основе фрагментации (legacy, use IP or TCP instead)"""

    DNS = "dns"
    """DNS-based атаки и туннелирование (legacy, use TUNNELING instead)"""

    CUSTOM = "custom"
    """Пользовательские атаки"""

    # Список всех доступных категорий
    ALL = [
        # Primary categories (recommended for new attacks)
        TCP,
        IP,
        TLS,
        HTTP,
        PAYLOAD,
        TUNNELING,
        COMBO,
        TIMING,
        # Legacy categories (for backward compatibility)
        SPLIT,
        DISORDER,
        FAKE,
        RACE,
        OVERLAP,
        FRAGMENT,
        DNS,
        CUSTOM,
    ]

    # Primary categories only (recommended for new implementations)
    PRIMARY = [TCP, IP, TLS, HTTP, PAYLOAD, TUNNELING, COMBO, TIMING, CUSTOM]

    # Legacy categories (deprecated but supported)
    LEGACY = [SPLIT, DISORDER, FAKE, RACE, OVERLAP, FRAGMENT, DNS]

    @classmethod
    def is_primary_category(cls, category: str) -> bool:
        """Check if category is a primary (recommended) category."""
        return category in cls.PRIMARY

    @classmethod
    def is_legacy_category(cls, category: str) -> bool:
        """Check if category is a legacy (deprecated) category."""
        return category in cls.LEGACY

    @classmethod
    def get_primary_equivalent(cls, legacy_category: str) -> str:
        """Get primary category equivalent for legacy category."""
        mapping = {
            cls.SPLIT: cls.TCP,
            cls.DISORDER: cls.TCP,
            cls.FAKE: cls.TCP,
            cls.RACE: cls.TCP,
            cls.OVERLAP: cls.TCP,
            cls.FRAGMENT: cls.IP,
            cls.DNS: cls.TUNNELING,
        }
        return mapping.get(legacy_category, legacy_category)


@dataclass
class ValidationResult:
    """
    Подробный результат валидации параметров атаки с поддержкой предупреждений.

    Структура результата:
    - is_valid: Основной флаг успешности валидации
    - error_message: Критическая ошибка, блокирующая выполнение
    - warnings: Некритичные проблемы, не блокирующие выполнение

    Использование:
    - Критические ошибки (is_valid=False): Атака не может быть выполнена
    - Предупреждения (warnings): Атака может быть выполнена, но с потенциальными проблемами

    Примеры критических ошибок:
    - Отсутствие обязательных параметров
    - Неправильные типы данных
    - Значения вне допустимых диапазонов

    Примеры предупреждений:
    - Использование значений по умолчанию
    - Потенциально неэффективные параметры
    - Устаревшие имена параметров
    """

    is_valid: bool
    """True если валидация прошла успешно"""

    error_message: Optional[str] = None
    """Сообщение об ошибке, если валидация не прошла"""

    warnings: Optional[List[str]] = None
    """Список предупреждений (не критичных проблем)"""

    def __post_init__(self):
        """Инициализация после создания."""
        if self.warnings is None:
            self.warnings = []

    def add_warning(self, warning: str) -> None:
        """Добавляет предупреждение к результату валидации."""
        if self.warnings is None:
            self.warnings = []
        self.warnings.append(warning)

    def has_warnings(self) -> bool:
        """Проверяет, есть ли предупреждения."""
        return bool(self.warnings)


@dataclass
class AttackExecutionContext:
    """
    Контекст выполнения атаки.

    Содержит дополнительную информацию, которая может быть полезна
    при выполнении атаки.
    """

    packet_info: Dict[str, Any]
    """Информация о пакете (адреса, порты, протокол)"""

    connection_info: Optional[Dict[str, Any]] = None
    """Информация о соединении"""

    strategy_context: Optional[Dict[str, Any]] = None
    """Контекст стратегии обхода"""

    execution_id: Optional[str] = None
    """Уникальный идентификатор выполнения"""


class AttackParameterTypes:
    """Типы параметров атак для валидации."""

    SPLIT_POSITION = "split_position"
    """Позиция разделения пакета (int или специальные значения)"""

    POSITIONS_LIST = "positions_list"
    """Список позиций для множественного разделения"""

    TTL_VALUE = "ttl_value"
    """Значение TTL (1-255)"""

    OVERLAP_SIZE = "overlap_size"
    """Размер перекрытия для seqovl атак"""

    FOOLING_METHODS = "fooling_methods"
    """Список методов обмана DPI"""

    BOOLEAN_FLAG = "boolean_flag"
    """Булевый флаг"""

    CUSTOM_DATA = "custom_data"
    """Пользовательские данные"""


class SpecialParameterValues:
    """Специальные значения параметров, которые требуют разрешения."""

    CIPHER = "cipher"
    """Позиция начала TLS cipher suite"""

    SNI = "sni"
    """Позиция начала Server Name Indication"""

    MIDSLD = "midsld"
    """Середина второго уровня домена"""

    RANDOM = "random"
    """Случайная позиция в пределах payload"""

    # Список всех специальных значений
    ALL = [CIPHER, SNI, MIDSLD, RANDOM]

    @classmethod
    def is_special_value(cls, value: str) -> bool:
        """Проверяет, является ли значение специальным."""
        return value in cls.ALL


class FoolingMethods:
    """Методы обмана DPI систем."""

    BADSUM = "badsum"
    """Неправильная контрольная сумма"""

    BADSEQ = "badseq"
    """Неправильный sequence number"""

    BADACK = "badack"
    """Неправильный acknowledgment number"""

    DATANOACK = "datanoack"
    """Данные без ACK флага"""

    HOPBYHOP = "hopbyhop"
    """IPv6 Hop-by-Hop заголовок"""

    MD5SIG = "md5sig"
    """MD5 signature TCP option"""

    # Список всех доступных методов
    ALL = [BADSUM, BADSEQ, BADACK, DATANOACK, HOPBYHOP, MD5SIG]

    @classmethod
    def is_valid_method(cls, method: str) -> bool:
        """Проверяет, является ли метод валидным."""
        return method in cls.ALL


class RegistrationPriority(Enum):
    """
    Приоритеты регистрации атак для разрешения конфликтов.

    Система приоритетов позволяет:
    - Гарантировать, что канонические реализации (из primitives.py) имеют высший приоритет
    - Предотвращать случайное перезаписывание проверенных атак экспериментальными
    - Обеспечивать предсказуемое поведение при конфликтах имен
    - Поддерживать механизм продвижения (promotion) эффективных реализаций

    Правила приоритетов:
    - CORE (100): Канонические реализации из primitives.py, не могут быть перезаписаны
    - HIGH (75): Проверенные эффективные реализации, требуют явного подтверждения для замены
    - NORMAL (50): Стандартные внешние атаки, могут быть заменены атаками с более высоким приоритетом
    - LOW (25): Экспериментальные атаки, легко заменяются любыми другими
    """

    CORE = 100
    """Канонические реализации из primitives.py - высший приоритет"""

    HIGH = 75
    """Проверенные эффективные реализации"""

    NORMAL = 50
    """Стандартные внешние атаки"""

    LOW = 25
    """Экспериментальные атаки"""


@dataclass
class AttackEntry:
    """
    Полная запись атаки в реестре с поддержкой приоритетов и отслеживания изменений.

    Содержит всю информацию об атаке:
    - Основные данные (обработчик, метаданные)
    - Информацию о регистрации (приоритет, источник, время)
    - Отслеживание алиасов и продвижений
    - Историю изменений для аудита
    """

    attack_type: str
    """Канонический тип атаки"""

    handler: Callable
    """Функция-обработчик для выполнения атаки"""

    metadata: "AttackMetadata"
    """Метаданные атаки"""

    priority: RegistrationPriority
    """Приоритет регистрации"""

    source_module: str
    """Модуль-источник атаки"""

    registration_time: datetime
    """Время регистрации"""

    is_canonical: bool = True
    """Является ли эта запись канонической (не алиасом)"""

    is_alias_of: Optional[str] = None
    """Ссылка на каноническую атаку, если это алиас"""

    promotion_history: List[Dict[str, Any]] = field(default_factory=list)
    """История продвижений этой атаки"""

    performance_data: Optional[Dict[str, Any]] = None
    """Данные о производительности и эффективности"""


@dataclass
class RegistrationResult:
    """
    Результат попытки регистрации атаки с подробной информацией.

    Предоставляет полную информацию о том, что произошло при регистрации:
    - Успешность операции
    - Выполненное действие (зарегистрировано, заменено, пропущено)
    - Подробное сообщение для логирования
    - Информация о конфликтах для анализа
    """

    success: bool
    """Успешность регистрации"""

    action: str
    """Выполненное действие: 'registered', 'replaced', 'skipped', 'promoted'"""

    message: str
    """Подробное сообщение о результате"""

    attack_type: Optional[str] = None
    """Тип атаки, которая была обработана"""

    conflicts: List[str] = field(default_factory=list)
    """Список конфликтующих атак или алиасов"""

    previous_priority: Optional[RegistrationPriority] = None
    """Предыдущий приоритет при замене"""

    new_priority: Optional[RegistrationPriority] = None
    """Новый приоритет после операции"""


def create_attack_metadata(
    name: str,
    description: str,
    category: str,
    required_params: List[str] = None,
    optional_params: Dict[str, Any] = None,
    aliases: List[str] = None,
) -> AttackMetadata:
    """
    Удобная функция для создания AttackMetadata.

    Args:
        name: Название атаки
        description: Описание атаки
        category: Категория атаки
        required_params: Обязательные параметры
        optional_params: Опциональные параметры
        aliases: Алиасы

    Returns:
        Экземпляр AttackMetadata
    """
    return AttackMetadata(
        name=name,
        description=description,
        required_params=required_params or [],
        optional_params=optional_params or {},
        aliases=aliases or [],
        category=category,
    )
