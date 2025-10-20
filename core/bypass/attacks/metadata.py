"""
Метаданные и вспомогательные классы для системы атак DPI обхода.

Этот модуль содержит:
- AttackMetadata: класс для описания метаданных атак
- AttackCategories: константы категорий атак
- ValidationResult: результат валидации параметров
"""

from dataclasses import dataclass
from typing import List, Dict, Any, Optional


@dataclass
class AttackMetadata:
    """
    Метаданные атаки DPI обхода.
    
    Содержит всю необходимую информацию для регистрации,
    валидации и использования атаки.
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
            raise ValueError(f"Invalid category '{self.category}'. Must be one of: {AttackCategories.ALL}")


class AttackCategories:
    """Константы для категорий атак DPI обхода."""
    
    SPLIT = "split"
    """Атаки, основанные на разделении пакетов"""
    
    DISORDER = "disorder"
    """Атаки, основанные на изменении порядка частей пакета"""
    
    FAKE = "fake"
    """Атаки с использованием фейковых пакетов"""
    
    RACE = "race"
    """Атаки типа race condition"""
    
    OVERLAP = "overlap"
    """Атаки с перекрытием последовательностей"""
    
    FRAGMENT = "fragment"
    """Атаки на основе фрагментации"""
    
    TIMING = "timing"
    """Атаки, основанные на временных задержках"""
    
    CUSTOM = "custom"
    """Пользовательские атаки"""
    
    # Список всех доступных категорий
    ALL = [SPLIT, DISORDER, FAKE, RACE, OVERLAP, FRAGMENT, TIMING, CUSTOM]


@dataclass
class ValidationResult:
    """
    Результат валидации параметров атаки.
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
    
    # Список всех специальных значений
    ALL = [CIPHER, SNI, MIDSLD]
    
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
    
    # Список всех доступных методов
    ALL = [BADSUM, BADSEQ, BADACK, DATANOACK, HOPBYHOP]
    
    @classmethod
    def is_valid_method(cls, method: str) -> bool:
        """Проверяет, является ли метод валидным."""
        return method in cls.ALL


def create_attack_metadata(name: str,
                          description: str,
                          category: str,
                          required_params: List[str] = None,
                          optional_params: Dict[str, Any] = None,
                          aliases: List[str] = None) -> AttackMetadata:
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
        category=category
    )