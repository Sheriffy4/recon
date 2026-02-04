# Attack Registry Components

Модульные компоненты рефакторенного AttackRegistry для управления DPI bypass атаками.

## Обзор

Этот пакет содержит рефакторенные компоненты AttackRegistry, разбитые на специализированные менеджеры с четким разделением ответственности.

## Архитектура

```
registry/
├── interfaces.py          # Интерфейсы для всех компонентов
├── models.py              # Модели данных (dataclasses)
├── config.py              # Централизованная конфигурация
├── alias_manager.py       # Управление алиасами атак
├── parameter_validator.py # Валидация параметров атак
├── priority_manager.py    # Управление приоритетами регистрации
├── lazy_loading_manager.py # Ленивая загрузка модулей
├── handler_factory.py     # Создание обработчиков атак
├── registration_manager.py # Управление регистрацией атак
└── decorator.py           # Декоратор для регистрации
```

## Компоненты

### 1. Interfaces (`interfaces.py`)
Определяет интерфейсы для всех компонентов:
- `IAliasManager` - управление алиасами
- `IParameterValidator` - валидация параметров
- `IPriorityManager` - управление приоритетами
- `ILazyLoadingManager` - ленивая загрузка
- `IHandlerFactory` - создание обработчиков
- `IAttackRegistry` - основной реестр
- `BaseRegistryComponent` - базовый компонент

### 2. Models (`models.py`)
Модели данных для реестра:
- `AttackEntry` - запись об атаке в реестре
- `AttackMetadata` - метаданные атаки
- `ValidationResult` - результат валидации
- `RegistrationResult` - результат регистрации
- `RegistrationPriority` - приоритеты регистрации
- `AttackExecutionContext` - контекст выполнения
- `ComponentStatus` - статус компонента
- `RegistryStats` - статистика реестра
- `LoadingStats` - статистика загрузки
- `ValidationConfig` - конфигурация валидации
- `LazyLoadingConfig` - конфигурация lazy loading

### 3. Config (`config.py`)
Централизованная конфигурация:
```python
from core.bypass.attacks.registry import RegistryConfig, DEFAULT_CONFIG

# Использование конфигурации по умолчанию
config = DEFAULT_CONFIG

# Создание кастомной конфигурации
custom_config = RegistryConfig(
    enable_lazy_loading=True,
    enable_alias_validation=True,
    max_alias_chain_depth=5
)
```

### 4. AliasManager (`alias_manager.py`)
Управление алиасами атак:
```python
from core.bypass.attacks.registry import AttackAliasManager

manager = AttackAliasManager()
manager.register_alias("fake_disorder", "fakeddisorder")
canonical = manager.resolve_name("fake_disorder")  # "fakeddisorder"
```

**Возможности**:
- Регистрация алиасов
- Разрешение алиасов в канонические имена
- Обнаружение конфликтов
- Поддержка цепочек алиасов

### 5. ParameterValidator (`parameter_validator.py`)
Валидация параметров атак:
```python
from core.bypass.attacks.registry import AttackParameterValidator

validator = AttackParameterValidator()
result = validator.validate_parameters(
    attack_type="fakeddisorder",
    params={"split_pos": 3, "ttl": 5},
    metadata=attack_metadata
)

if result.is_valid:
    print("Parameters valid")
else:
    print(f"Validation error: {result.error_message}")
```

**Возможности**:
- Проверка обязательных параметров
- Валидация типов
- Проверка диапазонов значений
- Кастомные валидаторы
- Детальные сообщения об ошибках

### 6. PriorityManager (`priority_manager.py`)
Управление приоритетами регистрации:
```python
from core.bypass.attacks.registry import PriorityManager, RegistrationPriority

manager = PriorityManager()
result = manager.resolve_conflict(
    existing_priority=RegistrationPriority.NORMAL,
    new_priority=RegistrationPriority.HIGH
)
```

**Приоритеты**:
- `CORE` (100) - встроенные атаки, наивысший приоритет
- `HIGH` (75) - важные внешние атаки
- `NORMAL` (50) - обычные атаки
- `LOW` (25) - экспериментальные атаки

### 7. LazyLoadingManager (`lazy_loading_manager.py`)
Ленивая загрузка модулей атак:
```python
from core.bypass.attacks.registry import LazyLoadingManager

manager = LazyLoadingManager()
manager.discover_modules(attacks_dir)
manager.load_module_on_demand("core.bypass.attacks.tcp.fakeddisorder")
stats = manager.get_loading_stats()
```

**Возможности**:
- Обнаружение модулей без загрузки
- Загрузка по требованию
- Кэширование загруженных модулей
- Статистика загрузки

### 8. HandlerFactory (`handler_factory.py`)
Создание обработчиков атак:
```python
from core.bypass.attacks.registry import AttackHandlerFactory

factory = AttackHandlerFactory()
handler = factory.create_handler("fakeddisorder", metadata)
```

**Поддерживаемые типы**:
- Функции
- Классы (с методом execute)
- Async функции/методы
- Lambda функции

### 9. RegistrationManager (`registration_manager.py`)
Управление регистрацией атак:
```python
from core.bypass.attacks.registry import RegistrationManager

manager = RegistrationManager()
result = manager.handle_duplicate_registration(
    attack_type="fakeddisorder",
    handler=new_handler,
    metadata=new_metadata,
    priority=RegistrationPriority.HIGH,
    source_module="external.module",
    existing_entry=existing_entry,
    attacks=attacks_dict,
    alias_manager=alias_manager
)
```

**Возможности**:
- Обработка дубликатов
- Разрешение конфликтов по приоритетам
- Отслеживание истории регистрации
- Статистика регистрации

### 10. Decorator (`decorator.py`)
Декоратор для регистрации атак:
```python
from core.bypass.attacks.registry import register_attack
from core.bypass.attacks.metadata import AttackCategories

@register_attack(
    name="my_attack",
    category=AttackCategories.TCP,
    priority=RegistrationPriority.NORMAL,
    required_params=["split_pos"],
    optional_params={"ttl": 3},
    aliases=["my_attack_alias"],
    description="My custom attack"
)
class MyAttack(BaseAttack):
    def execute(self, context):
        # Implementation
        pass
```

## Использование

### Базовое использование
```python
from core.bypass.attacks import get_attack_registry

# Получить реестр
registry = get_attack_registry()

# Получить обработчик атаки
handler = registry.get_attack_handler("fakeddisorder")

# Получить метаданные
metadata = registry.get_attack_metadata("fakeddisorder")

# Валидировать параметры
result = registry.validate_parameters("fakeddisorder", {"split_pos": 3})
```

### Использование компонентов напрямую
```python
from core.bypass.attacks import (
    AttackAliasManager,
    AttackParameterValidator,
    AttackHandlerFactory
)

# Создать alias manager
alias_manager = AttackAliasManager()
alias_manager.register_alias("fake_disorder", "fakeddisorder")

# Создать validator
validator = AttackParameterValidator()
result = validator.validate_parameters("attack", params, metadata)

# Создать handler factory
factory = AttackHandlerFactory()
handler = factory.create_handler("attack", metadata)
```

## Документация

- [Step 11 Complete](../../../REFACTORING_STEP_11_COMPLETE.md) - Детальная документация Step 11
- [Steps 1-11 Complete](../../../REFACTORING_STEPS_1-11_COMPLETE.md) - Общий обзор рефакторинга
- [Bugfix Report](../../../BUGFIX_ATTACK_REGISTRY_IMPORTS.md) - Исправления импортов

## Лицензия

См. LICENSE в корне проекта.
