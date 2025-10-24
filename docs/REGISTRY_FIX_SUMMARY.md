# Registry Import Fix Summary

## Проблема
После рефакторинга появились ошибки импорта модулей реестра атак:
- `No module named 'core.bypass.attacks.registry'`
- `No module named 'core.bypass.attacks.modern_registry'`
- Множественные предупреждения о невозможности импорта модулей атак
- Ошибки регистрации DNS атак

## Корневые причины
1. **Отсутствующие файлы реестра**: Модули атак пытались импортировать `registry.py` и `modern_registry.py`, которые не существовали
2. **Неправильные вызовы регистрации**: DNS атаки использовали неправильный API для регистрации
3. **Отсутствующая категория DNS**: В `AttackCategories` не было категории для DNS атак
4. **Тестовые файлы в загрузке**: Тестовый файл `simple_obfuscation_test.py` пытался загружаться как модуль атак

## Исправления

### 1. Создание недостающих файлов реестра

**Создан `core/bypass/attacks/registry.py`:**
```python
# Импорты из attack_registry.py для обратной совместимости
from .attack_registry import (
    AttackRegistry,
    get_attack_registry,
    register_attack,
    # ... другие функции
)
```

**Создан `core/bypass/attacks/modern_registry.py`:**
```python
# Современный реестр как алиас для существующего
ModernAttackRegistry = AttackRegistry
def get_modern_registry():
    return get_attack_registry()
```

### 2. Добавление недостающих функций в attack_registry.py

Добавлены функции-обертки для глобального доступа:
- `list_attacks()`
- `get_attack_metadata()`
- `clear_registry()`

### 3. Исправление регистрации DNS атак

**Было:**
```python
registry.register_attack(definition, attack_class)  # Неправильные параметры
```

**Стало:**
```python
metadata = AttackMetadata(
    name=definition.name,
    description=definition.description,
    category=AttackCategories.DNS,
    # ... другие параметры
)
registry.register_attack(definition.id, create_handler(attack_class), metadata)
```

### 4. Добавление категории DNS

**В `core/bypass/attacks/metadata.py`:**
```python
class AttackCategories:
    # ... существующие категории
    DNS = "dns"
    """DNS-based атаки и туннелирование"""
    
    # Обновлен список всех категорий
    ALL = [SPLIT, DISORDER, FAKE, RACE, OVERLAP, FRAGMENT, TIMING, CUSTOM, DNS]
```

### 5. Исключение тестовых файлов

Обновлена функция `load_all_attacks()` для исключения:
- `simple_obfuscation_test` (тестовый файл)
- Другие демо и тестовые файлы

## Результаты

### До исправления:
- ❌ Множественные ошибки импорта registry
- ❌ 0 DNS атак зарегистрировано
- ❌ Предупреждения о невозможности импорта модулей

### После исправления:
- ✅ Все модули атак загружаются без ошибок
- ✅ 4 DNS атаки успешно зарегистрированы
- ✅ 19 атак загружено в общей сложности
- ✅ Только предупреждения о перезаписи (нормальное поведение)

## Загруженные атаки
Теперь успешно загружается 19 атак:
1. fakeddisorder
2. seqovl  
3. multidisorder
4. disorder
5. disorder2
6. multisplit
7. split
8. fake
9. fake_fakeddisorder
10. tcp_window_scaling
11. dns_doh_tunneling
12. dns_dot_tunneling
13. dns_query_manipulation
14. dns_cache_poisoning_prevention
15. ... и другие

## Ключевые принципы исправления
1. **Обратная совместимость**: Созданы файлы-мосты для старых импортов
2. **Правильная архитектура**: Использование существующего `attack_registry.py` как основы
3. **Полная валидация**: Добавлена поддержка новых категорий атак
4. **Чистая загрузка**: Исключение тестовых файлов из автоматической загрузки