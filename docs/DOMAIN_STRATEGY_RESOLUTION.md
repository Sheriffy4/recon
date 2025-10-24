# Domain Strategy Resolution - Унификация Стратегий

## Проблема

При тестировании обхода DPI для одного и того же сайта могут получаться разные стратегии для `www.example.com` и `example.com`:

```
www.x.com    → --dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 ... (2317.8ms)
x.com        → --dpi-desync=fake,disorder2 --dpi-desync-split-pos=1 ...     (1254.4ms)
mobile.x.com → --dpi-desync=fake,disorder2 --dpi-desync-split-pos=1 ...     (1264.3ms)
```

**Вопрос**: Какая стратегия будет применяться в итоге?

## Решение

Система автоматического разрешения конфликтов доменов:

1. **Нормализация**: `www.example.com` → `example.com`
2. **Группировка**: Все варианты домена группируются вместе
3. **Разрешение конфликтов**: Выбирается лучшая стратегия по score
4. **Применение**: Одна стратегия применяется ко всем вариантам

## Компоненты

### 1. DomainStrategyResolver

Основной класс для разрешения конфликтов:

```python
from core.strategy.domain_strategy_resolver import DomainStrategyResolver

# Создать resolver
resolver = DomainStrategyResolver()

# Добавить стратегии
resolver.add_strategy(
    domain="www.x.com",
    strategy="--dpi-desync=fake,fakeddisorder ...",
    latency_ms=2317.8,
    confidence=0.95
)

resolver.add_strategy(
    domain="x.com",
    strategy="--dpi-desync=fake,disorder2 ...",
    latency_ms=1254.4,
    confidence=0.90
)

# Разрешить конфликты
resolved = resolver.resolve_conflicts()

# Получить унифицированные стратегии
unified = resolver.export_unified_strategies()
# {'x.com': '--dpi-desync=fake,disorder2 ...'}  # Выбрана стратегия с меньшим latency
```

### 2. UnifiedStrategySaver

Сохранение стратегий с автоматическим разрешением:

```python
from core.strategy.unified_strategy_saver import UnifiedStrategySaver

# Создать saver
saver = UnifiedStrategySaver(
    output_file="unified_strategies.json",
    report_file="strategy_resolution_report.json"
)

# Сохранить с разрешением конфликтов
strategies = {
    "www.x.com": {"strategy": "...", "latency_ms": 2317.8},
    "x.com": {"strategy": "...", "latency_ms": 1254.4}
}

unified = saver.save_strategies(strategies)

# Получить стратегию для любого варианта домена
strategy = saver.get_strategy_for_domain("www.x.com")  # Вернет стратегию для x.com
```

## Правила Разрешения Конфликтов

### 1. Нормализация Доменов

```python
www.example.com  → example.com
WWW.EXAMPLE.COM  → example.com
Example.Com      → example.com
```

### 2. Группировка Вариантов

Все варианты одного домена группируются:

```
Группа "x.com":
  - www.x.com
  - x.com
  - WWW.X.COM
```

### 3. Выбор Лучшей Стратегии

**Score Formula**:
```
normalized_latency = min(latency_ms / 5000.0, 1.0)
score = confidence * (1.0 - normalized_latency)
```

**Критерии** (в порядке приоритета):
1. **Score** (выше = лучше)
2. **Latency** (меньше = лучше)
3. **Confidence** (выше = лучше)

**Пример**:
```
www.x.com: latency=2317.8ms, confidence=0.95 → score = 0.95 * (1 - 0.464) = 0.509
x.com:     latency=1254.4ms, confidence=0.90 → score = 0.90 * (1 - 0.251) = 0.674

Выбрана: x.com (score 0.674 > 0.509)
```

### 4. Поддомены

Поддомены обрабатываются отдельно, но могут наследовать стратегию родителя:

```
example.com      → стратегия A
api.example.com  → стратегия B (если есть)
                 → стратегия A (если нет своей)
```

## Использование

### Базовое Использование

```python
from core.strategy.domain_strategy_resolver import resolve_domain_strategies

# Простой словарь стратегий
strategies = {
    "www.x.com": {
        "strategy": "--dpi-desync=fake,fakeddisorder ...",
        "latency_ms": 2317.8,
        "confidence": 0.95
    },
    "x.com": {
        "strategy": "--dpi-desync=fake,disorder2 ...",
        "latency_ms": 1254.4,
        "confidence": 0.90
    }
}

# Разрешить конфликты
unified = resolve_domain_strategies(strategies)

print(unified)
# {'x.com': '--dpi-desync=fake,disorder2 ...'}
```

### Сохранение с Разрешением

```python
from core.strategy.unified_strategy_saver import save_unified_strategies

# Сохранить с автоматическим разрешением
unified = save_unified_strategies(
    strategies,
    output_file="unified_strategies.json",
    report_file="strategy_resolution_report.json"
)

# Файлы созданы:
# - unified_strategies.json - унифицированные стратегии
# - strategy_resolution_report.json - детальный отчет
```

### Загрузка и Получение Стратегии

```python
from core.strategy.unified_strategy_saver import UnifiedStrategySaver

saver = UnifiedStrategySaver("unified_strategies.json")

# Загрузить все стратегии
all_strategies = saver.load_strategies()

# Получить стратегию для конкретного домена
strategy = saver.get_strategy_for_domain("www.x.com")
# Вернет стратегию для x.com (канонический домен)

# Работает для любого варианта
strategy1 = saver.get_strategy_for_domain("x.com")
strategy2 = saver.get_strategy_for_domain("www.x.com")
strategy3 = saver.get_strategy_for_domain("WWW.X.COM")
# Все вернут одну и ту же стратегию
```

### Объединение со Существующими

```python
saver = UnifiedStrategySaver("unified_strategies.json")

# Новые стратегии
new_strategies = {
    "www.example.com": {"strategy": "...", "latency_ms": 500.0}
}

# Объединить с существующими
unified = saver.merge_with_existing(
    new_strategies,
    prefer_new=True  # Предпочитать новые при конфликтах
)
```

### Просмотр Отчета

```python
saver = UnifiedStrategySaver(
    output_file="unified_strategies.json",
    report_file="strategy_resolution_report.json"
)

# Сохранить стратегии
saver.save_strategies(strategies)

# Вывести отчет о конфликтах
saver.print_conflicts_report()
```

**Вывод**:
```
================================================================================
STRATEGY RESOLUTION REPORT
================================================================================
Total strategies: 7
Resolved domains: 4
Conflicts detected: 3

--------------------------------------------------------------------------------
CONFLICTS RESOLVED:
--------------------------------------------------------------------------------

x.com:
  Strategy: --dpi-desync=fake,disorder2 --dpi-desync-split-pos=1 ...
  Applies to: www.x.com, x.com, mobile.x.com
  Latency: 1254.4ms
  Confidence: 0.90
  Reasoning:
    Conflict resolved for x.com:
      Selected: x.com (score: 0.674, latency: 1254.4ms)
      Rejected: www.x.com (score: 0.509, latency: 2317.8ms)

youtube.com:
  Strategy: --dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 ...
  Applies to: www.youtube.com, youtube.com
  Latency: 634.6ms
  Confidence: 0.95
  ...
```

## Интеграция

### С Recon Summary

```python
import json
from core.strategy.unified_strategy_saver import UnifiedStrategySaver

# Загрузить recon_summary.json
with open("recon_summary.json") as f:
    recon_data = json.load(f)

# Извлечь стратегии
strategies = {}
for result in recon_data.get("results", []):
    domain = result.get("domain")
    strategy = result.get("best_strategy", {})
    
    strategies[domain] = {
        "strategy": strategy.get("strategy", ""),
        "latency_ms": strategy.get("avg_latency_ms", 0.0),
        "confidence": strategy.get("success_rate", 1.0)
    }

# Сохранить с разрешением
saver = UnifiedStrategySaver()
unified = saver.save_strategies(strategies)
```

### С Hybrid Engine

```python
from core.hybrid_engine import HybridEngine
from core.strategy.unified_strategy_saver import UnifiedStrategySaver

# Получить результаты тестирования
engine = HybridEngine()
results = await engine.test_strategies_hybrid(...)

# Преобразовать в формат для сохранения
strategies = {}
for result in results:
    domain = result.get("domain")
    strategies[domain] = {
        "strategy": result.get("strategy"),
        "latency_ms": result.get("avg_latency_ms"),
        "confidence": result.get("success_rate")
    }

# Сохранить с разрешением
saver = UnifiedStrategySaver()
unified = saver.save_strategies(strategies)
```

### С CLI

```python
# cli.py

@click.command()
@click.option('--input', required=True, help='Input strategies file')
@click.option('--output', default='unified_strategies.json')
def unify_strategies(input: str, output: str):
    """Унифицировать стратегии с разрешением конфликтов"""
    
    # Загрузить входные стратегии
    with open(input) as f:
        strategies = json.load(f)
    
    # Сохранить с разрешением
    from core.strategy.unified_strategy_saver import UnifiedStrategySaver
    
    saver = UnifiedStrategySaver(
        output_file=output,
        report_file=output.replace('.json', '_report.json')
    )
    
    unified = saver.save_strategies(strategies)
    
    click.echo(f"Unified {len(strategies)} → {len(unified)} strategies")
    click.echo(f"Saved to {output}")
    
    # Вывести отчет
    saver.print_conflicts_report()
```

## Формат Файлов

### unified_strategies.json

```json
{
  "metadata": {
    "timestamp": "2025-10-21T12:00:00",
    "total_input_strategies": 7,
    "unified_strategies": 4,
    "conflicts_resolved": 3
  },
  "strategies": {
    "x.com": "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=1 ...",
    "youtube.com": "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 ...",
    "facebook.com": "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=midsld ...",
    "instagram.com": "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=1 ..."
  }
}
```

### strategy_resolution_report.json

```json
{
  "metadata": {
    "timestamp": "2025-10-21T12:00:00",
    "total_input_strategies": 7,
    "unified_strategies": 4,
    "conflicts_resolved": 3
  },
  "total_strategies": 7,
  "resolved_domains": 4,
  "conflicts_detected": 3,
  "strategies": [
    {
      "canonical_domain": "x.com",
      "strategy": "--dpi-desync=fake,disorder2 ...",
      "applies_to": ["www.x.com", "x.com", "mobile.x.com"],
      "latency_ms": 1254.4,
      "confidence": 0.90,
      "has_conflict": true,
      "reasoning": [
        "Conflict resolved for x.com:",
        "  Selected: x.com (score: 0.674, latency: 1254.4ms)",
        "  Rejected: www.x.com (score: 0.509, latency: 2317.8ms)",
        "  Rejected: mobile.x.com (score: 0.673, latency: 1264.3ms)"
      ]
    }
  ]
}
```

## Примеры

### Пример 1: Базовое Разрешение

```python
from core.strategy.domain_strategy_resolver import DomainStrategyResolver

resolver = DomainStrategyResolver()

# Добавить конфликтующие стратегии
resolver.add_strategy("www.x.com", "strategy_A", 2000.0, confidence=0.95)
resolver.add_strategy("x.com", "strategy_B", 1000.0, confidence=0.90)

# Разрешить
resolved = resolver.resolve_conflicts()

# Результат: выбрана strategy_B (лучший score)
print(resolved["x.com"].strategy)  # "strategy_B"
```

### Пример 2: Поддомены

```python
resolver = DomainStrategyResolver()

# Родительский домен
resolver.add_strategy("example.com", "strategy_parent", 1000.0)

# Поддомен со своей стратегией
resolver.add_strategy("api.example.com", "strategy_api", 500.0)

resolver.resolve_conflicts()

# Получить стратегии
parent_strategy = resolver.get_strategy_for_domain("example.com")
api_strategy = resolver.get_strategy_for_domain("api.example.com")
unknown_strategy = resolver.get_strategy_for_domain("unknown.example.com")

print(parent_strategy.strategy)   # "strategy_parent"
print(api_strategy.strategy)      # "strategy_api"
print(unknown_strategy.strategy)  # "strategy_parent" (наследуется)
```

### Пример 3: Объединение Источников

```python
from core.strategy.unified_strategy_saver import UnifiedStrategySaver

saver = UnifiedStrategySaver("unified_strategies.json")

# Существующие стратегии (из предыдущего запуска)
# x.com → strategy_old

# Новые стратегии (из нового тестирования)
new_strategies = {
    "www.x.com": {"strategy": "strategy_new", "latency_ms": 800.0, "confidence": 0.95}
}

# Объединить (предпочитать новые)
unified = saver.merge_with_existing(new_strategies, prefer_new=True)

# Результат: strategy_new (новая стратегия с высоким confidence)
```

## Best Practices

### 1. Всегда Разрешайте Конфликты

```python
# ❌ Плохо: сохранять без разрешения
with open("strategies.json", "w") as f:
    json.dump(strategies, f)

# ✅ Хорошо: использовать UnifiedStrategySaver
saver = UnifiedStrategySaver()
saver.save_strategies(strategies)
```

### 2. Сохраняйте Отчеты

```python
# ✅ Всегда сохраняйте отчет для отладки
saver = UnifiedStrategySaver(
    output_file="strategies.json",
    report_file="resolution_report.json"  # Важно!
)
```

### 3. Проверяйте Конфликты

```python
saver.save_strategies(strategies)

# Проверить сколько конфликтов
report = saver.resolver.export_detailed_report()
if report['conflicts_detected'] > 0:
    print(f"⚠️  {report['conflicts_detected']} conflicts detected")
    saver.print_conflicts_report()
```

### 4. Используйте Канонические Домены

```python
# ❌ Плохо: хранить оба варианта
strategies = {
    "www.example.com": "strategy_A",
    "example.com": "strategy_B"
}

# ✅ Хорошо: использовать канонический
strategies = {
    "example.com": "strategy_unified"
}
```

## Troubleshooting

### Проблема: Неожиданная Стратегия

**Симптом**: Для `www.x.com` применяется стратегия от `x.com`

**Решение**: Это нормально! Система унифицирует домены. Проверьте отчет:

```python
saver.print_conflicts_report()
```

### Проблема: Поддомен Не Находит Стратегию

**Симптом**: `api.example.com` возвращает `None`

**Решение**: Убедитесь что есть стратегия для родительского домена:

```python
# Добавить стратегию для родителя
resolver.add_strategy("example.com", "strategy", 1000.0)

# Теперь поддомены будут наследовать
strategy = resolver.get_strategy_for_domain("api.example.com")
```

### Проблема: Конфликт Не Разрешается

**Симптом**: Обе стратегии имеют одинаковый score

**Решение**: Система выберет по latency. Можно увеличить confidence для предпочитаемой:

```python
resolver.add_strategy("x.com", "preferred", 1000.0, confidence=0.95)
resolver.add_strategy("www.x.com", "other", 1000.0, confidence=0.90)
# Будет выбрана "preferred" (выше confidence)
```

## См. Также

- `core/strategy/domain_strategy_resolver.py` - Основной класс
- `core/strategy/unified_strategy_saver.py` - Сохранение стратегий
- `docs/FINGERPRINTING_INTEGRATION_GUIDE.md` - Интеграция с fingerprinting
