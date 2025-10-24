# Domain Strategy Unification - Краткая Инструкция

## Проблема

При запуске службы обхода для одного сайта получаются разные стратегии:

```
www.x.com    → стратегия A (2317.8ms)
x.com        → стратегия B (1254.4ms)
mobile.x.com → стратегия B (1264.3ms)
```

**Вопрос**: Какая стратегия применится?

## Решение

Система автоматической унификации доменов:

1. ✅ **Нормализация**: `www.example.com` → `example.com`
2. ✅ **Группировка**: Все варианты домена объединяются
3. ✅ **Выбор лучшей**: По формуле `score = confidence * (1 - latency/5000)`
4. ✅ **Применение**: Одна стратегия для всех вариантов

## Быстрый Старт

### 1. Базовое Использование

```python
from core.strategy.unified_strategy_saver import save_unified_strategies

# Ваши стратегии (из recon_summary.json или другого источника)
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

# Сохранить с автоматическим разрешением конфликтов
unified = save_unified_strategies(
    strategies,
    output_file="unified_strategies.json",
    report_file="strategy_resolution_report.json"
)

# Результат:
# unified = {'x.com': '--dpi-desync=fake,disorder2 ...'}
# Выбрана стратегия с лучшим score (меньше latency)
```

### 2. Интеграция с Существующим Кодом

```python
from core.strategy.unified_strategy_saver import UnifiedStrategySaver

# Создать saver
saver = UnifiedStrategySaver("unified_strategies.json")

# Сохранить стратегии
saver.save_strategies(your_strategies)

# Получить стратегию для любого варианта домена
strategy = saver.get_strategy_for_domain("www.x.com")
# Вернет стратегию для x.com (канонический домен)

# Работает для всех вариантов:
saver.get_strategy_for_domain("x.com")        # → та же стратегия
saver.get_strategy_for_domain("www.x.com")    # → та же стратегия
saver.get_strategy_for_domain("WWW.X.COM")    # → та же стратегия
```

### 3. Просмотр Отчета

```python
saver = UnifiedStrategySaver(
    output_file="unified_strategies.json",
    report_file="strategy_resolution_report.json"
)

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
```

## Правила Выбора Стратегии

### Score Formula
```python
normalized_latency = min(latency_ms / 5000.0, 1.0)
score = confidence * (1.0 - normalized_latency)
```

### Критерии (в порядке приоритета)
1. **Score** (выше = лучше)
2. **Latency** (меньше = лучше)
3. **Confidence** (выше = лучше)

### Пример Расчета

```
www.x.com:
  latency = 2317.8ms, confidence = 0.95
  normalized_latency = 2317.8 / 5000 = 0.464
  score = 0.95 * (1 - 0.464) = 0.509

x.com:
  latency = 1254.4ms, confidence = 0.90
  normalized_latency = 1254.4 / 5000 = 0.251
  score = 0.90 * (1 - 0.251) = 0.674

Выбрана: x.com (score 0.674 > 0.509)
```

## Интеграция с CLI

### Добавить команду унификации

```python
# cli.py

@click.command()
@click.option('--input', required=True, help='Input strategies file')
@click.option('--output', default='unified_strategies.json')
def unify_strategies(input: str, output: str):
    """Унифицировать стратегии с разрешением конфликтов"""
    
    import json
    from core.strategy.unified_strategy_saver import UnifiedStrategySaver
    
    # Загрузить входные стратегии
    with open(input) as f:
        strategies = json.load(f)
    
    # Сохранить с разрешением
    saver = UnifiedStrategySaver(
        output_file=output,
        report_file=output.replace('.json', '_report.json')
    )
    
    unified = saver.save_strategies(strategies)
    
    click.echo(f"✅ Unified {len(strategies)} → {len(unified)} strategies")
    click.echo(f"📄 Saved to {output}")
    
    # Вывести отчет
    saver.print_conflicts_report()
```

### Использование

```bash
# Унифицировать стратегии из recon_summary.json
python cli.py unify-strategies --input recon_summary.json --output unified_strategies.json

# Результат:
# ✅ Unified 7 → 4 strategies
# 📄 Saved to unified_strategies.json
# 
# STRATEGY RESOLUTION REPORT
# ...
```

## Интеграция с Recon Summary

```python
import json
from core.strategy.unified_strategy_saver import UnifiedStrategySaver

# Загрузить recon_summary.json
with open("recon_summary.json") as f:
    recon_data = json.load(f)

# Извлечь стратегии по доменам
strategies = {}
for result in recon_data.get("results", []):
    domain = result.get("domain")
    best_strategy = result.get("best_strategy", {})
    
    strategies[domain] = {
        "strategy": best_strategy.get("strategy", ""),
        "latency_ms": best_strategy.get("avg_latency_ms", 0.0),
        "confidence": best_strategy.get("success_rate", 1.0),
        "source": "recon"
    }

# Сохранить с разрешением
saver = UnifiedStrategySaver()
unified = saver.save_strategies(strategies, metadata={
    "source": "recon_summary.json",
    "recon_timestamp": recon_data.get("timestamp")
})

print(f"✅ Saved {len(unified)} unified strategies")
```

## Формат Выходных Файлов

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

Детальный отчет о разрешении конфликтов с reasoning для каждого домена.

## Применение в Службе Обхода

### Вариант 1: Использовать Унифицированные Стратегии

```python
from core.strategy.unified_strategy_saver import UnifiedStrategySaver

# Загрузить унифицированные стратегии
saver = UnifiedStrategySaver("unified_strategies.json")
strategies = saver.load_strategies()

# Применить к службе обхода
for domain, strategy in strategies.items():
    apply_strategy_to_service(domain, strategy)
    
    # Стратегия автоматически применится ко всем вариантам:
    # - example.com
    # - www.example.com
    # - WWW.EXAMPLE.COM
```

### Вариант 2: Динамическое Получение

```python
saver = UnifiedStrategySaver("unified_strategies.json")

# Получить стратегию для конкретного запроса
def get_strategy_for_request(domain: str) -> str:
    strategy = saver.get_strategy_for_domain(domain)
    if strategy:
        return strategy
    
    # Fallback: использовать стратегию по умолчанию
    return DEFAULT_STRATEGY

# Использование
strategy = get_strategy_for_request("www.x.com")  # Вернет стратегию для x.com
```

## Преимущества

✅ **Консистентность**: Одна стратегия для всех вариантов домена  
✅ **Оптимальность**: Автоматический выбор лучшей стратегии  
✅ **Прозрачность**: Детальный отчет о разрешении конфликтов  
✅ **Гибкость**: Поддержка поддоменов и наследования  
✅ **Простота**: Минимум кода для интеграции  

## Файлы

**Код**:
- `core/strategy/domain_strategy_resolver.py` - Основной класс разрешения
- `core/strategy/unified_strategy_saver.py` - Сохранение с разрешением

**Документация**:
- `docs/DOMAIN_STRATEGY_RESOLUTION.md` - Полная документация
- `DOMAIN_UNIFICATION_SUMMARY.md` - Эта инструкция

## Примеры

### Пример 1: Из Вашего Лога

```python
from core.strategy.unified_strategy_saver import save_unified_strategies

# Данные из вашего лога
strategies = {
    "www.x.com": {
        "strategy": "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=5",
        "latency_ms": 2317.8
    },
    "x.com": {
        "strategy": "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=1 --dpi-desync-fooling=badsum --dpi-desync-ttl=2",
        "latency_ms": 1254.4
    },
    "mobile.x.com": {
        "strategy": "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=1 --dpi-desync-fooling=badsum --dpi-desync-ttl=2",
        "latency_ms": 1264.3
    }
}

# Унифицировать
unified = save_unified_strategies(strategies)

# Результат:
# {
#   "x.com": "--dpi-desync=fake,disorder2 --dpi-desync-split-pos=1 --dpi-desync-fooling=badsum --dpi-desync-ttl=2"
# }
#
# Эта стратегия будет применяться для:
# - x.com
# - www.x.com
# - mobile.x.com
```

### Пример 2: Все Домены из Лога

```python
strategies = {
    "www.x.com": {"strategy": "...", "latency_ms": 2317.8},
    "x.com": {"strategy": "...", "latency_ms": 1254.4},
    "mobile.x.com": {"strategy": "...", "latency_ms": 1264.3},
    "www.youtube.com": {"strategy": "...", "latency_ms": 634.6},
    "youtube.com": {"strategy": "...", "latency_ms": 1782.4},
    "www.facebook.com": {"strategy": "...", "latency_ms": 201.9},
    "facebook.com": {"strategy": "...", "latency_ms": 2279.9},
    "instagram.com": {"strategy": "...", "latency_ms": 3034.7},
    # ... и т.д.
}

unified = save_unified_strategies(strategies)

# Результат: 4 унифицированных домена вместо 7+
# - x.com (для www.x.com, x.com, mobile.x.com)
# - youtube.com (для www.youtube.com, youtube.com)
# - facebook.com (для www.facebook.com, facebook.com)
# - instagram.com
```

## Следующие Шаги

1. ✅ **Интегрировать в CLI**: Добавить команду `unify-strategies`
2. ✅ **Обновить recon workflow**: Автоматически унифицировать после тестирования
3. ✅ **Применить к службе**: Использовать унифицированные стратегии
4. ✅ **Мониторинг**: Отслеживать конфликты в production

## Поддержка

Для вопросов и проблем:
- См. `docs/DOMAIN_STRATEGY_RESOLUTION.md` - полная документация
- Запустить примеры: `python core/strategy/domain_strategy_resolver.py`
- Запустить примеры: `python core/strategy/unified_strategy_saver.py`

---

**Статус**: ✅ Готово к использованию  
**Дата**: 2025-10-21
