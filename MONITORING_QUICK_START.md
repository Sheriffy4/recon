# Мониторинг и Автоматическая Оптимизация - Быстрый Старт

## Проблема

У вас есть стратегии в `domain_strategies.json`, но:
- ❌ rutracker.org и nnmclub.to открываются, но картинки не загружаются
- ⚠️  x.com работает медленно
- ❌ instagram висит на начальном экране

**Нужно**: Автоматически мониторить и оптимизировать стратегии.

## Решение

Система автоматического мониторинга и оптимизации:

1. ✅ **Мониторинг** - Периодическая проверка доступности
2. ✅ **Обнаружение проблем** - Детекция деградации
3. ✅ **Автооптимизация** - Автоматический поиск лучших стратегий
4. ✅ **Адаптация** - Обновление стратегий при изменении DPI

## Быстрый Старт

### 1. Запустить Мониторинг

```bash
# Запустить с автооптимизацией
python cli_monitor.py start

# Или с настройками
python cli_monitor.py start \
    --strategies domain_strategies.json \
    --interval 300 \
    --threshold 3
```

**Что происходит:**
- Каждые 5 минут (300s) проверяются все домены
- При 3 неудачах подряд запускается оптимизация
- Новые стратегии автоматически сохраняются

### 2. Проверить Статус

```bash
# Показать текущий статус
python cli_monitor.py status

# Проверить конкретный домен
python cli_monitor.py check instagram.com
```

### 3. Оптимизировать Вручную

```bash
# Оптимизировать один домен
python cli_monitor.py optimize instagram.com --save

# Оптимизировать все домены
python cli_monitor.py optimize-all
```

## Решение Ваших Проблем

### Проблема 1: Картинки не загружаются (rutracker.org, nnmclub.to)

**Причина**: Стратегия работает для основного домена, но не для поддоменов/CDN.

**Решение**:

```bash
# 1. Добавить поддомены в мониторинг
python cli_monitor.py add-domains \
    static.rutracker.cc \
    i.rutracker.cc \
    cdn.nnmclub.to

# 2. Оптимизировать
python cli_monitor.py optimize static.rutracker.cc --save
python cli_monitor.py optimize cdn.nnmclub.to --save

# 3. Запустить мониторинг
python cli_monitor.py start
```

**Альтернатива** - Использовать wildcard стратегию:

```json
{
  "strategies": {
    "rutracker.org": "стратегия A",
    "*.rutracker.cc": "стратегия A",  // Для всех поддоменов
    "nnmclub.to": "стратегия B",
    "*.nnmclub.to": "стратегия B"
  }
}
```

### Проблема 2: x.com работает медленно

**Причина**: Текущая стратегия не оптимальна.

**Решение**:

```bash
# 1. Проверить текущую производительность
python cli_monitor.py check x.com

# Вывод:
# ✅ x.com is accessible
#    Response time: 2317.8ms  ← Медленно!
#    Success rate: 0.95

# 2. Оптимизировать
python cli_monitor.py optimize x.com --save

# Вывод:
# ✅ Optimization successful!
#    New strategy: --dpi-desync=fake,disorder2 --dpi-desync-split-pos=1 ...
#    Confidence: 0.90
#    Expected latency: ~1254ms  ← Быстрее!

# 3. Проверить снова
python cli_monitor.py check x.com

# Вывод:
# ✅ x.com is accessible
#    Response time: 1254.4ms  ← Улучшилось!
```

### Проблема 3: Instagram висит на начальном экране

**Причина**: Стратегия не работает или DPI изменился.

**Решение**:

```bash
# 1. Проверить доступность
python cli_monitor.py check instagram.com

# Вывод:
# ❌ instagram.com is NOT accessible
#    Consecutive failures: 5
#    Issues: timeout, ConnectionResetError

# 2. Оптимизировать (найдет рабочую стратегию)
python cli_monitor.py optimize instagram.com --save

# 3. Добавить связанные домены
python cli_monitor.py add-domains \
    www.instagram.com \
    static.cdninstagram.com \
    scontent.cdninstagram.com

# 4. Оптимизировать все
python cli_monitor.py optimize-all
```

## Автоматический Режим

### Запустить и Забыть

```bash
# Запустить мониторинг в фоне
nohup python cli_monitor.py start > monitor.log 2>&1 &

# Или через systemd (Linux)
sudo systemctl start dpi-monitor
```

**Что будет происходить:**
1. Каждые 5 минут проверка всех доменов
2. При проблемах автоматическая оптимизация
3. Логирование в `monitor.log`
4. Уведомления о критических проблемах

### Настройка Автооптимизации

```bash
# Агрессивная оптимизация (быстрая реакция)
python cli_monitor.py start \
    --interval 60 \      # Проверять каждую минуту
    --threshold 2        # Оптимизировать после 2 неудач

# Консервативная (экономия ресурсов)
python cli_monitor.py start \
    --interval 600 \     # Проверять каждые 10 минут
    --threshold 5        # Оптимизировать после 5 неудач

# Только мониторинг (без автооптимизации)
python cli_monitor.py start --no-auto-optimize
```

## Программное Использование

### Python API

```python
import asyncio
from core.monitoring.adaptive_strategy_monitor import AdaptiveStrategyMonitor

async def main():
    # Создать монитор
    monitor = AdaptiveStrategyMonitor(
        strategies_file="domain_strategies.json",
        check_interval=300,
        optimization_threshold=3,
        enable_auto_optimization=True
    )
    
    # Запустить
    await monitor.start()
    
    # Работать в фоне
    try:
        while True:
            await asyncio.sleep(60)
            
            # Получить статус
            status = monitor.get_status_report()
            
            # Проверить критические домены
            if status['domains']['critical'] > 0:
                print(f"⚠️  {status['domains']['critical']} critical domains!")
                monitor.print_status()
    
    except KeyboardInterrupt:
        await monitor.stop()

asyncio.run(main())
```

### Интеграция с Существующим Кодом

```python
from core.monitoring.adaptive_strategy_monitor import AdaptiveStrategyMonitor

# В вашем основном скрипте
monitor = AdaptiveStrategyMonitor()
await monitor.start()

# Проверить конкретный домен
health = monitor.domain_health.get("instagram.com")
if health and health.is_critical():
    print("Instagram критичен, запускаем оптимизацию...")
    result = await monitor._optimize_domain("instagram.com", "manual")
```

## Мониторинг Вывод

### Нормальная Работа

```
================================================================================
ADAPTIVE STRATEGY MONITOR STATUS
================================================================================
Running: True
Domains monitored: 15
  Accessible: 15
  Degraded: 0
  Critical: 0

Checks performed: 42
Optimizations triggered: 0
Optimizations successful: 0
Optimization queue: 0
Last check: 2025-10-21T14:30:00
================================================================================
```

### Обнаружены Проблемы

```
================================================================================
ADAPTIVE STRATEGY MONITOR STATUS
================================================================================
Running: True
Domains monitored: 15
  Accessible: 12
  Degraded: 2
  Critical: 1

Checks performed: 42
Optimizations triggered: 3
Optimizations successful: 2
Optimization queue: 1

--------------------------------------------------------------------------------
CRITICAL DOMAINS:
--------------------------------------------------------------------------------
  ❌ instagram.com
     Failures: 5
     Success rate: 0.20
     Issues: timeout, ConnectionResetError

--------------------------------------------------------------------------------
DEGRADED DOMAINS:
--------------------------------------------------------------------------------
  ⚠️  x.com
     Latency: 2317.8ms
     Success rate: 0.85

  ⚠️  rutracker.org
     Latency: 1454.8ms
     Success rate: 0.75
================================================================================
```

## Логи

### Просмотр Логов

```bash
# Последние 50 строк
tail -n 50 monitor.log

# Следить в реальном времени
tail -f monitor.log

# Фильтровать критические
grep "CRITICAL\|ERROR" monitor.log
```

### Пример Логов

```
2025-10-21 14:30:00 INFO Starting adaptive strategy monitor
2025-10-21 14:30:00 INFO Loaded 15 strategies
2025-10-21 14:30:00 INFO Monitor started: 15 domains, check interval: 300s

2025-10-21 14:35:00 DEBUG Checking 15 domains
2025-10-21 14:35:02 DEBUG ✅ x.com: 200 (1254.4ms)
2025-10-21 14:35:03 DEBUG ✅ youtube.com: 200 (634.6ms)
2025-10-21 14:35:05 WARNING ⏱️  instagram.com: Timeout
2025-10-21 14:35:05 WARNING DEGRADED: instagram.com - failures: 3, latency: 0.0ms

2025-10-21 14:40:00 INFO 🔧 Optimization queued for instagram.com (reason: consecutive_failures, priority: 10)
2025-10-21 14:40:05 INFO 🔧 Starting optimization for instagram.com
2025-10-21 14:40:10 INFO Fingerprinting instagram.com...
2025-10-21 14:40:15 INFO ✅ Optimization completed for instagram.com: --dpi-desync=fake,fakeddisorder ...
2025-10-21 14:40:15 INFO Updated strategy for instagram.com
```

## Расширенные Возможности

### 1. Уведомления

Добавьте уведомления в `adaptive_strategy_monitor.py`:

```python
async def _send_notification(self, domain: str, issue: str):
    """Отправить уведомление о проблеме"""
    # Email
    # Telegram
    # Slack
    # etc.
```

### 2. Метрики

Экспортируйте метрики для Prometheus/Grafana:

```python
def export_metrics(self) -> str:
    """Экспорт метрик в формате Prometheus"""
    metrics = []
    
    for domain, health in self.domain_health.items():
        metrics.append(f'domain_accessible{{domain="{domain}"}} {int(health.is_accessible)}')
        metrics.append(f'domain_response_time{{domain="{domain}"}} {health.response_time_ms}')
        metrics.append(f'domain_success_rate{{domain="{domain}"}} {health.success_rate}')
    
    return '\n'.join(metrics)
```

### 3. Веб-интерфейс

Создайте простой веб-интерфейс:

```python
from flask import Flask, jsonify

app = Flask(__name__)
monitor = AdaptiveStrategyMonitor()

@app.route('/status')
def status():
    return jsonify(monitor.get_status_report())

@app.route('/optimize/<domain>')
async def optimize(domain):
    result = await monitor._optimize_domain(domain, "manual")
    return jsonify(result)
```

## Troubleshooting

### Проблема: Мониторинг не запускается

```bash
# Проверить файл стратегий
python cli_monitor.py status

# Проверить права
ls -la domain_strategies.json

# Проверить синтаксис JSON
python -m json.tool domain_strategies.json
```

### Проблема: Оптимизация не работает

```bash
# Проверить fingerprinting
python -c "
from core.fingerprint.unified_fingerprinter import UnifiedFingerprinter
import asyncio

async def test():
    fp = UnifiedFingerprinter()
    result = await fp.fingerprint_target('instagram.com', 443)
    print(f'Reliability: {result.reliability_score}')

asyncio.run(test())
"
```

### Проблема: Слишком много оптимизаций

```bash
# Увеличить порог
python cli_monitor.py start --threshold 5

# Или отключить автооптимизацию
python cli_monitor.py start --no-auto-optimize
```

## Следующие Шаги

1. ✅ Запустить мониторинг: `python cli_monitor.py start`
2. ✅ Добавить проблемные домены: `python cli_monitor.py add-domains ...`
3. ✅ Оптимизировать: `python cli_monitor.py optimize-all`
4. ✅ Настроить автозапуск (systemd/cron)
5. ✅ Добавить уведомления
6. ✅ Настроить метрики

## Файлы

**Код**:
- `core/monitoring/adaptive_strategy_monitor.py` - Основной монитор
- `cli_monitor.py` - CLI интерфейс

**Конфигурация**:
- `domain_strategies.json` - Стратегии для доменов

**Логи**:
- `monitor.log` - Логи мониторинга
- `optimization_report.json` - Отчет об оптимизации

## Поддержка

Для вопросов:
- Запустить демо: `python cli_monitor.py start`
- Проверить статус: `python cli_monitor.py status`
- Посмотреть логи: `tail -f monitor.log`

---

**Статус**: ✅ Готово к использованию  
**Дата**: 2025-10-21
