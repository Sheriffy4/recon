# Diagnostic Tools

Набор инструментов для диагностики и проверки соответствия между testing mode и service mode.

## Инструменты

### 1. Strategy Diff Tool (`strategy_diff.py`)

Сравнивает стратегии между режимами, показывает различия в параметрах и генерирует детальный отчет.

**Requirements:** 5.1, 5.2, 5.5

**Использование:**

```bash
# Сравнить стратегии из двух файлов
python tools/strategy_diff.py --testing domain_strategies_testing.json --service domain_strategies_service.json

# Сохранить отчет в файл
python tools/strategy_diff.py --testing domain_strategies_testing.json --service domain_strategies_service.json --output report.txt

# Сгенерировать JSON отчет
python tools/strategy_diff.py --testing domain_strategies_testing.json --service domain_strategies_service.json --json-output report.json

# Включить отладочный вывод
python tools/strategy_diff.py --testing domain_strategies_testing.json --service domain_strategies_service.json --debug
```

**Выходные данные:**
- Текстовый отчет с различиями между стратегиями
- JSON отчет с детальной информацией
- Exit code 0 если все стратегии совместимы, 1 если есть несовместимые

---

### 2. PCAP Comparison Tool (`pcap_compare.py`)

Сравнивает PCAP файлы из разных режимов, находит различия в применении стратегий и генерирует визуальный отчет.

**Requirements:** 8.5, 8.6, 8.7

**Использование:**

```bash
# Сравнить два PCAP файла
python tools/pcap_compare.py compare --testing testing.pcap --service service.pcap

# Сравнить с ожидаемой стратегией
python tools/pcap_compare.py compare --testing testing.pcap --service service.pcap --expected-strategy strategy.json

# Сохранить отчет
python tools/pcap_compare.py compare --testing testing.pcap --service service.pcap --output report.txt --json-output report.json

# Анализировать один PCAP файл
python tools/pcap_compare.py analyze --pcap capture.pcap

# Анализировать с ожидаемой стратегией
python tools/pcap_compare.py analyze --pcap capture.pcap --expected-strategy strategy.json --output analysis.txt
```

**Выходные данные:**
- Детальный анализ применения стратегий в PCAP
- Сравнение split positions, SNI values, checksums
- Similarity score между PCAP файлами
- Exit code 0 если similarity >= 70%, 1 если ниже

---

### 3. Mode Validator (`mode_validator.py`)

Проверяет соответствие между режимами, тестирует одинаковые стратегии в обоих режимах и генерирует отчет о несоответствиях.

**Requirements:** 5.1, 5.2, 5.3

**Использование:**

```bash
# Проверить все стратегии
python tools/mode_validator.py --strategies domain_strategies.json

# Проверить конкретные домены
python tools/mode_validator.py --strategies domain_strategies.json --domains x.com youtube.com

# Установить таймаут
python tools/mode_validator.py --strategies domain_strategies.json --timeout 15

# Сохранить отчет
python tools/mode_validator.py --strategies domain_strategies.json --output report.txt --json-output report.json
```

**Выходные данные:**
- Отчет о соответствии между режимами
- Список несоответствий с причинами
- Статистика успешности в каждом режиме
- Exit code 0 если все режимы согласованы, 1 если есть несоответствия

---

### 4. Health Check Tool (`health_check.py`)

Проверяет работоспособность всех компонентов системы: DoH, SNI, PCAP, WinDivert и генерирует отчет о состоянии системы.

**Requirements:** 11.1, 11.2, 11.3

**Использование:**

```bash
# Проверить все компоненты
python tools/health_check.py

# Сохранить отчет
python tools/health_check.py --output health_report.txt

# Сгенерировать JSON отчет
python tools/health_check.py --json-output health_report.json

# Включить отладочный вывод
python tools/health_check.py --debug
```

**Проверяемые компоненты:**
- DoH Resolver (импорт, создание экземпляра, тестовая резолюция)
- SNI Manipulator (импорт, поиск SNI позиции)
- PCAP Analyzer (импорт, доступность Scapy)
- WinDivert (наличие DLL/driver, импорт pydivert)
- Strategy Loader (импорт, загрузка тестовой стратегии)
- Bypass Engine (импорт, доступность)

**Выходные данные:**
- Детальный отчет о состоянии каждого компонента
- Общий статус системы (healthy/degraded/unhealthy)
- Exit code 0 если система healthy или degraded, 1 если unhealthy

---

## Metrics Integration

### DiagnosticsMetricsCollector

Коллектор метрик для интеграции с существующей MonitoringSystem.

**Requirements:** 11.1, 11.2, 11.6

**Использование в коде:**

```python
from core.diagnostics import get_diagnostics_metrics_collector

# Получить коллектор
collector = get_diagnostics_metrics_collector()

# Записать успешное применение стратегии
collector.record_strategy_success(
    domain='x.com',
    strategy_type='fakeddisorder',
    latency_ms=45.2
)

# Записать неудачное применение
collector.record_strategy_failure(
    domain='x.com',
    strategy_type='multisplit'
)

# Записать DoH запрос
collector.record_doh_query(
    provider='cloudflare',
    success=True,
    resolution_time_ms=23.5,
    cache_hit=False
)

# Записать PCAP захват
collector.record_pcap_capture(
    success=True,
    packets=150,
    bytes_captured=45000,
    duration_ms=1000.0
)

# Получить метрики
all_metrics = collector.get_all_metrics()
strategy_metrics = collector.get_strategy_metrics(domain='x.com')
doh_metrics = collector.get_doh_metrics(provider='cloudflare')
pcap_metrics = collector.get_pcap_metrics()
```

**Собираемые метрики:**

1. **Strategy Metrics:**
   - Общее количество попыток
   - Успешные/неудачные попытки
   - Success rate
   - Средняя/мин/макс задержка
   - Время последнего успеха/неудачи

2. **DoH Metrics:**
   - Общее количество запросов
   - Успешные/неудачные запросы
   - Success rate
   - Cache hit rate
   - Среднее/мин/макс время резолюции

3. **PCAP Metrics:**
   - Общее количество захватов
   - Успешные/неудачные захваты
   - Success rate
   - Среднее количество пакетов на захват
   - Средняя длительность захвата

---

## Интеграция с MonitoringSystem

Метрики автоматически интегрируются с существующей MonitoringSystem:

```python
from core.monitoring_system import MonitoringSystem, MonitoringConfig
from core.diagnostics import get_diagnostics_metrics_collector

# Создать систему мониторинга
config = MonitoringConfig()
monitoring = MonitoringSystem(config)

# Получить коллектор метрик
collector = get_diagnostics_metrics_collector()

# Метрики будут доступны через monitoring.get_status_report()
report = monitoring.get_status_report()

# Отчет будет содержать:
# - diagnostics_metrics: все метрики диагностики
# - strategy_success_rate: общий процент успешности стратегий
# - doh_success_rate: общий процент успешности DoH
# - pcap_success_rate: общий процент успешности PCAP
```

---

## Примеры использования

### Проверка соответствия после изменений

```bash
# 1. Сравнить стратегии
python tools/strategy_diff.py \
  --testing domain_strategies_testing.json \
  --service domain_strategies_service.json \
  --output strategy_diff_report.txt

# 2. Проверить работоспособность компонентов
python tools/health_check.py --output health_report.txt

# 3. Проверить соответствие режимов
python tools/mode_validator.py \
  --strategies domain_strategies.json \
  --output mode_validation_report.txt
```

### Анализ PCAP после тестирования

```bash
# 1. Захватить PCAP в testing mode
# (выполняется автоматически при cli.py auto)

# 2. Захватить PCAP в service mode
# (выполняется автоматически при работе службы)

# 3. Сравнить PCAP файлы
python tools/pcap_compare.py compare \
  --testing testing_capture.pcap \
  --service service_capture.pcap \
  --output pcap_comparison.txt \
  --json-output pcap_comparison.json
```

### Мониторинг в production

```python
# В коде службы
from core.diagnostics import get_diagnostics_metrics_collector

collector = get_diagnostics_metrics_collector()

# При применении стратегии
try:
    start_time = time.time()
    # ... применить стратегию ...
    latency_ms = (time.time() - start_time) * 1000
    
    collector.record_strategy_success(
        domain=domain,
        strategy_type=strategy_type,
        latency_ms=latency_ms
    )
except Exception as e:
    collector.record_strategy_failure(
        domain=domain,
        strategy_type=strategy_type
    )

# Периодически получать метрики
metrics = collector.get_all_metrics()
print(f"Strategy success rate: {metrics['summary']['strategy_success_rate']:.2%}")
```

---

## Troubleshooting

### Strategy Diff показывает много различий

**Причина:** Стратегии сохраняются в разных форматах или с разными параметрами.

**Решение:**
1. Проверить формат сохранения стратегий в обоих режимах
2. Использовать UnifiedStrategyLoader для нормализации
3. Проверить логи для деталей различий

### PCAP Compare не может найти стратегию

**Причина:** PCAP файл не содержит достаточно пакетов или Scapy недоступен.

**Решение:**
1. Убедиться что Scapy установлен: `pip install scapy`
2. Проверить что PCAP содержит TLS пакеты
3. Увеличить длительность захвата

### Mode Validator показывает несоответствия

**Причина:** Стратегии работают по-разному в разных режимах.

**Решение:**
1. Проверить что используется один и тот же UnifiedBypassEngine
2. Проверить конфигурацию обоих режимов
3. Использовать PCAP Compare для детального анализа

### Health Check показывает unhealthy компоненты

**Причина:** Компоненты не установлены или требуют прав администратора.

**Решение:**
1. Установить недостающие зависимости
2. Запустить с правами администратора (для WinDivert)
3. Проверить логи для деталей ошибок

---

## См. также

- [Requirements Document](../.kiro/specs/testing-service-mode-parity/requirements.md)
- [Design Document](../.kiro/specs/testing-service-mode-parity/design.md)
- [Tasks Document](../.kiro/specs/testing-service-mode-parity/tasks.md)
