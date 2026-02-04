# Архитектура BlockingPatternDetector

## Обзор

Модульная система детекции паттернов блокировки DPI с использованием паттернов Facade, Registry и Strategy.

---

## Диаграмма компонентов

```
┌─────────────────────────────────────────────────────────────────┐
│                   BlockingPatternDetector                       │
│                         (Facade)                                │
│                                                                 │
│  + detect_blocking_patterns()                                   │
│  + classify_dpi_aggressiveness()                                │
│  + get_detection_statistics()                                   │
│  + update_detection_rules()                                     │
│  + clear_cache()                                                │
│  + analyze_pattern_evolution()                                  │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         │ использует
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    DetectorRegistry                             │
│                      (Registry)                                 │
│                                                                 │
│  + register_detector()                                          │
│  + unregister_detector()                                        │
│  + detect_all()                                                 │
│  + get_detector_stats()                                         │
│  + get_registered_detectors()                                   │
│  + clear_stats()                                                │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         │ управляет
                         ▼
         ┌───────────────────────────────────────┐
         │         BaseDetector                  │
         │         (Interface)                   │
         │                                       │
         │  + detect(packets, domain, ip)        │
         └───────────────┬───────────────────────┘
                         │
                         │ реализуют
         ┌───────────────┴───────────────┐
         │                               │
    ┌────▼────┐  ┌────────┐  ┌────────┐ │  ┌────────┐
    │   RST   │  │  DNS   │  │  TLS   │ │  │  HTTP  │
    │Detector │  │Detector│  │Detector│ │  │Detector│
    └─────────┘  └────────┘  └────────┘ │  └────────┘
                                        │
                                   ┌────▼────┐
                                   │ Timeout │
                                   │Detector │
                                   └─────────┘
```

---

## Поток данных

```
1. Пользователь вызывает:
   detector.detect_blocking_patterns(packets, domain, ip)
                    │
                    ▼
2. BlockingPatternDetector (Facade):
   - Проверяет доступность Scapy
   - Запускает таймер
                    │
                    ▼
3. DetectorRegistry.detect_all():
   - Итерирует по всем детекторам
   - Вызывает detector.detect() для каждого
   - Собирает результаты
   - Обновляет статистику
                    │
                    ▼
4. Каждый детектор:
   - Фильтрует пакеты
   - Анализирует паттерны
   - Возвращает BlockingEvidence[]
                    │
                    ▼
5. BlockingPatternDetector:
   - Объединяет результаты
   - Обновляет общую статистику
   - Возвращает все найденные паттерны
```

---

## Структура файлов

```
core/intelligence/
│
├── blocking_pattern_detector.py (429 строк)
│   ├── DPIAggressivenessLevel (Enum)
│   ├── BlockingPattern (Enum)
│   ├── BlockingEvidence (Dataclass)
│   ├── DPICharacteristics (Dataclass)
│   └── BlockingPatternDetector (Class)
│       ├── __init__()
│       ├── detect_blocking_patterns()
│       ├── classify_dpi_aggressiveness()
│       ├── get_detection_statistics()
│       ├── update_detection_rules()
│       ├── clear_cache()
│       ├── analyze_pattern_evolution()
│       ├── _initialize_detection_rules()
│       └── _initialize_timing_thresholds()
│
├── detectors/
│   ├── __init__.py (23 строки)
│   │   └── Exports: BaseDetector, *Detector, DetectorRegistry
│   │
│   ├── base.py (32 строки)
│   │   └── BaseDetector (ABC)
│   │       └── detect() [abstract]
│   │
│   ├── registry.py (147 строк)
│   │   └── DetectorRegistry
│   │       ├── __init__()
│   │       ├── register_detector()
│   │       ├── unregister_detector()
│   │       ├── detect_all()
│   │       ├── get_detector_stats()
│   │       ├── get_registered_detectors()
│   │       └── clear_stats()
│   │
│   ├── rst_detector.py (230 строк)
│   │   └── RSTDetector(BaseDetector)
│   │       ├── detect()
│   │       ├── _analyze_rst_timing()
│   │       ├── _analyze_rst_source()
│   │       ├── _analyze_rst_tcp_parameters()
│   │       └── _calculate_rst_suspicion_score()
│   │
│   ├── dns_detector.py (160 строк)
│   │   └── DNSDetector(BaseDetector)
│   │       ├── detect()
│   │       └── _analyze_dns_timing()
│   │
│   ├── tls_detector.py (139 строк)
│   │   └── TLSDetector(BaseDetector)
│   │       ├── detect()
│   │       └── _analyze_tls_timing()
│   │
│   ├── http_detector.py (205 строк)
│   │   └── HTTPDetector(BaseDetector)
│   │       ├── detect()
│   │       ├── _detect_http_redirects()
│   │       └── _detect_content_filtering()
│   │
│   └── timeout_detector.py (108 строк)
│       └── TimeoutDetector(BaseDetector)
│           └── detect()
│
└── utils/
    ├── __init__.py (7 строк)
    │   └── Exports: extract_dns_answers
    │
    └── dns_utils.py (56 строк)
        └── extract_dns_answers(response)
```

---

## Паттерны проектирования

### 1. Facade Pattern
**Класс:** `BlockingPatternDetector`

**Цель:** Предоставить простой интерфейс к сложной системе детекции

**Преимущества:**
- Скрывает сложность реестра и детекторов
- Единая точка входа для клиентов
- Обратная совместимость

```python
# Клиент работает только с фасадом
detector = BlockingPatternDetector()
evidence = await detector.detect_blocking_patterns(packets, domain, ip)
```

### 2. Registry Pattern
**Класс:** `DetectorRegistry`

**Цель:** Управление коллекцией детекторов

**Преимущества:**
- Динамическая регистрация/удаление
- Централизованное управление
- Статистика по детекторам

```python
# Регистрация нового детектора
registry.register_detector(CustomDetector(), "custom_stat_key")

# Запуск всех детекторов
evidence = await registry.detect_all(packets, domain, ip)
```

### 3. Strategy Pattern
**Интерфейс:** `BaseDetector`

**Цель:** Инкапсуляция алгоритмов детекции

**Преимущества:**
- Взаимозаменяемые алгоритмы
- Легко добавлять новые
- Изолированное тестирование

```python
# Каждый детектор - отдельная стратегия
class CustomDetector(BaseDetector):
    async def detect(self, packets, domain, ip):
        # Ваша логика
        return evidence_list
```

### 4. Factory Pattern
**Метод:** `DetectorRegistry._register_default_detectors()`

**Цель:** Создание детекторов по умолчанию

**Преимущества:**
- Централизованное создание
- Легко изменить набор
- Конфигурируемость

```python
def _register_default_detectors(self):
    self.register_detector(RSTDetector(), "rst_injections_found")
    self.register_detector(DNSDetector(), "dns_poisoning_found")
    # ...
```

---

## Зависимости

```
BlockingPatternDetector
    ├── DetectorRegistry
    │   ├── RSTDetector
    │   ├── DNSDetector
    │   │   └── dns_utils.extract_dns_answers()
    │   ├── TLSDetector
    │   ├── HTTPDetector
    │   └── TimeoutDetector
    └── Scapy (опционально)
```

---

## Расширение системы

### Добавление нового детектора

1. **Создать класс детектора:**
```python
# detectors/custom_detector.py
from .base import BaseDetector

class CustomDetector(BaseDetector):
    async def detect(self, packets, domain, target_ip):
        # Ваша логика детекции
        evidence_list = []
        # ...
        return evidence_list
```

2. **Зарегистрировать в реестре:**
```python
# detectors/registry.py
from .custom_detector import CustomDetector

def _register_default_detectors(self):
    # ...
    self.register_detector(CustomDetector(), "custom_detections_found")
```

3. **Экспортировать:**
```python
# detectors/__init__.py
from .custom_detector import CustomDetector

__all__ = [..., "CustomDetector"]
```

### Добавление общей утилиты

1. **Создать функцию:**
```python
# utils/custom_utils.py
def custom_parser(data):
    # Ваша логика
    return parsed_data
```

2. **Экспортировать:**
```python
# utils/__init__.py
from .custom_utils import custom_parser

__all__ = [..., "custom_parser"]
```

3. **Использовать в детекторах:**
```python
from ..utils.custom_utils import custom_parser

result = custom_parser(packet_data)
```

---

## Тестирование

### Unit-тесты детекторов

```python
import pytest
from core.intelligence.detectors.rst_detector import RSTDetector

@pytest.mark.asyncio
async def test_rst_detector():
    detector = RSTDetector()
    packets = create_test_packets()
    
    evidence = await detector.detect(packets, "example.com", "1.2.3.4")
    
    assert len(evidence) > 0
    assert evidence[0].pattern == BlockingPattern.RST_INJECTION
```

### Integration-тесты реестра

```python
@pytest.mark.asyncio
async def test_detector_registry():
    registry = DetectorRegistry()
    packets = create_test_packets()
    
    evidence = await registry.detect_all(packets, "example.com", "1.2.3.4")
    
    assert len(evidence) > 0
    stats = registry.get_detector_stats()
    assert stats["RSTDetector"]["detections"] > 0
```

### End-to-end тесты

```python
@pytest.mark.asyncio
async def test_blocking_pattern_detector():
    detector = BlockingPatternDetector()
    packets = create_test_packets()
    
    evidence = await detector.detect_blocking_patterns(
        packets, "example.com", "1.2.3.4"
    )
    
    assert len(evidence) > 0
    stats = detector.get_detection_statistics()
    assert stats["patterns_detected"] > 0
```

---

## Производительность

### Оптимизации

1. **Параллельная детекция** (будущее улучшение):
```python
async def detect_all(self, packets, domain, target_ip):
    tasks = [
        detector.detect(packets, domain, target_ip)
        for detector in self._detectors
    ]
    results = await asyncio.gather(*tasks)
    return [item for sublist in results for item in sublist]
```

2. **Кэширование результатов:**
```python
# Уже реализовано в BlockingPatternDetector
self.analysis_cache = {}
```

3. **Ленивая загрузка детекторов:**
```python
# Детекторы создаются только при первом использовании
```

---

## Безопасность

### Обработка ошибок

- Все детекторы используют `try-except` с `exc_info=True`
- Ошибки логируются, но не прерывают работу других детекторов
- Реестр продолжает работу даже если один детектор упал

### Валидация входных данных

- Проверка доступности Scapy
- Проверка пустых списков пакетов
- Безопасная обработка некорректных пакетов

---

## Мониторинг

### Статистика детекции

```python
stats = detector.get_detection_statistics()
# {
#     "patterns_detected": 42,
#     "rst_injections_found": 10,
#     "dns_poisoning_found": 5,
#     "tls_interrupts_found": 8,
#     "http_redirects_found": 12,
#     "connection_timeouts_found": 7,
#     "analysis_time_total": 1.234,
#     "average_analysis_time": 0.029,
#     ...
# }
```

### Статистика детекторов

```python
detector_stats = registry.get_detector_stats()
# {
#     "RSTDetector": {
#         "stat_key": "rst_injections_found",
#         "detections": 10,
#         "errors": 0
#     },
#     ...
# }
```

---

## Конфигурация

### Правила детекции

```python
detection_rules = {
    "rst_injection": {
        "min_suspicion_score": 0.6,
        "timing_threshold_ms": 100,
        "ttl_threshold": 32,
    },
    "dns_poisoning": {
        "min_confidence": 0.3,
        "response_time_threshold_ms": 1,
        "suspicious_ips": ["127.0.0.1", "0.0.0.0"],
    },
    # ...
}
```

### Обновление правил

```python
detector.update_detection_rules({
    "rst_injection": {
        "min_suspicion_score": 0.7,  # Более строгий порог
    }
})
```

---

## Совместимость

### Обратная совместимость

- Все публичные методы сохранены
- Dataclasses не изменены
- Сигнатуры методов идентичны

### Миграция

Не требуется! Существующий код продолжает работать без изменений.

---

*Архитектура спроектирована с учетом принципов SOLID и best practices.*
