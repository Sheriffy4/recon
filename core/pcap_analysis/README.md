# PCAP Analysis Modules

Модули для анализа PCAP файлов и детекции различных типов DPI блокировок.

## Архитектура

```
pcap_analysis/
├── rst_analyzer.py              # Анализ RST инъекций
├── tls_analyzer.py              # Анализ TLS handshake
├── fragmentation_analyzer.py    # Анализ фрагментации
├── sni_analyzer.py              # Анализ SNI фильтрации
└── failure_detector.py          # Детекция типов блокировок
```

## Модули

### RSTAnalyzer
Анализ RST (Reset) пакетов для детекции DPI инъекций.

**Основные методы:**
- `analyze_rst_injection()` - главный метод анализа RST инъекций
- `analyze_rst_ttl()` - анализ TTL значений
- `analyze_rst_sequence_numbers()` - анализ seq/ack номеров
- `analyze_rst_timing()` - временной анализ
- `analyze_rst_sources()` - анализ источников RST
- `compute_block_index()` - вычисление индекса блокировки

**Индикаторы инъекции:**
- Множественные RST пакеты
- Подозрительные TTL значения
- Невалидные sequence/acknowledgment номера
- Нереалистичное время прихода RST
- Множественные источники RST

**Пример использования:**
```python
from core.pcap_analysis.rst_analyzer import RSTAnalyzer

analyzer = RSTAnalyzer()
result = analyzer.analyze_rst_injection(rst_packets, all_tcp_packets)

if result["is_injection"]:
    print(f"RST инъекция обнаружена с уверенностью {result['confidence']}")
    print(f"Индикаторы: {result['injection_indicators']}")
```

---

### TLSAnalyzer
Анализ TLS handshake для детекции блокировок.

**Основные методы:**
- `analyze_tls_handshake()` - анализ TLS handshake
- `is_client_hello_payload()` - детекция ClientHello
- `is_server_hello_payload()` - детекция ServerHello
- `is_tls_alert()` - детекция TLS Alert
- `parse_tls_alert()` - парсинг Alert сообщений
- `get_tls_alert_description()` - описания Alert кодов

**Пример использования:**
```python
from core.pcap_analysis.tls_analyzer import TLSAnalyzer

analyzer = TLSAnalyzer()
result = analyzer.analyze_tls_handshake(tcp_packets)

if result["handshake_failed"]:
    print(f"TLS handshake failed")
    print(f"ClientHello: {result['client_hello_count']}")
    print(f"ServerHello: {result['server_hello_count']}")
    print(f"Alerts: {result['tls_alerts']}")
```

---

### FragmentationAnalyzer
Анализ эффективности стратегий фрагментации.

**Основные методы:**
- `is_fragmentation_strategy()` - проверка типа стратегии
- `analyze_fragmentation_effectiveness()` - анализ эффективности
- `block_after_reassembly()` - детекция блокировки после сборки
- `normal_tcp_reassembly_but_blocked()` - детекция блокировки на уровне приложения
- `ordered_fragments_blocked()` - детекция блокировки упорядоченных фрагментов

**Индикаторы сборки фрагментов DPI:**
- Блокировка после получения всех фрагментов
- Нормальная TCP сборка, но блокировка на уровне приложения
- Упорядоченные фрагменты блокируются

**Пример использования:**
```python
from core.pcap_analysis.fragmentation_analyzer import FragmentationAnalyzer

analyzer = FragmentationAnalyzer()
result = analyzer.analyze_fragmentation_effectiveness(tcp_packets, strategy)

if result["fragments_reassembled"]:
    print(f"DPI собирает фрагменты!")
    print(f"Индикаторы: {result['reassembly_indicators']}")
```

---

### SNIAnalyzer
Анализ SNI (Server Name Indication) фильтрации.

**Основные методы:**
- `analyze_sni_filtering()` - главный метод анализа SNI
- `extract_sni_from_client_hello()` - извлечение SNI
- `parse_sni_extension()` - парсинг SNI extension
- `rst_after_client_hello()` - проверка RST после ClientHello
- `is_blocked_domain_pattern()` - проверка паттернов заблокированных доменов

**Пример использования:**
```python
from core.pcap_analysis.sni_analyzer import SNIAnalyzer

analyzer = SNIAnalyzer()
result = analyzer.analyze_sni_filtering(tcp_packets)

if result["sni_blocked"]:
    print(f"SNI фильтрация обнаружена!")
    print(f"Домены: {result['sni_domains']}")
```

---

### FailureDetector
Детекция различных типов блокировок и неудач.

**Основные методы:**
- `detect_stateful_tracking()` - детекция stateful tracking
- `is_connection_refused()` - детекция connection refused
- `filter_relevant_packets()` - фильтрация релевантных пакетов

**Пример использования:**
```python
from core.pcap_analysis.failure_detector import FailureDetector

detector = FailureDetector()

if detector.detect_stateful_tracking(tcp_packets, strategy):
    print("DPI использует stateful tracking")

if detector.is_connection_refused(tcp_packets):
    print("Соединение отклонено")
```

---

## Интеграция

Все анализаторы интегрированы в `StrategyFailureAnalyzer` через композицию:

```python
class StrategyFailureAnalyzer:
    def __init__(self):
        self.rst_analyzer = RSTAnalyzer()
        self.tls_analyzer = TLSAnalyzer()
        self.fragmentation_analyzer = FragmentationAnalyzer()
        self.sni_analyzer = SNIAnalyzer()
        self.failure_detector = FailureDetector()
```

## Backward Compatibility

Все методы доступны через thin wrappers в `StrategyFailureAnalyzer` для обратной совместимости:

```python
# Старый способ (все еще работает)
analyzer = StrategyFailureAnalyzer()
result = analyzer._analyze_rst_injection(rst_packets, tcp_packets)

# Новый способ (рекомендуется)
rst_analyzer = RSTAnalyzer()
result = rst_analyzer.analyze_rst_injection(rst_packets, tcp_packets)
```

## Тестирование

Каждый модуль можно тестировать независимо:

```python
import pytest
from core.pcap_analysis.rst_analyzer import RSTAnalyzer

def test_rst_injection_detection():
    analyzer = RSTAnalyzer()
    # ... тестовые данные
    result = analyzer.analyze_rst_injection(rst_packets, tcp_packets)
    assert result["is_injection"] == True
```

## Производительность

- Все анализаторы работают с `RawPacket` объектами
- Используются утилиты из `packet_parser_utils` для эффективного парсинга
- Минимальное дублирование кода
- Оптимизированные алгоритмы детекции

## Расширение

Для добавления нового анализатора:

1. Создайте новый файл в `pcap_analysis/`
2. Создайте класс с методами анализа
3. Добавьте в `StrategyFailureAnalyzer.__init__()`
4. Создайте thin wrappers для backward compatibility
5. Добавьте тесты

Пример:
```python
# new_analyzer.py
class NewAnalyzer:
    def analyze_something(self, packets):
        # ваша логика
        return result

# В StrategyFailureAnalyzer
def __init__(self):
    # ...
    self.new_analyzer = NewAnalyzer()

def _analyze_something(self, packets):
    """Backward compatibility wrapper."""
    return self.new_analyzer.analyze_something(packets)
```
