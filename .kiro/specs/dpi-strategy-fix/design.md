# Design Document

## Overview

Данный документ описывает архитектурное решение для исправления критических проблем в DPI стратегии обхода. Решение включает рефакторинг модулей обработки пакетов, реализацию корректной логики разделения и интеграцию badsum функциональности.

## Architecture

### High-Level Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   CLI Parser    │───▶│  Strategy Engine │───▶│ Packet Modifier │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
                       ┌──────────────────┐    ┌─────────────────┐
                       │ Position Resolver│    │   TCP Builder   │
                       └──────────────────┘    └─────────────────┘
                                │                        │
                                ▼                        ▼
                       ┌──────────────────┐    ┌─────────────────┐
                       │   SNI Detector   │    │ Checksum Fooler │
                       └──────────────────┘    └─────────────────┘
```

### Core Components

1. **Strategy Engine** - Центральный компонент для управления DPI стратегиями
2. **Position Resolver** - Определение позиций разделения (3, 10, SNI)
3. **Packet Modifier** - Модификация пакетов согласно стратегии
4. **SNI Detector** - Поиск SNI extension в TLS пакетах
5. **Checksum Fooler** - Изменение TCP checksums
6. **TCP Builder** - Построение корректных TCP пакетов

## Components and Interfaces

### 1. Strategy Engine

**Location:** `core/bypass/strategies/dpi_strategy_engine.py`

```python
class DPIStrategyEngine:
    def __init__(self, config: DPIConfig):
        self.config = config
        self.position_resolver = PositionResolver()
        self.packet_modifier = PacketModifier()
        self.sni_detector = SNIDetector()
        self.checksum_fooler = ChecksumFooler()
    
    def apply_strategy(self, packet: bytes) -> List[bytes]:
        """Применяет DPI стратегию к пакету"""
        
    def should_split_packet(self, packet: bytes) -> bool:
        """Определяет, нужно ли разделять пакет"""
        
    def get_split_positions(self, packet: bytes) -> List[int]:
        """Возвращает позиции для разделения пакета"""
```

**Interfaces:**
- `IDPIStrategy` - интерфейс для DPI стратегий
- `IPacketProcessor` - интерфейс для обработки пакетов

### 2. Position Resolver

**Location:** `core/bypass/strategies/position_resolver.py`

```python
class PositionResolver:
    def resolve_positions(self, packet: bytes, config: SplitConfig) -> List[int]:
        """Определяет все позиции разделения для пакета"""
        
    def resolve_numeric_positions(self, packet: bytes, positions: List[int]) -> List[int]:
        """Обрабатывает числовые позиции (3, 10)"""
        
    def resolve_sni_position(self, packet: bytes) -> Optional[int]:
        """Находит позицию SNI extension"""
        
    def validate_position(self, packet: bytes, position: int) -> bool:
        """Проверяет валидность позиции для разделения"""
```

### 3. SNI Detector

**Location:** `core/bypass/strategies/sni_detector.py`

```python
class SNIDetector:
    def find_sni_position(self, tls_packet: bytes) -> Optional[int]:
        """Находит позицию SNI extension в TLS Client Hello"""
        
    def is_client_hello(self, packet: bytes) -> bool:
        """Проверяет, является ли пакет TLS Client Hello"""
        
    def parse_tls_extensions(self, packet: bytes) -> Dict[int, int]:
        """Парсит TLS extensions и возвращает их позиции"""
        
    def extract_sni_value(self, packet: bytes, position: int) -> Optional[str]:
        """Извлекает значение SNI для логирования"""
```

### 4. Packet Modifier

**Location:** `core/bypass/strategies/packet_modifier.py`

```python
class PacketModifier:
    def split_packet(self, packet: bytes, positions: List[int]) -> List[bytes]:
        """Разделяет пакет на части по указанным позициям"""
        
    def create_tcp_segments(self, original_packet: TCPPacket, parts: List[bytes]) -> List[TCPPacket]:
        """Создает TCP сегменты из частей пакета"""
        
    def update_sequence_numbers(self, packets: List[TCPPacket]) -> List[TCPPacket]:
        """Обновляет TCP sequence numbers для разделенных пакетов"""
        
    def apply_fooling(self, packet: TCPPacket, fooling_type: str) -> TCPPacket:
        """Применяет fooling стратегии (badsum, etc.)"""
```

### 5. Checksum Fooler

**Location:** `core/bypass/strategies/checksum_fooler.py`

```python
class ChecksumFooler:
    def apply_badsum(self, packet: TCPPacket) -> TCPPacket:
        """Применяет неверную контрольную сумму"""
        
    def calculate_bad_checksum(self, original_checksum: int) -> int:
        """Вычисляет заведомо неверную контрольную сумму"""
        
    def should_apply_badsum(self, packet: TCPPacket, config: FoolingConfig) -> bool:
        """Определяет, нужно ли применять badsum к пакету"""
```

## Data Models

### Configuration Models

```python
@dataclass
class DPIConfig:
    desync_mode: str  # "split"
    split_positions: List[Union[int, str]]  # [3, 10, "sni"]
    fooling_methods: List[str]  # ["badsum"]
    enabled: bool = True

@dataclass
class SplitConfig:
    numeric_positions: List[int]  # [3, 10]
    use_sni: bool  # True if "sni" in positions
    priority_order: List[str]  # ["sni", "numeric"]

@dataclass
class FoolingConfig:
    badsum: bool = False
    fake_packets: bool = False
    disorder: bool = False

@dataclass
class PacketSplitResult:
    original_packet: bytes
    split_parts: List[bytes]
    split_positions: List[int]
    applied_strategies: List[str]
    sni_position: Optional[int] = None
```

### Packet Models

```python
@dataclass
class TLSPacketInfo:
    is_client_hello: bool
    sni_position: Optional[int]
    sni_value: Optional[str]
    packet_size: int
    extensions: Dict[int, int]  # extension_type -> position

@dataclass
class TCPPacketInfo:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    seq_num: int
    ack_num: int
    flags: int
    checksum: int
    payload: bytes
```

## Error Handling

### Exception Hierarchy

```python
class DPIStrategyError(Exception):
    """Base exception for DPI strategy errors"""

class InvalidSplitPositionError(DPIStrategyError):
    """Raised when split position is invalid"""

class SNINotFoundError(DPIStrategyError):
    """Raised when SNI is required but not found"""

class PacketTooSmallError(DPIStrategyError):
    """Raised when packet is too small for split"""

class ChecksumCalculationError(DPIStrategyError):
    """Raised when checksum calculation fails"""
```

### Error Handling Strategy

1. **Graceful Degradation** - если одна стратегия не применима, пробуем следующую
2. **Logging** - все ошибки логируются с контекстом
3. **Fallback** - возврат к оригинальному пакету при критических ошибках
4. **Validation** - проверка входных данных перед обработкой

## Testing Strategy

### Unit Tests

1. **Position Resolver Tests**
   - Тестирование определения позиций 3, 10
   - Тестирование поиска SNI позиции
   - Тестирование валидации позиций

2. **SNI Detector Tests**
   - Тестирование парсинга TLS Client Hello
   - Тестирование поиска SNI extension
   - Тестирование различных TLS версий

3. **Packet Modifier Tests**
   - Тестирование разделения пакетов
   - Тестирование обновления sequence numbers
   - Тестирование создания TCP сегментов

4. **Checksum Fooler Tests**
   - Тестирование применения badsum
   - Тестирование вычисления неверных checksums
   - Тестирование условий применения

### Integration Tests

1. **End-to-End Strategy Tests**
   - Тестирование полного pipeline обработки
   - Тестирование комбинации стратегий
   - Тестирование с реальными TLS пакетами

2. **PCAP Validation Tests**
   - Генерация тестовых PCAP файлов
   - Проверка применения стратегий через анализ
   - Сравнение до/после применения стратегий

### Performance Tests

1. **Throughput Tests** - измерение производительности обработки пакетов
2. **Memory Usage Tests** - контроль потребления памяти
3. **Latency Tests** - измерение задержки обработки

## Implementation Plan

### Phase 1: Core Infrastructure
1. Создание базовых интерфейсов и моделей данных
2. Реализация Position Resolver
3. Реализация SNI Detector
4. Базовые unit tests

### Phase 2: Packet Processing
1. Реализация Packet Modifier
2. Реализация TCP Builder
3. Интеграция с существующим packet processing pipeline
4. Integration tests

### Phase 3: Fooling Strategies
1. Реализация Checksum Fooler
2. Интеграция badsum функциональности
3. Тестирование fooling стратегий

### Phase 4: Strategy Engine
1. Реализация DPI Strategy Engine
2. Интеграция всех компонентов
3. End-to-end тестирование
4. PCAP validation

### Phase 5: CLI Integration
1. Обновление CLI парсера
2. Интеграция с существующим CLI
3. Обновление документации
4. Финальное тестирование

## Performance Considerations

1. **Caching** - кэширование результатов парсинга TLS пакетов
2. **Memory Pool** - переиспользование объектов для снижения GC pressure
3. **Lazy Evaluation** - вычисление позиций только при необходимости
4. **Batch Processing** - обработка нескольких пакетов за раз

## Security Considerations

1. **Input Validation** - проверка всех входных данных
2. **Buffer Overflow Protection** - защита от переполнения буферов
3. **Resource Limits** - ограничение потребления ресурсов
4. **Logging Security** - избежание логирования чувствительных данных