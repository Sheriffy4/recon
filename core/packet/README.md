# Packet Utilities

Утилиты для парсинга и обработки сетевых пакетов.

## packet_parser_utils.py

Переиспользуемые функции для парсинга IP и TCP заголовков из RawPacket объектов.

### Функции

#### `parse_tcp_packet_headers(packet: RawPacket) -> Optional[Tuple[IPHeader, TCPHeader, int]]`

Парсинг IP и TCP заголовков из RawPacket.

**Параметры:**
- `packet` - RawPacket объект для парсинга

**Возвращает:**
- `Tuple[IPHeader, TCPHeader, int]` - IP заголовок, TCP заголовок, размер IP заголовка
- `None` если пакет слишком мал или парсинг не удался

**Пример:**
```python
from core.packet.packet_parser_utils import parse_tcp_packet_headers

headers = parse_tcp_packet_headers(packet)
if headers:
    ip_header, tcp_header, ip_header_size = headers
    print(f"TTL: {ip_header.ttl}")
    print(f"Flags: {tcp_header.flags}")
```

---

#### `extract_rst_packets(tcp_packets: List[RawPacket]) -> List[RawPacket]`

Извлечение RST пакетов из списка TCP пакетов.

**Параметры:**
- `tcp_packets` - Список TCP пакетов (RawPacket)

**Возвращает:**
- `List[RawPacket]` - список пакетов с установленным флагом RST

**Пример:**
```python
from core.packet.packet_parser_utils import extract_rst_packets

rst_packets = extract_rst_packets(tcp_packets)
print(f"Найдено {len(rst_packets)} RST пакетов")
```

---

#### `has_tcp_flag(packet: RawPacket, flag: int) -> bool`

Проверка наличия TCP флага в пакете.

**Параметры:**
- `packet` - RawPacket объект
- `flag` - TCP флаг для проверки (например, `TCPHeader.FLAG_RST`)

**Возвращает:**
- `bool` - True если флаг установлен

**Пример:**
```python
from core.packet.packet_parser_utils import has_tcp_flag
from core.packet.raw_packet_engine import TCPHeader

if has_tcp_flag(packet, TCPHeader.FLAG_RST):
    print("Это RST пакет")

if has_tcp_flag(packet, TCPHeader.FLAG_SYN):
    print("Это SYN пакет")
```

---

#### `get_tcp_flags(packet: RawPacket) -> Optional[int]`

Получение TCP флагов из пакета.

**Параметры:**
- `packet` - RawPacket объект

**Возвращает:**
- `int` - значение TCP флагов или None если парсинг не удался

**Пример:**
```python
from core.packet.packet_parser_utils import get_tcp_flags
from core.packet.raw_packet_engine import TCPHeader

flags = get_tcp_flags(packet)
if flags:
    if flags & TCPHeader.FLAG_SYN:
        print("SYN установлен")
    if flags & TCPHeader.FLAG_ACK:
        print("ACK установлен")
```

---

#### `get_tcp_sequence_numbers(packet: RawPacket) -> Optional[Tuple[int, int]]`

Получение sequence и acknowledgment номеров из TCP пакета.

**Параметры:**
- `packet` - RawPacket объект

**Возвращает:**
- `Tuple[int, int]` - (seq_num, ack_num) или None если парсинг не удался

**Пример:**
```python
from core.packet.packet_parser_utils import get_tcp_sequence_numbers

seq_ack = get_tcp_sequence_numbers(packet)
if seq_ack:
    seq_num, ack_num = seq_ack
    print(f"SEQ: {seq_num}, ACK: {ack_num}")
```

---

#### `get_ip_ttl(packet: RawPacket) -> Optional[int]`

Получение TTL значения из IP заголовка.

**Параметры:**
- `packet` - RawPacket объект

**Возвращает:**
- `int` - TTL значение или None если парсинг не удался

**Пример:**
```python
from core.packet.packet_parser_utils import get_ip_ttl

ttl = get_ip_ttl(packet)
if ttl:
    print(f"TTL: {ttl}")
    if ttl < 10:
        print("Подозрительно низкий TTL!")
```

---

## Преимущества

### Устранение дублирования
До рефакторинга парсинг IP/TCP заголовков дублировался в ~30 местах:
```python
# Старый способ (дублировался везде)
if len(p.data) >= 40:
    ip_header = IPHeader.unpack(p.data[:20])
    ip_header_size = ip_header.ihl * 4
    tcp_header = TCPHeader.unpack(p.data[ip_header_size:])
    if tcp_header.flags & TCPHeader.FLAG_RST:
        # ...
```

После рефакторинга:
```python
# Новый способ (переиспользуемая функция)
if has_tcp_flag(p, TCPHeader.FLAG_RST):
    # ...
```

### Обработка ошибок
Все функции корректно обрабатывают ошибки и возвращают `None` вместо exception'ов:
```python
headers = parse_tcp_packet_headers(packet)
if headers is None:
    # Пакет некорректный или слишком мал
    continue
```

### Производительность
- Минимальные проверки размера пакета
- Эффективный unpacking заголовков
- Кэширование результатов парсинга (где возможно)

## Использование в других модулях

Все анализаторы используют эти утилиты:

```python
# В RSTAnalyzer
from core.packet.packet_parser_utils import parse_tcp_packet_headers, get_ip_ttl

def analyze_rst_ttl(self, rst_packets, all_tcp_packets):
    for p in all_tcp_packets:
        headers = parse_tcp_packet_headers(p)
        if headers:
            ip_header, tcp_header, _ = headers
            # ...

# В TLSAnalyzer
from core.packet.packet_parser_utils import parse_tcp_packet_headers

def analyze_tls_handshake(self, tcp_packets):
    for p in tcp_packets:
        headers = parse_tcp_packet_headers(p)
        if headers:
            _, tcp_header, _ = headers
            # ...
```

## Тестирование

```python
import pytest
from core.packet.packet_parser_utils import *
from core.packet.raw_packet_engine import RawPacket, TCPHeader

def test_parse_tcp_packet_headers():
    # Создаем тестовый пакет
    packet = create_test_packet()
    
    headers = parse_tcp_packet_headers(packet)
    assert headers is not None
    
    ip_header, tcp_header, ip_size = headers
    assert ip_size >= 20
    assert tcp_header.flags is not None

def test_extract_rst_packets():
    packets = [create_syn_packet(), create_rst_packet(), create_ack_packet()]
    rst_packets = extract_rst_packets(packets)
    assert len(rst_packets) == 1
```

## Расширение

Для добавления новой утилиты:

1. Добавьте функцию в `packet_parser_utils.py`
2. Используйте `parse_tcp_packet_headers()` как базу
3. Обрабатывайте ошибки корректно (возвращайте `None`)
4. Добавьте docstring с примером
5. Добавьте unit-тесты

Пример:
```python
def get_tcp_window_size(packet: RawPacket) -> Optional[int]:
    """
    Получение размера TCP окна.
    
    Args:
        packet: RawPacket объект
    
    Returns:
        int - размер окна или None
    """
    headers = parse_tcp_packet_headers(packet)
    if headers is None:
        return None
    
    _, tcp_header, _ = headers
    return tcp_header.window_size
```
