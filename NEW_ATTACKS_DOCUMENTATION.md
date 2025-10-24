# Документация по новым атакам

## Обзор

Реализовано **13 новых продвинутых атак** для обхода DPI систем.

## TCP-уровень атаки (6 атак)

### 1. tcp_window_manipulation
**Описание**: Манипуляция размером TCP окна для сбивания flow control tracking.

**Параметры**:
- `window_size` (int): Размер окна (по умолчанию: 2048)
- `split_pos` (int): Позиция разделения payload

**Пример**:
```
tcp_window_manipulation:window_size=1024,split_pos=100
```

**Эффективность**: Средняя против DPI с TCP flow tracking

---

### 2. tcp_sequence_manipulation
**Описание**: Манипуляция TCP sequence numbers для сбивания stream reassembly.

**Параметры**:
- `split_pos` (int): Позиция разделения
- `seq_offset` (int): Offset для sequence number (по умолчанию: 1000)

**Пример**:
```
tcp_sequence_manipulation:split_pos=50,seq_offset=2000
```

**Эффективность**: Высокая против простых DPI систем

---

### 3. tcp_window_scaling
**Описание**: Использование TCP Window Scaling опции.

**Параметры**:
- `scale_factor` (int): Фактор масштабирования (0-14, по умолчанию: 7)

**Пример**:
```
tcp_window_scaling:scale_factor=10
```

**Эффективность**: Средняя, полезна в комбинации с другими атаками

---

### 4. urgent_pointer_manipulation
**Описание**: Манипуляция Urgent Pointer и URG флага.

**Параметры**:
- `urgent_offset` (int): Позиция urgent pointer (по умолчанию: 10)

**Пример**:
```
urgent_pointer_manipulation:urgent_offset=20
```

**Эффективность**: Средняя против DPI, не обрабатывающих URG правильно

---

### 5. tcp_options_padding
**Описание**: Добавление padding в TCP опции.

**Параметры**:
- `padding_size` (int): Размер padding в байтах (по умолчанию: 20)

**Пример**:
```
tcp_options_padding:padding_size=30
```

**Эффективность**: Низкая, но может помочь в комбинации

---

### 6. tcp_timestamp_manipulation
**Описание**: Манипуляция TCP Timestamp опцией.

**Параметры**:
- `ts_ecr` (int): Timestamp Echo Reply (по умолчанию: 0)

**Пример**:
```
tcp_timestamp_manipulation:ts_ecr=12345
```

**Эффективность**: Средняя против timing-based DPI

---

## TLS-уровень атаки (3 атаки)

### 7. sni_manipulation
**Описание**: Манипуляция Server Name Indication (SNI).

**Параметры**:
- `mode` (str): Режим - 'fake', 'remove', 'duplicate' (по умолчанию: 'fake')
- `fake_sni` (str): Фейковый SNI (по умолчанию: 'example.com')

**Примеры**:
```
sni_manipulation:mode=fake,fake_sni=google.com
sni_manipulation:mode=remove
sni_manipulation:mode=duplicate
```

**Эффективность**: Очень высокая против SNI-based блокировок

---

### 8. alpn_manipulation
**Описание**: Манипуляция ALPN (Application-Layer Protocol Negotiation).

**Параметры**:
- `protocols` (list): Список протоколов (по умолчанию: ['h2', 'http/1.1'])

**Пример**:
```
alpn_manipulation:protocols=[h2,http/1.1,http/1.0]
```

**Эффективность**: Средняя против protocol-based блокировок

---

### 9. grease_injection
**Описание**: Инъекция GREASE значений для имитации современных браузеров.

**Параметры**:
- `count` (int): Количество GREASE значений (по умолчанию: 3)

**Пример**:
```
grease_injection:count=5
```

**Эффективность**: Высокая для обхода fingerprinting

---

## IP-уровень и обфускация (4 атаки)

### 10. ip_ttl_manipulation
**Описание**: Манипуляция IP TTL.

**Параметры**:
- `ttl` (int): Значение TTL (по умолчанию: 64)

**Пример**:
```
ip_ttl_manipulation:ttl=128
```

**Эффективность**: Средняя, зависит от DPI

---

### 11. ip_id_manipulation
**Описание**: Манипуляция IP ID field.

**Параметры**:
- `ip_id` (int): Значение IP ID (по умолчанию: случайное)

**Пример**:
```
ip_id_manipulation:ip_id=12345
```

**Эффективность**: Низкая, но может помочь

---

### 12. payload_padding
**Описание**: Добавление padding к payload.

**Параметры**:
- `padding_size` (int): Размер padding (по умолчанию: 100)

**Пример**:
```
payload_padding:padding_size=200
```

**Эффективность**: Средняя против signature-based DPI

---

### 13. noise_injection
**Описание**: Инъекция случайного шума в payload.

**Параметры**:
- `noise_size` (int): Размер шума (по умолчанию: 50)
- `position` (str): Позиция - 'start', 'middle', 'end' (по умолчанию: 'end')

**Пример**:
```
noise_injection:noise_size=100,position=middle
```

**Эффективность**: Высокая против signature-based DPI

---

## Комбинированное использование

Атаки можно комбинировать для максимальной эффективности:

```
# TCP + TLS комбинация
tcp_window_manipulation:window_size=1024 + sni_manipulation:mode=fake

# Обфускация + манипуляция
noise_injection:noise_size=100 + tcp_sequence_manipulation:seq_offset=2000

# Полная защита
sni_manipulation:mode=fake + grease_injection:count=5 + payload_padding:padding_size=150
```

## Статистика реализации

- **Всего новых атак**: 13
- **TCP-уровень**: 6 атак
- **TLS-уровень**: 3 атаки
- **IP/Обфускация**: 4 атаки

## Следующие шаги

Для полной реализации всех 154 атак потребуется:
1. HTTP/2 атаки (10 атак)
2. QUIC/HTTP3 атаки (9 атак)
3. DNS атаки (9 атак)
4. Туннелирование (8 атак)
5. Стеганография (10 атак)
6. И другие категории...

**Текущий прогресс**: 28 атак из 169 (16.6%)