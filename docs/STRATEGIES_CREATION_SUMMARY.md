# Создание Файла Стратегий DPI Обхода

## Обзор

Создан комплексный файл стратегий `strategies.txt` на основе всех доступных атак в системе для тестирования DPI обхода.

## Созданные Файлы

### 1. strategies.txt
Содержит 113 различных стратегий DPI обхода, включающих:

#### Базовые TCP Атаки
- **Split attacks**: Простое разделение пакетов на позициях 3, 10, sni, cipher
- **Disorder attacks**: Изменение порядка сегментов без фейковых пакетов  
- **Fake packet attacks**: Race condition атаки с различными TTL (1, 3, 5)

#### Продвинутые Атаки
- **FakeDisorder**: Zapret-совместимые атаки с фейковыми пакетами
- **Sequence Overlap (seqovl)**: Атаки с перекрытием TCP последовательностей
- **Multi-Split**: Множественное разделение пакетов
- **Multi-Disorder**: Множественное изменение порядка

#### TCP Манипуляции
- **TCP Fragmentation**: Фрагментация на уровне TCP
- **TCP Options**: Манипуляции с TCP опциями и padding
- **TCP Window**: Манипуляции с размером окна и масштабированием
- **TCP Sequence**: Манипуляции с номерами последовательности
- **Urgent Pointer**: Манипуляции с указателем срочности

#### Комбинированные Стратегии
- Комбинации split + fooling методов
- Вариации TTL (1-5)
- Вариации позиций разделения (1-100)
- Вариации размеров перекрытия (1-50)
- Множественные позиции разделения

#### Протокол-Специфичные Атаки
- TLS-специфичные атаки (SNI, cipher позиции)
- HTTP-специфичные атаки
- Timing-based атаки с задержками

#### Fooling Методы
- **badsum**: Неправильная TCP checksum
- **badseq**: Неправильный sequence number
- **md5sig**: MD5 signature манипуляции
- Комбинации нескольких методов

### 2. sites.txt
Тестовый файл с 10 популярными доменами:
- google.com, youtube.com, facebook.com
- twitter.com, instagram.com, github.com
- stackoverflow.com, wikipedia.org, reddit.com, amazon.com

## Доступные Атаки в Системе

### Базовые Атаки (из реестра)
```
disorder, disorder2, fake, fakeddisorder, multidisorder, multisplit, 
seqovl, split, tcp_fragmentation, tcp_multisplit, tcp_options_modification,
tcp_options_padding, tcp_sequence_manipulation, tcp_timestamp_manipulation,
tcp_window_manipulation, tcp_window_scaling, tcp_wssize_limit, 
urgent_pointer_manipulation
```

### Продвинутые Атаки (из диспетчера)
```
fakeddisorder, multidisorder, multisplit, seqovl
```

### Категории Атак по Директориям
- **combo/**: Комбинированные и адаптивные атаки
- **dns/**: DNS туннелирование и манипуляции
- **http/**: HTTP/2, QUIC, заголовки
- **ip/**: IP фрагментация и манипуляции заголовков
- **obfuscation/**: Обфускация трафика и протоколов
- **payload/**: Шифрование и обфускация payload
- **tcp/**: TCP манипуляции и timing
- **tls/**: TLS evasion и манипуляции
- **timing/**: Timing-based атаки
- **tunneling/**: Протокольное туннелирование
- **udp/**: UDP и QUIC атаки

## Исправленные Проблемы

### 1. Рекурсивная Ошибка при Cleanup
**Проблема**: `RecursionError: maximum recursion depth exceeded` при отмене задач
**Решение**: Исключение текущей задачи из списка задач для отмены в `cleanup_aiohttp_sessions()`

### 2. Ошибка enabled_only
**Проблема**: `AttackRegistry.list_attacks() got an unexpected keyword argument 'enabled_only'`
**Решение**: Добавлен параметр `enabled_only` в метод `list_attacks()` для совместимости

## Команды для Тестирования

### Тест одной стратегии
```bash
python cli.py google.com --strategy "fakeddisorder:split_pos=3,ttl=1" --no-generate --fingerprint --analysis-level fast
```

### Тест всех стратегий из файла
```bash
python cli.py -d sites.txt --strategies-file strategies.txt --no-generate --parallel 15 --fingerprint --pcap out2.pcap --analysis-level full --enable-enhanced-tracking --telemetry-full
```

### Тест на одном домене
```bash
python cli.py google.com --strategies-file strategies.txt --no-generate --parallel 10 --fingerprint --analysis-level fast
```

## Следующие Шаги

1. **Тестирование**: Запустить полное тестирование всех стратегий
2. **Анализ PCAP**: Проверить корректность генерируемых пакетов
3. **Валидатор**: Создать автоматический валидатор атак по результатам
4. **Циклическое тестирование**: Итеративное исправление багов в атаках
5. **Оптимизация**: Улучшение производительности и надежности

## Статус

✅ **Файл стратегий создан** - 113 стратегий готовы к тестированию
✅ **Основные ошибки исправлены** - система работает стабильно  
✅ **Тестовые файлы готовы** - sites.txt и strategies.txt созданы
⏳ **Готово к полному тестированию** - можно запускать массовые тесты