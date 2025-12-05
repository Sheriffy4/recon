# Использование кастомного Payload в CLI

## Обзор

Система поддерживает использование кастомных TLS ClientHello payload для fake атак. Это позволяет использовать реальный ClientHello от браузера вместо сгенерированного curl.

## Новые опции CLI

### --custom-payload FILE

Указывает путь к файлу с кастомным TLS ClientHello payload.

```bash
# Использовать кастомный payload из файла
python cli.py auto nnmclub.to --custom-payload data/payloads/captured/tls_clienthello_nnmclub_to.bin
```

### --fake-payload-file FILE_OR_PLACEHOLDER

Более гибкая опция, поддерживающая:
- Путь к файлу (.bin)
- Placeholder (PAYLOADTLS, PAYLOADHTTP, PAYLOADQUIC)
- Hex-строку (0x16030100...)

```bash
# Использовать bundled payload
python cli.py auto nnmclub.to --fake-payload-file PAYLOADTLS

# Использовать hex-строку
python cli.py auto nnmclub.to --fake-payload-file 0x160301...
```

### --extract-payload PCAP_FILE

Извлекает TLS ClientHello из PCAP файла и сохраняет в `data/payloads/captured/`.

```bash
# Извлечь ClientHello из PCAP
python cli.py --extract-payload log2.pcap
```

## Приоритет выбора payload для fake атак

1. **--payload / --fake-payload** (CLI аргумент) - высший приоритет
2. **PayloadManager lookup** по домену (если есть captured payload)
3. **Bundled payload** (tls_clienthello_www_google_com.bin по умолчанию)
4. **Built-in generator** (fallback)

## Как использовать ClientHello браузера

### Шаг 1: Захватить трафик браузера

1. Запустите Wireshark
2. Установите фильтр: `tcp port 443`
3. Откройте целевой сайт в браузере
4. Остановите захват
5. Сохраните как `browser_capture.pcap`

### Шаг 2: Извлечь ClientHello

```bash
python cli.py --extract-payload browser_capture.pcap
```

Вывод:
```
Extracting TLS ClientHello from PCAP
PCAP file: browser_capture.pcap

Loaded 150 packets
✓ Found TLS ClientHello: 517 bytes
✓ SNI: nnmclub.to

✓ Payload saved!
  File: data/payloads/captured/tls_clienthello_nnmclub_to.bin
  Size: 517 bytes
  Domain: nnmclub.to

Use with: python cli.py auto nnmclub.to --payload data/payloads/captured/tls_clienthello_nnmclub_to.bin
```

### Шаг 3: Использовать при тестировании

```bash
python cli.py auto nnmclub.to --custom-payload data/payloads/captured/tls_clienthello_nnmclub_to.bin --mode deep
```

## Bundled Payloads

Система включает готовые payload в `data/payloads/bundled/`:

| Файл | Домен | Размер |
|------|-------|--------|
| tls_clienthello_www_google_com.bin | www.google.com | 652 B |
| tls_clienthello_vk_com.bin | vk.com | 517 B |
| tls_clienthello_gosuslugi_ru.bin | gosuslugi.ru | 517 B |
| tls_clienthello_sberbank_ru.bin | sberbank.ru | 517 B |
| tls_clienthello_rutracker_org_kyber.bin | rutracker.org | 1.7 KB |

### Просмотр доступных payload

```bash
python cli.py payload list
```

## Как это работает

### Для fake атак

Когда стратегия включает fake атаку (fake, fakeddisorder, fakedsplit), система:

1. Проверяет CLI аргументы `--payload` / `--fake-payload`
2. Если указан, загружает кастомный payload
3. Регистрирует payload в глобальном PayloadManager для целевого домена
4. Все fake атаки используют этот payload вместо дефолтного

### Код интеграции

```python
# В FakedDisorderAttack._generate_zapret_fake_payload():

# Priority 1: Direct bytes payload from config
if self.config.fake_payload is not None:
    return self.config.fake_payload

# Priority 2: Use PayloadManager if available
if PAYLOAD_SYSTEM_AVAILABLE:
    fake_payload = get_attack_payload(
        payload_param=payload_param,
        payload_type=payload_type,
        domain=context.domain
    )
    if fake_payload:
        return fake_payload

# Priority 3 & 4: Fall back to built-in generation
```

## Примеры использования

### Тестирование с браузерным ClientHello

```bash
# 1. Извлечь ClientHello из PCAP браузера
python cli.py --extract-payload browser_nnmclub.pcap

# 2. Запустить тестирование с этим payload
python cli.py auto nnmclub.to --payload data/payloads/captured/tls_clienthello_nnmclub_to.bin --mode deep
```

### Использование Google ClientHello для всех доменов

```bash
python cli.py auto nnmclub.to --fake-payload PAYLOADTLS
```

### Сравнение разных payload

```bash
# Тест 1: С curl-generated payload (по умолчанию)
python cli.py auto nnmclub.to --mode quick > test_curl.log 2>&1

# Тест 2: С браузерным payload
python cli.py auto nnmclub.to --custom-payload browser_clienthello.bin --mode quick > test_browser.log 2>&1

# Сравнить результаты
diff test_curl.log test_browser.log
```

## Troubleshooting

### Payload не найден

```
Warning: Payload file not found: custom.bin
Will use default payload from bundled payloads
```

**Решение:** Проверьте путь к файлу. Используйте абсолютный путь или путь относительно директории recon.

### Не удалось извлечь ClientHello

```
Error: No TLS ClientHello found in PCAP
```

**Решение:** Убедитесь, что PCAP содержит TLS трафик на порт 443. Проверьте фильтр захвата.

### Payload слишком маленький

```
Warning: Payload too short for split_pos=50
```

**Решение:** Используйте payload большего размера или уменьшите split_pos.

## См. также

- [PayloadManager API](../core/payload/manager.py)
- [Attack Integration](../core/payload/attack_integration.py)
- [FakedDisorderAttack](../core/bypass/attacks/tcp/fakeddisorder_attack.py)
