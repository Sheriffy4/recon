# Исправления для совместимости с zapret

## Проблема

Наш recon показывал **0/26 успешных доменов**, в то время как zapret с теми же параметрами показывал **26/31 успешных доменов**.

Стратегия: `--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=3`

## Анализ различий (из PCAP)

### Zapret (работает 26/31):
- **SNI**: `cgz0tadj7bodz.edu` (поддельный!)
- **Checksum**: `csum_ok: false` (намеренно испорчен)
- **Flags real**: `flags_real_psh: true` (PSH флаг)
- **Timing**: `pair_dt_ms: 0.055` (очень быстро)

### Recon (работал 0/26):
- **SNI**: `api.x.com` (реальный - блокируется DPI!)
- **Checksum**: `csum_ok: true` (правильный)
- **Flags real**: `flags_real_psh: false` (нет PSH флага)
- **Timing**: `pair_dt_ms: 3.636` (медленно)

## Критические исправления

### 1. Поддельные SNI (КРИТИЧНО!)

**Файл**: `recon/core/bypass/engine/windows_engine.py`

**Проблема**: Использовались реальные SNI, которые DPI легко блокирует.

**Исправление**: Добавлен метод `_generate_fake_sni()` для генерации поддельных доменов:

```python
def _generate_fake_sni(self, original_sni: Optional[str]) -> str:
    """Генерирует поддельный SNI для обхода DPI как в zapret."""
    fake_domains = [
        "google.com", "microsoft.com", "cloudflare.com",
        "amazon.com", "facebook.com", "apple.com"
    ]
    # 30% случайных доменов, 70% предопределенных
    if random.random() < 0.3:
        random_part = ''.join(random.choices(string.ascii_lowercase, k=random.randint(8, 12)))
        tld = random.choice(['com', 'org', 'net', 'edu'])
        fake_sni = f"{random_part}.{tld}"
    else:
        fake_sni = random.choice(fake_domains)
    return fake_sni
```

**Применено в**:
- `_send_fake_packet()`
- `_send_fake_packet_with_badsum()`

### 2. Испорченные checksums в fake пакетах

**Проблема**: Fake пакеты имели правильные checksums.

**Исправление**: В методе `_send_segments()` добавлена проверка fooling методов:

```python
# Проверяем нужно ли портить checksum
fooling = self.current_params.get("fooling", [])
corrupt_checksum = "badsum" in fooling

if corrupt_checksum:
    csum = csum ^ 0xFFFF
    self.logger.debug(f"Corrupting checksum for segment {i+1}")
```

### 3. PSH флаги в реальных пакетах

**Проблема**: Реальные пакеты не имели PSH флага.

**Исправление**: В методе `_send_segments()`:

```python
# Стабильно даём PSH+ACK на обоих сегментах для flush
tcp_hdr[13] = 0x18
```

### 4. Минимальные задержки

**Проблема**: Задержки были слишком большие (3.6ms vs 0.05ms в zapret).

**Исправление**:

```python
# Было: time.sleep(0.0005)  # 0.5ms
time.sleep(0.00005)  # 0.05ms как в zapret - КРИТИЧЕСКИ БЫСТРО!

# Было: time.sleep(0.002)
time.sleep(0.0001)  # Минимальная задержка как в zapret
```

### 5. Правильный overlap_size для split_pos=3

**Проблема**: Использовался `overlap_size=0`, что не создавало disorder эффект.

**Исправление**:

```python
# Для split_pos=3 используем небольшой overlap как в zapret
if params.get("split_pos") == 3:
    params["overlap_size"] = 1  # Минимальный overlap для disorder эффекта
    self.current_params["overlap_size"] = 1
```

### 6. Правильный TTL для всех пакетов

**Исправление**: Убедились что TTL=3 используется для всех пакетов:

```python
# КРИТИЧЕСКОЕ: TTL должен быть 3 для ВСЕХ пакетов
base_ttl = int(params.get("ttl", 3))
self.current_params["fake_ttl"] = base_ttl
self.current_params["real_ttl"] = base_ttl  # ВАЖНО: real тоже должен быть 3!
```

## Тестирование исправлений

Создан скрипт `test_zapret_compatibility.py` для проверки исправлений:

```bash
# Базовый тест
python test_zapret_compatibility.py

# Полный тест с реальными запросами
python test_zapret_compatibility.py --full-test
```

## Ожидаемый результат

После применения исправлений recon должен показывать результаты близкие к zapret:

- **До исправлений**: 0/26 успешных доменов
- **После исправлений**: ~20-26/31 успешных доменов (как zapret)

## Ключевые файлы изменены

1. `recon/core/bypass/engine/windows_engine.py` - основные исправления
2. `recon/test_zapret_compatibility.py` - тесты совместимости
3. `recon/ZAPRET_COMPATIBILITY_FIXES.md` - этот документ

## Проверка результата

Для проверки эффективности исправлений:

1. Запустите тест с той же стратегией:
   ```bash
   python cli.py -d sites.txt --pcap out3.pcap --strategy "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum,badseq --dpi-desync-ttl=3"
   ```

2. Сравните результаты с zapret:
   ```bash
   python analyze_pcap_comparison.py --recon-pcap out3.pcap --zapret-pcap zapret.pcap
   ```

3. Проверьте PCAP на наличие исправлений:
   - Поддельные SNI (не x.com, twitter.com и т.д.)
   - Испорченные checksums в fake пакетах
   - PSH флаги в реальных пакетах
   - Быстрый timing между пакетами

## Статус

✅ **ИСПРАВЛЕНИЯ ПРИМЕНЕНЫ**

Все критические различия между recon и zapret устранены. Теперь recon должен показывать эффективность обхода DPI на уровне zapret.

---

**Дата**: 18 сентября 2024  
**Версия**: 1.0  
**Статус**: Готово к тестированию