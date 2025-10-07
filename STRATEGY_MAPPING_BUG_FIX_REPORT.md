# Strategy Mapping Bug Fix Report

## Дата: 2025-10-03

## Проблема

Пользователь сообщил, что после применения всех предыдущих исправлений bypass сервис запускается, но **заблокированные домены всё равно не открываются**.

## Диагностика

### Анализ лога

При анализе обновлённого `log.txt` обнаружено:

```
2025-10-03 16:05:15 [INFO] ReconService: Parsed strategy config: {'desync_method': 'fakeddisorder', 'ttl': 3, 'split_pos': 3, 'fooling': 'badsum', 'overlap_size': 336}
2025-10-03 16:05:15 [INFO] ReconService: Mapped x.com -> badsum_race({'ttl': 3, ...})
```

**Проблема**: Стратегия для x.com парсится как `fakeddisorder`, но мапится на `badsum_race`!

### Ожидаемое поведение

Для x.com в `strategies.json`:
```json
"x.com": "--dpi-desync=fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-split-seqovl=336 --dpi-desync-ttl=3 --dpi-desync-autottl=2 --dpi-desync-fooling=badsum,badseq --dpi-desync-repeats=1"
```

Должно мапиться на: `fakeddisorder` с параметрами overlap_size=336, ttl=3

### Фактическое поведение

Мапилось на: `badsum_race` с параметрами extra_ttl=5, delay_ms=5

## Корневая причина

В функции `_config_to_strategy_task()` в `recon_service.py` (строки ~415-445) была неправильная логика:

```python
elif desync_method in ("fake", "fakeddisorder", "seqovl"):
    base_params = {...}
    if fooling == "badsum":  # ❌ Эта проверка выполнялась ПЕРВОЙ
        task_type = "badsum_race"
        ...
    elif desync_method == "fakeddisorder":  # Эта проверка никогда не выполнялась!
        ...
```

**Проблема**: Проверка `fooling == "badsum"` выполнялась раньше проверки `desync_method == "fakeddisorder"`, поэтому для стратегии `fakeddisorder + badsum` всегда выбиралась `badsum_race`.

## Решение

Изменён порядок проверок - сначала проверяется `desync_method`, затем `fooling`:

```python
elif desync_method in ("fake", "fakeddisorder", "seqovl"):
    base_params = {...}
    
    # ✅ Для fakeddisorder всегда используем fakeddisorder стратегию
    if desync_method == "fakeddisorder":
        task_type = "fakeddisorder"
        base_params["overlap_size"] = config.get("overlap_size", 336)
        if fooling == "badsum":
            base_params["corrupt_fake_checksum"] = True
    elif fooling == "badsum":
        task_type = "badsum_race"
        ...
```

## Тестирование

Создан тест `test_strategy_mapping_fix.py`, который проверяет:

1. ✅ `fakeddisorder + badsum` → `fakeddisorder` (с overlap_size=336, corrupt_fake_checksum=True)
2. ✅ `fake + badsum` → `badsum_race` (с extra_ttl=5, delay_ms=5)
3. ✅ `fake + badseq` → `fakedisorder`
4. ✅ `multisplit` → `multisplit`

Результат: **Все критичные тесты пройдены** ✅

## Затронутые домены

Исправление влияет на следующие домены из `strategies.json`:

- `x.com`
- `www.x.com`
- `api.x.com`
- `mobile.x.com`
- `twitter.com`
- `www.twitter.com`
- `mobile.twitter.com`

Все эти домены используют стратегию `fakeddisorder` с `fooling=badsum`, которая теперь будет применяться правильно.

## Инструкции по применению

1. **Остановить** текущий сервис bypass (Ctrl+C)
2. **Запустить** сервис заново: `python setup.py` → [2]
3. **Проверить** в логе правильную стратегию:
   ```
   🎯 Applying bypass for 172.66.0.227 -> Type: fakeddisorder, Params: {...}
   ```
4. **Попробовать** открыть x.com или другие заблокированные домены

## Ожидаемый результат

После применения исправления:
- Сервис будет применять правильную стратегию `fakeddisorder` для x.com
- Bypass должен работать корректно
- Заблокированные домены должны открываться

## Файлы

- **Исправлен**: `recon/recon_service.py` (функция `_config_to_strategy_task`)
- **Создан тест**: `recon/test_strategy_mapping_fix.py`
- **Документация**: 
  - `recon/STRATEGY_MAPPING_FIX_APPLIED.txt`
  - `recon/БЫСТРОЕ_РЕШЕНИЕ.txt`
  - `recon/STRATEGY_MAPPING_BUG_FIX_REPORT.md`

## Статус

✅ **ИСПРАВЛЕНО** - Готово к тестированию пользователем

---

**Примечание**: Это исправление критично для работы bypass на доменах x.com/twitter.com и других, использующих стратегию `fakeddisorder`.
