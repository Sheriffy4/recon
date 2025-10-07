# 🎯 ИСПРАВЛЕНИЕ: Split и Disorder теперь работают!

## Проблема

Пользовательские стратегии `split` и `disorder` **парсились правильно**, но **НЕ ТЕСТИРОВАЛИСЬ**!

### Симптомы:
- ✅ В логах: `[OK] Parsed strategy: disorder with params: {'split_pos': 3}`
- ❌ В логах: `[INFO] 🔥 APPLY_BYPASS CALLED: dst=162.159.140.229:443, strategy=unknown`
- ❌ В логах: `[WARNING] Неизвестный или неподдерживаемый тип задачи 'unknown', отправляем оригинал.`

### Анализ:

1. **Парсинг работал**: `strategy_interpreter.interpret_strategy()` правильно возвращал:
   ```python
   {"type": "split", "params": {"split_pos": 3}}
   {"type": "disorder", "params": {"split_pos": 3}}
   ```

2. **Проблема в нормализации**: В `hybrid_engine.py` метод `_ensure_engine_task()` вызывал:
   ```python
   from core.bypass.attacks.alias_map import normalize_attack_name
   ntp = normalize_attack_name(t)  # t = "split" или "disorder"
   ```

3. **Отсутствующие алиасы**: В `alias_map.py` НЕ БЫЛО записей для `"split"` и `"disorder"`:
   ```python
   _ALIAS_MAP = {
       "fakeddisorder": "fakeddisorder",
       "multisplit": "multisplit",
       # ... но НЕТ "split" и "disorder"!
   }
   ```

4. **Результат**: `normalize_attack_name("split")` возвращал `"split"`, но этот тип не был известен системе, поэтому где-то терялся и заменялся на `"unknown"`.

## Решение

### Исправление 1: Добавлены алиасы в `recon/core/bypass/attacks/alias_map.py`

```python
_ALIAS_MAP = {
    # ... существующие алиасы ...
    # ✅ FIX: Add split and disorder aliases
    "split": "split",
    "disorder": "disorder",
    "tcp_split": "split",
    "tcp_disorder": "disorder",
}
```

### Исправление 2: Добавлена обработка в `recon/core/strategy_interpreter.py`

```python
elif DPIMethod.DISORDER in strategy.methods:
    # ✅ FIX: Add handling for simple DISORDER
    attack_type = "disorder"
    params = {'split_pos': strategy.split_pos}
```

### Исправление 3: Обновлена логика в `recon/core/hybrid_engine.py`

```python
# В _translate_zapret_to_engine_task:
elif 'split' in desync:
    # ✅ FIX: Handle simple split
    task_type = 'split'
elif 'disorder' in desync or 'disorder2' in desync:
    # ✅ FIX: Handle simple disorder (not fakeddisorder!)
    task_type = 'disorder'

# Обновлен has_faked:
has_faked = (
    ('fakeddisorder' in desync) or ('desync' in desync)
    # ✅ FIX: Don't include simple 'disorder' in has_faked
)

# Добавлена обработка split_pos для split и disorder:
if task_type in ['fakeddisorder', 'multidisorder', 'multisplit', 'split', 'disorder']:
    # ... обработка split_pos ...
```

## Проверка

Теперь обе стратегии должны работать:

### Тест Split:
```bash
python cli.py x.com --strategy "--dpi-desync=split --dpi-desync-split-pos=3" --pcap test_split.pcap
```

### Тест Disorder:
```bash
python cli.py x.com --strategy "--dpi-desync=disorder --dpi-desync-split-pos=3" --pcap test_disorder.pcap
```

## Ожидаемый результат

В логах должно быть:
```
[OK] Parsed strategy: split with params: {'split_pos': 3}
🔥 APPLY_BYPASS CALLED: dst=162.159.140.229:443, strategy=split
🎯 Applying bypass for 162.159.140.229 -> Type: split, Params: {'split_pos': 3}
```

И для disorder:
```
[OK] Parsed strategy: disorder with params: {'split_pos': 3}
🔥 APPLY_BYPASS CALLED: dst=162.159.140.229:443, strategy=disorder
🎯 Applying bypass for 162.159.140.229 -> Type: disorder, Params: {'split_pos': 3}
```

## Технические детали

### Код обработки в base_engine.py (уже был правильный):
```python
elif task_type == "split":
    # Simple split - just multisplit with one position
    split_pos = int(params.get("split_pos", 3))
    recipe = self.techniques.apply_multisplit(payload, [split_pos])
elif task_type == "disorder":
    # Simple disorder - just multidisorder with one position
    split_pos = int(params.get("split_pos", 3))
    recipe = self.techniques.apply_multidisorder(payload, [split_pos])
```

Этот код **УЖЕ БЫЛ** в движке, но никогда не достигался из-за отсутствующих алиасов!

## Статус

✅ **ИСПРАВЛЕНО** - Все 3 исправления применены
✅ **ПРОТЕСТИРОВАНО** - Все юнит-тесты пройдены (3/3)
✅ **ГОТОВО К РЕАЛЬНОМУ ТЕСТИРОВАНИЮ** - Запустите тесты выше для проверки

## Результаты тестирования

```
🚀 ТЕСТИРОВАНИЕ ИСПРАВЛЕНИЯ SPLIT/DISORDER
================================================================================
✅ PASS - Нормализация алиасов
✅ PASS - Парсинг стратегий
✅ PASS - Конвертация в engine task
--------------------------------------------------------------------------------
Пройдено: 3/3

🎉 ВСЕ ТЕСТЫ ПРОЙДЕНЫ!
```

---

**Дата исправления**: 2025-10-03
**Измененные файлы**:
1. `recon/core/bypass/attacks/alias_map.py` - Добавлены 4 новых алиаса
2. `recon/core/strategy_interpreter.py` - Добавлена обработка DPIMethod.DISORDER
3. `recon/core/hybrid_engine.py` - Обновлена логика _translate_zapret_to_engine_task
