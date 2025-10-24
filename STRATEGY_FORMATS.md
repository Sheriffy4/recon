# Поддерживаемые форматы стратегий

`UnifiedStrategyLoader` поддерживает несколько форматов стратегий для максимальной гибкости.

## 1. Zapret CLI формат (рекомендуется)

Формат командной строки zapret - наиболее распространенный и хорошо документированный.

```
--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-ttl=3 --dpi-desync-fooling=badsum
```

**Примеры:**
- `--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-ttl=3`
- `--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-ttl=3`
- `--dpi-desync=seqovl --dpi-desync-split-pos=5 --dpi-desync-split-seqovl=20`

## 2. Функциональный формат

Формат вызова функции с параметрами в скобках.

```
fakeddisorder(split_pos=3, ttl=3, fooling=['badsum', 'badseq'])
```

**Примеры:**
- `fakeddisorder(split_pos=3, ttl=3, fooling=['badsum'])`
- `multisplit(positions=[1,5,10], ttl=3)`
- `seqovl(split_pos=5, overlap_size=20, ttl=3)`

## 3. Формат с двоеточием (НОВЫЙ)

Компактный формат с двоеточием для разделения типа атаки и параметров.

### Полный формат:
```
attack:param1=value1,param2=value2
```

**Примеры:**
- `seqovl:split_pos=10,overlap_size=20,fake_ttl=1`
- `fakeddisorder:split_pos=sni,ttl=1,fooling=[badsum,badseq,md5sig]`
- `multisplit:positions=[1,5,10],ttl=3`

### Сокращенный формат (одиночное значение):
```
attack:value
```

Одиночное значение автоматически интерпретируется как:
- `split_pos` для атак: split, disorder, disorder2, fakeddisorder, seqovl
- `ttl` для атаки: fake
- `split_pos` для других атак (по умолчанию)

**Примеры сокращенного формата:**
- `split:3` → `split:split_pos=3`
- `split:sni` → `split:split_pos=sni`
- `disorder:10` → `disorder:split_pos=10`
- `fake:3` → `fake:ttl=3`
- `fakeddisorder:5` → `fakeddisorder:split_pos=5`

## 4. Словарный формат (программный)

Формат Python словаря для программного использования.

```python
{
    "type": "fakeddisorder",
    "params": {
        "split_pos": 3,
        "ttl": 3,
        "fooling": ["badsum"]
    }
}
```

## Автоматическое определение формата

`UnifiedStrategyLoader` автоматически определяет формат стратегии:

```python
from core.unified_strategy_loader import UnifiedStrategyLoader

loader = UnifiedStrategyLoader()

# Все эти форматы работают одинаково
strategy1 = loader.load_strategy("--dpi-desync=fake,disorder --dpi-desync-split-pos=3")
strategy2 = loader.load_strategy("fakeddisorder(split_pos=3, ttl=3)")
strategy3 = loader.load_strategy("fakeddisorder:split_pos=3,ttl=3")
strategy4 = loader.load_strategy({"type": "fakeddisorder", "params": {"split_pos": 3}})
```

## Специальные значения параметров

Некоторые параметры поддерживают специальные значения:

### split_pos
- `cipher` - позиция после cipher suite в TLS ClientHello
- `sni` - позиция после SNI в TLS ClientHello
- `midsld` - середина второго уровня домена
- Числовое значение - конкретная позиция в байтах

### fooling
- `badsum` - неправильная контрольная сумма TCP
- `badseq` - неправильный sequence number
- `md5sig` - неправильная MD5 подпись
- `none` - без обмана

### Примеры со специальными значениями:
```
fakeddisorder:split_pos=sni,ttl=3,fooling=[badsum]
seqovl:split_pos=cipher,overlap_size=20,ttl=2
multisplit:positions=[midsld,5,10],ttl=3
```

## Валидация

Все форматы проходят одинаковую валидацию:
- Проверка обязательных параметров
- Проверка диапазонов значений
- Проверка специальных значений
- Автоматическое разрешение конфликтов (например, ttl vs autottl)

## Нормализация

Все форматы нормализуются к единому внутреннему представлению:

```python
NormalizedStrategy(
    type='fakeddisorder',
    params={'split_pos': 3, 'ttl': 3, 'fooling': ['badsum']},
    no_fallbacks=True,
    forced=True
)
```

## Рекомендации

1. **Для конфигурационных файлов** - используйте Zapret CLI формат (наиболее читаемый)
2. **Для программного использования** - используйте словарный формат
3. **Для компактной записи** - используйте формат с двоеточием
4. **Для тестирования** - используйте функциональный формат (наиболее наглядный)

## Совместимость

Все форматы полностью совместимы и взаимозаменяемы. Выбирайте тот, который удобнее для вашего случая использования.