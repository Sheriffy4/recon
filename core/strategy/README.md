# Strategy Modules

Модули для работы со стратегиями обхода DPI.

## recommendation_engine.py

Генератор рекомендаций для улучшения стратегий обхода на основе анализа неудач.

### RecommendationEngine

Класс для генерации intent-based рекомендаций и предложения альтернативных подходов.

#### Основные методы

##### `generate_recommendations(failure_report) -> List[Recommendation]`

Генерация рекомендаций на основе отчета о неудаче.

**Параметры:**
- `failure_report` - FailureReport объект с результатами анализа

**Возвращает:**
- `List[Recommendation]` - топ-5 рекомендаций, отсортированных по приоритету

**Пример:**
```python
from core.strategy.recommendation_engine import RecommendationEngine

engine = RecommendationEngine()
recommendations = engine.generate_recommendations(failure_report)

for rec in recommendations:
    print(f"Действие: {rec.action}")
    print(f"Обоснование: {rec.rationale}")
    print(f"Приоритет: {rec.priority}")
    print(f"Параметры: {rec.parameters}")
```

---

### Recommendation (dataclass)

Структура данных для рекомендации.

**Поля:**
- `action: str` - действие для применения (например, "apply_intent_short_ttl_decoy")
- `rationale: str` - обоснование рекомендации
- `priority: float` - приоритет (0.0-1.0)
- `parameters: Dict[str, Any]` - параметры для применения

**Пример:**
```python
from core.strategy.recommendation_engine import Recommendation

rec = Recommendation(
    action="apply_intent_conceal_sni",
    rationale="Обнаружена SNI фильтрация",
    priority=0.85,
    parameters={
        "intent_key": "conceal_sni",
        "split_position": "sni",
        "fooling_method": "badsum"
    }
)
```

---

## Маппинг причин неудач → Intent'ы

RecommendationEngine использует маппинг для генерации рекомендаций:

```python
cause_to_intents = {
    "DPI_SNI_FILTERING": [
        "conceal_sni",
        "record_fragmentation",
        "fake_sni"
    ],
    "DPI_ACTIVE_RST_INJECTION": [
        "short_ttl_decoy",
        "sequence_overlap",
        "timing_manipulation"
    ],
    "DPI_CONTENT_INSPECTION": [
        "payload_obfuscation",
        "tls_extension_manipulation",
        "record_fragmentation"
    ],
    "DPI_REASSEMBLES_FRAGMENTS": [
        "packet_reordering",
        "sequence_overlap",
        "timing_manipulation"
    ],
    "DPI_STATEFUL_TRACKING": [
        "sequence_overlap",
        "out_of_order_decoy",
        "timing_manipulation"
    ],
    "NETWORK_TIMEOUT": [
        "timeout_adjustment",
        "ipv6_fallback"
    ],
    "CONNECTION_REFUSED": [
        "port_randomization",
        "ipv6_fallback"
    ],
    "TLS_HANDSHAKE_FAILURE": [
        "tls_extension_manipulation",
        "record_fragmentation"
    ]
}
```

---

## Intent-specific параметры

Каждый intent имеет специфичные параметры:

### short_ttl_decoy
```python
{
    "ttl": 1,
    "fooling_method": "badseq",
    "reason": "rst_injection_detected"
}
```

### conceal_sni
```python
{
    "split_position": "sni",
    "fooling_method": "badsum",
    "reason": "sni_filtering_detected"
}
```

### record_fragmentation
```python
{
    "split_count": 8,
    "split_position": "random",
    "reason": "content_inspection_detected"
}
```

### packet_reordering
```python
{
    "reorder_method": "simple",
    "split_positions": [2, 3],
    "reason": "fragmentation_reassembly_detected"
}
```

### sequence_overlap
```python
{
    "overlap_size": 2,
    "reason": "stateful_tracking_detected"
}
```

### timing_manipulation
```python
{
    "delay_ms": 50,
    "jitter_enabled": True,
    "reason": "timing_sensitive_dpi"
}
```

---

## Адаптивные параметры

RecommendationEngine адаптирует параметры на основе технических деталей:

```python
# Пример: адаптация TTL для short_ttl_decoy
if intent_key == "short_ttl_decoy" and "injection_indicators" in technical_details:
    indicators = technical_details["injection_indicators"]
    if "suspicious_ttl" in indicators:
        base_parameters["ttl"] = 2  # Используем TTL=2 если DPI использует TTL=1

# Пример: адаптация количества фрагментов
if intent_key == "record_fragmentation" and "fragmented_packets" in technical_details:
    frag_count = technical_details.get("fragmented_packets", 0)
    if frag_count > 0:
        base_parameters["split_count"] = min(16, frag_count * 2)
```

---

## Альтернативные рекомендации

Engine предлагает альтернативные подходы на основе индикаторов:

### Для RST инъекций

**Множественные источники RST:**
```python
Recommendation(
    action="apply_intent_timing_manipulation",
    rationale="Обнаружены множественные источники RST - попробуйте манипуляции с таймингом",
    priority=0.75,
    parameters={"intent_key": "timing_manipulation", "delay_ms": 100}
)
```

**Нереалистичный тайминг:**
```python
Recommendation(
    action="apply_intent_sequence_overlap",
    rationale="DPI реагирует слишком быстро - используйте перекрытие последовательностей",
    priority=0.8,
    parameters={"intent_key": "sequence_overlap", "overlap_size": 4}
)
```

### Для фрагментации

**TCP сборка работает:**
```python
Recommendation(
    action="apply_intent_payload_obfuscation",
    rationale="TCP сборка работает - попробуйте обфускацию на уровне приложения",
    priority=0.85,
    parameters={"intent_key": "payload_obfuscation", "obfuscation_method": "xor"}
)
```

---

## Вычисление уверенности

Уверенность в рекомендации вычисляется на основе:

1. **Базовая уверенность** из failure_report.confidence
2. **Бонус за специфичность** (+0.1 если есть technical_details)
3. **Бонус за количество индикаторов** (+0.1 если >2 индикаторов)

```python
def _calculate_confidence(self, failure_report, intent_key: str) -> float:
    base_confidence = failure_report.confidence
    
    technical_details = failure_report.failure_details.get("technical_details", {})
    if technical_details:
        base_confidence += 0.1
    
    indicators = technical_details.get("injection_indicators", [])
    if len(indicators) > 2:
        base_confidence += 0.1
    
    return min(1.0, base_confidence)
```

---

## Дедупликация

Рекомендации дедуплицируются по ключу `(action, intent_key)`:

```python
def _deduplicate_recommendations(self, recommendations):
    seen = set()
    unique = []
    
    for rec in recommendations:
        key = (rec.action, rec.parameters.get("intent_key"))
        if key not in seen:
            seen.add(key)
            unique.append(rec)
    
    return unique
```

---

## Полный пример использования

```python
from core.strategy_failure_analyzer import StrategyFailureAnalyzer
from core.strategy.recommendation_engine import RecommendationEngine

# Анализ неудачи
analyzer = StrategyFailureAnalyzer()
failure_report = await analyzer.analyze_pcap(pcap_file, strategy, domain)

# Генерация рекомендаций
engine = RecommendationEngine()
recommendations = engine.generate_recommendations(failure_report)

# Применение топ рекомендации
if recommendations:
    top_rec = recommendations[0]
    print(f"Рекомендуется: {top_rec.action}")
    print(f"Причина: {top_rec.rationale}")
    print(f"Уверенность: {top_rec.priority:.2%}")
    
    # Применяем intent с рекомендованными параметрами
    intent_key = top_rec.parameters["intent_key"]
    params = {k: v for k, v in top_rec.parameters.items() if k != "intent_key"}
    
    # Создаем новую стратегию с рекомендованным intent'ом
    new_strategy = create_strategy_with_intent(intent_key, params)
```

---

## Интеграция с StrategyFailureAnalyzer

RecommendationEngine интегрирован в главный анализатор:

```python
class StrategyFailureAnalyzer:
    def __init__(self):
        # ...
        self.recommendation_engine = RecommendationEngine()
    
    async def analyze_pcap(self, pcap_file, strategy, domain):
        # ... анализ ...
        
        # Генерация рекомендаций
        recommendations = self.recommendation_engine.generate_recommendations(failure_report)
        
        return failure_report
```

---

## Расширение

Для добавления нового intent'а:

1. Добавьте в `cause_to_intents` маппинг
2. Добавьте параметры в `intent_specific_params`
3. Добавьте логику адаптации параметров (опционально)
4. Добавьте альтернативные рекомендации (опционально)

Пример:
```python
# В cause_to_intents
"NEW_FAILURE_TYPE": ["new_intent", "fallback_intent"]

# В intent_specific_params
"new_intent": {
    "param1": "value1",
    "param2": 42,
    "reason": "new_failure_detected"
}

# Адаптация параметров
if intent_key == "new_intent" and "special_indicator" in technical_details:
    base_parameters["param1"] = "adapted_value"
```
