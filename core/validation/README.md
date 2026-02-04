# Results Validation System

Система валидации результатов адаптивного мониторинга DPI bypass.

## Быстрый старт

```python
from core.validation import ResultsValidationSystem

# Создание системы валидации
validator = ResultsValidationSystem("validation_config.json")

# Валидация стратегии
result = await validator.validate_strategy_effectiveness(
    strategy_name="fake",
    domain="example.com",
    test_count=5
)

print(f"Success rate: {result.success_rate:.2%}")
print(f"Reliability: {result.reliability_score:.2f}")
```

## Архитектура

### Модули

#### 1. ConfigLoader
Управление конфигурацией системы.

```python
from core.validation import ValidationConfigLoader

loader = ValidationConfigLoader()
config = loader.load_config("validation_config.json")
```

#### 2. HistoryManager
Сохранение и загрузка истории валидации.

```python
from core.validation import ValidationHistoryManager

manager = ValidationHistoryManager()
history = manager.load_history(results_dir, ValidationReport)
manager.save_history(results_dir, history)
```

#### 3. MetricsCalculator
Расчет метрик качества системы.

```python
from core.validation import ValidationMetricsCalculator

calculator = ValidationMetricsCalculator()
success_rate = calculator.calculate_overall_success_rate(reports)
reliability = calculator.calculate_system_reliability(reports)
```

#### 4. StrategyTester
Тестирование стратегий обхода.

```python
from core.validation import StrategyTester

tester = StrategyTester()
success = await tester.test_strategy_once(
    strategy_name="fake",
    domain="example.com",
    timeout=30.0,
    bypass_engine=engine
)
```

#### 5. FingerprintValidator
Валидация DPI fingerprint'ов.

```python
from core.validation import FingerprintValidator

validator = FingerprintValidator()
prediction = validator.predict_dpi_behavior("example.com", "test.com")
metrics = validator.calculate_accuracy_metrics(predictions, actual)
```

## Основные функции

### Валидация стратегий

```python
# Тестирование эффективности стратегии
result = await validator.validate_strategy_effectiveness(
    strategy_name="disorder",
    domain="blocked-site.com",
    test_count=10
)

# Результаты
print(f"Success rate: {result.success_rate:.2%}")
print(f"Avg response time: {result.avg_response_time:.2f}s")
print(f"Consistency: {result.consistency_score:.2f}")
print(f"Reliability: {result.reliability_score:.2f}")
```

### Валидация fingerprint'ов

```python
# Проверка точности DPI fingerprint
result = await validator.validate_dpi_fingerprint_accuracy(
    domain="example.com",
    fingerprint_id="fp_001",
    test_domains=["test1.com", "test2.com"]
)

# Метрики
print(f"Accuracy: {result.accuracy_score:.2%}")
print(f"False positive rate: {result.false_positive_rate:.2%}")
print(f"Confidence calibration: {result.confidence_calibration:.2f}")
```

### A/B тестирование

```python
# Сравнение подходов
result = await validator.run_ab_testing(
    test_name="adaptive_vs_traditional",
    control_approach="traditional",
    treatment_approach="adaptive",
    test_domains=["site1.com", "site2.com", "site3.com"]
)

# Результаты
print(f"Control success: {result.control_success_rate:.2%}")
print(f"Treatment success: {result.treatment_success_rate:.2%}")
print(f"Statistical significance: {result.statistical_significance:.4f}")
print(f"Recommendation: {result.recommendation}")
```

### Сбор метрик качества

```python
# Получение текущих метрик
metrics = await validator.collect_quality_metrics()

print(f"Overall success rate: {metrics.overall_success_rate:.2%}")
print(f"System reliability: {metrics.system_reliability:.2f}")
print(f"Performance score: {metrics.performance_score:.2f}")
print(f"Improvement trend: {metrics.improvement_trend:+.2f}")
```

### Генерация отчетов

```python
# Комплексный отчет валидации
report = await validator.generate_validation_report(
    test_domains=["example.com", "test.com"],
    include_ab_testing=True
)

print(f"Total tests: {report.total_tests}")
print(f"Passed: {report.passed_tests}")
print(f"Failed: {report.failed_tests}")
print(f"Overall score: {report.overall_score:.2f}")

# Рекомендации
for recommendation in report.recommendations:
    print(f"- {recommendation}")
```

## Конфигурация

Пример `validation_config.json`:

```json
{
  "results_dir": "validation_results",
  "strategy_validation": {
    "enabled": true,
    "test_count_per_strategy": 5,
    "success_threshold": 0.8,
    "consistency_threshold": 0.7,
    "timeout_seconds": 30
  },
  "fingerprint_validation": {
    "enabled": true,
    "accuracy_threshold": 0.75,
    "confidence_threshold": 0.6,
    "test_domains_count": 10
  },
  "ab_testing": {
    "enabled": true,
    "sample_size": 20,
    "significance_level": 0.05,
    "minimum_effect_size": 0.1
  },
  "quality_metrics": {
    "enabled": true,
    "collection_interval_hours": 24,
    "retention_days": 30,
    "alert_thresholds": {
      "success_rate": 0.7,
      "avg_trials": 10,
      "fingerprint_accuracy": 0.6
    }
  }
}
```

## Модели данных

### ValidationStatus
```python
class ValidationStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
```

### StrategyValidationResult
```python
@dataclass
class StrategyValidationResult:
    strategy_name: str
    domain: str
    success_rate: float
    avg_response_time: float
    consistency_score: float
    reliability_score: float
    test_count: int
    failures: List[str]
    metadata: Dict[str, Any]
```

### FingerprintValidationResult
```python
@dataclass
class FingerprintValidationResult:
    domain: str
    fingerprint_id: str
    accuracy_score: float
    prediction_accuracy: float
    false_positive_rate: float
    false_negative_rate: float
    confidence_calibration: float
    validation_details: Dict[str, Any]
```

## Обработка ошибок

Все методы используют специфичные исключения:

```python
try:
    result = await validator.validate_strategy_effectiveness(...)
except json.JSONDecodeError as e:
    print(f"Invalid JSON: {e}")
except IOError as e:
    print(f"File I/O error: {e}")
except asyncio.TimeoutError as e:
    print(f"Operation timed out: {e}")
```

## Логирование

Система использует стандартный Python logging:

```python
import logging

# Настройка уровня логирования
logging.basicConfig(level=logging.INFO)

# Или для конкретного модуля
logging.getLogger("ResultsValidationSystem").setLevel(logging.DEBUG)
```

## Тестирование

```bash
# Запуск тестов
python -m pytest tests/test_validation*.py -v

# Проверка импортов
python -c "from core.validation import ResultsValidationSystem; print('OK')"

# Форматирование кода
python -m black core/validation/*.py --line-length 100
```

## Миграция с предыдущей версии

Старый код продолжает работать без изменений:

```python
# Старый способ (работает)
from core.validation.results_validation_system import ResultsValidationSystem

# Новый способ (рекомендуется)
from core.validation import ResultsValidationSystem
```

## Производительность

- **Timeout enforcement:** Все операции с таймаутом через `asyncio.wait_for()`
- **Кэширование:** История валидации кэшируется в памяти
- **Асинхронность:** Все I/O операции асинхронные
- **Оптимизация:** Метрики рассчитываются только при необходимости

## Лицензия

См. LICENSE.txt в корне проекта.
