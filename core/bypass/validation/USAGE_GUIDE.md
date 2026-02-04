# Reliability Validation Usage Guide

## Quick Start

### Basic Usage

```python
from core.bypass.validation import ReliabilityValidator

# Create validator instance
validator = ReliabilityValidator(
    max_concurrent_tests=10,
    timeout=30.0
)

# Validate a strategy
result = await validator.validate_strategy_effectiveness(
    strategy_id="my_strategy",
    domain="example.com",
    port=443,
    test_iterations=5
)

# Check results
print(f"Effectiveness: {result.effectiveness_score:.2f}")
print(f"Reliability: {result.reliability_level.value}")
print(f"Recommendation: {result.recommendation}")

# Cleanup when done
validator.cleanup()
```

### Using Global Validator

```python
from core.bypass.validation import get_global_reliability_validator

# Get singleton instance
validator = get_global_reliability_validator()

# Use it
result = await validator.validate_strategy_effectiveness(...)
```

### Convenience Functions

```python
from core.bypass.validation import (
    validate_domain_accessibility,
    validate_strategy_reliability
)

# Quick domain check
accessibility = await validate_domain_accessibility("example.com", 443)
print(f"Status: {accessibility.status.value}")

# Quick strategy validation
effectiveness = await validate_strategy_reliability(
    "my_strategy", "example.com", 443, iterations=3
)
print(f"Score: {effectiveness.effectiveness_score:.2f}")
```

## Advanced Usage

### Batch Validation

```python
# Validate multiple strategies at once
strategy_domain_pairs = [
    ("strategy1", "example.com", 443),
    ("strategy2", "test.com", 443),
    ("strategy3", "demo.com", 443),
]

results = await validator.batch_validate_strategies(
    strategy_domain_pairs,
    test_iterations=3
)

# Process results
for result in results:
    print(f"{result.strategy_id}: {result.effectiveness_score:.2f}")
```

### Generate Reports

```python
# After batch validation
report = validator.generate_reliability_report(results)

# Access report data
print(f"Total strategies tested: {report['summary']['total_strategies_tested']}")
print(f"Average effectiveness: {report['summary']['avg_effectiveness_score']:.2f}")

# Top strategies
for rank in report['strategy_ranking']:
    print(f"{rank['strategy_id']}: {rank['effectiveness_score']:.2f}")

# Recommendations
for rec in report['recommendations']:
    print(f"- {rec}")
```

### Custom Configuration

```python
validator = ReliabilityValidator(
    max_concurrent_tests=20,  # More concurrent tests
    timeout=60.0  # Longer timeout
)

# Customize thresholds
validator.false_positive_thresholds = {
    "response_time_variance": 1.5,  # Stricter variance
    "content_similarity": 0.9,  # Higher similarity required
    "status_code_consistency": 0.95,
    "dns_consistency": 0.98,
}

# Customize performance baselines
validator.performance_baselines = {
    "max_response_time": 5.0,  # Stricter timing
    "min_success_rate": 0.8,  # Higher success rate
    "consistency_threshold": 0.9,
}
```

### Using Individual Validators

```python
from core.bypass.validation.validators import (
    validate_http_response,
    validate_dns_resolution,
    validate_ssl_handshake
)

# Use validators directly
http_result = await validate_http_response("example.com", 443, timeout=30.0)
print(f"HTTP check: {http_result.success}")

# DNS with cache
dns_cache = {}
dns_result = await validate_dns_resolution(
    "example.com", 
    timeout=10.0, 
    dns_cache=dns_cache,
    thread_pool=None  # Will create internally
)
print(f"DNS resolved: {dns_result.metadata.get('primary_ip')}")
```

### Using Calculator Functions

```python
from core.bypass.validation.reliability_calculator import (
    calculate_reliability_score,
    determine_reliability_level,
    generate_strategy_recommendation
)

# Calculate scores manually
reliability_score = calculate_reliability_score(
    validation_results,
    max_response_time=10.0
)

# Determine level
level = determine_reliability_level(
    effectiveness_score=0.85,
    consistency_score=0.90,
    false_positive_rate=0.05
)

# Get recommendation
recommendation = generate_strategy_recommendation(
    reliability_level=level,
    false_positive_rate=0.05,
    consistency_score=0.90,
    performance_score=0.85
)
```

### Using Level Classifier

```python
from core.utils.level_classifier import (
    classify_by_thresholds,
    create_threshold_classifier
)
from enum import Enum

class Priority(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    NORMAL = "normal"

# One-time classification
thresholds = [(0.9, Priority.CRITICAL), (0.7, Priority.HIGH)]
priority = classify_by_thresholds(0.85, thresholds, Priority.NORMAL)

# Reusable classifier
classifier = create_threshold_classifier(thresholds, Priority.NORMAL)
priorities = [classifier(score) for score in [0.95, 0.75, 0.5]]
```

## Common Patterns

### Pattern 1: Validate and Report

```python
async def validate_and_report(strategies, domains):
    validator = ReliabilityValidator()
    
    # Create pairs
    pairs = [(s, d, 443) for s in strategies for d in domains]
    
    # Validate
    results = await validator.batch_validate_strategies(pairs)
    
    # Generate report
    report = validator.generate_reliability_report(results)
    
    # Cleanup
    validator.cleanup()
    
    return report
```

### Pattern 2: Continuous Monitoring

```python
async def monitor_strategy(strategy_id, domain, interval=300):
    validator = get_global_reliability_validator()
    
    while True:
        result = await validator.validate_strategy_effectiveness(
            strategy_id, domain, 443, test_iterations=3
        )
        
        if result.reliability_level in [
            ReliabilityLevel.POOR,
            ReliabilityLevel.UNRELIABLE
        ]:
            alert(f"Strategy {strategy_id} degraded!")
        
        await asyncio.sleep(interval)
```

### Pattern 3: A/B Testing

```python
async def compare_strategies(strategy_a, strategy_b, domain):
    validator = ReliabilityValidator()
    
    # Test both strategies
    result_a = await validator.validate_strategy_effectiveness(
        strategy_a, domain, 443, test_iterations=5
    )
    result_b = await validator.validate_strategy_effectiveness(
        strategy_b, domain, 443, test_iterations=5
    )
    
    # Compare
    if result_a.effectiveness_score > result_b.effectiveness_score:
        winner = strategy_a
        improvement = result_a.effectiveness_score - result_b.effectiveness_score
    else:
        winner = strategy_b
        improvement = result_b.effectiveness_score - result_a.effectiveness_score
    
    validator.cleanup()
    
    return {
        "winner": winner,
        "improvement": improvement,
        "result_a": result_a,
        "result_b": result_b
    }
```

### Pattern 4: Fallback Selection

```python
async def select_best_strategy(strategies, domain):
    validator = ReliabilityValidator()
    
    # Test all strategies
    pairs = [(s, domain, 443) for s in strategies]
    results = await validator.batch_validate_strategies(pairs)
    
    # Filter reliable strategies
    reliable = [
        r for r in results
        if r.reliability_level in [
            ReliabilityLevel.EXCELLENT,
            ReliabilityLevel.VERY_GOOD,
            ReliabilityLevel.GOOD
        ]
    ]
    
    # Sort by effectiveness
    reliable.sort(key=lambda r: r.effectiveness_score, reverse=True)
    
    validator.cleanup()
    
    return reliable[0] if reliable else None
```

## Error Handling

### Handling Validation Failures

```python
try:
    result = await validator.validate_strategy_effectiveness(
        strategy_id, domain, port
    )
except asyncio.TimeoutError:
    print("Validation timed out")
except Exception as e:
    print(f"Validation failed: {e}")
```

### Checking Individual Results

```python
result = await validator.multi_level_accessibility_check(domain, port)

# Check for errors
for validation in result.validation_results:
    if not validation.success:
        print(f"{validation.method.value} failed: {validation.error_message}")

# Check false positives
if result.false_positive_detected:
    print("Warning: False positive detected!")
```

## Performance Tips

### 1. Reuse Validator Instance

```python
# Good - reuse instance
validator = ReliabilityValidator()
for strategy in strategies:
    result = await validator.validate_strategy_effectiveness(...)
validator.cleanup()

# Bad - create new instance each time
for strategy in strategies:
    validator = ReliabilityValidator()
    result = await validator.validate_strategy_effectiveness(...)
    validator.cleanup()
```

### 2. Use Batch Validation

```python
# Good - batch validation
results = await validator.batch_validate_strategies(pairs)

# Bad - sequential validation
results = []
for strategy, domain, port in pairs:
    result = await validator.validate_strategy_effectiveness(...)
    results.append(result)
```

### 3. Adjust Concurrency

```python
# For high-latency networks
validator = ReliabilityValidator(max_concurrent_tests=5)

# For low-latency networks
validator = ReliabilityValidator(max_concurrent_tests=20)
```

### 4. Cache Awareness

```python
# DNS cache is automatic
# Baseline cache is automatic
# Both are thread-safe

# Clear caches if needed
validator._dns_cache.clear()
validator._baseline_cache.clear()
```

## Thread Safety

The validator is thread-safe for concurrent use:

```python
import asyncio
from concurrent.futures import ThreadPoolExecutor

validator = ReliabilityValidator()

# Safe to call from multiple threads
with ThreadPoolExecutor(max_workers=5) as executor:
    futures = [
        executor.submit(
            asyncio.run,
            validator.validate_strategy_effectiveness(s, d, 443)
        )
        for s, d in strategy_domain_pairs
    ]
    
    results = [f.result() for f in futures]

validator.cleanup()
```

## Troubleshooting

### Issue: Timeouts

```python
# Increase timeout
validator = ReliabilityValidator(timeout=60.0)

# Or adjust per validation
validator.timeout = 60.0
```

### Issue: False Positives

```python
# Adjust thresholds
validator.false_positive_thresholds["content_similarity"] = 0.95
validator.false_positive_thresholds["status_code_consistency"] = 0.95
```

### Issue: Low Performance Scores

```python
# Relax performance baselines
validator.performance_baselines["max_response_time"] = 15.0
validator.performance_baselines["min_success_rate"] = 0.6
```

### Issue: Memory Usage

```python
# Clear caches periodically
if len(validator._dns_cache) > 1000:
    validator._dns_cache.clear()

if len(validator._baseline_cache) > 100:
    validator._baseline_cache.clear()
```

## Best Practices

1. **Always cleanup**: Call `validator.cleanup()` when done
2. **Use batch validation**: More efficient than sequential
3. **Reuse instances**: Avoid creating new validators repeatedly
4. **Monitor false positives**: Adjust thresholds if needed
5. **Log results**: Keep track of validation history
6. **Handle errors**: Wrap in try-except blocks
7. **Test in staging**: Validate thresholds before production
8. **Use global validator**: For singleton pattern
9. **Adjust concurrency**: Based on network conditions
10. **Clear caches**: Periodically to avoid memory growth

## Examples

See `tests/unit/bypass/validation/` for comprehensive examples.

## References

- Architecture: `ARCHITECTURE.md`
- API Reference: Module docstrings
- Tests: `tests/unit/bypass/validation/`
