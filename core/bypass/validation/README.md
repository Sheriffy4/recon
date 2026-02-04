# Reliability Validation System

Comprehensive reliability validation system for bypass strategies with multi-level accessibility checking, false positive detection, and effectiveness scoring.

## 🚀 Quick Start

```python
from core.bypass.validation import (
    ReliabilityValidator,
    validate_domain_accessibility,
    validate_strategy_reliability,
)

# Simple domain accessibility check
result = await validate_domain_accessibility("example.com", 443)
print(f"Status: {result.status}")
print(f"Reliability: {result.reliability_score:.2f}")

# Strategy effectiveness validation
effectiveness = await validate_strategy_reliability(
    strategy_id="my_strategy",
    domain="example.com",
    port=443,
    iterations=5
)
print(f"Effectiveness: {effectiveness.effectiveness_score:.2f}")
print(f"Reliability: {effectiveness.reliability_level}")
print(f"Recommendation: {effectiveness.recommendation}")
```

## 📦 Module Structure

```
validation/
├── reliability_validator.py    # Main orchestrator (329 LOC)
├── validators.py              # 8 validation methods (461 LOC)
├── reliability_calculator.py  # 9 calculation functions (246 LOC)
├── report_generator.py        # Report generation (114 LOC)
├── types.py                   # Type definitions (75 LOC)
├── __init__.py               # Package exports (31 LOC)
├── ARCHITECTURE.md           # Architecture documentation
├── USAGE_GUIDE.md           # Usage examples and patterns
└── README.md                # This file
```

## ✨ Features

- **Multi-level validation**: 8 different validation methods
- **False positive detection**: Advanced detection algorithms
- **Thread-safe**: Concurrent cache access with locks
- **Batch validation**: Validate multiple strategies efficiently
- **Comprehensive reporting**: Detailed effectiveness reports
- **Pure functions**: Easy to test and compose
- **Type-safe**: Full type hints throughout

## 🧪 Testing

```bash
# Run unit tests
python -m pytest tests/unit/bypass/validation/ -v

# Run integration tests
python -m pytest tests/integration/test_reliability_validation_integration.py -v

# Run all validation tests
python -m pytest tests/unit/ tests/integration/test_reliability_validation_integration.py -v
```

**Test Coverage**: 37 tests (24 unit + 13 integration) - All passing ✅

## 📚 Documentation

- **[ARCHITECTURE.md](ARCHITECTURE.md)**: Complete architecture guide with diagrams, design patterns, and extension points
- **[USAGE_GUIDE.md](USAGE_GUIDE.md)**: Comprehensive usage examples, patterns, and best practices

## 🎯 Key Components

### ReliabilityValidator
Main orchestrator class that coordinates validation workflows.

```python
validator = ReliabilityValidator(
    max_concurrent_tests=10,
    timeout=30.0
)

# Multi-level accessibility check
result = await validator.multi_level_accessibility_check("example.com", 443)

# Strategy effectiveness validation
effectiveness = await validator.validate_strategy_effectiveness(
    strategy_id="my_strategy",
    domain="example.com",
    port=443,
    test_iterations=5
)

# Batch validation
results = await validator.batch_validate_strategies([
    ("strategy1", "example.com", 443),
    ("strategy2", "test.org", 443),
])

# Cleanup
validator.cleanup()
```

### Validation Methods
8 different validation methods for comprehensive checking:

1. **HTTP_RESPONSE**: Basic HTTP response validation
2. **CONTENT_CHECK**: Content similarity validation
3. **TIMING_ANALYSIS**: Response time analysis
4. **MULTI_REQUEST**: Multiple request consistency
5. **DNS_RESOLUTION**: DNS resolution validation
6. **SSL_HANDSHAKE**: SSL/TLS handshake validation
7. **HEADER_ANALYSIS**: HTTP header analysis
8. **PAYLOAD_VERIFICATION**: Payload integrity verification

### Reliability Levels
- **EXCELLENT**: High reliability (>0.9)
- **GOOD**: Good reliability (0.7-0.9)
- **MODERATE**: Moderate reliability (0.5-0.7)
- **POOR**: Poor reliability (0.3-0.5)
- **UNRELIABLE**: Unreliable (<0.3)

## 🔒 Thread Safety

All cache operations are thread-safe:

```python
# DNS cache with Lock
with validator._dns_cache_lock:
    validator._dns_cache[domain] = ip

# Baseline cache with Lock
with validator._baseline_cache_lock:
    validator._baseline_cache[key] = data
```

## 📊 Metrics

- **Code Reduction**: 77% (1,429 → 329 LOC in main file)
- **Test Coverage**: 37 tests (100% passing)
- **Execution Time**: <2s for all tests
- **Thread Safety**: Full (DNS + baseline caches)

## 🎓 Best Practices

1. **Use convenience functions** for simple cases
2. **Reuse validator instances** for efficiency
3. **Call cleanup()** when done
4. **Use batch validation** for multiple strategies
5. **Configure timeouts** appropriately
6. **Monitor false positive rates**
7. **Check reliability levels** before deployment
8. **Use thread-safe cache access**

## 🔧 Configuration

```python
# Custom configuration
validator = ReliabilityValidator(
    max_concurrent_tests=20,
    timeout=60.0
)

# Customize thresholds
validator.false_positive_thresholds["content_similarity"] = 0.95
validator.performance_baselines["max_response_time"] = 15.0

# Customize validation methods
validator.validation_methods = [
    ValidationMethod.HTTP_RESPONSE,
    ValidationMethod.CONTENT_CHECK,
    ValidationMethod.DNS_RESOLUTION,
]
```

## 🐛 Error Handling

All validation methods use specific exception handling:

- `asyncio.TimeoutError`: Request timeout
- `aiohttp.ClientError`: HTTP client errors
- `dns.resolver.NXDOMAIN`: DNS resolution failures
- `ssl.SSLError`: SSL/TLS errors

## 📈 Performance

- **Concurrent validation**: Up to 10 concurrent tests (configurable)
- **Caching**: DNS and baseline measurements cached
- **Batch processing**: Efficient batch validation with semaphores
- **Pure functions**: No side effects, easy to optimize

## 🚀 Production Ready

✅ Thread-safe implementation  
✅ Comprehensive error handling  
✅ Resource cleanup  
✅ High test coverage  
✅ Complete documentation  
✅ Backward compatible  

## 📝 License

See [LICENSE](../../../../LICENSE) for details.

---

**Status**: ✅ Production Ready  
**Version**: 1.0  
**Last Updated**: January 30, 2026  
**Tests**: 37/37 passing
