# Fingerprinting System - Quick Start Guide

## Overview

The optimized fingerprinting system provides fast, accurate DPI detection and strategy recommendations through a three-phase approach:

1. **Passive Analysis** (1-3s): Quick diagnosis without full connections
2. **Bypass Probes** (2-6s): Validate strategies with real tests
3. **HTTP Analysis** (optional): Deep inspection when baseline works

## Quick Start

### 1. Fast Fingerprinting (Recommended)

Get actionable results in 5-10 seconds:

```python
from core.fingerprint.unified_fingerprinter import UnifiedFingerprinter, FingerprintingConfig

# Configure for fast mode
config = FingerprintingConfig(
    analysis_level="fast",
    connect_timeout=1.5,
    tls_timeout=3.0,
    enable_http_analysis=False
)

# Create fingerprinter
fingerprinter = UnifiedFingerprinter(config)

# Fingerprint target
fingerprint = await fingerprinter.fingerprint_target("example.com", 443)

# Get recommendations
for strategy in fingerprint.recommended_strategies:
    print(f"{strategy.strategy_name}: {strategy.confidence:.2f}")
```

### 2. Passive Analysis Only

Ultra-fast diagnosis (1-3 seconds):

```python
from core.fingerprint.passive_analyzer import PassiveDPIAnalyzer

analyzer = PassiveDPIAnalyzer(timeout=3.0)
result = await analyzer.analyze_blocking_method("example.com", 443)

print(f"Blocking method: {result.blocking_method.value}")
print(f"Recommended bypasses: {result.recommended_bypasses}")
```

### 3. Bypass Probes

Test if strategies actually work:

```python
from core.fingerprint.bypass_prober import QuickBypassProber

prober = QuickBypassProber(timeout=2.0)
results = await prober.probe_bypasses("example.com", "93.184.216.34", 443)

# Get best working strategy
best = prober.get_best_strategy(results)
if best:
    print(f"Best strategy: {best['name']}")
```

### 4. Strategy Mapping

Convert fingerprint to concrete strategies:

```python
from core.fingerprint.strategy_mapping import get_strategies_for_fingerprint

# Get fingerprint first
fingerprint = await fingerprinter.fingerprint_target("example.com", 443)

# Map to strategies
strategies = get_strategies_for_fingerprint(fingerprint.to_dict())

for strategy in strategies[:5]:
    print(f"{strategy['name']}: {strategy['reasoning']}")
```

## Analysis Levels

### Fast (5-10 seconds)
- Passive analysis + bypass probes
- No HTTP analysis
- Best for quick diagnosis

```python
config = FingerprintingConfig(
    analysis_level="fast",
    enable_http_analysis=False
)
```

### Balanced (1-2 minutes)
- Passive analysis + bypass probes + HTTP (with fail-fast)
- Recommended for most use cases

```python
config = FingerprintingConfig(
    analysis_level="balanced",
    enable_http_analysis=True
)
```

### Comprehensive (5-10 minutes)
- All analyzers + ML classification
- Use when you need detailed analysis

```python
config = FingerprintingConfig(
    analysis_level="comprehensive",
    enable_http_analysis=True,
    enable_dns_analysis=True,
    enable_ml_classification=True
)
```

## Common Patterns

### Pattern 1: Quick Diagnosis Before Strategy Generation

```python
# 1. Fast fingerprint
config = FingerprintingConfig(analysis_level="fast")
fingerprinter = UnifiedFingerprinter(config)
fingerprint = await fingerprinter.fingerprint_target(target, 443)

# 2. Get strategies
from core.fingerprint.strategy_mapping import get_strategies_for_fingerprint
strategies = get_strategies_for_fingerprint(fingerprint.to_dict())

# 3. Use top 3 strategies
top_strategies = strategies[:3]
```

### Pattern 2: Batch Fingerprinting with Circuit Breaker

```python
targets = [("site1.com", 443), ("site2.com", 443), ("site3.com", 443)]

results = await fingerprinter.fingerprint_batch(
    targets,
    max_concurrent=5,
    force_refresh=True
)

# Filter successful
successful = [r for r in results if r.reliability_score > 0.6]
```

### Pattern 3: Passive Analysis → Bypass Probes → Full Fingerprint

```python
# 1. Passive analysis (1-3s)
passive_analyzer = PassiveDPIAnalyzer()
passive_result = await passive_analyzer.analyze_blocking_method(target, 443)

# 2. If blocking detected, run bypass probes (2-6s)
if passive_result.confidence > 0.7:
    prober = QuickBypassProber()
    probe_results = await prober.probe_bypasses(target, ip, 443)
    
    # 3. If probes fail, run full fingerprint
    if not any(r.success for r in probe_results):
        fingerprint = await fingerprinter.fingerprint_target(target, 443)
```

## Strategy Recommendations

### Understanding Recommendations

Each strategy recommendation includes:

```python
StrategyRecommendation(
    strategy_name="fakeddisorder_cipher",
    predicted_effectiveness=0.9,  # 0.0-1.0
    confidence=0.8,                # 0.0-1.0
    reasoning=["TLS-specific blocking detected"]
)
```

- **strategy_name**: Identifier for the strategy
- **predicted_effectiveness**: How likely it is to work (0-1)
- **confidence**: How confident we are in this prediction (0-1)
- **reasoning**: Why this strategy was recommended

### Priority Levels

Strategies are prioritized based on:

1. **Bypass probe results** (highest priority)
   - Confirmed working strategies
   - Confidence: 0.9

2. **Passive analysis recommendations**
   - Based on TTL/RST patterns
   - Confidence: 0.7-0.8

3. **Strategy mapping**
   - Based on DPI characteristics
   - Confidence: 0.6-0.8

4. **Fallback strategies**
   - Generic high-probability strategies
   - Confidence: 0.5

## Blocking Methods Detected

### 1. TCP RST Injection
**Characteristics**: RST packets sent by DPI

**Low TTL (≤10)**:
- `fakeddisorder(ttl=1)`
- `badsum_race(ttl=2)`
- `ip_fragmentation`

**High TTL (>10)**:
- `multisplit`
- `seqovl(overlap_size=336)`

### 2. TLS SNI Filtering
**Characteristics**: Blocks based on SNI in ClientHello

**Strategies**:
- `fakeddisorder(split_pos=sni)`
- `multidisorder(positions=[5,10,15])`
- `split(split_pos=sld)`

### 3. Silent Drop
**Characteristics**: Packets dropped without RST

**Strategies**:
- `multisplit`
- `seqovl(overlap_size=336)`

### 4. Content Filtering
**Characteristics**: Inspects HTTP content

**Strategies**:
- `multisplit(delay=0.01)`
- `tlsrec_split(split_pos=12)`

## Performance Tips

### 1. Use Fast Mode by Default
```python
# Fast mode is 6-8x faster than balanced
config = FingerprintingConfig(analysis_level="fast")
```

### 2. Disable Proxy for Accuracy
```python
# Proxy can skew results
config = FingerprintingConfig(use_system_proxy=False)
```

### 3. Reduce Timeouts
```python
# Aggressive timeouts for faster failure detection
config = FingerprintingConfig(
    connect_timeout=1.0,
    tls_timeout=2.0
)
```

### 4. Limit Concurrency
```python
# 5-8 concurrent fingerprints is optimal
results = await fingerprinter.fingerprint_batch(
    targets,
    max_concurrent=5
)
```

### 5. Use Caching
```python
# Cache results for 1 hour
config = FingerprintingConfig(
    enable_cache=True,
    cache_ttl=3600
)
```

## Troubleshooting

### Low Reliability Score

**Problem**: `fingerprint.reliability_score < 0.5`

**Solutions**:
1. Check network connectivity
2. Try passive analysis only
3. Increase timeouts
4. Check if target is actually blocked

```python
# Debug low reliability
if fingerprint.reliability_score < 0.5:
    print(f"Errors: {fingerprint.errors}")
    print(f"TCP analysis: {fingerprint.tcp_analysis.status}")
    print(f"HTTP analysis: {fingerprint.http_analysis.status}")
```

### No Recommended Strategies

**Problem**: `len(fingerprint.recommended_strategies) == 0`

**Solutions**:
1. Use fallback strategies
2. Run bypass probes manually
3. Try comprehensive analysis

```python
from core.fingerprint.strategy_mapping import get_fallback_strategies

if not fingerprint.recommended_strategies:
    fallback = get_fallback_strategies()
    print(f"Using fallback strategies: {fallback}")
```

### Timeout Errors

**Problem**: Fingerprinting times out

**Solutions**:
1. Reduce timeout values
2. Use fast mode
3. Skip HTTP analysis

```python
config = FingerprintingConfig(
    connect_timeout=1.0,
    tls_timeout=2.0,
    enable_http_analysis=False
)
```

## Examples

See `examples/fingerprinting_demo.py` for complete working examples.

## API Reference

See `docs/API_REFERENCE.md` for detailed API documentation.

## Migration from Old System

### Before
```python
# Old system (30-40 minutes)
fingerprinter = UnifiedFingerprinter()
result = await fingerprinter.fingerprint_target("example.com", 443)
```

### After
```python
# New system (5-10 seconds)
config = FingerprintingConfig(analysis_level="fast")
fingerprinter = UnifiedFingerprinter(config)
result = await fingerprinter.fingerprint_target("example.com", 443)
```

**No breaking changes** - old code continues to work, but new code is much faster.
