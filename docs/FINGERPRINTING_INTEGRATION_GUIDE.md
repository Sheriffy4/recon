# Fingerprinting System Integration Guide

## Overview

This guide shows how to integrate the optimized fingerprinting system with your existing DPI bypass workflow, particularly with the strategy generator and hybrid engine.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Fingerprinting Pipeline                   │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  Phase 1: Passive Analysis (1-3s)                           │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ PassiveDPIAnalyzer                                    │  │
│  │ • TCP SYN probe → detect RST/timeout                 │  │
│  │ • TLS ClientHello probe → detect SNI filtering       │  │
│  │ • Output: blocking_method + recommended_bypasses     │  │
│  └──────────────────────────────────────────────────────┘  │
│                          ↓                                   │
│  Phase 2: Bypass Probes (2-6s)                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ QuickBypassProber                                     │  │
│  │ • Test 2-3 high-probability strategies               │  │
│  │ • Validate with real TLS handshake                   │  │
│  │ • Output: working_strategy (if found)                │  │
│  └──────────────────────────────────────────────────────┘  │
│                          ↓                                   │
│  Phase 3: HTTP Analysis (optional, 1-2min)                  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ HTTPAnalyzer (with fail-fast gate)                   │  │
│  │ • Baseline connectivity test                         │  │
│  │ • If fails → skip advanced tests                     │  │
│  │ • If succeeds → run full HTTP suite                  │  │
│  └──────────────────────────────────────────────────────┘  │
│                          ↓                                   │
│  Strategy Mapping                                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ get_strategies_for_fingerprint()                     │  │
│  │ • Map DPI characteristics → concrete strategies      │  │
│  │ • Prioritize by confidence                           │  │
│  │ • Output: ranked strategy list                       │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Integration Points

### 1. With Strategy Generator

The fingerprinting system provides input to your strategy generator:

```python
from core.fingerprint.unified_fingerprinter import UnifiedFingerprinter, FingerprintingConfig
from core.fingerprint.strategy_mapping import get_strategies_for_fingerprint
from core.strategy.intelligent_strategy_generator import IntelligentStrategyGenerator

async def generate_strategies_with_fingerprinting(target: str, port: int = 443):
    """Generate strategies using fingerprinting data"""
    
    # 1. Fast fingerprint (5-10s)
    config = FingerprintingConfig(analysis_level="fast")
    fingerprinter = UnifiedFingerprinter(config)
    fingerprint = await fingerprinter.fingerprint_target(target, port)
    
    # 2. Map to strategies
    strategies = get_strategies_for_fingerprint(fingerprint.to_dict())
    
    # 3. Feed to intelligent generator
    generator = IntelligentStrategyGenerator()
    
    # Convert fingerprint strategies to generator format
    for strategy in strategies[:5]:  # Top 5
        generator.add_fingerprint_hint(
            strategy_type=strategy['type'],
            params=strategy['params'],
            confidence=strategy['priority'] / 100.0,
            reasoning=strategy['reasoning']
        )
    
    # 4. Generate final strategies
    final_strategies = await generator.generate_intelligent_strategies(
        target_domain=target,
        count=10
    )
    
    return final_strategies
```

### 2. With Hybrid Engine

Use fingerprinting to pre-filter strategies before testing:

```python
from core.hybrid_engine import HybridEngine
from core.fingerprint.unified_fingerprinter import UnifiedFingerprinter, FingerprintingConfig

async def test_with_fingerprinting(target: str, ip: str, port: int = 443):
    """Test strategies using fingerprinting pre-filter"""
    
    # 1. Fingerprint target
    config = FingerprintingConfig(analysis_level="fast")
    fingerprinter = UnifiedFingerprinter(config)
    fingerprint = await fingerprinter.fingerprint_target(target, port)
    
    # 2. Get recommended strategies
    from core.fingerprint.strategy_mapping import get_strategies_for_fingerprint
    strategies = get_strategies_for_fingerprint(fingerprint.to_dict())
    
    # 3. Convert to engine format
    engine_strategies = []
    for strategy in strategies[:5]:
        # Convert to zapret-style command
        cmd = _convert_to_zapret_command(strategy)
        engine_strategies.append(cmd)
    
    # 4. Test with hybrid engine
    engine = HybridEngine()
    results = await engine.test_strategies_hybrid(
        strategies=engine_strategies,
        test_sites=[f"https://{target}"],
        ips={ip},
        dns_cache={target: ip},
        port=port,
        domain=target,
        fast_filter=True
    )
    
    return results

def _convert_to_zapret_command(strategy: dict) -> str:
    """Convert strategy dict to zapret command format"""
    strategy_type = strategy['type']
    params = strategy['params']
    
    if strategy_type == 'fakeddisorder':
        ttl = params.get('ttl', 1)
        split_pos = params.get('split_pos', 'midsld')
        fooling = ','.join(params.get('fooling', []))
        return f"--dpi-desync=fake,disorder --dpi-desync-ttl={ttl} --dpi-desync-split-pos={split_pos} --dpi-desync-fooling={fooling}"
    
    elif strategy_type == 'multisplit':
        positions = ','.join(map(str, params.get('positions', [3, 7, 11])))
        return f"--dpi-desync=multisplit --dpi-desync-split-count={len(params.get('positions', []))} --dpi-desync-split-pos={positions}"
    
    elif strategy_type == 'seqovl':
        ttl = params.get('ttl', 1)
        overlap = params.get('overlap_size', 20)
        return f"--dpi-desync=seqovl --dpi-desync-ttl={ttl} --dpi-desync-split-seqovl={overlap}"
    
    # Add more conversions as needed
    return ""
```

### 3. With PCAP Analysis

Combine fingerprinting with PCAP analysis for comprehensive diagnosis:

```python
from core.fingerprint.unified_fingerprinter import UnifiedFingerprinter, FingerprintingConfig
from core.pcap.rst_analyzer import RSTTriggerAnalyzer

async def analyze_with_pcap_fallback(target: str, port: int, pcap_path: str):
    """Analyze using fingerprinting + PCAP fallback"""
    
    # 1. Try fingerprinting first
    config = FingerprintingConfig(analysis_level="balanced")
    fingerprinter = UnifiedFingerprinter(config)
    fingerprint = await fingerprinter.fingerprint_target(target, port)
    
    # 2. If low reliability, use PCAP fallback
    if fingerprint.reliability_score < 0.5:
        print(f"Low reliability ({fingerprint.reliability_score:.2f}), using PCAP fallback")
        
        # Analyze PCAP
        analyzer = RSTTriggerAnalyzer(pcap_path)
        triggers = analyzer.analyze()
        
        # Extract strategies from PCAP
        pcap_strategies = _extract_strategies_from_pcap(triggers, target)
        
        # Merge with fingerprint strategies
        fingerprint_strategies = fingerprint.recommended_strategies
        
        # Combine and deduplicate
        all_strategies = _merge_strategies(fingerprint_strategies, pcap_strategies)
        
        return all_strategies
    
    return fingerprint.recommended_strategies
```

### 4. With CLI Workflow

Integrate into CLI for user-facing fingerprinting:

```python
# cli.py or similar

import click
from core.fingerprint.unified_fingerprinter import UnifiedFingerprinter, FingerprintingConfig

@click.command()
@click.option('--target', required=True, help='Target domain')
@click.option('--port', default=443, help='Target port')
@click.option('--mode', type=click.Choice(['fast', 'balanced', 'comprehensive']), default='fast')
@click.option('--output', type=click.Path(), help='Output file for results')
def fingerprint_command(target: str, port: int, mode: str, output: str):
    """Fingerprint a target for DPI characteristics"""
    
    async def run():
        # Configure based on mode
        config = FingerprintingConfig(
            analysis_level=mode,
            enable_http_analysis=(mode != 'fast')
        )
        
        fingerprinter = UnifiedFingerprinter(config)
        
        click.echo(f"Fingerprinting {target}:{port} (mode: {mode})...")
        
        fingerprint = await fingerprinter.fingerprint_target(target, port)
        
        # Display results
        click.echo(f"\nReliability: {fingerprint.reliability_score:.2f}")
        click.echo(f"Duration: {fingerprint.analysis_duration:.2f}s")
        
        if fingerprint.ml_classification.predicted_dpi_type:
            click.echo(f"DPI Type: {fingerprint.ml_classification.predicted_dpi_type}")
        
        click.echo(f"\nRecommended Strategies ({len(fingerprint.recommended_strategies)}):")
        for i, strategy in enumerate(fingerprint.recommended_strategies[:5], 1):
            click.echo(f"{i}. {strategy.strategy_name} (confidence: {strategy.confidence:.2f})")
            click.echo(f"   {', '.join(strategy.reasoning)}")
        
        # Save to file if requested
        if output:
            import json
            with open(output, 'w') as f:
                json.dump(fingerprint.to_dict(), f, indent=2)
            click.echo(f"\nResults saved to {output}")
    
    import asyncio
    asyncio.run(run())
```

## Common Workflows

### Workflow 1: Quick Diagnosis → Strategy Generation → Testing

```python
async def quick_bypass_workflow(target: str, ip: str, port: int = 443):
    """Complete workflow: fingerprint → generate → test"""
    
    # 1. Quick fingerprint (5-10s)
    config = FingerprintingConfig(analysis_level="fast")
    fingerprinter = UnifiedFingerprinter(config)
    fingerprint = await fingerprinter.fingerprint_target(target, port)
    
    print(f"Fingerprint reliability: {fingerprint.reliability_score:.2f}")
    
    # 2. Get strategies
    from core.fingerprint.strategy_mapping import get_strategies_for_fingerprint
    strategies = get_strategies_for_fingerprint(fingerprint.to_dict())
    
    print(f"Found {len(strategies)} strategies")
    
    # 3. Convert to engine format
    engine_strategies = [_convert_to_zapret_command(s) for s in strategies[:5]]
    
    # 4. Test with hybrid engine
    from core.hybrid_engine import HybridEngine
    engine = HybridEngine()
    
    results = await engine.test_strategies_hybrid(
        strategies=engine_strategies,
        test_sites=[f"https://{target}"],
        ips={ip},
        dns_cache={target: ip},
        port=port,
        domain=target
    )
    
    # 5. Find best working strategy
    working = [r for r in results if r.get('success_rate', 0) > 0]
    
    if working:
        best = max(working, key=lambda r: r['success_rate'])
        print(f"\n✅ Best strategy: {best['strategy']}")
        print(f"   Success rate: {best['success_rate']:.0%}")
        print(f"   Latency: {best['avg_latency_ms']:.1f}ms")
        return best
    else:
        print("\n❌ No working strategies found")
        return None
```

### Workflow 2: Batch Fingerprinting → Aggregate Analysis

```python
async def batch_fingerprint_and_analyze(targets: list):
    """Fingerprint multiple targets and aggregate results"""
    
    config = FingerprintingConfig(analysis_level="fast")
    fingerprinter = UnifiedFingerprinter(config)
    
    # 1. Batch fingerprint
    results = await fingerprinter.fingerprint_batch(
        targets,
        max_concurrent=5
    )
    
    # 2. Aggregate by DPI type
    dpi_types = {}
    for fp in results:
        dpi_type = fp.ml_classification.predicted_dpi_type or "unknown"
        if dpi_type not in dpi_types:
            dpi_types[dpi_type] = []
        dpi_types[dpi_type].append(fp)
    
    # 3. Find common strategies
    from collections import Counter
    all_strategies = []
    for fp in results:
        for strategy in fp.recommended_strategies:
            all_strategies.append(strategy.strategy_name)
    
    common_strategies = Counter(all_strategies).most_common(5)
    
    print(f"\nAnalyzed {len(results)} targets")
    print(f"DPI types detected: {list(dpi_types.keys())}")
    print(f"\nMost common strategies:")
    for strategy, count in common_strategies:
        print(f"  {strategy}: {count} targets")
    
    return dpi_types, common_strategies
```

### Workflow 3: Adaptive Strategy Selection

```python
async def adaptive_strategy_selection(target: str, ip: str, port: int = 443):
    """Adaptively select strategies based on fingerprint confidence"""
    
    # 1. Passive analysis first (1-3s)
    from core.fingerprint.passive_analyzer import PassiveDPIAnalyzer
    passive_analyzer = PassiveDPIAnalyzer()
    passive_result = await passive_analyzer.analyze_blocking_method(target, port)
    
    print(f"Passive analysis: {passive_result.blocking_method.value} (confidence: {passive_result.confidence:.2f})")
    
    # 2. If high confidence, use passive recommendations
    if passive_result.confidence > 0.8:
        print("High confidence - using passive recommendations")
        strategies = passive_result.recommended_bypasses
        return strategies
    
    # 3. If medium confidence, run bypass probes
    elif passive_result.confidence > 0.5:
        print("Medium confidence - running bypass probes")
        from core.fingerprint.bypass_prober import QuickBypassProber
        prober = QuickBypassProber()
        probe_results = await prober.probe_bypasses(target, ip, port)
        
        best = prober.get_best_strategy(probe_results)
        if best:
            print(f"Found working strategy: {best['name']}")
            return [best['name']]
    
    # 4. If low confidence, run full fingerprint
    print("Low confidence - running full fingerprint")
    config = FingerprintingConfig(analysis_level="balanced")
    fingerprinter = UnifiedFingerprinter(config)
    fingerprint = await fingerprinter.fingerprint_target(target, port)
    
    strategies = [s.strategy_name for s in fingerprint.recommended_strategies[:5]]
    return strategies
```

## Performance Optimization Tips

### 1. Use Caching for Repeated Targets

```python
config = FingerprintingConfig(
    enable_cache=True,
    cache_ttl=3600  # 1 hour
)

fingerprinter = UnifiedFingerprinter(config)

# First call: full fingerprint
fp1 = await fingerprinter.fingerprint_target("example.com", 443)

# Second call: cached (instant)
fp2 = await fingerprinter.fingerprint_target("example.com", 443)
```

### 2. Adjust Concurrency Based on Network

```python
# Fast network: higher concurrency
config_fast_network = FingerprintingConfig(max_concurrent=10)

# Slow network: lower concurrency
config_slow_network = FingerprintingConfig(max_concurrent=3)
```

### 3. Use Fast Mode for Initial Scan

```python
# Initial scan: fast mode
config_scan = FingerprintingConfig(analysis_level="fast")
fingerprints = await fingerprinter.fingerprint_batch(all_targets, config=config_scan)

# Deep analysis: only for interesting targets
interesting = [fp for fp in fingerprints if fp.reliability_score < 0.5]

config_deep = FingerprintingConfig(analysis_level="comprehensive")
for fp in interesting:
    detailed = await fingerprinter.fingerprint_target(fp.target, fp.port, config=config_deep)
```

## Error Handling

### Handle Low Reliability

```python
fingerprint = await fingerprinter.fingerprint_target(target, port)

if fingerprint.reliability_score < 0.5:
    print(f"⚠️  Low reliability: {fingerprint.reliability_score:.2f}")
    
    # Check errors
    for error in fingerprint.errors:
        print(f"  Error: {error.message}")
    
    # Use fallback strategies
    from core.fingerprint.strategy_mapping import get_fallback_strategies
    strategies = get_fallback_strategies()
    print(f"Using {len(strategies)} fallback strategies")
```

### Handle Timeouts

```python
try:
    fingerprint = await asyncio.wait_for(
        fingerprinter.fingerprint_target(target, port),
        timeout=30.0  # 30 second timeout
    )
except asyncio.TimeoutError:
    print(f"Fingerprinting timed out for {target}")
    # Use passive analysis only
    passive_result = await passive_analyzer.analyze_blocking_method(target, port)
    strategies = passive_result.recommended_bypasses
```

## Testing Integration

### Unit Test Example

```python
import pytest
from unittest.mock import Mock, patch

@pytest.mark.asyncio
async def test_fingerprint_to_strategy_integration():
    """Test integration between fingerprinting and strategy generation"""
    
    # Mock fingerprint
    fingerprint = Mock()
    fingerprint.tcp_analysis.rst_injection_detected = True
    fingerprint.tcp_analysis.rst_ttl = 5
    fingerprint.to_dict.return_value = {
        "tcp_analysis": {"rst_injection_detected": True, "rst_ttl": 5},
        "http_analysis": {},
        "tls_analysis": {}
    }
    
    # Get strategies
    from core.fingerprint.strategy_mapping import get_strategies_for_fingerprint
    strategies = get_strategies_for_fingerprint(fingerprint.to_dict())
    
    # Verify
    assert len(strategies) > 0
    assert any('fakeddisorder' in s['name'] for s in strategies)
```

## Migration Checklist

- [ ] Update strategy generator to use fingerprinting hints
- [ ] Integrate passive analysis into CLI workflow
- [ ] Add bypass probes before full testing
- [ ] Update batch processing to use fast mode
- [ ] Add caching for repeated targets
- [ ] Update error handling for low reliability
- [ ] Add performance monitoring
- [ ] Update documentation with new workflows
- [ ] Train team on new fingerprinting modes
- [ ] Set up monitoring for fingerprinting success rates

## Next Steps

1. **Test in production**: Start with fast mode on a subset of targets
2. **Monitor performance**: Track fingerprinting duration and reliability
3. **Tune timeouts**: Adjust based on your network characteristics
4. **Expand strategy mapping**: Add more DPI characteristics as you discover them
5. **Integrate with ML**: Use fingerprinting data to train strategy prediction models

## Support

For issues or questions:
- See `docs/FINGERPRINTING_QUICK_START.md` for basic usage
- See `FINGERPRINTING_OPTIMIZATION_SUMMARY.md` for technical details
- Run `examples/fingerprinting_demo.py` for working examples
- Check `tests/test_fingerprinting_optimization.py` for test patterns
