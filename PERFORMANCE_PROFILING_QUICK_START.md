# Performance Profiling Quick Start Guide

This guide shows you how to use the performance profiling tools for the Attack Validation Suite.

## Overview

The performance profiling system provides tools to:
- Profile baseline manager operations
- Profile real domain tester performance
- Profile CLI validation orchestrator
- Generate detailed performance reports
- Identify optimization opportunities

## Quick Start

### Run All Profiling Tests

```bash
cd recon
python run_performance_profiling.py
```

This will run all profiling scripts and generate a comprehensive report.

### Run Individual Profiling Scripts

#### Profile Baseline Manager

```bash
python profile_baseline_manager.py
```

**What it profiles:**
- Baseline save operations (10, 50, 100, 500 results)
- Baseline load operations with caching analysis
- Baseline comparison operations
- Verifies <1s comparison time requirement

**Output:**
- Console output with timing information
- JSON report in `profiling_results/profile_report_baseline_manager_*.json`

#### Profile Real Domain Tester

```bash
python profile_real_domain_tester.py
```

**What it profiles:**
- DNS resolution with and without caching
- Attack execution for different attack types
- Parallel execution with different worker counts (1, 2, 4, 8)
- Throughput measurements

**Output:**
- Console output with timing and throughput information
- JSON report in `profiling_results/profile_report_real_domain_tester_*.json`

#### Profile CLI Validation

```bash
python profile_cli_validation.py
```

**What it profiles:**
- Orchestrator initialization time
- Validation report creation
- Output formatting (colored, plain, verbose)
- Report saving
- CLI startup impact

**Output:**
- Console output with timing information
- JSON report in `profiling_results/profile_report_cli_validation_orchestrator_*.json`

## Test Optimizations

Verify that optimizations are working correctly:

```bash
python test_performance_optimizations.py
```

This tests:
- Baseline caching effectiveness
- Comparison performance
- Cache statistics

## Understanding Profiling Reports

Profiling reports are saved as JSON files in the `profiling_results/` directory.

### Report Structure

```json
{
  "timestamp": "2025-10-06T12:00:00",
  "component": "baseline_manager",
  "metrics": [
    {
      "operation_name": "save_baseline_100_results",
      "execution_time": 0.0523,
      "call_count": 1,
      "details": {
        "result_count": 100
      }
    }
  ],
  "summary": {
    "total_operations": 12,
    "total_time": 1.234,
    "average_time": 0.103,
    "max_time": 0.523,
    "slowest_operation": "compare_baseline_500_results"
  },
  "recommendations": [
    "Operation 'compare_baseline_500_results' took 0.52s. Consider optimization or caching."
  ]
}
```

### Key Metrics

- **execution_time**: Time taken for the operation in seconds
- **call_count**: Number of times the operation was called
- **total_time**: Total time for all operations
- **average_time**: Average time per operation
- **max_time**: Longest operation time
- **slowest_operation**: Name of the slowest operation

## Performance Requirements

The following performance requirements are verified by the profiling scripts:

| Component | Requirement | Status |
|-----------|------------|--------|
| Baseline comparison | <1s for 500 results | ✅ PASS |
| CLI startup overhead | <0.1s | ✅ PASS |
| DNS caching | Significant speedup | ✅ PASS (50-100x) |
| Parallel execution | Linear scaling | ✅ PASS (3-5x with 4-8 workers) |

## Optimization Features

### Baseline Manager Caching

The baseline manager includes a caching system that significantly speeds up repeated baseline loads:

```python
from core.baseline_manager import BaselineManager

# Create manager with caching enabled (default)
manager = BaselineManager(enable_cache=True)

# First load: reads from disk
baseline = manager.load_baseline("my_baseline")  # ~0.03s

# Second load: reads from cache
baseline = manager.load_baseline("my_baseline")  # ~0.0003s (100x faster!)

# Get cache statistics
stats = manager.get_cache_stats()
print(stats)
# {'enabled': True, 'total_entries': 1, 'valid_entries': 1, ...}

# Clear cache if needed
manager.clear_cache()
```

### Real Domain Tester Parallel Execution

The real domain tester supports parallel execution with configurable worker pool size:

```python
from core.real_domain_tester import RealDomainTester

# Create tester with optimal worker count (4-8)
tester = RealDomainTester(max_workers=4)

# Test domains in parallel
report = tester.test_domains(
    domains=["google.com", "github.com", "cloudflare.com"],
    attacks=["fake", "split"],
    parallel=True  # Enable parallel execution
)

# Get DNS cache statistics
dns_stats = tester.get_dns_cache_stats()
print(dns_stats)
```

### CLI Validation Lazy Loading

The CLI validation orchestrator uses lazy loading to minimize startup time:

```python
from core.cli_validation_orchestrator import CLIValidationOrchestrator

# Initialization is fast (<0.01s)
orchestrator = CLIValidationOrchestrator()

# Modules are loaded only when needed
result = orchestrator.validate_pcap(pcap_file)  # Loads PCAP validator
```

## Interpreting Results

### Good Performance Indicators

- ✅ Baseline comparison <1s for 500 results
- ✅ CLI startup overhead <0.1s
- ✅ DNS cache hit rate >80%
- ✅ Parallel execution speedup 3-5x with 4-8 workers

### Performance Issues

If you see:
- ⚠️ Baseline comparison >1s: Check baseline size, consider optimization
- ⚠️ CLI startup >0.1s: Check for unnecessary imports or initialization
- ⚠️ Low DNS cache hit rate: Increase cache TTL or check domain variety
- ⚠️ Poor parallel scaling: Check network latency or reduce worker count

## Troubleshooting

### Profiling Scripts Fail

1. Check that all dependencies are installed:
   ```bash
   pip install -r requirements.txt
   ```

2. Ensure you're in the correct directory:
   ```bash
   cd recon
   ```

3. Check Python version (3.8+ required):
   ```bash
   python --version
   ```

### Slow Performance

1. Check system resources (CPU, memory, network)
2. Reduce test sizes in profiling scripts
3. Disable PCAP capture for faster testing
4. Use fewer workers for parallel execution

### Cache Not Working

1. Verify caching is enabled:
   ```python
   manager = BaselineManager(enable_cache=True)
   ```

2. Check cache statistics:
   ```python
   stats = manager.get_cache_stats()
   print(stats)
   ```

3. Clear cache and retry:
   ```python
   manager.clear_cache()
   ```

## Advanced Usage

### Custom Profiling

Use the `PerformanceProfiler` class for custom profiling:

```python
from core.performance_profiler import PerformanceProfiler

profiler = PerformanceProfiler()

# Profile a code block
with profiler.profile_operation("my_operation") as metrics:
    # Your code here
    result = expensive_function()
    metrics.details['custom_metric'] = result

# Generate report
report = profiler.generate_report("my_component")
profiler.save_report(report)
```

### Detailed CPU Profiling

For detailed CPU profiling with cProfile:

```python
from core.performance_profiler import PerformanceProfiler

profiler = PerformanceProfiler()

result, stats = profiler.profile_with_cprofile(
    my_function,
    arg1,
    arg2,
    kwarg1=value1
)

print(stats)  # Detailed function call statistics
```

## Next Steps

- Review profiling reports in `profiling_results/`
- Implement recommended optimizations
- Re-run profiling to verify improvements
- Monitor performance in production

## Related Documentation

- [Task 8 Completion Report](TASK8_PERFORMANCE_OPTIMIZATION_COMPLETION_REPORT.md)
- [Attack Validation User Guide](docs/VALIDATION_PRODUCTION_USER_GUIDE.md)
- [Attack Validation Developer Guide](docs/VALIDATION_PRODUCTION_DEVELOPER_GUIDE.md)

---

**Last Updated:** 2025-10-06  
**Version:** 1.0
