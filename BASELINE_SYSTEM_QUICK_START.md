# Baseline System Quick Start Guide

## Overview

The Baseline System provides regression detection for the Attack Validation Suite by comparing current test results against saved baselines.

## Quick Start

### 1. Run Tests and Save Baseline

```bash
# Run all attacks and save as baseline
python test_all_attacks.py --save-baseline baseline_v1

# Run specific categories and save
python test_all_attacks.py --categories tcp tls --save-baseline tcp_tls_baseline
```

### 2. Compare with Baseline

```bash
# Run tests and compare with baseline
python test_all_attacks.py --compare-baseline baseline_v1

# This will:
# - Load the baseline
# - Run current tests
# - Compare results
# - Generate regression report
# - Display warnings if regressions detected
```

### 3. List Available Baselines

```bash
# List all baselines
python test_all_attacks.py --list-baselines

# Output:
# Available Baselines:
# ================================================================================
#   - baseline_20251006_115311
#   - baseline_20251006_115312
#   - baseline_v1
# ================================================================================
```

### 4. Archive Old Baselines

```bash
# Archive a baseline (moves to archive/ directory)
python test_all_attacks.py --archive-baseline baseline_v1
```

## Programmatic Usage

### Save Baseline

```python
from test_all_attacks import AttackTestOrchestrator

# Create orchestrator
orchestrator = AttackTestOrchestrator()

# Run tests
report = orchestrator.test_all_attacks()

# Save baseline
baseline_file = orchestrator.save_baseline("my_baseline")
print(f"Baseline saved: {baseline_file}")
```

### Compare with Baseline

```python
from test_all_attacks import AttackTestOrchestrator

# Create orchestrator
orchestrator = AttackTestOrchestrator()

# Load baseline
baseline = orchestrator.load_baseline("my_baseline")

# Run tests
report = orchestrator.test_all_attacks()

# Compare
comparison = orchestrator.compare_with_baseline()

# Check for regressions
if comparison.regressions:
    print(f"⚠️  {len(comparison.regressions)} regressions detected!")
    for reg in comparison.regressions:
        print(f"[{reg.severity.value}] {reg.attack_name}: {reg.description}")
else:
    print("✅ No regressions detected")

# Check for improvements
if comparison.improvements:
    print(f"✨ {len(comparison.improvements)} improvements detected!")
    for imp in comparison.improvements:
        print(f"[IMPROVEMENT] {imp.attack_name}: {imp.description}")
```

### Generate Regression Report

```python
from test_all_attacks import AttackTestOrchestrator

orchestrator = AttackTestOrchestrator()
orchestrator.load_baseline("my_baseline")
report = orchestrator.test_all_attacks()
comparison = orchestrator.compare_with_baseline()

# Generate detailed report
report_file = orchestrator.generate_regression_report()
print(f"Report saved: {report_file}")

# Report includes:
# - JSON file with full comparison data
# - TXT file with human-readable summary
```

## Regression Severity Levels

The system detects regressions at different severity levels:

### Critical (🔴)
- **Condition:** Attack passed in baseline but fails in current
- **Example:** `fake` attack was working, now fails
- **Action:** Immediate investigation required

### High (🟠)
- **Condition:** Validation passed in baseline but fails in current
- **Example:** Packets generated but validation fails
- **Action:** Review validation logic and packet structure

### Medium (🟡)
- **Condition:** Packet count decreased by >20%
- **Example:** Attack generated 5 packets, now generates 2
- **Action:** Check if attack behavior changed

## Baseline Storage

Baselines are stored in the `baselines/` directory:

```
baselines/
├── baseline_20251006_115311.json    # Timestamped baseline
├── baseline_20251006_115312.json    # Another baseline
├── baseline_v1.json                 # Named baseline
├── current_baseline.json            # Symlink to latest
└── archive/
    └── baseline_old.json            # Archived baseline
```

## Baseline Format

Baselines are stored as JSON files:

```json
{
  "name": "baseline_v1",
  "timestamp": "2025-10-06T11:53:11.395368",
  "version": "1.0",
  "total_tests": 10,
  "passed_tests": 8,
  "failed_tests": 2,
  "results": [
    {
      "attack_name": "fake",
      "passed": true,
      "packet_count": 5,
      "validation_passed": true,
      "validation_issues": [],
      "execution_time": 0.5,
      "metadata": {
        "params": {"ttl": 1, "fooling": ["badsum"]}
      }
    }
  ],
  "metadata": {}
}
```

## Advanced Usage

### Direct BaselineManager Usage

```python
from core.baseline_manager import BaselineManager, BaselineReport, BaselineResult

# Create manager
manager = BaselineManager(baselines_dir="my_baselines")

# Create baseline report
results = [
    BaselineResult(
        attack_name="fake",
        passed=True,
        packet_count=5,
        validation_passed=True,
        validation_issues=[],
        execution_time=0.5
    )
]

report = BaselineReport(
    name="my_baseline",
    timestamp="2025-10-06T12:00:00",
    version="1.0",
    total_tests=1,
    passed_tests=1,
    failed_tests=0,
    results=results
)

# Save
baseline_file = manager.save_baseline(report)

# Load
loaded = manager.load_baseline("my_baseline")

# Compare
comparison = manager.compare_with_baseline(current_report, loaded)
```

### Baseline Caching

The BaselineManager includes caching for performance:

```python
from core.baseline_manager import BaselineManager

# Create manager with caching enabled (default)
manager = BaselineManager(enable_cache=True)

# Get cache statistics
stats = manager.get_cache_stats()
print(f"Cache entries: {stats['total_entries']}")
print(f"Valid entries: {stats['valid_entries']}")
print(f"Cache TTL: {stats['cache_ttl']}s")

# Clear cache manually
manager.clear_cache()
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Regression Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.12'
      
      - name: Install dependencies
        run: pip install -r requirements.txt
      
      - name: Run tests and compare with baseline
        run: |
          python test_all_attacks.py --compare-baseline production_baseline
      
      - name: Check for regressions
        run: |
          if grep -q "REGRESSIONS DETECTED" test_results/*.txt; then
            echo "⚠️  Regressions detected!"
            exit 1
          fi
```

## Troubleshooting

### No baseline found
```
Error: No baseline found to compare against
```
**Solution:** Create a baseline first with `--save-baseline`

### Baseline version mismatch
```
Warning: Baseline version mismatch
```
**Solution:** Baselines from different versions may not be compatible. Create a new baseline.

### Cache issues
```
Error: Stale cache data
```
**Solution:** Clear cache with `manager.clear_cache()` or disable caching

## Best Practices

1. **Regular Baselines:** Create baselines after each major release
2. **Naming Convention:** Use descriptive names like `v1.0_release` or `feature_xyz`
3. **Archive Old Baselines:** Keep baseline directory clean by archiving old baselines
4. **CI/CD Integration:** Run baseline comparisons in CI/CD pipeline
5. **Review Regressions:** Always investigate critical and high severity regressions
6. **Track Improvements:** Document improvements for release notes

## Performance

- **Baseline Save:** <100ms
- **Baseline Load:** <10ms (cached), <50ms (uncached)
- **Baseline Comparison:** <100ms for 100 tests
- **Cache TTL:** 5 minutes (configurable)

## Support

For issues or questions:
1. Check `TASK_4_BASELINE_SYSTEM_COMPLETION_REPORT.md` for detailed documentation
2. Review test files: `test_baseline_integration.py` and `tests/integration/test_validation_production.py`
3. Check baseline manager source: `core/baseline_manager.py`

---

**Last Updated:** 2025-10-06  
**Version:** 1.0  
**Status:** Production Ready ✅
