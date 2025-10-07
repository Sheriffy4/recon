# CLI Baseline Comparison - Quick Start Guide

**Task 6.4: Integrate baseline comparison into CLI workflow**

## What is Baseline Comparison?

Baseline comparison allows you to:
- Save test results as a "baseline" (reference point)
- Compare future test runs against the baseline
- Automatically detect regressions (things that broke)
- Track improvements over time

## Quick Start

### 1. Save Your First Baseline

Run tests and save results as a baseline:

```bash
python cli.py example.com --validate --save-baseline my_first_baseline
```

This creates `baselines/my_first_baseline.json` with all test results.

### 2. Compare Against Baseline

Run tests again and compare with your baseline:

```bash
python cli.py example.com --validate --validate-baseline my_first_baseline
```

You'll see:
- ✅ **No regressions detected** - Everything still works!
- ⚠️ **Regressions detected** - Something broke!
- ✓ **Improvements** - Something got better!

### 3. Save New Baseline While Comparing

Compare with old baseline and save new one:

```bash
python cli.py example.com --validate --validate-baseline old_baseline --save-baseline new_baseline
```

## Example Output

### When Everything is Good ✅

```
======================================================================
BASELINE COMPARISON RESULTS
======================================================================
Baseline: my_first_baseline
Total Tests: 10
Regressions: 0
Improvements: 0
Unchanged: 10

✓ No regressions detected
======================================================================
```

### When Regressions are Detected ⚠️

```
======================================================================
BASELINE COMPARISON RESULTS
======================================================================
Baseline: my_first_baseline
Total Tests: 10
Regressions: 2
Improvements: 0
Unchanged: 8

⚠ REGRESSIONS DETECTED:
  [CRITICAL] fake_disorder: Attack fake_disorder regressed from PASS to FAIL
  [HIGH] multisplit: Attack multisplit validation degraded
======================================================================
```

## Common Use Cases

### Before/After Testing

Test before making changes:
```bash
python cli.py example.com --validate --save-baseline before_changes
```

Make your code changes, then test again:
```bash
python cli.py example.com --validate --validate-baseline before_changes
```

### Daily Regression Testing

Save a daily baseline:
```bash
python cli.py -d sites.txt --validate --save-baseline daily_20251006
```

Compare tomorrow's run:
```bash
python cli.py -d sites.txt --validate --validate-baseline daily_20251006
```

### Release Validation

Before release, compare with stable baseline:
```bash
python cli.py -d sites.txt --validate --validate-baseline stable_v1.0
```

If no regressions, save as new stable:
```bash
python cli.py -d sites.txt --validate --validate-baseline stable_v1.0 --save-baseline stable_v1.1
```

## Understanding Regression Severity

### 🔴 CRITICAL
An attack that was working now fails completely.
- **Example**: `fake_disorder` passed before, fails now
- **Action**: Fix immediately before release

### 🟠 HIGH
Validation degraded (packets are malformed).
- **Example**: Checksums were correct, now incorrect
- **Action**: Investigate and fix

### 🟡 MEDIUM
Performance degraded (fewer packets, slower).
- **Example**: Generated 10 packets before, only 5 now
- **Action**: Review and optimize

## Where are Baselines Stored?

Baselines are saved in the `baselines/` directory:

```
baselines/
├── my_first_baseline.json
├── before_changes.json
├── daily_20251006.json
└── current_baseline.json -> my_first_baseline.json
```

## Tips

1. **Use descriptive names**: `before_refactor`, `stable_v1.0`, `daily_20251006`
2. **Save before major changes**: Always have a reference point
3. **Compare regularly**: Catch regressions early
4. **Review all regressions**: Don't ignore warnings
5. **Archive old baselines**: Keep directory clean

## Testing the Feature

Run the test suite to verify everything works:

```bash
python test_cli_baseline_integration.py
```

Expected output:
```
✓ TEST 1 PASSED: Baseline Save and Load
✓ TEST 2 PASSED: Regression Detection
✓ TEST 3 PASSED: Improvement Detection
✓ TEST 4 PASSED: CLI Orchestrator Integration

✓ ALL TESTS PASSED
```

## Troubleshooting

### "No baseline found to compare against"
- Check the baseline name is correct
- List available baselines: `ls baselines/`

### "Baseline functionality not available"
- Ensure `--validate` flag is used
- Check all required modules are installed

### No regressions detected but something broke
- Verify test results format is correct
- Check attack names match between runs

## Next Steps

- Read full documentation: [docs/CLI_BASELINE_COMPARISON.md](docs/CLI_BASELINE_COMPARISON.md)
- Learn about PCAP validation: [docs/CLI_PCAP_VALIDATION.md](docs/CLI_PCAP_VALIDATION.md)
- Explore strategy validation: [docs/STRATEGY_VALIDATION_CLI_INTEGRATION.md](docs/STRATEGY_VALIDATION_CLI_INTEGRATION.md)

## Implementation Status

✅ **COMPLETE** - Task 6.4: Integrate baseline comparison into CLI workflow

All features working:
- ✅ Save baselines with `--save-baseline`
- ✅ Compare with baselines using `--validate-baseline`
- ✅ Detect and report regressions prominently
- ✅ Detect and report improvements
- ✅ Comprehensive testing and documentation

---

**Quick Reference:**

```bash
# Save baseline
python cli.py <target> --validate --save-baseline <name>

# Compare with baseline
python cli.py <target> --validate --validate-baseline <name>

# Both
python cli.py <target> --validate --validate-baseline <old> --save-baseline <new>
```
