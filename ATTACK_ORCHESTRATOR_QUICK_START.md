# Attack Test Orchestrator - Quick Start Guide

## 🚀 Quick Start

### Run All Tests
```bash
cd recon
python test_all_attacks.py
```

### Run Basic Verification
```bash
python test_orchestrator_basic.py
```

## 📋 Common Commands

### Generate Reports
```bash
# HTML report (default)
python test_all_attacks.py --html

# Text report
python test_all_attacks.py --text

# JSON report
python test_all_attacks.py --json

# All formats
python test_all_attacks.py --html --text --json
```

### Test Specific Categories
```bash
# Test only TCP attacks
python test_all_attacks.py --categories tcp

# Test multiple categories
python test_all_attacks.py --categories tcp tls dns
```

### Regression Testing
```bash
# Step 1: Save baseline
python test_all_attacks.py --baseline

# Step 2: Make changes to code

# Step 3: Run regression tests
python test_all_attacks.py --regression
```

### Custom Output Directory
```bash
python test_all_attacks.py --output-dir my_test_results
```

## 🐍 Python API

### Basic Usage
```python
from test_all_attacks import AttackTestOrchestrator

# Create orchestrator
orchestrator = AttackTestOrchestrator()

# Run tests
report = orchestrator.test_all_attacks()

# Generate reports
orchestrator.generate_html_report()
orchestrator.generate_text_report()
orchestrator.generate_json_report()

# Print summary
print(f"Passed: {report.passed}/{report.total_tests}")
print(f"Success Rate: {(report.passed/report.total_tests*100):.2f}%")
```

### Test Specific Categories
```python
# Test only TCP attacks
report = orchestrator.test_all_attacks(categories=['tcp'])

# Test multiple categories
report = orchestrator.test_all_attacks(categories=['tcp', 'tls', 'dns'])
```

### Regression Testing
```python
# Save baseline
orchestrator.save_baseline()

# Later, load and compare
orchestrator.load_baseline()
regressions = orchestrator.detect_regressions()

if regressions:
    print(f"Found {len(regressions)} regressions!")
    orchestrator.generate_regression_report()
```

### Access Results
```python
# Get all results
for result in report.results:
    print(f"{result.attack_name}: {result.status.value}")
    if result.validation:
        print(f"  Validation: {result.validation.passed}")

# Get attack summary
for attack_name, stats in report.attack_summary.items():
    print(f"{attack_name}: {stats['success_rate']:.1f}% success")

# Get failure patterns
patterns = report.attack_summary.get('failure_patterns', {})
for pattern, count in patterns.items():
    print(f"{pattern}: {count}")
```

## 📊 Understanding Reports

### HTML Report
- **Green rows**: Tests passed
- **Red rows**: Tests failed
- **Orange rows**: Tests had errors
- Click on details to see validation info

### Text Report
```
SUMMARY
--------------------------------------------------------------------------------
Total Tests:   45
Passed:        38
Failed:        5
Errors:        2
Success Rate:  84.44%

ATTACK SUMMARY
--------------------------------------------------------------------------------
Attack               Total Passed Failed Errors Success  Avg Time
--------------------------------------------------------------------------------
fake                     5      4      1      0   80.0%    0.234s
split                    3      3      0      0  100.0%    0.156s
```

### JSON Report
```json
{
  "summary": {
    "total_tests": 45,
    "passed": 38,
    "failed": 5,
    "errors": 2,
    "success_rate": "84.44%"
  },
  "attack_summary": {
    "fake": {
      "total": 5,
      "passed": 4,
      "failed": 1,
      "success_rate": 80.0
    }
  },
  "results": [...]
}
```

## 🔍 Troubleshooting

### No Attacks Found
```
⚠ Found 7 missing attacks: ['fake', 'split', 'fakeddisorder', ...]
```

**Solution**: Attacks need to be registered with `@register_attack` decorator. Import attack modules before running tests.

### Tests Fail to Execute
```
✗ ERROR - fake: Could not execute attack
```

**Solution**: Check that BypassEngine is properly configured and attack execution is implemented.

### Validation Failures
```
✗ FAILED - fakeddisorder: Sequence number mismatch
```

**Solution**: Review PCAP files and attack implementation. Check PacketValidator configuration.

## 📁 Output Files

### Default Structure
```
test_results/
├── test_fake_12345.pcap
├── test_split_67890.pcap
├── attack_test_report_20251004_120000.html
├── attack_test_report_20251004_120000.txt
├── attack_test_report_20251004_120000.json
├── baseline_results.json
└── regression_report_20251004_120000.json
```

### File Naming
- **PCAP files**: `test_{attack}_{param_hash}.pcap`
- **Reports**: `attack_test_report_{timestamp}.{format}`
- **Baseline**: `baseline_results.json`
- **Regressions**: `regression_report_{timestamp}.json`

## 🎯 Best Practices

### 1. Establish Baseline Early
```bash
# After implementing attacks, save baseline
python test_all_attacks.py --baseline
```

### 2. Run Regression Tests Before Commits
```bash
# Before committing changes
python test_all_attacks.py --regression
```

### 3. Review Failed Tests
```bash
# Generate detailed reports
python test_all_attacks.py --html --text

# Review HTML report in browser
# Check text report for quick overview
```

### 4. Test Incrementally
```bash
# Test one category at a time during development
python test_all_attacks.py --categories tcp
```

### 5. Keep Baselines Updated
```bash
# After fixing issues, update baseline
python test_all_attacks.py --baseline
```

## 🔧 Configuration

### Custom Output Directory
```python
orchestrator = AttackTestOrchestrator(output_dir=Path("my_results"))
```

### Custom Report Filenames
```python
orchestrator.generate_html_report(output_file=Path("my_report.html"))
orchestrator.generate_text_report(output_file=Path("my_report.txt"))
orchestrator.generate_json_report(output_file=Path("my_report.json"))
```

### Custom Baseline Location
```python
orchestrator.save_baseline(baseline_file=Path("my_baseline.json"))
orchestrator.load_baseline(baseline_file=Path("my_baseline.json"))
```

## 📚 Related Documentation

- **Full Documentation**: `ATTACK_TEST_ORCHESTRATOR_README.md`
- **Completion Report**: `TASK3_ATTACK_ORCHESTRATOR_COMPLETION_REPORT.md`
- **Packet Validator**: `core/PACKET_VALIDATOR_README.md`
- **Strategy Parser**: `STRATEGY_PARSER_V2_QUICK_START.md`

## 💡 Tips

1. **Start Small**: Test one attack at a time during development
2. **Use Categories**: Group related attacks for focused testing
3. **Check Logs**: Enable DEBUG logging for detailed information
4. **Review PCAPs**: Manually inspect PCAP files when tests fail
5. **Update Baselines**: Keep baselines current with expected behavior

## 🐛 Debug Mode

```python
import logging

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)

# Run tests
orchestrator = AttackTestOrchestrator()
report = orchestrator.test_all_attacks()
```

## 📞 Support

For issues or questions:
1. Check the full documentation
2. Review completion report for known limitations
3. Check test logs for detailed error messages
4. Verify attack registration and configuration

---

**Quick Reference**: Keep this guide handy for daily testing workflows!
