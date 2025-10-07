# Attack Test Orchestrator

Comprehensive testing suite for validating all DPI bypass attacks in the recon system.

## Overview

The Attack Test Orchestrator provides automated testing, validation, and reporting for all registered DPI bypass attacks. It ensures that attacks generate correct packets according to their specifications and tracks regressions over time.

## Features

### 1. Attack Registry Loader (Subtask 3.1)
- Loads all attacks from the AttackRegistry
- Extracts attack metadata (category, parameters, etc.)
- Generates test cases with default and variation parameters
- Handles missing attacks gracefully

### 2. Test Execution (Subtask 3.2)
- Executes each attack with specified parameters
- Captures packets to PCAP files
- Handles errors gracefully with detailed logging
- Collects telemetry (duration, status, etc.)

### 3. Result Aggregation (Subtask 3.3)
- Collects all test results
- Calculates pass/fail statistics
- Identifies patterns in failures (sequence errors, checksum errors, etc.)
- Generates attack-level summaries

### 4. Report Generation (Subtask 3.4)
- **HTML Report**: Interactive web-based report with color-coded results
- **Text Report**: Console-friendly plain text report
- **JSON Report**: Machine-readable structured data
- Includes visual diffs and detailed validation results

### 5. Regression Testing (Subtask 3.5)
- Saves baseline results for comparison
- Compares current results with baseline
- Detects regressions (tests that previously passed now fail)
- Reports new failures with detailed information

## Usage

### Basic Usage

```python
from test_all_attacks import AttackTestOrchestrator

# Create orchestrator
orchestrator = AttackTestOrchestrator(output_dir="test_results")

# Run all tests
report = orchestrator.test_all_attacks()

# Generate reports
orchestrator.generate_html_report()
orchestrator.generate_text_report()
orchestrator.generate_json_report()

# Print summary
print(f"Passed: {report.passed}/{report.total_tests}")
```

### Command Line Usage

```bash
# Test all attacks
python test_all_attacks.py

# Test specific categories
python test_all_attacks.py --categories tcp tls

# Generate specific report formats
python test_all_attacks.py --html --text --json

# Save as baseline
python test_all_attacks.py --baseline

# Run regression testing
python test_all_attacks.py --regression

# Specify output directory
python test_all_attacks.py --output-dir my_results
```

### Advanced Usage

```python
from test_all_attacks import AttackTestOrchestrator

orchestrator = AttackTestOrchestrator()

# Test specific categories
report = orchestrator.test_all_attacks(categories=['tcp', 'tls'])

# Save baseline
orchestrator.save_baseline()

# Load baseline and detect regressions
orchestrator.load_baseline()
regressions = orchestrator.detect_regressions()

if regressions:
    print(f"Found {len(regressions)} regressions!")
    orchestrator.generate_regression_report()
```

## Architecture

### Components

1. **AttackRegistryLoader**
   - Loads attacks from AttackRegistry
   - Extracts metadata and generates test cases
   - Handles missing attacks

2. **AttackTestOrchestrator**
   - Main coordinator for test execution
   - Manages test lifecycle
   - Generates reports

3. **TestResult**
   - Represents result of a single test
   - Contains validation details, errors, timing

4. **TestReport**
   - Aggregates all test results
   - Calculates statistics
   - Provides summary data

### Data Flow

```
AttackRegistry → AttackRegistryLoader → AttackTestOrchestrator
                                              ↓
                                    Execute Attack + Validate
                                              ↓
                                        TestResult
                                              ↓
                                        TestReport
                                              ↓
                            HTML/Text/JSON Reports + Regression Analysis
```

## Test Metadata

Each attack is tested with:

- **Default Parameters**: Standard configuration for the attack
- **Test Variations**: Multiple parameter combinations to test edge cases
- **Category**: Attack classification (tcp, tls, dns, etc.)
- **Requirements**: Whether attack needs a target

### Example Attack Metadata

```python
AttackMetadata(
    name='fakeddisorder',
    normalized_name='fakeddisorder',
    category='tcp',
    default_params={'split_pos': 2, 'ttl': 1, 'fooling': ['badsum']},
    test_variations=[
        {'split_pos': 2, 'ttl': 1, 'fooling': []},
        {'split_pos': 10, 'ttl': 3, 'fooling': ['badsum']},
        {'split_pos': 76, 'overlap_size': 336, 'ttl': 3}
    ],
    requires_target=True
)
```

## Report Formats

### HTML Report

Interactive web-based report with:
- Color-coded status indicators
- Summary statistics
- Attack-level breakdown
- Detailed test results with expandable details

### Text Report

Console-friendly format with:
- ASCII table formatting
- Summary section
- Attack summary table
- Failure patterns
- Detailed results

### JSON Report

Machine-readable format with:
- Complete test data
- Validation details
- Timing information
- Structured for programmatic access

## Regression Testing

### Workflow

1. **Establish Baseline**
   ```bash
   python test_all_attacks.py --baseline
   ```

2. **Make Changes** to attack implementations

3. **Run Regression Tests**
   ```bash
   python test_all_attacks.py --regression
   ```

4. **Review Regressions**
   - Check `regression_report_*.json`
   - Investigate failed tests
   - Fix issues or update baseline

### Regression Detection

The orchestrator detects:
- Tests that previously passed but now fail
- New errors in previously working attacks
- Changes in validation results

## Integration with Validation

The orchestrator integrates with `PacketValidator` to:
- Validate sequence numbers
- Verify checksums (good/bad as specified)
- Check TTL values
- Validate packet counts
- Compare packet order

## Error Handling

The orchestrator handles errors gracefully:
- **Parser Errors**: Logged with strategy details
- **Execution Errors**: Captured with stack traces
- **Validation Errors**: Detailed in test results
- **Missing Attacks**: Reported but don't block testing

## Performance

- Tests run sequentially for reliability
- Each test is isolated (separate PCAP files)
- Timing data collected for performance analysis
- Results cached for regression comparison

## Extensibility

### Adding New Test Variations

```python
def _generate_test_variations(self, attack_name: str):
    if attack_name == 'my_attack':
        return [
            {'param1': 'value1'},
            {'param1': 'value2', 'param2': 10}
        ]
```

### Custom Validation

Integrate with `PacketValidator` for custom validation rules:

```python
validator = PacketValidator()
validation = validator.validate_attack(
    attack_name='my_attack',
    params={'param': 'value'},
    pcap_file='test.pcap'
)
```

## Requirements

- Python 3.8+
- AttackRegistry with registered attacks
- StrategyParserV2 for parsing
- PacketValidator for validation
- PCAP capture capability

## Limitations

- Currently uses placeholder for actual attack execution
- Requires integration with bypass engine for real testing
- PCAP capture needs to be implemented
- Some attacks may not have test variations defined

## Future Enhancements

1. **Parallel Execution**: Run tests in parallel for speed
2. **Real Attack Execution**: Integrate with bypass engine
3. **Live PCAP Capture**: Capture real network traffic
4. **Visual Diffs**: Generate packet comparison visualizations
5. **CI/CD Integration**: Automated testing in pipelines
6. **Performance Benchmarks**: Track attack performance over time
7. **Coverage Analysis**: Ensure all attack parameters tested

## Example Output

```
================================================================================
TEST SUMMARY
================================================================================
Total Tests: 45
Passed:      38
Failed:      5
Errors:      2
Success Rate: 84.44%
Duration:    12.34s
================================================================================

ATTACK SUMMARY
--------------------------------------------------------------------------------
Attack               Total Passed Failed Errors Success  Avg Time
--------------------------------------------------------------------------------
fake                     5      4      1      0   80.0%    0.234s
split                    3      3      0      0  100.0%    0.156s
fakeddisorder            8      6      2      0   75.0%    0.289s
disorder                 4      4      0      0  100.0%    0.178s
multisplit               5      4      0      1   80.0%    0.312s
```

## Troubleshooting

### No Attacks Found

If the registry is empty:
1. Ensure attacks are registered with `@register_attack`
2. Import attack modules before running tests
3. Check AttackRegistry initialization

### Tests Fail to Execute

If tests error during execution:
1. Check strategy parser configuration
2. Verify bypass engine is available
3. Review error logs for details

### Validation Failures

If validation fails unexpectedly:
1. Check PacketValidator configuration
2. Review PCAP files manually
3. Verify attack specifications are correct

## Contributing

When adding new attacks:
1. Register with AttackRegistry
2. Add default parameters to `_generate_default_params`
3. Add test variations to `_generate_test_variations`
4. Update attack specifications if needed

## License

Part of the recon DPI bypass toolkit.
