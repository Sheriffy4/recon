# End-to-End DPI Strategy Validation System

This directory contains a comprehensive end-to-end validation system for DPI (Deep Packet Inspection) bypass strategies. The system provides automated testing, PCAP analysis, and comprehensive reporting to validate the effectiveness of DPI strategy implementations.

## Overview

The validation system consists of several integrated components:

1. **End-to-End Testing** - Conducts real-world testing with various DPI configurations
2. **PCAP Analysis** - Analyzes packet captures to validate strategy application
3. **Strategy Validation** - Verifies that specific DPI strategies are working correctly
4. **Comprehensive Reporting** - Generates detailed reports with recommendations

## Components

### Core Modules

- `end_to_end_validation.py` - Main end-to-end testing framework
- `pcap_strategy_validator.py` - PCAP analysis for strategy validation
- `integrated_pcap_analyzer.py` - Comprehensive PCAP analysis tool
- `real_world_tester.py` - Real-world traffic testing utilities
- `validation_report_generator.py` - Comprehensive report generation
- `run_complete_validation.py` - Master script for complete workflow

### Test Configurations

The system tests the following DPI strategies:

- **Split Position 3** - Splits packets at byte position 3
- **Split Position 10** - Splits packets at byte position 10  
- **SNI Split** - Splits TLS packets at SNI extension position
- **Badsum** - Applies invalid TCP checksums
- **Combined Strategies** - Tests combinations of the above

## Quick Start

### Run Complete Validation Workflow

The easiest way to run the complete validation is using the master script:

```bash
# Run complete validation with default settings
python tests/run_complete_validation.py

# Run with custom domain and duration
python tests/run_complete_validation.py --domain youtube.com --duration 60

# Run with verbose logging
python tests/run_complete_validation.py --verbose --output-dir my_validation_results
```

### Run Individual Components

#### 1. End-to-End Testing Only

```bash
python tests/end_to_end_validation.py --output-dir e2e_results --verbose
```

#### 2. PCAP Analysis Only

```bash
# Analyze a specific PCAP file
python tests/pcap_strategy_validator.py my_capture.pcap --strategies split_3 split_10 badsum

# Comprehensive PCAP analysis
python tests/integrated_pcap_analyzer.py my_capture.pcap --output-dir analysis_results
```

#### 3. Real-World Testing

```bash
# Test specific DPI configuration
python tests/real_world_tester.py --domain youtube.com --split-pos 3 10 sni --fooling badsum
```

#### 4. Generate Reports

```bash
# Generate report from existing results
python tests/validation_report_generator.py \
    --end-to-end-results e2e_results.json \
    --pcap-analysis-results analysis1.json analysis2.json \
    --output-dir reports
```

## Output Structure

The validation system creates the following output structure:

```
validation_results/
├── end_to_end_tests/           # End-to-end test results
│   ├── test_baseline_*.pcap    # PCAP files from tests
│   ├── test_split_3_*.pcap
│   └── end_to_end_results.json # Summary results
├── pcap_analysis/              # PCAP analysis results
│   ├── analysis_result_*.json  # Detailed analysis data
│   └── analysis_report_*.txt   # Human-readable reports
├── reports/                    # Final comprehensive reports
│   ├── validation_report_*.json    # Complete data
│   ├── validation_report_*.txt     # Human-readable report
│   └── *_executive_summary.txt     # Executive summary
└── workflow_results.json       # Overall workflow results
```

## Understanding Results

### Success Metrics

- **Success Rate** - Percentage of tests that completed successfully
- **Effectiveness Score** - How well strategies are being applied (0.0-1.0)
- **Strategy Applications** - Number of times each strategy was detected
- **Confidence Score** - Confidence in strategy detection (0.0-1.0)

### Strategy Validation

Each strategy is validated by looking for specific patterns in PCAP files:

- **Split Position 3** - Looks for packets with exactly 3 bytes of payload
- **Split Position 10** - Looks for packets with exactly 10 bytes of payload
- **SNI Split** - Analyzes TLS handshake structure for SNI-based splits
- **Badsum** - Checks for invalid TCP checksums (0x0000 or 0xFFFF)

### Report Interpretation

#### Effectiveness Scores
- **0.9-1.0** - Excellent: Strategies working very well
- **0.7-0.8** - Good: Strategies mostly working, minor issues
- **0.5-0.6** - Fair: Strategies partially working, needs improvement
- **0.0-0.4** - Poor: Strategies not working, major issues

#### Common Issues
- **No packets captured** - Check network permissions and capture setup
- **No strategy applications detected** - Verify DPI engine integration
- **Low confidence scores** - May indicate partial implementation
- **High error rates** - Check logs for specific error messages

## Troubleshooting

### Common Problems

#### 1. Scapy Import Errors
```bash
# Install Scapy
pip install scapy

# On Windows, may need WinPcap or Npcap
# Download from: https://nmap.org/npcap/
```

#### 2. Permission Errors (Packet Capture)
```bash
# Linux: Run with sudo or add user to appropriate groups
sudo python tests/run_complete_validation.py

# Windows: Run as Administrator
```

#### 3. No PCAP Files Generated
- Check that packet capture is working
- Verify network interface is accessible
- Ensure target domain is reachable

#### 4. Mock Data Warning
If you see "Using mock data" warnings, it means:
- Scapy is not available, or
- Packet capture failed, or
- PCAP files are missing

The system will generate realistic mock data for demonstration purposes.

### Debug Mode

Enable verbose logging to see detailed information:

```bash
python tests/run_complete_validation.py --verbose
```

Check log files in the output directory for detailed error information.

## Integration with Existing Tools

The validation system integrates with existing analysis tools:

- `analyze_youtube_pcap.py` - YouTube-specific PCAP analysis
- `split_position_analyzer.py` - Split position detection
- `client_hello_analyzer.py` - TLS Client Hello analysis

These tools are automatically used when available.

## Customization

### Adding New Test Configurations

Edit `run_complete_validation.py` and modify the `create_test_configurations()` function:

```python
def create_test_configurations():
    configurations = []
    
    # Add your custom configuration
    configurations.append(DPIConfig(
        desync_mode="split",
        split_positions=["5"],  # Custom split position
        fooling_methods=["badsum"],
        enabled=True,
        # ... other parameters
    ))
    
    return configurations
```

### Adding New Strategy Validators

Create a new validation method in `pcap_strategy_validator.py`:

```python
def _validate_custom_strategy(self, packets: List) -> StrategyValidationResult:
    # Your custom validation logic
    return StrategyValidationResult(
        strategy_name="custom_strategy",
        expected_behavior="Description of expected behavior",
        observed_behavior="What was actually observed",
        validation_passed=True,  # Your validation result
        confidence_score=0.9,
        evidence=["Evidence of strategy application"],
        issues=[]
    )
```

### Custom Report Formats

The report generator can be extended to support additional output formats by modifying `validation_report_generator.py`.

## Requirements

### Python Dependencies
- `scapy` - Packet capture and analysis
- `pathlib` - Path handling
- `dataclasses` - Data structures
- `json` - Data serialization
- `logging` - Logging functionality

### System Requirements
- Python 3.7+
- Network access for real-world testing
- Packet capture permissions (may require admin/root)
- Sufficient disk space for PCAP files and reports

### Optional Dependencies
- Existing analysis tools in the project root
- DPI strategy engine implementation
- Network monitoring tools

## Performance Considerations

- **PCAP File Size** - Large captures may take time to analyze
- **Test Duration** - Longer captures provide more data but take more time
- **Concurrent Tests** - Running multiple tests simultaneously may affect results
- **Memory Usage** - Large PCAP files require significant memory

## Security Notes

- The system may require elevated privileges for packet capture
- PCAP files may contain sensitive network data
- Ensure proper handling of captured traffic
- Consider data retention policies for test results

## Contributing

When adding new features:

1. Follow the existing code structure and patterns
2. Add appropriate logging and error handling
3. Update this README with new functionality
4. Include unit tests where possible
5. Ensure compatibility with existing components

## Support

For issues or questions:

1. Check the troubleshooting section above
2. Review log files for detailed error information
3. Verify all dependencies are installed correctly
4. Ensure proper network permissions and access