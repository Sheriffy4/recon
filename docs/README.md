# DPI Strategy Testing Suite

This directory contains comprehensive tests for the DPI strategy implementation.

## Test Structure

### Unit Tests
- `test_position_resolver.py` - Tests for position resolution logic
- `test_sni_detector.py` - Tests for SNI detection and parsing
- `test_checksum_fooler.py` - Tests for badsum functionality
- `test_dpi_strategy_engine.py` - Tests for main strategy engine

### Integration Tests
- `test_strategy_integration.py` - Tests for strategy combinations and component interactions

### PCAP Validation Tests
- `test_pcap_validation.py` - Tests for PCAP analysis and strategy verification

## Running Tests

### Quick Start
```bash
# Run all tests
python tests/run_tests.py

# Run specific category
python tests/run_tests.py unit
python tests/run_tests.py integration
python tests/run_tests.py pcap_validation

# Run with verbose output
python tests/run_tests.py -v

# Run specific test file
python -m pytest tests/test_position_resolver.py -v
```

### Test Categories
- **unit**: Core component unit tests
- **integration**: Component interaction tests  
- **pcap_validation**: PCAP analysis and validation tests

## Test Coverage

The test suite covers:
- Position resolution (numeric positions 3, 10, SNI)
- SNI detection and parsing in TLS packets
- Badsum application and checksum manipulation
- Strategy engine orchestration and error handling
- Integration between all components
- PCAP validation and analysis
- Performance and stress testing
- Error scenarios and edge cases

## Requirements Validation

Tests verify compliance with requirements:
- 5.1: Strategy application visible in PCAP analysis
- 5.2: Position 3 and 10 splits detectable in PCAP
- 5.3: SNI splits detectable in PCAP  
- 5.4: Badsum application detectable in PCAP
- 5.5: Invalid TCP checksums visible in analysis
- 5.6: Comprehensive component testing