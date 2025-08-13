# Integration Testing Guide for Native Attack Orchestration

## Overview

This guide covers the comprehensive integration testing suite for the Native Attack Orchestration system. The testing suite validates the complete integration of all components and ensures production readiness.

## Test Suite Structure

### 1. Core Integration Tests (`test_native_attack_orchestration_integration.py`)

Tests the complete integration of all system components:

- **NativePyDivertEngine** integration with segment orchestration
- **SegmentPacketBuilder** integration with various packet options
- **PreciseTimingController** integration and accuracy
- **SegmentDiagnosticLogger** comprehensive logging
- **AttackContext** with TCP session support
- End-to-end segment orchestration workflows

#### Key Test Scenarios:
- Complete system integration with all components
- Segment packet builder integration with various options
- Timing controller performance and accuracy
- Diagnostic system integration
- Error handling across all components
- Performance integration testing
- TCP session context integration
- Comprehensive reporting integration
- Concurrent execution scenarios

### 2. End-to-End Attack Scenarios (`test_end_to_end_attack_scenarios.py`)

Tests realistic attack scenarios that would be used in production:

#### HTTP Request Segmentation Attack
- Segments HTTP requests strategically to bypass DPI
- Uses fake packets with low TTL
- Corrupts checksums on critical headers
- Tests timing precision for segment delivery

#### TLS Handshake Manipulation Attack
- Segments TLS Client Hello messages
- Bypasses SNI filtering through strategic fragmentation
- Tests checksum corruption before SNI extension
- Validates timing between TLS record segments

#### DNS Query Fragmentation Attack
- Fragments DNS queries to bypass domain filtering
- Uses fake DNS queries with different domains
- Tests domain name segmentation
- Validates query reconstruction

#### Multi-Stage Attack Sequences
- Combines DNS, HTTP, and TLS attacks
- Tests sequential attack execution
- Validates timing between attack stages
- Measures overall attack effectiveness

#### High-Volume Attack Scenarios
- Tests system performance with 100+ segments
- Validates memory usage patterns
- Measures throughput and latency
- Tests error recovery under load

### 3. Performance Benchmarks (`test_performance_benchmarks.py`)

Comprehensive performance testing and benchmarking:

#### Segment Construction Performance
- Benchmarks packet construction speed
- Tests various payload sizes (10B to 5KB)
- Validates >1000 packets/sec construction rate
- Measures memory allocation patterns

#### Timing Controller Performance
- Tests timing accuracy across different delay ranges
- Validates >90% average timing accuracy
- Benchmarks sub-millisecond precision
- Tests timing strategy selection

#### Memory Usage Patterns
- Monitors memory usage under various loads
- Tests with 10 to 1000 segments
- Validates linear memory scaling
- Ensures <50MB usage for 1000 segments

#### Concurrent Execution Performance
- Tests multi-threaded segment execution
- Validates >50 segments/sec throughput
- Tests thread safety and resource contention
- Measures concurrent execution overhead

#### Scalability Limits
- Tests system limits with up to 5000 segments
- Validates linear performance scaling
- Identifies performance bottlenecks
- Tests memory and CPU usage patterns

#### Diagnostic System Performance
- Benchmarks diagnostic logging overhead
- Tests >1000 operations/sec logging rate
- Validates minimal performance impact
- Tests diagnostic data collection efficiency

### 4. Backward Compatibility Tests (`test_backward_compatibility_integration.py`)

Ensures full compatibility with existing attack implementations:

#### Legacy Attack Compatibility
- Tests attacks using `modified_payload`
- Validates existing attack workflows
- Ensures no breaking changes
- Tests fallback mechanisms

#### Modern Segment Attack Compatibility
- Tests new segment-based attacks
- Validates segment orchestration
- Tests advanced timing features
- Validates diagnostic integration

#### Mixed Attack Execution
- Tests sequential execution of legacy and modern attacks
- Validates statistics collection for both types
- Tests error handling compatibility
- Ensures consistent behavior

#### Fallback Mechanisms
- Tests fallback to `modified_payload` when segments are empty
- Tests fallback to original packet when both are unavailable
- Validates graceful degradation
- Tests error recovery scenarios

## Running the Integration Tests

### Prerequisites

```bash
# Install required dependencies
pip install pytest psutil

# Ensure you're in the project root directory
cd /path/to/your/project
```

### Running Individual Test Files

```bash
# Run core integration tests
python -m pytest tests/test_native_attack_orchestration_integration.py -v

# Run end-to-end scenarios
python -m pytest tests/test_end_to_end_attack_scenarios.py -v

# Run performance benchmarks
python -m pytest tests/test_performance_benchmarks.py -v

# Run compatibility tests
python -m pytest tests/test_backward_compatibility_integration.py -v
```

### Running Complete Integration Suite

```bash
# Run all integration tests with comprehensive reporting
python tests/run_integration_tests.py
```

The integration test runner provides:
- Sequential execution of all test files
- Comprehensive performance reporting
- Detailed failure analysis
- Production readiness assessment

## Performance Requirements

The integration tests validate the following performance requirements:

### Segment Construction
- **Requirement**: >1000 packets/sec construction rate
- **Test**: Various payload sizes from 10B to 5KB
- **Validation**: Average construction time <1ms

### Timing Accuracy
- **Requirement**: >90% average timing accuracy
- **Test**: Delays from 0.1ms to 100ms
- **Validation**: Minimum 70% accuracy for all ranges

### Memory Usage
- **Requirement**: <50MB for 1000 segments
- **Test**: Linear scaling from 10 to 1000 segments
- **Validation**: <0.1MB per segment average

### Concurrent Performance
- **Requirement**: >50 segments/sec concurrent throughput
- **Test**: Multi-threaded execution with 5 threads
- **Validation**: Average execution time <0.1s

### Scalability
- **Requirement**: Linear scaling up to 5000 segments
- **Test**: Increasing segment counts with performance monitoring
- **Validation**: <6x time increase for 5x segment increase

### End-to-End Latency
- **Requirement**: <2s average execution time
- **Test**: Realistic attack scenarios
- **Validation**: 95% success rate with <5s maximum time

## Test Data and Scenarios

### HTTP Request Scenarios
```python
# Example HTTP request segmentation
http_request = (
    b"GET /blocked-content HTTP/1.1\r\n"
    b"Host: blocked-site.com\r\n"
    b"User-Agent: Mozilla/5.0\r\n"
    b"Accept: text/html\r\n"
    b"Connection: keep-alive\r\n"
    b"\r\n"
)

segments = [
    # Fake packet with low TTL
    (b"GET /malicious HTTP/1.1\r\n", 0, {"ttl": 1, "delay_ms": 20}),
    # Real request line
    (b"GET /blocked-content HTTP/1.1\r\n", 0, {"ttl": 64, "delay_ms": 5}),
    # Host header with corrupted checksum
    (b"Host: blocked-site.com\r\n", 28, {"ttl": 64, "bad_checksum": True, "delay_ms": 3}),
    # Remaining headers
    (b"User-Agent: Mozilla/5.0\r\n", 51, {"ttl": 64, "delay_ms": 2}),
    (b"Accept: text/html\r\n", 78, {"ttl": 64, "delay_ms": 1}),
    (b"Connection: keep-alive\r\n\r\n", 97, {"ttl": 64})
]
```

### TLS Handshake Scenarios
```python
# Example TLS Client Hello segmentation
tls_client_hello = (
    b"\x16\x03\x01\x00\xc4"  # TLS Record Header
    b"\x01\x00\x00\xc0"      # Handshake Header
    b"\x03\x03"              # TLS Version
    b"\x00" * 32             # Random
    b"\x00"                  # Session ID Length
    b"\x00\x02\x13\x01"      # Cipher Suites
    b"\x01\x00"              # Compression Methods
    b"\x00\x95"              # Extensions Length
    # SNI Extension
    b"\x00\x00\x00\x17\x00\x15\x00\x00\x12blocked-site.com"
)

segments = [
    # Fake TLS record with different SNI
    (b"\x16\x03\x01\x00\x20" + b"\x00" * 32, 0, {"ttl": 1, "delay_ms": 25}),
    # Real TLS record header
    (b"\x16\x03\x01\x00\xc4", 0, {"ttl": 64, "delay_ms": 10}),
    # Handshake header and version
    (b"\x01\x00\x00\xc0\x03\x03", 5, {"ttl": 64, "delay_ms": 8}),
    # Random and session ID
    (b"\x00" * 33, 11, {"ttl": 64, "delay_ms": 5}),
    # Cipher suites with corrupted checksum
    (b"\x00\x02\x13\x01\x01\x00", 44, {"ttl": 64, "bad_checksum": True, "delay_ms": 3}),
    # Extensions and SNI
    (tls_client_hello[50:], 50, {"ttl": 64, "delay_ms": 2})
]
```

## Troubleshooting Integration Tests

### Common Issues

#### 1. PyDivert Mock Failures
```python
# Ensure proper mock setup
with patch('core.bypass.engines.native_pydivert_engine.pydivert') as mock:
    mock_handle = Mock()
    mock_handle.send = Mock()
    mock.WinDivert.return_value = mock_handle
```

#### 2. Timing Test Failures
- Timing tests may fail on heavily loaded systems
- Adjust timing thresholds for CI/CD environments
- Use relative timing measurements when possible

#### 3. Memory Test Failures
- Run garbage collection before memory measurements
- Account for Python interpreter overhead
- Use relative memory measurements

#### 4. Concurrent Test Failures
- Ensure proper thread synchronization
- Use appropriate timeouts for thread operations
- Handle race conditions in test setup

### Performance Tuning

#### For Development Systems
```python
# Relaxed performance requirements for development
SEGMENT_CONSTRUCTION_MIN_PPS = 500  # Instead of 1000
TIMING_ACCURACY_MIN_PERCENT = 80    # Instead of 90
MEMORY_MAX_MB_1000_SEGMENTS = 100   # Instead of 50
```

#### For CI/CD Systems
```python
# Adjusted requirements for CI/CD
CONCURRENT_THROUGHPUT_MIN = 25      # Instead of 50
SCALABILITY_MAX_TIME_RATIO = 8      # Instead of 6
END_TO_END_MAX_TIME = 10           # Instead of 5
```

## Integration with CI/CD

### GitHub Actions Example
```yaml
name: Integration Tests

on: [push, pull_request]

jobs:
  integration-tests:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: '3.9'
    
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install pytest psutil
    
    - name: Run integration tests
      run: python tests/run_integration_tests.py
    
    - name: Upload test results
      uses: actions/upload-artifact@v2
      if: always()
      with:
        name: integration-test-results
        path: test-results/
```

## Production Readiness Checklist

After successful integration test completion, verify:

- [ ] All core integration tests pass
- [ ] All end-to-end scenarios execute successfully
- [ ] Performance benchmarks meet requirements
- [ ] Backward compatibility is maintained
- [ ] Memory usage is within acceptable limits
- [ ] Concurrent execution performs adequately
- [ ] Error handling works correctly
- [ ] Diagnostic system captures all events
- [ ] Timing accuracy meets precision requirements
- [ ] Scalability limits are documented

## Monitoring and Alerting

### Production Monitoring
- Monitor segment construction rate
- Track timing accuracy in production
- Alert on memory usage spikes
- Monitor error rates and types
- Track diagnostic system performance

### Performance Baselines
- Establish baseline performance metrics
- Monitor performance degradation over time
- Set up automated performance regression testing
- Create performance dashboards

## Conclusion

The integration testing suite provides comprehensive validation of the Native Attack Orchestration system. Successful completion of all tests indicates the system is ready for production deployment with confidence in its performance, reliability, and compatibility characteristics.

For questions or issues with the integration tests, refer to the troubleshooting section or contact the development team.