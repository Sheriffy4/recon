# Dry Run Testing Mode

This document describes the dry run testing mode in the Native Attack Orchestration system, which allows testing segment-based attacks without actual network transmission.

## Overview

The dry run testing mode provides a safe way to:

- **Test Attack Logic**: Validate attack implementations without network impact
- **Segment Validation**: Verify segment generation and formatting
- **Performance Analysis**: Measure attack execution performance
- **Development Testing**: Test new attacks during development
- **Integration Testing**: Validate attack integration with the system

## Key Features

- **Network-Safe Execution**: No actual packets are transmitted
- **Complete Simulation**: Full attack execution simulation
- **Validation Testing**: Comprehensive segment and payload validation
- **Performance Metrics**: Detailed timing and performance analysis
- **Error Detection**: Early detection of implementation issues

## Usage

### Basic Dry Run Execution

```python
from core.integration.attack_adapter import AttackAdapter
from core.bypass.attacks.base import AttackContext

# Create attack adapter
adapter = AttackAdapter()

# Create attack context
context = AttackContext(
    dst_ip="1.2.3.4",
    dst_port=443,
    payload=b"test_payload",
    protocol="tcp"
)

# Execute attack in dry run mode
result = await adapter.execute_attack_by_name(
    "fake_disorder_attack", context, dry_run=True
)

# Analyze results
if result.metadata["dry_run"]:
    print(f"Simulation completed in {result.metadata['simulation_time_ms']:.3f}ms")
    print(f"Segments generated: {result.metadata.get('segments_count', 0)}")
```

### Segment-Based Attack Testing

```python
# Test segment-based attack
result = await adapter.execute_attack_by_name(
    "multisplit_attack", context, dry_run=True
)

# Analyze segment validation
if "segment_analysis" in result.metadata:
    analysis = result.metadata["segment_analysis"]
    print(f"Total segments: {analysis['total_segments']}")
    print(f"TTL modifications: {analysis['ttl_modifications']}")
    print(f"Checksum corruptions: {analysis['checksum_corruptions']}")
    print(f"Timing delays: {analysis['timing_delays']}")

# Check validation results
if result.metadata.get("segments_valid"):
    print("✓ All segments passed validation")
else:
    print("✗ Validation errors found:")
    for error in result.metadata.get("validation_errors", []):
        print(f"  - {error}")
```

### Payload Modification Testing

```python
# Test payload modification attack
result = await adapter.execute_attack_by_name(
    "header_manipulation_attack", context, dry_run=True
)

# Analyze payload changes
if result.metadata.get("payload_modified"):
    original_size = result.metadata["original_payload_size"]
    modified_size = result.metadata["modified_payload_size"]
    print(f"Payload modified: {original_size} → {modified_size} bytes")
    
    if result.modified_payload:
        print(f"Modified payload preview: {result.modified_payload[:100]}...")
```

## Dry Run Result Structure

### Metadata Fields

Dry run results include comprehensive metadata:

```python
{
    "dry_run": True,
    "simulation_mode": True,
    "attack_name": "fake_disorder_attack",
    "simulation_time_ms": 15.234,
    "dry_run_timestamp": 1640995200.0,
    
    # Context summary
    "context_summary": {
        "dst_ip": "1.2.3.4",
        "dst_port": 443,
        "protocol": "tcp",
        "payload_size": 150,
        "domain": "example.com",
        "has_tcp_session": True
    },
    
    # Segment analysis (if applicable)
    "segments_count": 3,
    "segment_analysis": {
        "total_segments": 3,
        "total_payload_size": 150,
        "ttl_modifications": 1,
        "checksum_corruptions": 1,
        "timing_delays": 2
    },
    
    # Validation results
    "segments_valid": True,
    "validation_errors": [],
    
    # Payload analysis (if applicable)
    "payload_modified": True,
    "original_payload_size": 150,
    "modified_payload_size": 200
}
```

### Status Codes

Dry run results use standard AttackStatus codes:

- `SUCCESS`: Simulation completed successfully
- `FAILED`: Simulation encountered errors
- `TIMEOUT`: Simulation timed out (rare)

## Validation Testing

### Segment Validation

The dry run mode performs comprehensive segment validation:

```python
# Validation checks performed:
# 1. Segment format validation
# 2. Payload data type checking
# 3. Sequence offset validation
# 4. Options dictionary validation
# 5. TCP session compatibility

result = await adapter.execute_attack_by_name(
    "segment_attack", context, dry_run=True
)

# Check validation results
validation_errors = result.metadata.get("validation_errors", [])
if validation_errors:
    print("Validation issues found:")
    for error in validation_errors:
        print(f"  - {error}")
```

### Context Validation

Attack context is validated before simulation:

```python
# Context validation includes:
# - IP address format
# - Port range validation
# - Protocol compatibility
# - Payload size limits
# - Required parameter checking

try:
    result = await adapter.execute_attack_by_name(
        "attack_name", invalid_context, dry_run=True
    )
except AttackExecutionError as e:
    print(f"Context validation failed: {e}")
```

## Performance Analysis

### Timing Measurement

Dry run mode provides detailed timing analysis:

```python
# Execute multiple dry runs for performance analysis
results = []
for i in range(10):
    result = await adapter.execute_attack_by_name(
        "attack_name", context, dry_run=True
    )
    results.append(result.metadata["simulation_time_ms"])

# Analyze performance
avg_time = sum(results) / len(results)
min_time = min(results)
max_time = max(results)

print(f"Average simulation time: {avg_time:.3f}ms")
print(f"Performance range: {min_time:.3f}ms - {max_time:.3f}ms")
```

### Statistics Collection

The adapter collects comprehensive dry run statistics:

```python
# Get dry run statistics
stats = adapter.get_dry_run_stats()

print(f"Total dry runs: {stats['total_dry_runs']}")
print(f"Segments simulated: {stats['segments_simulated']}")
print(f"Average simulation time: {stats['average_simulation_time_ms']:.3f}ms")
print(f"Average segments per run: {stats['average_segments_per_run']:.1f}")
print(f"Validation error rate: {stats['validation_error_rate']:.2%}")
```

## Development Workflow

### Attack Development

Use dry run mode during attack development:

```python
class NewAttack(BaseAttack):
    def execute(self, context: AttackContext) -> AttackResult:
        # Check if running in dry run mode
        is_dry_run = context.params.get("dry_run", False)
        
        if is_dry_run:
            # Add dry run specific logging
            self.logger.info("Running in dry run mode")
        
        # Implement attack logic
        segments = self.generate_segments(context)
        
        result = AttackResult(
            status=AttackStatus.SUCCESS,
            technique_used=self.name
        )
        result._segments = segments
        
        return result

# Test during development
result = await adapter.execute_attack_by_name(
    "new_attack", context, dry_run=True
)

# Validate implementation
assert result.status == AttackStatus.SUCCESS
assert result.metadata["segments_valid"] == True
```

### Unit Testing

Integrate dry run mode with unit tests:

```python
import pytest

class TestAttackImplementation:
    @pytest.mark.asyncio
    async def test_attack_dry_run(self):
        """Test attack in dry run mode."""
        adapter = AttackAdapter()
        context = create_test_context()
        
        result = await adapter.execute_attack_by_name(
            "test_attack", context, dry_run=True
        )
        
        # Validate dry run results
        assert result.metadata["dry_run"] == True
        assert result.status == AttackStatus.SUCCESS
        assert result.metadata["segments_valid"] == True
        
        # Check segment analysis
        analysis = result.metadata["segment_analysis"]
        assert analysis["total_segments"] > 0
        assert analysis["total_payload_size"] > 0
```

## Comparison Testing

### Dry Run vs Real Execution

Compare dry run and real execution results:

```python
# Execute in dry run mode
dry_result = await adapter.execute_attack_by_name(
    "attack_name", context, dry_run=True
)

# Execute in real mode
real_result = await adapter.execute_attack_by_name(
    "attack_name", context, dry_run=False
)

# Compare results
print("Comparison Results:")
print(f"Both successful: {dry_result.status == real_result.status}")
print(f"Same technique: {dry_result.technique_used == real_result.technique_used}")

# Compare segments
dry_segments = len(dry_result._segments) if hasattr(dry_result, '_segments') else 0
real_segments = len(real_result._segments) if hasattr(real_result, '_segments') else 0
print(f"Segments match: {dry_segments == real_segments}")
```

### Validation Consistency

Ensure validation consistency between modes:

```python
# Test with various contexts
test_contexts = [
    create_valid_context(),
    create_invalid_context(),
    create_edge_case_context()
]

for context in test_contexts:
    dry_result = await adapter.execute_attack_by_name(
        "attack_name", context, dry_run=True
    )
    
    # Dry run should catch validation issues
    if not dry_result.metadata.get("segments_valid"):
        print(f"Validation issues detected in dry run: {context}")
```

## Error Handling

### Simulation Errors

Dry run mode handles various error scenarios:

```python
# Simulation error handling
result = await adapter.execute_attack_by_name(
    "problematic_attack", context, dry_run=True
)

if result.status == AttackStatus.FAILED:
    if "simulation_error" in result.metadata:
        print(f"Simulation error: {result.metadata['simulation_error']}")
    else:
        print(f"Attack error: {result.error_message}")
```

### Validation Errors

Handle validation errors gracefully:

```python
# Check for validation errors
if not result.metadata.get("segments_valid", True):
    errors = result.metadata.get("validation_errors", [])
    print(f"Found {len(errors)} validation errors:")
    for error in errors:
        print(f"  - {error}")
```

## Best Practices

### Development Testing

1. **Always Test in Dry Run First**: Test new attacks in dry run mode before real execution
2. **Validate Segments**: Ensure all generated segments pass validation
3. **Check Performance**: Monitor simulation times for performance issues
4. **Test Edge Cases**: Use dry run to test various edge cases safely

### Integration Testing

1. **Comprehensive Coverage**: Test all attack types in dry run mode
2. **Validation Testing**: Verify validation logic catches issues
3. **Performance Benchmarking**: Use dry run for performance analysis
4. **Regression Testing**: Include dry run tests in CI/CD pipelines

### Production Validation

1. **Pre-deployment Testing**: Validate attacks in dry run before deployment
2. **Configuration Testing**: Test different configurations safely
3. **Compatibility Testing**: Ensure backward compatibility
4. **Error Scenario Testing**: Test error handling in safe environment

## Configuration

### Adapter Configuration

Configure dry run behavior:

```python
config = IntegrationConfig(
    debug_mode=True,  # Enable detailed logging
    cache_attack_results=False,  # Disable caching for testing
    attack_timeout_seconds=30  # Set reasonable timeout
)

adapter = AttackAdapter(config)
```

### Logging Configuration

Configure logging for dry run analysis:

```python
import logging

# Enable detailed logging for dry run analysis
logging.getLogger("AttackAdapter").setLevel(logging.DEBUG)
logging.getLogger("SegmentDiagnostics").setLevel(logging.INFO)

# Configure format for better analysis
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
```

## Limitations

### Network Simulation

Dry run mode has some limitations:

- **No Network Interaction**: Cannot test actual network behavior
- **No DPI Response**: Cannot test DPI system responses
- **No Timing Validation**: Cannot validate real-world timing requirements
- **No Infrastructure Testing**: Cannot test network infrastructure compatibility

### Simulation Accuracy

- **Simplified Validation**: Some validations may be simplified
- **Performance Differences**: Simulation performance may differ from real execution
- **Context Limitations**: Some context-dependent behaviors may not be simulated

## Future Enhancements

### Planned Features

1. **Network Simulation**: Simulate network conditions and responses
2. **DPI Simulation**: Simulate DPI system behavior
3. **Advanced Validation**: More comprehensive validation rules
4. **Performance Modeling**: Better performance prediction models

### Integration Improvements

1. **IDE Integration**: Better integration with development environments
2. **Automated Testing**: Enhanced automated testing capabilities
3. **Reporting**: Comprehensive dry run reporting
4. **Visualization**: Visual analysis of dry run results

## Conclusion

The dry run testing mode provides a powerful and safe way to test segment-based attacks without network impact. It enables comprehensive validation, performance analysis, and development testing, making it an essential tool for attack development and system validation.

Use dry run mode to:
- Validate attack implementations safely
- Test segment generation and formatting
- Analyze performance characteristics
- Develop and debug attacks efficiently
- Ensure system reliability and correctness