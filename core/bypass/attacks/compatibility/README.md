# Backward Compatibility System

This directory contains the complete backward compatibility and migration system for the Native Attack Orchestration project. The system ensures that existing attacks continue to work while providing tools and utilities for migrating to the new segment-based architecture.

## Overview

The backward compatibility system provides:

- **Seamless compatibility**: Existing attacks work without modification
- **Migration utilities**: Tools for analyzing and migrating attacks
- **Validation framework**: Comprehensive testing for migrated attacks
- **Performance monitoring**: Statistics and metrics for compatibility overhead
- **Documentation and examples**: Complete migration guides and examples

## Components

### Core Components

1. **[BackwardCompatibilityManager](backward_compatibility_manager.py)**
   - Main compatibility orchestration
   - Fallback execution mechanisms
   - Statistics collection and monitoring
   - Migration plan generation

2. **[AttackMigrationUtility](migration_utilities.py)**
   - Code analysis for migration planning
   - Automated migration template generation
   - Migration validation and testing
   - Code transformation utilities

### Tools and Utilities

3. **[Migration Validation Tool](../../tools/migration_validation_tool.py)**
   - Automated migration validation
   - Performance benchmarking
   - Comprehensive reporting
   - CLI interface for validation

### Documentation

4. **[Comprehensive Migration Guide](../../docs/migration_guide_comprehensive.md)**
   - Complete migration instructions
   - Best practices and patterns
   - Troubleshooting guide
   - Performance optimization tips

5. **[Migration Examples](../../examples/migration_examples_before_after.py)**
   - Before/after migration examples
   - Real-world migration scenarios
   - Performance comparisons
   - Common patterns demonstration

### Testing

6. **[Comprehensive Tests](../../tests/test_backward_compatibility_comprehensive.py)**
   - Unit tests for all components
   - Integration testing scenarios
   - Performance validation
   - Error handling verification

7. **[System Final Tests](../../tests/test_backward_compatibility_system_final.py)**
   - End-to-end system validation
   - Complete workflow testing
   - Concurrent execution testing
   - Statistics and monitoring validation

## Quick Start

### Check Attack Compatibility

```python
from core.bypass.attacks.compatibility.backward_compatibility_manager import check_attack_compatibility

# Check if your attack is compatible
attack = YourAttackClass()
report = check_attack_compatibility(attack)

print(f"Segments support: {report.has_segments_support}")
print(f"Legacy support: {report.has_legacy_support}")
print(f"Migration required: {report.migration_required}")
```

### Execute with Compatibility

```python
from core.bypass.attacks.compatibility.backward_compatibility_manager import ensure_backward_compatibility
from core.bypass.attacks.base import AttackContext

# Execute any attack with automatic compatibility handling
context = AttackContext(
    dst_ip="192.168.1.1",
    dst_port=80,
    payload=b"GET /test HTTP/1.1\r\n\r\n",
    connection_id="test"
)

result = ensure_backward_compatibility(your_attack, context)
print(f"Status: {result.status}")
print(f"Segments: {len(result._segments)}")
```

### Analyze for Migration

```python
from core.bypass.attacks.compatibility.migration_utilities import analyze_attack_for_migration

# Analyze your attack for migration requirements
analysis = analyze_attack_for_migration(YourAttackClass)

print(f"Migration complexity: {analysis['estimated_effort']}")
print(f"Uses modified_payload: {analysis['uses_modified_payload']}")
print("Suggestions:")
for suggestion in analysis['migration_suggestions']:
    print(f"  - {suggestion['description']}")
```

### Generate Migration Template

```python
from core.bypass.attacks.compatibility.migration_utilities import generate_migration_template

# Generate migration template
template = generate_migration_template(YourAttackClass)

print(f"Complexity score: {template.complexity_score}/10")
print("Migration notes:")
for note in template.migration_notes:
    print(f"  - {note}")

# Save migrated code
with open("migrated_attack.py", "w") as f:
    f.write(template.migrated_code)
```

## Migration Workflow

### 1. Assessment Phase

```python
from core.bypass.attacks.compatibility.backward_compatibility_manager import BackwardCompatibilityManager

manager = BackwardCompatibilityManager()

# Analyze multiple attacks
attacks = [Attack1(), Attack2(), Attack3()]
migration_plan = manager.generate_migration_plan(attacks)

print("High Priority:")
for item in migration_plan['high_priority']:
    print(f"  - {item['name']}: {item['complexity']}")
```

### 2. Migration Phase

```python
from core.bypass.attacks.compatibility.migration_utilities import AttackMigrationUtility
from pathlib import Path

utility = AttackMigrationUtility()

# Generate and apply migration template
template = utility.generate_migration_template(YourAttackClass)
output_path = Path("migrated_attacks/your_attack_migrated.py")
utility.apply_migration_template(template, output_path)
```

### 3. Validation Phase

```python
from tools.migration_validation_tool import MigrationValidationTool

# Validate migrated attack
validation_tool = MigrationValidationTool()
result = validation_tool.validate_single_attack(YourMigratedAttack, YourOriginalAttack)

print(f"Validation passed: {result.validation_passed}")
print(f"Compatibility score: {result.compatibility_score:.2f}")
print(f"Performance score: {result.performance_score:.2f}")
```

## Compatibility Modes

The system supports multiple compatibility modes:

### AUTO_DETECT (Default)
Automatically detects the best execution mode for each attack.

```python
# Automatic mode selection
result = manager.execute_with_fallback(attack, context)
```

### SEGMENTS_ONLY
Forces segment-based execution only.

```python
from core.bypass.attacks.compatibility.backward_compatibility_manager import CompatibilityMode

result = manager.execute_with_fallback(attack, context, CompatibilityMode.SEGMENTS_ONLY)
```

### LEGACY_ONLY
Forces legacy execution with conversion to segments.

```python
result = manager.execute_with_fallback(attack, context, CompatibilityMode.LEGACY_ONLY)
```

### HYBRID
Tries segments first, falls back to legacy if needed.

```python
result = manager.execute_with_fallback(attack, context, CompatibilityMode.HYBRID)
```

## Migration Patterns

### Simple Payload Modification

**Before:**
```python
def execute(self, context):
    modified = context.payload.replace(b'GET', b'POST')
    return AttackResult(status=AttackStatus.SUCCESS, modified_payload=modified)
```

**After:**
```python
def _generate_segments(self, context):
    modified = context.payload.replace(b'GET', b'POST')
    return [(modified, 0, {})]
```

### Timing-Based Attacks

**Before:**
```python
def execute(self, context):
    time.sleep(0.1)
    modified = self.transform(context.payload)
    return AttackResult(status=AttackStatus.SUCCESS, modified_payload=modified)
```

**After:**
```python
def _generate_segments(self, context):
    chunks = self.split_payload(context.payload, 3)
    segments = []
    for i, chunk in enumerate(chunks):
        segments.append((chunk, i * len(chunk), {"delay_ms": i * 100}))
    return segments
```

### Packet Manipulation

**Before:**
```python
def execute(self, context):
    packet = self.build_custom_packet(context.payload, ttl=32)
    return AttackResult(status=AttackStatus.SUCCESS, modified_payload=packet)
```

**After:**
```python
def _generate_segments(self, context):
    chunks = self.split_payload(context.payload, 2)
    segments = []
    for i, chunk in enumerate(chunks):
        options = {"ttl": 32 + i, "flags": 0x18}
        segments.append((chunk, i * len(chunk), options))
    return segments
```

## Performance Monitoring

### Compatibility Statistics

```python
# Get system-wide compatibility statistics
stats = manager.get_compatibility_stats()

print(f"Total attacks analyzed: {stats['total_attacks_analyzed']}")
print(f"Segments supported: {stats['segments_supported']}")
print(f"Legacy supported: {stats['legacy_supported']}")
print(f"Compatibility percentage: {stats['compatibility_percentage']:.1f}%")
```

### Fallback Statistics

```python
# Get fallback usage statistics
fallback_stats = stats['fallback_stats']

for attack_name, attack_stats in fallback_stats.items():
    print(f"{attack_name}:")
    print(f"  Segments attempts: {attack_stats['segments_attempts']}")
    print(f"  Legacy attempts: {attack_stats['legacy_attempts']}")
    print(f"  Fallback used: {attack_stats['fallback_used']}")
```

## Validation and Testing

### Automated Validation

```python
# Validate migration with comprehensive testing
test_contexts = [
    AttackContext(dst_ip="1.2.3.4", dst_port=80, payload=b"test1", connection_id="test1"),
    AttackContext(dst_ip="1.2.3.5", dst_port=443, payload=b"test2", connection_id="test2")
]

validation_results = utility.validate_migrated_attack(YourMigratedAttack, test_contexts)

print(f"Success rate: {validation_results['success_rate']:.1f}%")
if validation_results['errors']:
    print("Errors:")
    for error in validation_results['errors']:
        print(f"  - {error}")
```

### Performance Benchmarking

```python
import time

def benchmark_attack(attack, context, iterations=100):
    times = []
    for _ in range(iterations):
        start = time.time()
        result = attack.execute(context)
        times.append(time.time() - start)
    
    return {
        'avg_time': sum(times) / len(times),
        'min_time': min(times),
        'max_time': max(times)
    }

# Compare legacy vs migrated performance
legacy_perf = benchmark_attack(legacy_attack, context)
migrated_perf = benchmark_attack(migrated_attack, context)

print(f"Legacy avg: {legacy_perf['avg_time']*1000:.2f}ms")
print(f"Migrated avg: {migrated_perf['avg_time']*1000:.2f}ms")
```

## CLI Tools

### Migration Validation Tool

```bash
# Validate a single migrated attack
python tools/migration_validation_tool.py \
    --attack-file migrated_attack.py \
    --attack-class MigratedAttack \
    --reference-file legacy_attack.py \
    --reference-class LegacyAttack \
    --verbose

# Output will show validation results and generate report
```

## Error Handling

### Common Issues and Solutions

#### "No segments generated"
```python
def _generate_segments(self, context):
    segments = []
    # ... your logic ...
    
    # Always ensure at least one segment
    if not segments:
        segments = [(context.payload, 0, {})]
    
    return segments
```

#### "Invalid segment format"
```python
# Correct format: (payload_bytes, sequence_offset, options_dict)
segments = [
    (b"payload_data", 0, {"delay_ms": 10}),  # Correct
    # Not: [payload_data, 0, {}]  # Wrong type
    # Not: (payload_data, 0)      # Missing options
]
```

#### "Context validation failed"
```python
def validate_context(self, context):
    if not context.payload:
        return False, "Empty payload not supported"
    
    if len(context.payload) < 5:
        return False, "Payload too small"
    
    return True, None
```

### Debug Mode

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Enable debug logging for detailed information
result = manager.execute_with_fallback(attack, context)
```

## Best Practices

### Migration Strategy

1. **Start Simple**: Begin with simple payload modification attacks
2. **Test Thoroughly**: Use comprehensive test suites for validation
3. **Monitor Performance**: Track execution times and resource usage
4. **Gradual Rollout**: Deploy migrated attacks incrementally
5. **Keep Fallbacks**: Maintain legacy support during transition

### Code Quality

1. **Follow Patterns**: Use established migration patterns
2. **Add Tests**: Include unit and integration tests
3. **Document Changes**: Update documentation and comments
4. **Validate Interface**: Ensure all required methods are implemented
5. **Handle Errors**: Include comprehensive error handling

### Performance Optimization

1. **Minimize Segments**: Use optimal segment count for performance
2. **Cache Operations**: Cache expensive computations
3. **Profile Code**: Identify and optimize bottlenecks
4. **Monitor Memory**: Track memory usage and optimize allocation
5. **Benchmark Regularly**: Compare performance with legacy versions

## Contributing

### Adding New Migration Patterns

1. Update migration patterns in `migration_utilities.py`
2. Add pattern detection logic
3. Include code transformation rules
4. Add tests for the new pattern
5. Update documentation with examples

### Extending Compatibility Features

1. Add new compatibility modes if needed
2. Extend statistics collection
3. Add new validation checks
4. Update reporting functionality
5. Include comprehensive tests

### Improving Performance

1. Profile compatibility overhead
2. Optimize hot paths in execution
3. Add caching where appropriate
4. Minimize memory allocation
5. Benchmark improvements

## Troubleshooting

### Performance Issues

- Check segment count (reduce if too many)
- Profile execution to find bottlenecks
- Verify caching is working properly
- Monitor memory usage patterns

### Compatibility Issues

- Verify attack implements required interface
- Check segment format is correct
- Ensure context validation is proper
- Test with various payload types

### Migration Issues

- Review migration template carefully
- Test with comprehensive contexts
- Validate against original behavior
- Check error handling is complete

## Future Enhancements

### Planned Features

1. **Automated Migration**: Fully automated code migration
2. **ML-Based Analysis**: Machine learning for migration complexity assessment
3. **Real-time Monitoring**: Live performance and compatibility monitoring
4. **Advanced Validation**: More sophisticated validation algorithms
5. **IDE Integration**: Direct integration with development environments

### Extension Points

1. **Custom Patterns**: Framework for adding custom migration patterns
2. **Validation Rules**: Extensible validation rule system
3. **Reporting Formats**: Multiple output formats for reports
4. **Integration APIs**: APIs for external tool integration
5. **Plugin System**: Plugin architecture for extensions

## License

This backward compatibility system is part of the Native Attack Orchestration project and follows the same licensing terms as the main project.