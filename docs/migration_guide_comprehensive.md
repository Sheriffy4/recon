# Comprehensive Migration Guide

This guide provides complete instructions for migrating existing attacks to the new segment-based architecture in the Native Attack Orchestration system.

## Overview

The Native Attack Orchestration system introduces a new segment-based architecture that provides better performance, flexibility, and capabilities compared to the legacy `modified_payload` approach. This guide helps you migrate existing attacks while maintaining backward compatibility.

## Migration Benefits

### Performance Improvements
- **Reduced memory usage**: Segments are processed incrementally
- **Better timing control**: Precise millisecond-level delays
- **Parallel processing**: Multiple segments can be processed concurrently
- **Caching optimizations**: Packet construction caching

### Enhanced Capabilities
- **Timing manipulation**: Variable delays between segments
- **Packet-level control**: TTL, checksum, flags modification
- **Sequence management**: Precise TCP sequence number control
- **Advanced diagnostics**: Detailed execution monitoring

### Better Integration
- **Unified interface**: Consistent API across all attacks
- **Monitoring support**: Built-in statistics and diagnostics
- **Testing framework**: Dry-run mode and validation tools
- **Documentation**: Auto-generated attack documentation

## Migration Process

### Phase 1: Assessment

#### 1.1 Analyze Existing Attacks

Use the migration utility to analyze your attacks:

```python
from core.bypass.attacks.compatibility.migration_utilities import analyze_attack_for_migration

# Analyze your attack class
analysis = analyze_attack_for_migration(YourAttackClass)

print(f"Migration complexity: {analysis['estimated_effort']}")
print(f"Uses modified_payload: {analysis['uses_modified_payload']}")
print(f"Uses timing: {analysis['uses_timing']}")
print("Migration suggestions:")
for suggestion in analysis['migration_suggestions']:
    print(f"  - {suggestion['description']}")
```

#### 1.2 Check Compatibility

Check current compatibility status:

```python
from core.bypass.attacks.compatibility.backward_compatibility_manager import check_attack_compatibility

attack_instance = YourAttackClass()
report = check_attack_compatibility(attack_instance)

print(f"Has segments support: {report.has_segments_support}")
print(f"Has legacy support: {report.has_legacy_support}")
print(f"Migration required: {report.migration_required}")
print(f"Recommended mode: {report.recommended_mode}")
```

### Phase 2: Migration Planning

#### 2.1 Generate Migration Plan

For multiple attacks:

```python
from core.bypass.attacks.compatibility.backward_compatibility_manager import BackwardCompatibilityManager

manager = BackwardCompatibilityManager()
attacks = [Attack1(), Attack2(), Attack3()]

migration_plan = manager.generate_migration_plan(attacks)

print("High Priority Migrations:")
for item in migration_plan['high_priority']:
    print(f"  - {item['name']}: {item['complexity']}")

print("Medium Priority Migrations:")
for item in migration_plan['medium_priority']:
    print(f"  - {item['name']}: {item['complexity']}")
```

#### 2.2 Estimate Effort

Migration effort estimates:

- **Minimal**: Simple payload modifications (1-2 hours)
- **Low**: Basic timing or packet modifications (4-8 hours)
- **Medium**: Complex logic with multiple features (1-2 days)
- **High**: Advanced attacks with state management (3-5 days)

### Phase 3: Implementation

#### 3.1 Generate Migration Template

```python
from core.bypass.attacks.compatibility.migration_utilities import generate_migration_template

template = generate_migration_template(YourAttackClass)

print(f"Migration complexity score: {template.complexity_score}/10")
print("Migration notes:")
for note in template.migration_notes:
    print(f"  - {note}")

# Save migrated code to file
from pathlib import Path
output_path = Path("migrated_attacks/your_attack_migrated.py")
migration_utility.apply_migration_template(template, output_path)
```

#### 3.2 Manual Migration Steps

##### Step 1: Update Class Structure

**Before (Legacy):**
```python
class YourAttack(BaseAttack):
    def execute(self, context: AttackContext) -> AttackResult:
        # Modify payload
        modified = self.transform_payload(context.payload)
        
        return AttackResult(
            status=AttackStatus.SUCCESS,
            modified_payload=modified,
            metadata={"attack_type": "your_attack"}
        )
```

**After (Segments):**
```python
class YourAttack(BaseAttack):
    def execute(self, context: AttackContext) -> AttackResult:
        try:
            # Validate context
            is_valid, error = self.validate_context(context)
            if not is_valid:
                return AttackResult(
                    status=AttackStatus.FAILED,
                    error_message=error,
                    metadata={"attack_type": "your_attack"}
                )
            
            # Generate segments
            segments = self._generate_segments(context)
            
            return AttackResult(
                status=AttackStatus.SUCCESS,
                _segments=segments,
                metadata={
                    "attack_type": "your_attack",
                    "segment_count": len(segments)
                }
            )
            
        except Exception as e:
            return AttackResult(
                status=AttackStatus.FAILED,
                error_message=f"Attack execution failed: {str(e)}",
                metadata={"attack_type": "your_attack"}
            )
```

##### Step 2: Implement Segment Generation

```python
def _generate_segments(self, context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
    """Generate segments based on attack logic."""
    segments = []
    payload = context.payload
    
    # Example: Split payload into chunks with timing
    chunk_size = len(payload) // 3
    for i in range(3):
        start = i * chunk_size
        end = start + chunk_size if i < 2 else len(payload)
        chunk = payload[start:end]
        
        # Transform chunk (your attack logic here)
        transformed_chunk = self.transform_payload_chunk(chunk)
        
        # Create segment with options
        options = {
            "delay_ms": i * 50,  # Increasing delays
            "ttl": 64 - i,       # Decreasing TTL
        }
        
        segments.append((transformed_chunk, start, options))
    
    return segments
```

##### Step 3: Add Required Methods

```python
def validate_context(self, context: AttackContext) -> Tuple[bool, Optional[str]]:
    """Validate attack context."""
    if not context.payload:
        return False, "Empty payload not supported"
    
    if len(context.payload) < 10:
        return False, "Payload too small for effective attack"
    
    # Add your specific validation logic
    return True, None

def estimate_effectiveness(self, context: AttackContext) -> float:
    """Estimate attack effectiveness."""
    # Implement based on your attack characteristics
    base_effectiveness = 0.7
    
    # Adjust based on payload size
    if len(context.payload) > 1000:
        base_effectiveness += 0.1
    
    # Adjust based on target port
    if context.dst_port in [80, 443]:
        base_effectiveness += 0.1
    
    return min(1.0, base_effectiveness)

def get_required_capabilities(self) -> List[str]:
    """Get required capabilities."""
    return ["packet_construction", "timing_control"]

def get_attack_info(self) -> Dict[str, Any]:
    """Get attack information."""
    return {
        "name": self.name,
        "type": "migrated",
        "description": "Migrated attack using segment-based architecture",
        "technique": "Your attack technique description",
        "effectiveness": "medium",
        "config": {},
        "advantages": [
            "Migrated to segment-based architecture",
            "Better performance and timing control",
            "Enhanced packet-level manipulation"
        ]
    }
```

### Phase 4: Testing and Validation

#### 4.1 Validate Migration

```python
from core.bypass.attacks.compatibility.migration_utilities import AttackMigrationUtility

migration_utility = AttackMigrationUtility()

# Create test contexts
test_contexts = [
    AttackContext(
        dst_ip="192.168.1.1",
        dst_port=80,
        payload=b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n",
        connection_id="test1"
    ),
    AttackContext(
        dst_ip="10.0.0.1",
        dst_port=443,
        payload=b"POST /api/data HTTP/1.1\r\nHost: api.example.com\r\n\r\n{\"data\":\"test\"}",
        connection_id="test2"
    )
]

# Validate migrated attack
validation_results = migration_utility.validate_migrated_attack(YourMigratedAttack, test_contexts)

print(f"Validation passed: {validation_results['validation_passed']}")
print(f"Success rate: {validation_results['test_results']}")

if validation_results['issues']:
    print("Issues found:")
    for issue in validation_results['issues']:
        print(f"  - {issue}")

if validation_results['recommendations']:
    print("Recommendations:")
    for rec in validation_results['recommendations']:
        print(f"  - {rec}")
```

#### 4.2 Performance Testing

```python
import time

def test_performance(attack, context, iterations=100):
    """Test attack performance."""
    times = []
    
    for _ in range(iterations):
        start_time = time.time()
        result = attack.execute(context)
        execution_time = time.time() - start_time
        times.append(execution_time)
        
        assert result.status == AttackStatus.SUCCESS
    
    avg_time = sum(times) / len(times)
    max_time = max(times)
    min_time = min(times)
    
    print(f"Average execution time: {avg_time*1000:.2f}ms")
    print(f"Min/Max execution time: {min_time*1000:.2f}ms / {max_time*1000:.2f}ms")
    
    return avg_time

# Test your migrated attack
migrated_attack = YourMigratedAttack()
test_context = AttackContext(...)

avg_time = test_performance(migrated_attack, test_context)
assert avg_time < 0.1, "Attack too slow"
```

#### 4.3 Regression Testing

```python
def test_backward_compatibility():
    """Test that migration maintains functionality."""
    original_attack = YourOriginalAttack()
    migrated_attack = YourMigratedAttack()
    
    test_context = AttackContext(...)
    
    # Execute both attacks
    original_result = original_attack.execute(test_context)
    migrated_result = migrated_attack.execute(test_context)
    
    # Both should succeed
    assert original_result.status == AttackStatus.SUCCESS
    assert migrated_result.status == AttackStatus.SUCCESS
    
    # Compare effectiveness
    original_effectiveness = original_attack.estimate_effectiveness(test_context)
    migrated_effectiveness = migrated_attack.estimate_effectiveness(test_context)
    
    # Migrated should be at least as effective
    assert migrated_effectiveness >= original_effectiveness
```

## Migration Patterns

### Pattern 1: Simple Payload Modification

**Legacy Pattern:**
```python
def execute(self, context):
    modified = context.payload.replace(b'GET', b'POST')
    return AttackResult(status=AttackStatus.SUCCESS, modified_payload=modified)
```

**Migrated Pattern:**
```python
def _generate_segments(self, context):
    modified = context.payload.replace(b'GET', b'POST')
    return [(modified, 0, {})]
```

### Pattern 2: Payload Splitting

**Legacy Pattern:**
```python
def execute(self, context):
    part1 = context.payload[:len(context.payload)//2]
    part2 = context.payload[len(context.payload)//2:]
    modified = part2 + part1  # Reorder
    return AttackResult(status=AttackStatus.SUCCESS, modified_payload=modified)
```

**Migrated Pattern:**
```python
def _generate_segments(self, context):
    mid = len(context.payload) // 2
    part1 = context.payload[:mid]
    part2 = context.payload[mid:]
    
    # Send in reverse order with timing
    return [
        (part2, mid, {"delay_ms": 0}),
        (part1, 0, {"delay_ms": 50})
    ]
```

### Pattern 3: Timing-Based Attacks

**Legacy Pattern:**
```python
def execute(self, context):
    time.sleep(0.1)  # Delay
    modified = self.transform(context.payload)
    return AttackResult(status=AttackStatus.SUCCESS, modified_payload=modified)
```

**Migrated Pattern:**
```python
def _generate_segments(self, context):
    chunks = self.split_payload(context.payload, 3)
    segments = []
    
    for i, chunk in enumerate(chunks):
        delay = i * 100  # 100ms increments
        segments.append((chunk, i * len(chunk), {"delay_ms": delay}))
    
    return segments
```

### Pattern 4: Packet Manipulation

**Legacy Pattern:**
```python
def execute(self, context):
    # Custom packet building (complex)
    packet = self.build_custom_packet(context.payload, ttl=32)
    return AttackResult(status=AttackStatus.SUCCESS, modified_payload=packet)
```

**Migrated Pattern:**
```python
def _generate_segments(self, context):
    segments = []
    chunks = self.split_payload(context.payload, 2)
    
    for i, chunk in enumerate(chunks):
        options = {
            "ttl": 32 + i,
            "flags": 0x18,  # PSH+ACK
            "delay_ms": i * 25
        }
        segments.append((chunk, i * len(chunk), options))
    
    return segments
```

## Common Migration Issues

### Issue 1: Missing Segments

**Problem:** Attack returns success but no segments generated.

**Solution:**
```python
def _generate_segments(self, context):
    segments = []
    # ... your logic ...
    
    # Ensure at least one segment
    if not segments:
        segments = [(context.payload, 0, {})]
    
    return segments
```

### Issue 2: Invalid Segment Format

**Problem:** Segments not in correct tuple format.

**Solution:**
```python
# Correct format: (payload_bytes, sequence_offset, options_dict)
segments = [
    (b"payload_data", 0, {"delay_ms": 10}),  # Correct
    # (payload_data, 0),  # Wrong - missing options
    # [payload_data, 0, {}],  # Wrong - should be tuple
]
```

### Issue 3: Performance Regression

**Problem:** Migrated attack is slower than original.

**Solutions:**
- Reduce number of segments
- Optimize payload processing
- Use caching for repeated operations
- Profile and identify bottlenecks

```python
def _generate_segments(self, context):
    # Cache expensive operations
    if not hasattr(self, '_cached_transform'):
        self._cached_transform = self._prepare_transform()
    
    # Minimize segments for performance
    return [(self._cached_transform(context.payload), 0, {})]
```

### Issue 4: Context Validation Failures

**Problem:** Attack fails validation with new context requirements.

**Solution:**
```python
def validate_context(self, context):
    # Be more permissive during migration
    if not context.payload:
        return False, "Empty payload not supported"
    
    # Allow smaller payloads during testing
    if len(context.payload) < 5:
        return False, "Payload too small"
    
    return True, None
```

## Testing Strategies

### Unit Testing

```python
import pytest
from core.bypass.attacks.base import AttackContext, AttackStatus

class TestYourMigratedAttack:
    @pytest.fixture
    def attack(self):
        return YourMigratedAttack()
    
    @pytest.fixture
    def context(self):
        return AttackContext(
            dst_ip="192.168.1.1",
            dst_port=80,
            payload=b"GET /test HTTP/1.1\r\n\r\n",
            connection_id="test"
        )
    
    def test_basic_execution(self, attack, context):
        result = attack.execute(context)
        assert result.status == AttackStatus.SUCCESS
        assert hasattr(result, '_segments')
        assert len(result._segments) > 0
    
    def test_segment_format(self, attack, context):
        result = attack.execute(context)
        for payload, offset, options in result._segments:
            assert isinstance(payload, bytes)
            assert isinstance(offset, int)
            assert isinstance(options, dict)
            assert offset >= 0
    
    def test_effectiveness_estimation(self, attack, context):
        effectiveness = attack.estimate_effectiveness(context)
        assert 0.0 <= effectiveness <= 1.0
    
    def test_required_capabilities(self, attack):
        capabilities = attack.get_required_capabilities()
        assert isinstance(capabilities, list)
        assert len(capabilities) > 0
```

### Integration Testing

```python
def test_with_compatibility_manager():
    """Test migrated attack with compatibility manager."""
    from core.bypass.attacks.compatibility.backward_compatibility_manager import ensure_backward_compatibility
    
    attack = YourMigratedAttack()
    context = AttackContext(...)
    
    result = ensure_backward_compatibility(attack, context)
    assert result.status == AttackStatus.SUCCESS
```

### Performance Testing

```python
def test_performance_requirements():
    """Test that migrated attack meets performance requirements."""
    attack = YourMigratedAttack()
    context = AttackContext(...)
    
    import time
    start_time = time.time()
    result = attack.execute(context)
    execution_time = time.time() - start_time
    
    assert result.status == AttackStatus.SUCCESS
    assert execution_time < 0.1  # 100ms limit
```

## Best Practices

### 1. Gradual Migration

- Start with simple attacks
- Test thoroughly before moving to complex attacks
- Keep original attacks as reference during migration
- Use compatibility manager during transition period

### 2. Maintain Backward Compatibility

- Don't remove original attacks immediately
- Use hybrid approach during transition
- Provide fallback mechanisms
- Document migration timeline

### 3. Performance Optimization

- Profile before and after migration
- Optimize segment count for performance
- Use caching for expensive operations
- Monitor memory usage

### 4. Testing Strategy

- Create comprehensive test suites
- Test with various payload sizes and types
- Validate against original attack behavior
- Include performance benchmarks

### 5. Documentation

- Document migration decisions
- Update attack documentation
- Provide usage examples
- Create troubleshooting guides

## Troubleshooting

### Common Errors

#### "No segments generated"
```python
# Check _generate_segments method
def _generate_segments(self, context):
    segments = []
    # ... your logic ...
    
    if not segments:
        # Always return at least one segment
        segments = [(context.payload, 0, {})]
    
    return segments
```

#### "Invalid segment format"
```python
# Ensure correct tuple format
segments = [
    (payload_bytes, sequence_offset, options_dict)
]
```

#### "Context validation failed"
```python
def validate_context(self, context):
    # Check all required fields
    if not hasattr(context, 'payload') or not context.payload:
        return False, "Missing or empty payload"
    
    return True, None
```

### Debug Tools

#### Enable Debug Logging
```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Your attack execution will now show debug information
```

#### Use Dry Run Mode
```python
# Test attack without network transmission
result = attack.execute(context)  # Will show execution plan in logs
```

#### Compatibility Analysis
```python
from core.bypass.attacks.compatibility.backward_compatibility_manager import check_attack_compatibility

report = check_attack_compatibility(your_attack)
print(f"Issues: {report.issues}")
print(f"Recommendations: {report.recommendations}")
```

## Migration Checklist

### Pre-Migration
- [ ] Analyze attack with migration utility
- [ ] Check compatibility status
- [ ] Estimate migration effort
- [ ] Plan testing strategy
- [ ] Backup original implementation

### During Migration
- [ ] Update class structure
- [ ] Implement segment generation
- [ ] Add required methods
- [ ] Update error handling
- [ ] Add configuration options

### Post-Migration
- [ ] Run unit tests
- [ ] Validate with compatibility manager
- [ ] Performance testing
- [ ] Integration testing
- [ ] Update documentation

### Production Deployment
- [ ] Deploy with compatibility manager
- [ ] Monitor performance metrics
- [ ] Collect effectiveness data
- [ ] Plan original attack deprecation
- [ ] Update user documentation

## Conclusion

Migrating to the segment-based architecture provides significant benefits in terms of performance, flexibility, and capabilities. By following this comprehensive guide and using the provided tools, you can successfully migrate your existing attacks while maintaining backward compatibility and ensuring robust operation.

The migration process may seem complex, but the tools and utilities provided make it manageable. Start with simple attacks, test thoroughly, and gradually work through your attack portfolio. The investment in migration will pay off with better performance, enhanced capabilities, and future-proof architecture.

For additional support, refer to the API documentation, example implementations, and the troubleshooting section. The compatibility manager ensures that your existing attacks continue to work during the migration process, allowing for a smooth transition.