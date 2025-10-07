# Simple Packet Validator

## Overview

The Simple Packet Validator is a lightweight tool for quick validation of DPI bypass attack packets. It focuses on three critical aspects:

1. **Sequence Numbers** - Validates TCP sequence numbers are correct
2. **Checksums** - Verifies TCP checksums are valid or intentionally corrupted
3. **TTL** - Checks Time-To-Live values match expectations

## Features

- ✅ Lightweight and fast validation
- ✅ No external dependencies (uses only Python stdlib)
- ✅ Simple API for quick checks
- ✅ Validates fake, split, fakeddisorder, and other attacks
- ✅ Detailed error reporting
- ✅ Debug mode for troubleshooting

## Quick Start

### Basic Usage

```python
from core.simple_packet_validator import quick_validate

# Validate a PCAP file
result = quick_validate(
    'test.pcap',
    attack_type='fake',
    params={'ttl': 1, 'fooling': ['badsum']}
)

if result['passed']:
    print("✓ Validation passed!")
else:
    print("✗ Validation failed:")
    for error in result['errors']:
        print(f"  - {error}")
```

### Advanced Usage

```python
from core.simple_packet_validator import SimplePacketValidator

# Create validator with debug mode
validator = SimplePacketValidator(debug=True)

# Validate fakeddisorder attack
result = validator.validate_pcap(
    'test_fakeddisorder.pcap',
    attack_type='fakeddisorder',
    params={
        'split_pos': 76,
        'overlap_size': 336,
        'ttl': 3,
        'fooling': ['badsum']
    }
)

# Check results
print(f"Passed: {result['passed']}")
print(f"Packet count: {result['packet_count']}")

# View details
for category, details in result['details'].items():
    print(f"\n{category}:")
    if 'details' in details:
        for detail in details['details']:
            print(f"  {detail}")
```

## Validation Details

### Sequence Number Validation

The validator checks:

- **Fakeddisorder**: Fake packet seq must equal first real packet seq
- **Split**: Second packet seq must be first_seq + first_payload_len
- **All attacks**: Sequence numbers must be consistent and sequential

Example output:
```
✓ Fake packet seq correct: 1000
✓ Packet 1 seq correct: 1050
✗ Packet 2 seq (1200) != expected (1100)
```

### Checksum Validation

The validator checks:

- **With badsum fooling**: Fake packets must have bad checksums, real packets must have good checksums
- **Without badsum**: All packets should have valid checksums
- **Detection**: Identifies WinDivert checksum recalculation issues

Example output:
```
✓ Fake packet 0 has bad checksum as expected
✓ Real packet 0 has good checksum
✗ Real packet 1 should have good checksum but has bad checksum
```

### TTL Validation

The validator checks:

- **Fake attacks**: Fake packets must have specified TTL (usually 1-3)
- **Real packets**: Should have normal TTL (64, 128, or 255)
- **Parameter matching**: TTL values match attack parameters

Example output:
```
✓ Fake packet 0 TTL correct: 1
✓ Real packet 0 TTL normal: 64
✗ Fake packet 0 TTL (5) != expected (1)
```

## Result Structure

The validation result is a dictionary with the following structure:

```python
{
    'passed': bool,              # Overall pass/fail
    'packet_count': int,         # Number of packets found
    'errors': List[str],         # Critical errors
    'warnings': List[str],       # Non-critical warnings
    'details': {                 # Detailed results per category
        'sequence_numbers': {
            'passed': bool,
            'errors': List[str],
            'warnings': List[str],
            'details': List[str]
        },
        'checksums': {
            'passed': bool,
            'errors': List[str],
            'warnings': List[str],
            'details': List[str]
        },
        'ttl': {
            'passed': bool,
            'errors': List[str],
            'warnings': List[str],
            'details': List[str]
        }
    }
}
```

## Supported Attack Types

- `fake` - Fake packet with low TTL
- `split` - Split packet at specified position
- `fakeddisorder` - Fake packet + disordered real packets
- `disorder` - Reordered packets
- `multisplit` - Multiple split packets
- `multidisorder` - Multiple disordered packets
- Generic validation for other attacks

## Attack Parameters

### Fake Attack
```python
params = {
    'ttl': 1,                    # TTL for fake packet
    'fooling': ['badsum']        # Fooling methods
}
```

### Split Attack
```python
params = {
    'split_pos': 1               # Position to split packet
}
```

### Fakeddisorder Attack
```python
params = {
    'split_pos': 76,             # Split position
    'overlap_size': 336,         # Overlap size
    'ttl': 3,                    # TTL for fake packet
    'fooling': ['badsum']        # Fooling methods
}
```

## Examples

### Example 1: Validate Fake Attack

```python
from core.simple_packet_validator import quick_validate

result = quick_validate(
    'test_fake.pcap',
    attack_type='fake',
    params={'ttl': 1, 'fooling': ['badsum']}
)

if result['passed']:
    print("✓ Fake attack validation passed")
else:
    print("✗ Fake attack validation failed")
    for error in result['errors']:
        print(f"  {error}")
```

### Example 2: Validate Split Attack

```python
from core.simple_packet_validator import SimplePacketValidator

validator = SimplePacketValidator()
result = validator.validate_pcap(
    'test_split.pcap',
    attack_type='split',
    params={'split_pos': 1}
)

print(f"Validation: {'PASSED' if result['passed'] else 'FAILED'}")
print(f"Packets: {result['packet_count']}")
```

### Example 3: Validate Fakeddisorder with Debug

```python
from core.simple_packet_validator import SimplePacketValidator

validator = SimplePacketValidator(debug=True)
result = validator.validate_pcap(
    'test_fakeddisorder.pcap',
    attack_type='fakeddisorder',
    params={
        'split_pos': 76,
        'overlap_size': 336,
        'ttl': 3,
        'fooling': ['badsum']
    }
)

# Print detailed results
for category, details in result['details'].items():
    print(f"\n{category.upper()}:")
    print(f"  Passed: {details['passed']}")
    if details['errors']:
        print("  Errors:")
        for error in details['errors']:
            print(f"    - {error}")
    if details['details']:
        print("  Details:")
        for detail in details['details']:
            print(f"    {detail}")
```

## Testing

Run the test suite:

```bash
python test_simple_packet_validator.py
```

Expected output:
```
============================================================
Simple Packet Validator Test Suite
============================================================

=== Test: Validator Initialization ===
✓ Validator initialized successfully
✓ Debug mode enabled successfully

=== Test: Quick Validate Function ===
✓ Quick validate handles missing file

=== Test: Sequence Number Validation ===
Sequence validation: PASSED
✓ Sequence number validation logic tested

=== Test: Checksum Validation ===
Checksum validation: PASSED
✓ Checksum validation logic tested

=== Test: TTL Validation ===
TTL validation: PASSED
✓ TTL validation logic tested

============================================================
✓ All tests completed successfully!
============================================================
```

## Comparison with Full PacketValidator

| Feature | SimplePacketValidator | PacketValidator |
|---------|----------------------|-----------------|
| Sequence validation | ✅ | ✅ |
| Checksum validation | ✅ | ✅ |
| TTL validation | ✅ | ✅ |
| YAML spec support | ❌ | ✅ |
| Visual diff generation | ❌ | ✅ |
| Packet count validation | ❌ | ✅ |
| Packet order validation | ❌ | ✅ |
| Rule engine | ❌ | ✅ |
| Performance | Fast | Slower |
| Complexity | Low | High |

## When to Use

### Use SimplePacketValidator when:
- ✅ You need quick validation during development
- ✅ You want to check basic packet properties
- ✅ You don't need YAML spec support
- ✅ Performance is important

### Use PacketValidator when:
- ✅ You need comprehensive validation
- ✅ You want to use YAML attack specifications
- ✅ You need visual diff generation
- ✅ You need detailed reporting

## Troubleshooting

### No packets found in PCAP file

**Problem**: `result['errors']` contains "No packets found in PCAP file"

**Solutions**:
1. Check PCAP file exists
2. Verify PCAP file format (must be standard libpcap format)
3. Enable debug mode to see parsing errors
4. Check file permissions

### Checksum validation fails

**Problem**: Real packets have bad checksums

**Solutions**:
1. Check if WinDivert is recalculating checksums
2. Verify network capture settings
3. Check if packets are being modified in transit

### Sequence number validation fails

**Problem**: Sequence numbers don't match expected values

**Solutions**:
1. Verify attack parameters are correct
2. Check if packets are being reordered
3. Verify split_pos and overlap_size parameters
4. Enable debug mode to see actual vs expected values

## API Reference

### SimplePacketValidator

```python
class SimplePacketValidator:
    def __init__(self, debug: bool = False)
    def validate_pcap(self, pcap_file: str, attack_type: str = None, 
                     params: Dict[str, Any] = None) -> Dict[str, Any]
    def validate_seq_numbers(self, packets: List[Dict], attack_type: str = None,
                            params: Dict[str, Any] = None) -> Dict[str, Any]
    def validate_checksums(self, packets: List[Dict], attack_type: str = None,
                          params: Dict[str, Any] = None) -> Dict[str, Any]
    def validate_ttl(self, packets: List[Dict], attack_type: str = None,
                    params: Dict[str, Any] = None) -> Dict[str, Any]
```

### quick_validate

```python
def quick_validate(pcap_file: str, attack_type: str = None, 
                  params: Dict[str, Any] = None, debug: bool = False) -> Dict[str, Any]
```

## Contributing

To add support for new attack types:

1. Add validation logic to `validate_seq_numbers()`, `validate_checksums()`, or `validate_ttl()`
2. Add test cases to `test_simple_packet_validator.py`
3. Update this README with examples

## License

Part of the Recon DPI bypass tool.
