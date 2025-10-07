# TTL Validation - Quick Start Guide

## Overview
TTL (Time To Live) validation is now available in the PCAP Content Validator. This feature allows you to validate that packets in a PCAP file have the expected TTL values.

## Usage

### Basic Usage

```python
from pathlib import Path
from core.pcap_content_validator import PCAPContentValidator

validator = PCAPContentValidator()

# Validate with expected TTL
attack_spec = {
    'expected_ttl': 1  # Expected TTL value
}

result = validator.validate_pcap(Path("capture.pcap"), attack_spec)

# Check results
print(f"TTL Mismatches: {result.details.get('ttl_mismatches', 0)}")
print(f"Expected TTL: {result.details.get('expected_ttl')}")

# View TTL issues
ttl_issues = [i for i in result.issues if i.category == 'ttl']
for issue in ttl_issues:
    print(f"Packet {issue.packet_index}: Expected={issue.expected}, Actual={issue.actual}")
```

### Attack-Specific Validation

```python
# Automatically extracts TTL from attack parameters
attack_params = {
    'ttl': 1,
    'split_pos': 2
}

result = validator.validate_attack_pcap(
    Path("capture.pcap"),
    'fakeddisorder',
    attack_params
)
```

### Without Expected TTL

```python
# If no expected TTL is specified, validation is skipped
attack_spec = {}  # No expected_ttl

result = validator.validate_pcap(Path("capture.pcap"), attack_spec)
# Will add warning: "No expected TTL specified, skipping validation"
```

## What Gets Validated

1. **TTL Extraction**: Extracts TTL value from IP layer of each packet
2. **Comparison**: Compares each packet's TTL with expected value
3. **Anomaly Detection**: Detects packets with mismatched TTL values
4. **Reporting**: Creates detailed ValidationIssue for each mismatch

## Validation Results

### ValidationIssue Structure
```python
ValidationIssue(
    severity='warning',
    category='ttl',
    packet_index=5,
    description='TTL value mismatch',
    expected=1,
    actual=64
)
```

### Result Details
```python
result.details = {
    'ttl_mismatches': 10,      # Number of packets with wrong TTL
    'expected_ttl': 1,          # Expected TTL value
    'ip_packets': 100,          # Total IP packets analyzed
    ...
}
```

## Common Use Cases

### 1. Validate Fake Packets (Low TTL)
```python
# Fake packets typically use TTL=1 to expire before reaching destination
attack_spec = {'expected_ttl': 1}
result = validator.validate_pcap(Path("fake_packets.pcap"), attack_spec)
```

### 2. Validate Normal Packets (Standard TTL)
```python
# Normal packets typically use TTL=64 (Linux) or TTL=128 (Windows)
attack_spec = {'expected_ttl': 64}
result = validator.validate_pcap(Path("normal_packets.pcap"), attack_spec)
```

### 3. Validate fakeddisorder Attack
```python
# fakeddisorder uses fake packets with low TTL
attack_params = {
    'ttl': 1,           # Fake packet TTL
    'split_pos': 2,
    'fooling': ['badsum']
}

result = validator.validate_attack_pcap(
    Path("fakeddisorder.pcap"),
    'fakeddisorder',
    attack_params
)
```

## Example Output

```
TTL Validation Results:
  Total Packets: 100
  IP Packets: 95
  TTL Mismatches: 5
  Expected TTL: 1

TTL Issues:
  Packet 10: Expected=1, Actual=64
  Packet 25: Expected=1, Actual=64
  Packet 40: Expected=1, Actual=128
  Packet 55: Expected=1, Actual=64
  Packet 70: Expected=1, Actual=64
```

## Testing

Run the focused test:
```bash
cd recon
python test_ttl_validation_focused.py
```

Run the comprehensive test:
```bash
cd recon
python test_pcap_content_validator.py
```

## Integration

TTL validation is automatically integrated into:
- `validate_pcap()` - Main validation method
- `validate_attack_pcap()` - Attack-specific validation
- Attack specification builder (`_build_attack_spec()`)

## Supported Attack Parameters

The validator automatically recognizes these parameter names:
- `ttl` - Standard TTL parameter
- `fake_ttl` - Alternative TTL parameter name

## Error Handling

The validator handles these cases gracefully:
- No expected TTL specified → Adds warning, skips validation
- No IP packets in PCAP → Adds warning, skips validation
- Invalid PCAP file → Returns error in validation result

## Performance

- **Complexity**: O(n) where n = number of IP packets
- **Memory**: Minimal overhead
- **Speed**: Fast TTL extraction from IP layer
- **Tested**: Up to 10,000+ packets

## Related Tasks

- ✅ Task 2.1: Packet count validation
- ✅ Task 2.2: Sequence number validation
- ✅ Task 2.3: Checksum validation
- ✅ Task 2.4: TTL validation (THIS TASK)
- ⏳ Task 2.5: TCP flags validation

## Documentation

- **Implementation**: `recon/core/pcap_content_validator.py`
- **Method**: `_validate_ttl()`
- **Tests**: `recon/test_ttl_validation_focused.py`
- **Completion Report**: `recon/TASK_2.4_TTL_VALIDATION_COMPLETE.md`

---

**Status**: ✅ Production Ready
**Version**: 1.0
**Last Updated**: October 5, 2025
