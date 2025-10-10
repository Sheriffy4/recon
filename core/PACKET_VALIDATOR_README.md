# PacketValidator - Comprehensive Packet Validation for DPI Bypass Attacks

## Overview

The `PacketValidator` class provides comprehensive validation of DPI bypass attack packets, ensuring they match expected behavior for:

- **Sequence numbers** - Validates TCP sequence numbers are correct for split/disorder attacks
- **Checksums** - Validates checksums are good/bad as specified (badsum fooling)
- **TTL values** - Validates Time-To-Live values for fake packets
- **Packet counts** - Validates correct number of packets generated
- **Visual diffs** - Generates side-by-side comparisons of expected vs actual packets

## Features

### 1. Sequence Number Validation

Validates that TCP sequence numbers are correct for various attack types:

**Fakeddisorder Attack:**
- Fake packet seq must equal original_seq (first real packet seq)
- Real packets must have sequential seq numbers
- Overlap calculations must be correct

**Split/Disorder Attacks:**
- Packets must have sequential sequence numbers
- Split positions must be respected

### 2. Checksum Validation

Validates TCP checksums are correct or corrupted as specified:

**With badsum fooling:**
- Fake packets must have bad checksums
- Real packets must have good checksums
- Detects WinDivert checksum recalculation issues

**Without badsum:**
- All packets must have good checksums

### 3. TTL Validation

Validates Time-To-Live values:

**Fake attacks:**
- Fake packets must have specified TTL (usually 1-3)
- Real packets must have default TTL (64, 128, or 255)

**Other attacks:**
- All packets must have reasonable TTL values (1-255)

### 4. Packet Count Validation

Validates correct number of packets generated:

- **fake**: 2 packets (fake + real)
- **split**: 2 packets (2 segments)
- **fakeddisorder**: 3 packets (fake + 2 real segments)
- **disorder**: 2-10 packets (reordered segments)

### 5. Visual Diff Generation

Generates visual comparisons between expected and actual packets:

- **Text format**: Side-by-side comparison in plain text
- **HTML format**: Interactive HTML table with color-coded differences
- **Export**: Save diffs to files for documentation

## Usage

### Basic Validation

```python
from core.packet_validator import validate_pcap

# Validate a fake attack
result = validate_pcap(
    attack_name='fake',
    params={'ttl': 3, 'fooling': ['badsum']},
    pcap_file='test_fake.pcap',
    debug=True
)

print(f"Validation passed: {result.passed}")
print(f"Critical issues: {len(result.get_critical_issues())}")
print(f"Errors: {len(result.get_errors())}")
print(f"Warnings: {len(result.get_warnings())}")

# Print validation details
for detail in result.details:
    status = "✓" if detail.passed else "❌"
    print(f"{status} {detail.aspect}: {detail.message}")
```

### Fakeddisorder Validation

```python
# Validate fakeddisorder attack
result = validate_pcap(
    attack_name='fakeddisorder',
    params={
        'ttl': 3,
        'split_pos': 76,
        'overlap_size': 336,
        'fooling': ['badsum']
    },
    pcap_file='test_fakeddisorder.pcap'
)

# Check for critical issues
critical_issues = result.get_critical_issues()
if critical_issues:
    print("Critical issues found:")
    for issue in critical_issues:
        print(f"  - {issue.message}")
        print(f"    Expected: {issue.expected}")
        print(f"    Actual: {issue.actual}")
```

### Split Attack Validation

```python
# Validate split attack
result = validate_pcap(
    attack_name='split',
    params={'split_pos': 5},
    pcap_file='test_split.pcap'
)

# Check sequence numbers
seq_details = [d for d in result.details if d.aspect == 'sequence_numbers']
for detail in seq_details:
    print(f"{detail.message}")
```

### Advanced Usage with PacketValidator Class

```python
from core.packet_validator import PacketValidator

# Create validator
validator = PacketValidator(debug_mode=True)

# Validate attack
result = validator.validate_attack(
    attack_name='fakeddisorder',
    params={'ttl': 3, 'split_pos': 76, 'fooling': ['badsum']},
    pcap_file='test.pcap'
)

# Parse PCAP manually
packets = validator.parse_pcap('test.pcap')
print(f"Found {len(packets)} packets")

for packet in packets:
    print(f"Packet {packet.index}:")
    print(f"  TTL: {packet.ttl}")
    print(f"  Seq: {packet.sequence_num}")
    print(f"  Checksum valid: {packet.checksum_valid}")
    print(f"  Is fake: {packet.is_fake_packet()}")
```

### Generate Visual Diff

```python
from core.packet_validator import generate_diff_report, PacketValidator

validator = PacketValidator()

# Define expected packets
expected = [
    {
        'ttl': 3,
        'sequence_num': 1000,
        'checksum_valid': False,
        'payload_length': 40
    },
    {
        'ttl': 64,
        'sequence_num': 1000,
        'checksum_valid': True,
        'payload_length': 100
    }
]

# Parse actual packets
actual = validator.parse_pcap('test.pcap')

# Generate HTML diff
html_diff = validator.generate_visual_diff(expected, actual, 'html')
validator.export_diff(html_diff, 'diff_report.html')

# Generate text diff
text_diff = validator.generate_visual_diff(expected, actual, 'text')
validator.export_diff(text_diff, 'diff_report.txt')
```

## Validation Result Structure

### ValidationResult

```python
@dataclass
class ValidationResult:
    attack_name: str          # Name of attack being validated
    params: Dict[str, Any]    # Attack parameters
    passed: bool              # Overall pass/fail status
    details: List[ValidationDetail]  # Detailed validation results
    packet_count: int         # Number of packets found
    error: Optional[str]      # Error message if validation failed
```

### ValidationDetail

```python
@dataclass
class ValidationDetail:
    aspect: str               # What was validated (e.g., 'sequence_numbers', 'checksum', 'ttl')
    passed: bool              # Did this check pass?
    expected: Any             # Expected value
    actual: Any               # Actual value
    message: str              # Human-readable message
    severity: ValidationSeverity  # INFO, WARNING, ERROR, CRITICAL
    packet_index: Optional[int]   # Which packet (if applicable)
```

### ValidationSeverity

```python
class ValidationSeverity(Enum):
    INFO = "info"           # Informational message
    WARNING = "warning"     # Warning (non-critical issue)
    ERROR = "error"         # Error (validation failed)
    CRITICAL = "critical"   # Critical error (attack will not work)
```

## Common Validation Scenarios

### Scenario 1: Fake Packet Has Good Checksum (WinDivert Issue)

```python
result = validate_pcap('fake', {'ttl': 3, 'fooling': ['badsum']}, 'test.pcap')

# Check for WinDivert recalculation
for detail in result.details:
    if 'WinDivert' in detail.message:
        print("⚠️ WinDivert is recalculating checksums!")
        print("   This breaks badsum fooling.")
        print("   Solution: Use raw socket or disable checksum offload")
```

### Scenario 2: Wrong Sequence Numbers in Fakeddisorder

```python
result = validate_pcap('fakeddisorder', 
                      {'ttl': 3, 'split_pos': 76, 'fooling': ['badsum']},
                      'test.pcap')

# Check sequence number issues
seq_issues = [d for d in result.details 
              if d.aspect == 'sequence_numbers' and not d.passed]

for issue in seq_issues:
    print(f"❌ Sequence number issue: {issue.message}")
    print(f"   Expected: {issue.expected}")
    print(f"   Actual: {issue.actual}")
    print(f"   Packet: {issue.packet_index}")
```

### Scenario 3: Wrong TTL Values

```python
result = validate_pcap('fake', {'ttl': 3, 'fooling': ['badsum']}, 'test.pcap')

# Check TTL issues
ttl_issues = [d for d in result.details 
              if d.aspect == 'ttl' and not d.passed]

for issue in ttl_issues:
    print(f"❌ TTL issue: {issue.message}")
    if issue.severity == ValidationSeverity.CRITICAL:
        print("   This is CRITICAL - fake packet will not expire!")
```

## Integration with Test Suite

The PacketValidator is designed to integrate with the Attack Validation Suite:

```python
from core.packet_validator import PacketValidator

# Test all attacks
validator = PacketValidator(debug_mode=True)

attacks = [
    ('fake', {'ttl': 1, 'fooling': ['badsum']}),
    ('split', {'split_pos': 1}),
    ('fakeddisorder', {'ttl': 3, 'split_pos': 76, 'fooling': ['badsum']})
]

for attack_name, params in attacks:
    pcap_file = f'test_{attack_name}.pcap'
    result = validator.validate_attack(attack_name, params, pcap_file)
    
    if result.passed:
        print(f"✓ {attack_name}: PASSED")
    else:
        print(f"❌ {attack_name}: FAILED")
        for issue in result.get_critical_issues():
            print(f"   - {issue.message}")
```

## Troubleshooting

### Issue: "No packets found in PCAP file"

**Cause:** PCAP file is empty or corrupted

**Solution:**
```python
# Check if PCAP file exists and has content
from pathlib import Path
pcap_path = Path('test.pcap')
if not pcap_path.exists():
    print("PCAP file does not exist")
elif pcap_path.stat().st_size == 0:
    print("PCAP file is empty")
```

### Issue: "Invalid PCAP magic number"

**Cause:** File is not a valid PCAP file

**Solution:**
```python
# Check PCAP magic number
with open('test.pcap', 'rb') as f:
    magic = f.read(4)
    print(f"Magic number: {magic.hex()}")
    # Should be: a1b2c3d4 (little-endian) or d4c3b2a1 (big-endian)
```

### Issue: "Checksum validation always fails"

**Cause:** Checksum offload enabled in network card

**Solution:**
- Disable checksum offload: `ethtool -K eth0 tx off`
- Use raw sockets instead of WinDivert
- Capture packets before checksum calculation

## Performance Considerations

- **Max packets**: Default limit is 10,000 packets per PCAP
- **Memory usage**: ~1KB per packet in memory
- **Processing speed**: ~10,000 packets/second on modern hardware

To adjust limits:

```python
validator = PacketValidator()
validator.max_packets = 50000  # Increase limit
```

## Requirements

- Python 3.7+
- No external dependencies (uses only stdlib)
- Works on Windows, Linux, macOS

## Testing

Run the test suite:

```bash
cd recon
python test_packet_validator.py
```

Expected output:
```
================================================================================
PacketValidator Test Suite
================================================================================

=== Testing Fake Attack Validation ===
✓ All checks passed

=== Testing Fakeddisorder Attack Validation ===
✓ All checks passed

=== Testing Split Attack Validation ===
✓ All checks passed

=== Testing Visual Diff Generation ===
✓ Diff generated successfully

Total: 4/4 tests passed
```

## Related Documentation

- [Attack Validation Suite Requirements](../../.kiro/specs/attack-validation-suite/requirements.md)
- [Attack Validation Suite Design](../../.kiro/specs/attack-validation-suite/design.md)
- [Attack Validation Suite Tasks](../../.kiro/specs/attack-validation-suite/tasks.md)
- [Strategy Parser V2](strategy_parser_v2.py)

## Support

For issues or questions:
1. Check the test suite for examples
2. Review validation details in the result object
3. Enable debug mode for verbose output
4. Check PCAP file with Wireshark to verify packet structure
