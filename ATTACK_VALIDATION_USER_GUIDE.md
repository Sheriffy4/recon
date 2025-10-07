# Attack Validation Suite - User Guide

**Version:** 1.0  
**Last Updated:** 2025-10-05  
**Status:** Production Ready

## Table of Contents

1. [Introduction](#introduction)
2. [Quick Start](#quick-start)
3. [Installation](#installation)
4. [Basic Usage](#basic-usage)
5. [Advanced Usage](#advanced-usage)
6. [Validation Rules](#validation-rules)
7. [Attack Specifications](#attack-specifications)
8. [Troubleshooting](#troubleshooting)
9. [API Reference](#api-reference)
10. [Examples](#examples)

## Introduction

The Attack Validation Suite is a comprehensive testing framework for validating that DPI bypass attacks generate correct packets according to their specifications. It provides:

- **Automated Testing:** Test all attacks with a single command
- **PCAP Validation:** Validate real PCAP files against specifications
- **Comprehensive Reports:** Detailed reports with visual diffs
- **Integration Testing:** Test against real-world network captures
- **CI/CD Ready:** Integrate with your build pipeline

### Key Features

- ✅ Validates sequence numbers, checksums, TTL, and packet counts
- ✅ Supports all attack types (fake, split, disorder, fakeddisorder, etc.)
- ✅ Connection-aware validation for multi-connection PCAPs
- ✅ Strict and lenient modes for testing vs production
- ✅ Comprehensive reporting in multiple formats
- ✅ Easy to extend with new attack types

## Quick Start

### Run Integration Test

```bash
cd recon
python validate_all_attacks_integration.py
```

This will:
1. Find all PCAP files in the project
2. Infer attack types from filenames
3. Validate each PCAP against specifications
4. Generate a detailed report

### Generate Report

```bash
python generate_final_integration_report.py
```

This will create reports in `final_integration_results/`:
- Markdown report (`.md`)
- Text report (`.txt`)
- JSON report (`.json`)

### View Results

```bash
# View summary
cat integration_validation_report.json | jq '.summary'

# View issues
cat integration_validation_report.json | jq '.issues[:5]'

# View by attack type
cat integration_validation_report.json | jq '.by_attack'
```

## Installation

### Prerequisites

- Python 3.8+
- Scapy (for PCAP parsing)
- PyYAML (for attack specifications)
- Required recon modules

### Install Dependencies

```bash
pip install scapy pyyaml
```

### Verify Installation

```bash
python -c "from core.packet_validator import PacketValidator; print('OK')"
```

## Basic Usage

### Validate a Single PCAP File

```python
from core.packet_validator import PacketValidator

validator = PacketValidator()

# Validate fakeddisorder attack
result = validator.validate_attack(
    attack_name='fakeddisorder',
    params={'split_pos': 76, 'overlap_size': 336, 'ttl': 3, 'fooling': ['badsum']},
    pcap_file='zapret.pcap'
)

if result.passed:
    print("✅ Validation passed!")
else:
    print("❌ Validation failed:")
    for detail in result.details:
        if not detail.passed:
            print(f"  - {detail.aspect}: {detail.message}")
```

### Validate Multiple Files

```python
from validate_all_attacks_integration import IntegrationValidator

validator = IntegrationValidator()
results = validator.validate_all()

# Print summary
validator.print_summary()

# Save report
validator.save_report('my_validation_report.json')
```

### Test a Specific Attack

```python
from test_all_attacks import AttackTestOrchestrator

orchestrator = AttackTestOrchestrator()

# Test fake attack
result = orchestrator.test_attack(
    attack_name='fake',
    params={'ttl': 1, 'fooling': ['badsum']}
)

print(f"Attack: {result.attack_name}")
print(f"Passed: {result.passed}")
print(f"Details: {result.validation}")
```

## Advanced Usage

### Strict Mode

Use strict mode for unit testing:

```python
validator = PacketValidator(strict_mode=True)

# Strict validation - enforces all rules
result = validator.validate_attack(
    attack_name='fake',
    params={'ttl': 1},
    pcap_file='test.pcap'
)
```

### Lenient Mode (Default)

Use lenient mode for production PCAPs:

```python
validator = PacketValidator(strict_mode=False)

# Lenient validation - accounts for real-world behavior
result = validator.validate_attack(
    attack_name='fakeddisorder',
    params={'split_pos': 76, 'ttl': 3},
    pcap_file='production.pcap'
)
```

### Custom Validation Rules

```python
from core.attack_spec_loader import AttackSpecLoader

# Load and modify spec
loader = AttackSpecLoader()
spec = loader.load_spec('fakeddisorder')

# Customize validation rules
spec['validation_rules']['strict_mode'] = False
spec['validation_rules']['ignore_background_traffic'] = True

# Validate with custom spec
result = validator.validate_attack_with_spec(
    spec=spec,
    params={'split_pos': 76, 'ttl': 3},
    pcap_file='custom.pcap'
)
```

### Filter Attack Packets

```python
# Filter to only attack-related packets
attack_packets = validator.filter_attack_packets(
    packets=all_packets,
    attack_name='fakeddisorder'
)

print(f"Total packets: {len(all_packets)}")
print(f"Attack packets: {len(attack_packets)}")
```

## Validation Rules

### Sequence Number Validation

**Rule:** Sequence numbers must be sequential within each TCP connection.

**Exceptions:**
- Disorder attacks: Packets intentionally out of order
- Fakeddisorder attacks: Overlapping sequences allowed
- Multi-connection PCAPs: Each connection validated separately

**Example:**
```python
# Valid sequence numbers
packets = [
    {'seq': 1000, 'len': 100},  # seq=1000
    {'seq': 1100, 'len': 50},   # seq=1100 (1000+100)
    {'seq': 1150, 'len': 25}    # seq=1150 (1100+50)
]

# Invalid sequence numbers (unless disorder attack)
packets = [
    {'seq': 1000, 'len': 100},  # seq=1000
    {'seq': 1200, 'len': 50},   # seq=1200 (gap!)
    {'seq': 1150, 'len': 25}    # seq=1150 (out of order!)
]
```

### Checksum Validation

**Rule:** Checksums must be valid unless badsum is specified.

**Exceptions:**
- Captured traffic: May have bad checksums due to offloading
- Lenient mode: Only validates attack packets
- Strict mode: Validates all packets

**Example:**
```python
# With badsum fooling
params = {'fooling': ['badsum']}
# Fake packet MUST have bad checksum
# Real packets MUST have good checksum

# Without badsum fooling
params = {}
# All packets SHOULD have good checksum (lenient mode)
# All packets MUST have good checksum (strict mode)
```

### TTL Validation

**Rule:** TTL must match specified value.

**Exceptions:**
- Hop decrements: TTL may be lower than specified
- Lenient mode: Uses TTL ranges
- Strict mode: Requires exact TTL

**Example:**
```python
# Fake packet with ttl=1
params = {'ttl': 1}
# Fake packet: TTL must be 1-10 (lenient) or 1 (strict)
# Real packets: TTL must be 30-128 (lenient) or 64/128 (strict)
```

### Packet Count Validation

**Rule:** Packet count must match expected count.

**Exceptions:**
- Background traffic: Ignored in lenient mode
- Multi-connection: Counted per connection
- Ranges: Min/max instead of exact count

**Example:**
```python
# Fakeddisorder attack
expected_packets = {
    'min': 2,  # At least fake + real
    'max': 10  # Up to 10 packets
}

# Actual packets: 3 (fake + 2 real parts)
# Result: PASS (within range)
```

## Attack Specifications

### Specification Format

Attack specifications are defined in YAML files in `specs/attacks/`:

```yaml
name: fakeddisorder
description: Send fake packet, then real packets in disorder
parameters:
  - name: split_pos
    type: int
    required: true
  - name: overlap_size
    type: int
    default: 0
  - name: ttl
    type: int
    default: 1
  - name: fooling
    type: list[str]
    default: []

expected_packets:
  count:
    min: 2
    max: 10
  order:
    - fake_packet
    - real_part2
    - real_part1

validation_rules:
  strict_mode: false
  ignore_background_traffic: true
  sequence_numbers:
    allow_disorder: true
    allow_overlap: true
  checksums:
    strict: false
    validate_fake_only: true
  ttl:
    fake_packet:
      min: 1
      max: 10
    real_packets:
      min: 30
      max: 128
```

### Supported Attack Types

1. **fake** - Send fake packet before real packet
2. **split** - Split packet at specified position
3. **disorder** - Send packets in disorder
4. **fakeddisorder** - Fake packet + disorder
5. **multisplit** - Multiple splits
6. **multidisorder** - Multiple disorder
7. **seqovl** - Sequence overlap

### Creating Custom Specifications

```yaml
name: my_custom_attack
description: My custom DPI bypass attack
parameters:
  - name: custom_param
    type: int
    required: true

expected_packets:
  count:
    min: 1
    max: 5

validation_rules:
  strict_mode: false
  custom_rule: true
```

## Troubleshooting

### Common Issues

#### Issue: "Could not infer attack type from filename"

**Cause:** Filename doesn't match known patterns.

**Solution:** Rename file or specify attack type explicitly:
```python
result = validator.validate_attack(
    attack_name='fakeddisorder',  # Specify explicitly
    params={...},
    pcap_file='unknown.pcap'
)
```

#### Issue: "Validation failed: sequence numbers"

**Cause:** Strict validation on multi-connection PCAP.

**Solution:** Use lenient mode:
```python
validator = PacketValidator(strict_mode=False)
```

#### Issue: "Validation failed: checksums"

**Cause:** Captured traffic has bad checksums.

**Solution:** Disable strict checksum validation:
```python
spec['validation_rules']['checksums']['strict'] = False
```

#### Issue: "Too many packets"

**Cause:** PCAP contains background traffic.

**Solution:** Enable packet filtering:
```python
spec['validation_rules']['ignore_background_traffic'] = True
```

### Debug Mode

Enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

validator = PacketValidator()
result = validator.validate_attack(...)
```

### Verbose Output

```python
validator = PacketValidator(verbose=True)
result = validator.validate_attack(...)

# Print detailed information
for detail in result.details:
    print(f"Aspect: {detail.aspect}")
    print(f"Passed: {detail.passed}")
    print(f"Message: {detail.message}")
    if detail.expected:
        print(f"Expected: {detail.expected}")
    if detail.actual:
        print(f"Actual: {detail.actual}")
```

## API Reference

### PacketValidator

```python
class PacketValidator:
    def __init__(self, strict_mode=False, verbose=False):
        """Initialize validator"""
        
    def validate_attack(self, attack_name, params, pcap_file):
        """Validate attack against PCAP file"""
        
    def filter_attack_packets(self, packets, attack_name):
        """Filter to attack-related packets"""
        
    def validate_seq_numbers(self, packets, spec, params):
        """Validate sequence numbers"""
        
    def validate_checksums(self, packets, spec, params):
        """Validate checksums"""
        
    def validate_ttl(self, packets, spec, params):
        """Validate TTL values"""
```

### IntegrationValidator

```python
class IntegrationValidator:
    def __init__(self):
        """Initialize integration validator"""
        
    def find_pcap_files(self):
        """Find all PCAP files"""
        
    def validate_all(self):
        """Validate all PCAP files"""
        
    def print_summary(self):
        """Print validation summary"""
        
    def save_report(self, output_file):
        """Save validation report"""
```

### AttackTestOrchestrator

```python
class AttackTestOrchestrator:
    def __init__(self):
        """Initialize test orchestrator"""
        
    def test_all_attacks(self):
        """Test all attacks in registry"""
        
    def test_attack(self, attack_name, params):
        """Test single attack"""
        
    def generate_report(self):
        """Generate test report"""
```

## Examples

### Example 1: Validate Fakeddisorder Attack

```python
from core.packet_validator import PacketValidator

validator = PacketValidator()

result = validator.validate_attack(
    attack_name='fakeddisorder',
    params={
        'split_pos': 76,
        'overlap_size': 336,
        'ttl': 3,
        'fooling': ['badsum']
    },
    pcap_file='zapret.pcap'
)

if result.passed:
    print("✅ All validations passed!")
else:
    print("❌ Validation failed:")
    for detail in result.details:
        if not detail.passed:
            print(f"  {detail.aspect}: {detail.message}")
```

### Example 2: Batch Validation

```python
from validate_all_attacks_integration import IntegrationValidator

validator = IntegrationValidator()

# Find and validate all PCAPs
results = validator.validate_all()

# Print summary
print(f"Total: {len(results)}")
print(f"Passed: {sum(1 for r in results if r.passed)}")
print(f"Failed: {sum(1 for r in results if not r.passed)}")

# Save report
validator.save_report('batch_validation.json')
```

### Example 3: Custom Validation

```python
from core.packet_validator import PacketValidator
from core.attack_spec_loader import AttackSpecLoader

# Load spec
loader = AttackSpecLoader()
spec = loader.load_spec('fake')

# Customize
spec['validation_rules']['strict_mode'] = True
spec['validation_rules']['checksums']['strict'] = True

# Validate
validator = PacketValidator()
result = validator.validate_attack_with_spec(
    spec=spec,
    params={'ttl': 1, 'fooling': ['badsum']},
    pcap_file='test_fake.pcap'
)
```

### Example 4: CI/CD Integration

```bash
#!/bin/bash
# validate_attacks.sh

# Run validation
python validate_all_attacks_integration.py

# Check exit code
if [ $? -eq 0 ]; then
    echo "✅ All validations passed"
    exit 0
else
    echo "❌ Validation failed"
    cat integration_validation_report.json | jq '.summary'
    exit 1
fi
```

### Example 5: Generate Report

```python
from generate_final_integration_report import FinalReportGenerator

generator = FinalReportGenerator()
md_file, txt_file, json_file = generator.save_report()

print(f"Reports generated:")
print(f"  - {md_file}")
print(f"  - {txt_file}")
print(f"  - {json_file}")
```

## Best Practices

### 1. Use Lenient Mode for Production

```python
# Production validation
validator = PacketValidator(strict_mode=False)
```

### 2. Use Strict Mode for Testing

```python
# Unit testing
validator = PacketValidator(strict_mode=True)
```

### 3. Filter Attack Packets

```python
# Filter before validation
attack_packets = validator.filter_attack_packets(all_packets, 'fakeddisorder')
result = validator.validate_attack_packets(attack_packets, spec, params)
```

### 4. Handle Errors Gracefully

```python
try:
    result = validator.validate_attack(...)
except Exception as e:
    print(f"Validation error: {e}")
    # Log error, continue with next file
```

### 5. Generate Reports Regularly

```bash
# Daily validation report
0 0 * * * cd /path/to/recon && python validate_all_attacks_integration.py
```

## Support

### Getting Help

- **Documentation:** See this guide and API reference
- **Examples:** Check `examples/` directory
- **Issues:** Report bugs on GitHub
- **Questions:** Ask on project forum

### Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Submit a pull request

### License

This project is licensed under the MIT License.

---

**User Guide Version:** 1.0  
**Last Updated:** 2025-10-05  
**Maintained By:** Attack Validation Suite Team
