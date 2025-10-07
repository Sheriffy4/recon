# PCAP Content Validator - Quick Start Guide

## Overview

The PCAP Content Validator provides comprehensive validation of PCAP files for the Attack Validation Suite. It validates packet counts, sequence numbers, checksums, TTL values, and TCP flags.

## Quick Usage

### Basic Validation

```python
from core.pcap_content_validator import PCAPContentValidator
from pathlib import Path

# Create validator
validator = PCAPContentValidator()

# Validate a PCAP file
result = validator.validate_pcap(Path("test.pcap"))

# Check results
print(result.get_summary())
print(f"Passed: {result.passed}")
print(f"Issues: {len(result.issues)}")
```

### Attack-Specific Validation

```python
# Validate for a specific attack
result = validator.validate_attack_pcap(
    pcap_file=Path("test.pcap"),
    attack_name="fakeddisorder",
    attack_params={'split_pos': 2, 'ttl': 1, 'fooling': ['badsum']}
)
```

### Custom Validation Spec

```python
# Define custom validation rules
attack_spec = {
    'expected_packet_count': 5,
    'expected_bad_checksums': True,
    'expected_ttl': 1,
    'expected_flags': ['SYN', 'ACK'],
    'validate_sequence': True
}

result = validator.validate_pcap(Path("test.pcap"), attack_spec)
```

## Validation Rules

### 1. Packet Count Validation
- Validates actual vs expected packet count
- Reports mismatches as errors

### 2. Sequence Number Validation
- Validates TCP sequence progression
- Groups packets by connection
- Detects retransmissions and anomalies

### 3. Checksum Validation
- Validates good/bad checksums as expected
- Useful for badsum attacks
- Reports checksum statistics

### 4. TTL Validation
- Validates TTL values match expected
- Useful for fake packet attacks
- Reports TTL mismatches

### 5. TCP Flags Validation
- Validates TCP flag combinations
- Checks for expected flags (SYN, ACK, FIN, etc.)
- Reports flag anomalies

## Integration with Test Orchestrator

The validator is automatically integrated into the AttackTestOrchestrator:

```python
from test_all_attacks import AttackTestOrchestrator

# Create orchestrator (PCAP validator is automatically initialized)
orchestrator = AttackTestOrchestrator()

# Run tests (PCAP validation happens automatically)
report = orchestrator.test_all_attacks()

# Check PCAP validation results
for result in report.results:
    if result.pcap_validation:
        print(f"{result.attack_name}: {result.pcap_validation.passed}")
```

## Testing

Run the test suite:

```bash
cd recon
python test_pcap_content_validator.py
```

## Validation Result Structure

```python
@dataclass
class PCAPValidationResult:
    passed: bool                          # Overall pass/fail
    pcap_file: Path                       # Path to PCAP file
    packet_count: int                     # Total packets
    expected_packet_count: Optional[int]  # Expected count
    issues: List[ValidationIssue]         # All issues found
    warnings: List[str]                   # Warnings
    details: Dict[str, Any]               # Additional details
```

## Issue Severity Levels

- **error**: Critical failures (e.g., packet count mismatch)
- **warning**: Non-critical issues (e.g., TTL mismatch)
- **info**: Informational (e.g., retransmissions)

## Attack-Specific Support

The validator automatically configures validation rules for known attacks:

- **badsum attacks**: Expects bad checksums
- **fake attacks**: Validates TTL values
- **split attacks**: Estimates packet count
- **fakeddisorder**: Validates TTL and checksums

## Example Output

```
PCAP Validation: PASSED
File: test_fakeddisorder.pcap
Packets: 2
Errors: 0, Warnings: 0
```

## Files

- `core/pcap_content_validator.py` - Main validator module
- `test_pcap_content_validator.py` - Test suite
- `test_all_attacks.py` - Integrated orchestrator

## Requirements

- Python 3.7+
- Scapy (`pip install scapy`)

## Next Steps

- Task 3: Module Debugging and Fixes
- Task 4: Baseline Testing System
- Task 5: Real Domain Testing

## Documentation

See `TASK2_PCAP_CONTENT_VALIDATOR_COMPLETION_REPORT.md` for detailed implementation report.
