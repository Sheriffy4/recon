# TLS Version Diagnostics Guide

## Overview

The TLS Version Diagnostics module helps identify TLS version mismatches between TEST and BYPASS modes that can cause inconsistent testing results.

## Quick Start

```python
from core.validation.tls_version_checker import TLSVersionChecker

# Extract TLS version from ClientHello
tls_version = TLSVersionChecker.extract_tls_version(clienthello_bytes)
print(f"TLS Version: {tls_version}")  # Output: "TLS 1.2" or "TLS 1.3"

# Compare TEST vs BYPASS
is_consistent, details = TLSVersionChecker.check_consistency(
    test_clienthello,
    bypass_clienthello
)

if not is_consistent:
    print(f"⚠️  Version mismatch detected!")
    print(f"TEST: {details['test_version']}")
    print(f"BYPASS: {details['bypass_version']}")
```

## Common Use Cases

### 1. PCAP Analysis

When analyzing PCAP files from TEST and BYPASS modes:

```python
from scapy.all import rdpcap, TCP
from core.validation.tls_version_checker import TLSVersionChecker

# Load PCAPs
test_pkts = rdpcap('test.pcap')
bypass_pkts = rdpcap('bypass.pcap')

# Find ClientHello packets (first packet with TLS handshake)
test_hello = None
bypass_hello = None

for pkt in test_pkts:
    if pkt.haslayer(TCP) and pkt[TCP].payload:
        payload = bytes(pkt[TCP].payload)
        if len(payload) > 6 and payload[0] == 0x16:  # TLS Handshake
            test_hello = payload
            break

for pkt in bypass_pkts:
    if pkt.haslayer(TCP) and pkt[TCP].payload:
        payload = bytes(pkt[TCP].payload)
        if len(payload) > 6 and payload[0] == 0x16:
            bypass_hello = payload
            break

# Compare versions
if test_hello and bypass_hello:
    is_consistent, details = TLSVersionChecker.check_consistency(
        test_hello, bypass_hello
    )
    
    if not is_consistent:
        print("❌ TLS version mismatch detected!")
        print(f"   This explains why testing doesn't match production.")
```

### 2. Strategy Validation

When validating that split_pos works for both TLS versions:

```python
from core.validation.tls_version_checker import TLSVersionChecker

# Typical ClientHello sizes
TLS12_SIZE = 562   # TLS 1.2 ClientHello
TLS13_SIZE = 1893  # TLS 1.3 ClientHello

# Validate split_pos
split_pos = 2
is_valid = TLSVersionChecker.validate_split_pos_for_versions(
    split_pos=split_pos,
    tls12_size=TLS12_SIZE,
    tls13_size=TLS13_SIZE
)

if not is_valid:
    print(f"❌ split_pos={split_pos} is too large for TLS 1.2!")
    print(f"   Use a smaller value that works for both versions.")
```

### 3. Automated Testing

Add TLS version checks to your test suite:

```python
import pytest
from core.validation.tls_version_checker import TLSVersionChecker

def test_tls_version_consistency():
    """Ensure TEST and BYPASS use same TLS version."""
    test_hello = capture_test_clienthello()
    bypass_hello = capture_bypass_clienthello()
    
    is_consistent, details = TLSVersionChecker.check_consistency(
        test_hello, bypass_hello
    )
    
    assert is_consistent, (
        f"TLS version mismatch: "
        f"TEST={details['test_version']}, "
        f"BYPASS={details['bypass_version']}"
    )
```

## API Reference

### `extract_tls_version(payload: bytes) -> Optional[str]`

Extracts TLS version from ClientHello payload.

**Parameters:**
- `payload`: Raw bytes of TLS ClientHello message

**Returns:**
- TLS version string (e.g., "TLS 1.2", "TLS 1.3")
- `None` if not found or invalid

**Example:**
```python
version = TLSVersionChecker.extract_tls_version(clienthello)
# Returns: "TLS 1.2" or "TLS 1.3"
```

### `extract_clienthello_size(payload: bytes) -> Optional[int]`

Extracts ClientHello message size from TLS record.

**Parameters:**
- `payload`: Raw bytes of TLS ClientHello message

**Returns:**
- Size of ClientHello in bytes
- `None` if not found or invalid

**Example:**
```python
size = TLSVersionChecker.extract_clienthello_size(clienthello)
# Returns: 562 or 1893
```

### `check_consistency(test_hello: bytes, bypass_hello: bytes) -> Tuple[bool, dict]`

Compares TLS versions and sizes between TEST and BYPASS ClientHello.

**Parameters:**
- `test_hello`: ClientHello from TEST mode
- `bypass_hello`: ClientHello from BYPASS mode

**Returns:**
- Tuple of `(is_consistent, details_dict)`
  - `is_consistent`: `True` if versions match
  - `details_dict`: Contains version and size information

**Details Dictionary:**
```python
{
    'test_version': "TLS 1.2",
    'bypass_version': "TLS 1.3",
    'test_size': 567,
    'bypass_size': 1898,
    'version_match': False,
    'size_diff_percent': 70.1
}
```

**Example:**
```python
is_consistent, details = TLSVersionChecker.check_consistency(
    test_hello, bypass_hello
)

if not is_consistent:
    print(f"Version mismatch: {details['test_version']} vs {details['bypass_version']}")
    print(f"Size difference: {details['size_diff_percent']:.1f}%")
```

### `validate_split_pos_for_versions(split_pos: int, tls12_size: int, tls13_size: int) -> bool`

Validates that split_pos works for both TLS 1.2 and TLS 1.3 ClientHello sizes.

**Parameters:**
- `split_pos`: Configured split position
- `tls12_size`: Typical TLS 1.2 ClientHello size
- `tls13_size`: Typical TLS 1.3 ClientHello size

**Returns:**
- `True` if split_pos is valid for both versions
- `False` if split_pos is too large for either version

**Example:**
```python
is_valid = TLSVersionChecker.validate_split_pos_for_versions(
    split_pos=2,
    tls12_size=562,
    tls13_size=1893
)
# Returns: True (2 < 562, so it works for both)

is_valid = TLSVersionChecker.validate_split_pos_for_versions(
    split_pos=600,
    tls12_size=562,
    tls13_size=1893
)
# Returns: False (600 > 562, too large for TLS 1.2)
```

## Understanding TLS Versions

### TLS Version Bytes

The TLS version is encoded in bytes 1-2 of the TLS record:

| Version | Bytes | Hex Value |
|---------|-------|-----------|
| TLS 1.0 | 0x03 0x01 | 0x0301 |
| TLS 1.1 | 0x03 0x02 | 0x0302 |
| TLS 1.2 | 0x03 0x03 | 0x0303 |
| TLS 1.3 | 0x03 0x04 | 0x0304 |

### Typical ClientHello Sizes

| Version | Typical Size | Notes |
|---------|--------------|-------|
| TLS 1.2 | ~562 bytes | Smaller, fits in 1 TCP segment |
| TLS 1.3 | ~1893 bytes | Larger, may span 2 TCP segments |

### Why Size Matters

When ClientHello spans multiple TCP segments:
- Strategy may only apply to first segment
- Second segment bypasses strategy application
- Testing with single-segment ClientHello doesn't reflect production

## Troubleshooting

### Problem: Version Mismatch Detected

**Symptom:**
```
⚠️  TLS version mismatch detected!
   TEST mode:   TLS 1.2
   BYPASS mode: TLS 1.3
```

**Solution:**
1. Configure TEST mode to use TLS 1.3
2. For curl: Use `--tls13-ciphers` or `--tlsv1.3` flag
3. For Python requests: Configure SSL context to use TLS 1.3
4. Ensure both modes use same TLS library version

### Problem: Large Size Difference

**Symptom:**
```
⚠️  ClientHello size differs significantly!
   TEST mode:   567 bytes
   BYPASS mode: 1898 bytes
   Difference:  70.1%
```

**Solution:**
- This usually indicates TLS version mismatch
- Check TLS versions first
- Ensure both modes use same cipher suites
- Consider using same TLS library in both modes

### Problem: split_pos Too Large

**Symptom:**
```
❌ split_pos=600 is too large!
   TLS 1.2 size: 562 bytes
   TLS 1.3 size: 1893 bytes
```

**Solution:**
- Use smaller split_pos that works for both versions
- Recommended: split_pos=2 (works for all TLS versions)
- Maximum safe value: min(tls12_size, tls13_size) - 1

## Best Practices

1. **Always check TLS version consistency** in PCAP analysis
2. **Use small split_pos values** (e.g., 2) that work for all TLS versions
3. **Configure TEST mode** to match BYPASS mode TLS version
4. **Add TLS version checks** to automated test suites
5. **Log TLS versions** in production for debugging

## Examples

See `examples/tls_version_diagnostics_demo.py` for comprehensive examples of:
- TLS version extraction
- Consistency checking
- Split position validation
- Real-world scenario analysis

Run the demo:
```bash
python examples/tls_version_diagnostics_demo.py
```

## Integration with Existing Tools

The TLS version checker is already integrated into:
- `detailed_comparison_nnmclub.py` - PCAP comparison tool

To integrate into your own tools:
```python
from core.validation.tls_version_checker import TLSVersionChecker

# Add to your PCAP analysis function
def analyze_pcap(pcap_file):
    # ... existing code ...
    
    # Extract ClientHello
    clienthello = extract_clienthello_from_pcap(pcap_file)
    
    # Log TLS version
    tls_version = TLSVersionChecker.extract_tls_version(clienthello)
    print(f"TLS Version: {tls_version}")
    
    # ... rest of analysis ...
```

## Related Documentation

- [Requirements Document](.kiro/specs/strategy-application-bugs/requirements.md) - Requirement 10
- [Design Document](.kiro/specs/strategy-application-bugs/design.md) - TLSVersionChecker component
- [Task Summary](TASK7_TLS_VERSION_DIAGNOSTICS_COMPLETE.md) - Implementation details
