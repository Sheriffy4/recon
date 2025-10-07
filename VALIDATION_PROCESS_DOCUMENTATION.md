# Attack Validation Process Documentation

**Version:** 1.0  
**Date:** 2025-10-05  
**Status:** Complete

## Overview

This document describes the complete validation process for DPI bypass attacks, from PCAP capture to final report generation.

## Validation Workflow

```
┌─────────────────┐
│  Capture PCAP   │
│   (Wireshark)   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Infer Attack   │
│  Type from Name │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Load Attack    │
│  Specification  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Parse PCAP     │
│  Extract Packets│
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Filter Attack  │
│  Packets        │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Group by       │
│  Connection     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Validate:      │
│  - Seq Numbers  │
│  - Checksums    │
│  - TTL Values   │
│  - Packet Count │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Generate       │
│  Report         │
└─────────────────┘
```

## Step-by-Step Process

### Step 1: Capture PCAP

**Tools:** Wireshark, tcpdump, or recon CLI

```bash
# Using recon CLI
python cli.py x.com --strategy "fakeddisorder(split_pos=76, ttl=3)" --pcap test.pcap

# Using Wireshark
# 1. Start capture on network interface
# 2. Apply filter: tcp.port == 443
# 3. Perform attack
# 4. Stop capture
# 5. Save as test.pcap
```

**Output:** `test.pcap` file

### Step 2: Infer Attack Type

**Method:** Analyze filename or specify explicitly

```python
# Automatic inference
attack_info = validator.infer_attack_from_filename('test_fakeddisorder.pcap')
# Returns: ('fakeddisorder', {})

# Known patterns
'zapret.pcap' -> ('fakeddisorder', {'split_pos': 76, 'ttl': 3, ...})
'test_split_3.pcap' -> ('split', {'split_pos': 3})
'test_fake.pcap' -> ('fake', {})

# Manual specification
attack_name = 'fakeddisorder'
params = {'split_pos': 76, 'overlap_size': 336, 'ttl': 3, 'fooling': ['badsum']}
```

### Step 3: Load Attack Specification

**Location:** `specs/attacks/*.yaml`

```python
from core.attack_spec_loader import AttackSpecLoader

loader = AttackSpecLoader()
spec = loader.load_spec('fakeddisorder')

# Spec contains:
# - Attack name and description
# - Parameter definitions
# - Expected packet structure
# - Validation rules
```

**Example Spec:**
```yaml
name: fakeddisorder
parameters:
  - name: split_pos
    type: int
    required: true
  - name: ttl
    type: int
    default: 1
expected_packets:
  count:
    min: 2
    max: 10
validation_rules:
  strict_mode: false
  sequence_numbers:
    allow_disorder: true
```

### Step 4: Parse PCAP

**Tool:** Scapy

```python
from scapy.all import rdpcap

# Read PCAP file
packets = rdpcap('test.pcap')

# Extract packet information
for pkt in packets:
    if pkt.haslayer('TCP'):
        print(f"Seq: {pkt['TCP'].seq}")
        print(f"TTL: {pkt['IP'].ttl}")
        print(f"Checksum: {pkt['TCP'].chksum}")
```

### Step 5: Filter Attack Packets

**Purpose:** Remove background traffic, focus on attack

```python
def filter_attack_packets(packets, attack_name):
    filtered = []
    
    for pkt in packets:
        # Only TCP packets
        if not pkt.haslayer('TCP'):
            continue
        
        # Only port 443 (TLS)
        if pkt['TCP'].dport != 443:
            continue
        
        # Only packets with payload
        if not pkt.haslayer('Raw'):
            continue
        
        # Only TLS ClientHello
        payload = bytes(pkt['Raw'].load)
        if len(payload) > 5 and payload[0] == 0x16:  # TLS Handshake
            filtered.append(pkt)
    
    return filtered
```

**Result:** Only attack-related packets remain

### Step 6: Group by Connection

**Purpose:** Validate each TCP connection separately

```python
def group_by_connection(packets):
    connections = {}
    
    for pkt in packets:
        # Create connection key (5-tuple)
        conn_key = (
            pkt['IP'].src,
            pkt['IP'].dst,
            pkt['TCP'].sport,
            pkt['TCP'].dport,
            'TCP'
        )
        
        if conn_key not in connections:
            connections[conn_key] = []
        
        connections[conn_key].append(pkt)
    
    return connections
```

**Result:** Packets grouped by connection

### Step 7: Validate Packets

**Validation Aspects:**

#### 7.1 Sequence Numbers

```python
def validate_seq_numbers(packets, spec, params):
    # For each connection
    for conn_packets in connections.values():
        # Sort by timestamp
        conn_packets.sort(key=lambda p: p.time)
        
        # Check sequential order (unless disorder attack)
        if spec['attack_type'] not in ['disorder', 'fakeddisorder']:
            for i in range(len(conn_packets) - 1):
                expected_seq = conn_packets[i]['TCP'].seq + len(conn_packets[i]['Raw'].load)
                actual_seq = conn_packets[i+1]['TCP'].seq
                
                if expected_seq != actual_seq:
                    return ValidationDetail(
                        aspect='sequence_numbers',
                        passed=False,
                        expected=f"seq={expected_seq}",
                        actual=f"seq={actual_seq}"
                    )
    
    return ValidationDetail(aspect='sequence_numbers', passed=True)
```

#### 7.2 Checksums

```python
def validate_checksums(packets, spec, params):
    fooling = params.get('fooling', [])
    
    if 'badsum' in fooling:
        # Fake packet (first) should have bad checksum
        fake_pkt = packets[0]
        if fake_pkt['TCP'].chksum == calculate_checksum(fake_pkt):
            return ValidationDetail(
                aspect='checksum',
                passed=False,
                message="Fake packet should have bad checksum"
            )
        
        # Real packets should have good checksum (in strict mode)
        if strict_mode:
            for pkt in packets[1:]:
                if pkt['TCP'].chksum != calculate_checksum(pkt):
                    return ValidationDetail(
                        aspect='checksum',
                        passed=False,
                        message="Real packet has bad checksum"
                    )
    
    return ValidationDetail(aspect='checksum', passed=True)
```

#### 7.3 TTL Values

```python
def validate_ttl(packets, spec, params):
    expected_ttl = params.get('ttl', 1)
    
    # Fake packet should have low TTL
    fake_pkt = packets[0]
    if fake_pkt['IP'].ttl > 10:
        return ValidationDetail(
            aspect='ttl',
            passed=False,
            expected=f"ttl <= 10",
            actual=f"ttl={fake_pkt['IP'].ttl}"
        )
    
    # Real packets should have normal TTL
    for pkt in packets[1:]:
        if pkt['IP'].ttl < 30 or pkt['IP'].ttl > 128:
            return ValidationDetail(
                aspect='ttl',
                passed=False,
                expected="ttl in [30, 128]",
                actual=f"ttl={pkt['IP'].ttl}"
            )
    
    return ValidationDetail(aspect='ttl', passed=True)
```

#### 7.4 Packet Count

```python
def validate_packet_count(packets, spec, params):
    expected_min = spec['expected_packets']['count']['min']
    expected_max = spec['expected_packets']['count']['max']
    actual_count = len(packets)
    
    if actual_count < expected_min or actual_count > expected_max:
        return ValidationDetail(
            aspect='packet_count',
            passed=False,
            expected=f"{expected_min}-{expected_max} packets",
            actual=f"{actual_count} packets"
        )
    
    return ValidationDetail(aspect='packet_count', passed=True)
```

### Step 8: Generate Report

**Report Contents:**

1. **Executive Summary**
   - Overall pass/fail status
   - Total packets analyzed
   - Issues found

2. **Detailed Results**
   - Per-aspect validation results
   - Expected vs actual values
   - Error messages

3. **Visual Diffs**
   - Side-by-side comparison
   - Highlighted differences
   - Packet structure diagrams

4. **Recommendations**
   - Fixes for failures
   - Optimization suggestions
   - Best practices

**Report Formats:**
- Markdown (`.md`)
- Text (`.txt`)
- JSON (`.json`)
- HTML (`.html`)

## Validation Rules Reference

### Sequence Numbers

| Attack Type | Rule | Strict Mode | Lenient Mode |
|-------------|------|-------------|--------------|
| fake | Sequential | Exact | ±10 |
| split | Sequential | Exact | ±10 |
| disorder | Non-sequential | Allow | Allow |
| fakeddisorder | Overlapping | Allow | Allow |

### Checksums

| Fooling | Fake Packet | Real Packets | Strict Mode | Lenient Mode |
|---------|-------------|--------------|-------------|--------------|
| badsum | Bad | Good | Enforce | Validate fake only |
| none | Good | Good | Enforce | Ignore |

### TTL

| Packet Type | Strict Mode | Lenient Mode |
|-------------|-------------|--------------|
| Fake | Exact value | 1-10 |
| Real | 64 or 128 | 30-128 |

### Packet Count

| Attack Type | Strict Mode | Lenient Mode |
|-------------|-------------|--------------|
| fake | Exact (2) | 2-5 |
| split | Exact (2) | 2-5 |
| disorder | Exact (2-3) | 2-10 |
| fakeddisorder | Exact (3) | 2-10 |

## Common Validation Scenarios

### Scenario 1: Perfect Attack

```
Input: test_fakeddisorder.pcap
Attack: fakeddisorder(split_pos=76, ttl=3, fooling=['badsum'])

Packets:
1. Fake packet: seq=1000, ttl=3, checksum=BAD
2. Real part 2: seq=1076, ttl=64, checksum=GOOD
3. Real part 1: seq=1000, ttl=64, checksum=GOOD

Validation:
✅ Sequence numbers: PASS (overlapping allowed)
✅ Checksums: PASS (fake has bad, real have good)
✅ TTL: PASS (fake=3, real=64)
✅ Packet count: PASS (3 packets)

Result: PASS
```

### Scenario 2: Missing Badsum

```
Input: test_fakeddisorder.pcap
Attack: fakeddisorder(split_pos=76, ttl=3, fooling=['badsum'])

Packets:
1. Fake packet: seq=1000, ttl=3, checksum=GOOD ❌
2. Real part 2: seq=1076, ttl=64, checksum=GOOD
3. Real part 1: seq=1000, ttl=64, checksum=GOOD

Validation:
❌ Checksums: FAIL (fake should have bad checksum)
   Expected: bad checksum
   Actual: good checksum

Result: FAIL
```

### Scenario 3: Wrong TTL

```
Input: test_fake.pcap
Attack: fake(ttl=1, fooling=['badsum'])

Packets:
1. Fake packet: seq=1000, ttl=64, checksum=BAD ❌
2. Real packet: seq=1000, ttl=64, checksum=GOOD

Validation:
❌ TTL: FAIL (fake packet has wrong TTL)
   Expected: ttl <= 10
   Actual: ttl=64

Result: FAIL
```

### Scenario 4: Background Traffic

```
Input: production.pcap (contains 1000 packets)
Attack: fakeddisorder(split_pos=76, ttl=3)

Before filtering: 1000 packets
After filtering: 3 packets (TLS ClientHello only)

Validation:
✅ Packet count: PASS (3 packets after filtering)

Result: PASS
```

## Troubleshooting Guide

### Issue: "Too many packets"

**Cause:** PCAP contains background traffic

**Solution:**
```python
# Enable packet filtering
spec['validation_rules']['ignore_background_traffic'] = True

# Or filter manually
attack_packets = validator.filter_attack_packets(all_packets, 'fakeddisorder')
```

### Issue: "Sequence numbers not sequential"

**Cause:** Multiple TCP connections in PCAP

**Solution:**
```python
# Use connection-aware validation
validator = PacketValidator(strict_mode=False)

# Or group by connection first
connections = validator.group_by_connection(packets)
for conn_packets in connections.values():
    validator.validate_seq_numbers(conn_packets, spec, params)
```

### Issue: "Bad checksums everywhere"

**Cause:** Checksum offloading in captured traffic

**Solution:**
```python
# Use lenient mode
validator = PacketValidator(strict_mode=False)

# Or disable checksum validation
spec['validation_rules']['checksums']['strict'] = False
```

### Issue: "TTL too high"

**Cause:** Packet traversed multiple hops

**Solution:**
```python
# Use TTL ranges
spec['validation_rules']['ttl']['fake_packet']['max'] = 10
spec['validation_rules']['ttl']['real_packets']['min'] = 30
```

## Best Practices

### 1. Always Filter Attack Packets

```python
# Filter before validation
attack_packets = validator.filter_attack_packets(all_packets, attack_name)
result = validator.validate_attack_packets(attack_packets, spec, params)
```

### 2. Use Appropriate Mode

```python
# Testing: strict mode
validator = PacketValidator(strict_mode=True)

# Production: lenient mode
validator = PacketValidator(strict_mode=False)
```

### 3. Group by Connection

```python
# For multi-connection PCAPs
connections = validator.group_by_connection(packets)
for conn_key, conn_packets in connections.items():
    result = validator.validate_connection(conn_packets, spec, params)
```

### 4. Generate Reports

```python
# Always generate reports for analysis
validator.save_report('validation_report.json')
generator = FinalReportGenerator()
generator.save_report()
```

### 5. Handle Errors Gracefully

```python
try:
    result = validator.validate_attack(...)
except Exception as e:
    logger.error(f"Validation error: {e}")
    # Continue with next file
```

## Conclusion

This validation process ensures that all DPI bypass attacks generate correct packets according to their specifications. By following this process, you can:

- Validate attacks automatically
- Identify issues quickly
- Generate comprehensive reports
- Maintain high quality standards
- Ensure production readiness

---

**Document Version:** 1.0  
**Last Updated:** 2025-10-05  
**Maintained By:** Attack Validation Suite Team
