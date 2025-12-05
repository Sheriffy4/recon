# nnmclub.to Strategy Behavior Documentation

## Overview

This document describes the actual behavior of the DPI bypass strategy for nnmclub.to after all bug fixes have been applied. The strategy uses a combination of fake packets, multi-fragment splitting, and disorder to evade Deep Packet Inspection.

## Strategy Configuration

```json
{
  "domain": "nnmclub.to",
  "type": "fake",
  "attacks": ["fake", "multisplit", "disorder"],
  "params": {
    "ttl": 1,
    "fooling": "badseq",
    "split_pos": 2,
    "split_count": 6,
    "disorder_method": "reverse",
    "fake_mode": "per_fragment",
    "no_fallbacks": true,
    "forced": true
  }
}
```

## Parameter Effects

### ttl=1

- **Purpose**: Sets IP TTL (Time To Live) field to 1 in all fake packets
- **Effect**: Fake packets expire after 1 network hop (before reaching DPI device)
- **Behavior**: Real packets use normal TTL (64 or 128), fake packets use TTL=1
- **Why it works**: DPI sees fake packet, but it never reaches the destination server

### fooling=badseq

- **Purpose**: Modifies TCP sequence number in fake packets to make them invalid
- **Effect**: Sequence number is offset by 0x10000000 (268,435,456)
- **Behavior**: DPI sees invalid sequence number and ignores the fake packet
- **Alternative**: `badsum` sets TCP checksum to 0xDEAD instead

### split_count=6

- **Purpose**: Divides the payload into 6 equal fragments
- **Effect**: For a 120-byte payload, creates ~20 bytes per fragment
- **Behavior**: Fragments are sent as separate TCP segments
- **Why it works**: DPI must reassemble all fragments to see full content

### fake_mode=per_fragment

- **Purpose**: Creates one fake packet before each real fragment
- **Effect**: Total packets = 6 fake + 6 real = 12 packets
- **Behavior**: Pattern is [fake1, real1, fake2, real2, fake3, real3, ...]
- **Why it works**: Each real fragment is preceded by a decoy

### disorder_method=reverse

- **Purpose**: Reverses the order of all segments before sending
- **Effect**: Original order [fake1, real1, ...] becomes [..., real1, fake1]
- **Behavior**: DPI sees packets arriving out of order
- **Why it works**: Makes reassembly more difficult for DPI

## Expected PCAP Output

### Packet Count
- **Total packets**: 12
- **Fake packets**: 6
- **Real packets**: 6

### Packet Sequence (after disorder)

After applying the strategy to a 120-byte TLS ClientHello:

| # | Type | Length | TTL | Fooling |
|---|------|--------|-----|---------|
| 1 | REAL | ~20 | 64/128 | none |
| 2 | FAKE | ~20 | 1 | badseq |
| 3 | REAL | ~20 | 64/128 | none |
| 4 | FAKE | ~20 | 1 | badseq |
| 5 | REAL | ~20 | 64/128 | none |
| 6 | FAKE | ~20 | 1 | badseq |
| 7 | REAL | ~20 | 64/128 | none |
| 8 | FAKE | ~20 | 1 | badseq |
| 9 | REAL | ~20 | 64/128 | none |
| 10 | FAKE | ~20 | 1 | badseq |
| 11 | REAL | ~20 | 64/128 | none |
| 12 | FAKE | ~20 | 1 | badseq |

Note: The exact order depends on the disorder implementation. The pattern alternates between REAL and FAKE after reversal.

### Identifying Fake Packets in PCAP

Fake packets can be identified by:
1. **TTL=1**: IP header TTL field is 1 (or very low)
2. **Modified sequence**: TCP sequence number is offset by 0x10000000
3. **Same payload**: Contains same data as corresponding real fragment

## Troubleshooting Guide

### If Strategy Fails

1. **Capture PCAP**: Use `python cli.py auto nnmclub.to --capture` to capture traffic
2. **Analyze PCAP**: Run `python detailed_comparison_nnmclub.py` to compare TEST and BYPASS modes
3. **Check parameters**: Verify all parameters are applied correctly

### Common Issues and Solutions

| Issue | Symptom | Cause | Solution |
|-------|---------|-------|----------|
| TTL=128 | Fake packets reach server | Hardcoded default not removed | Check `apply_fake()` method |
| fooling=badsum | Checksum corrupted instead of sequence | Parameter normalization bug | Check `ParameterNormalizer` |
| 2 fragments | Only 2 segments created | split_count ignored | Check `apply_split()` method |
| 1 fake | Only 1 fake packet | fake_mode not implemented | Check `_fake_per_fragment()` |
| No disorder | Packets in original order | apply_disorder() not called | Check `apply_recipe()` combo logic |

### TLS Version Mismatch

**Problem**: TEST mode may use different TLS version than BYPASS mode

| Mode | TLS Version | ClientHello Size |
|------|-------------|------------------|
| TEST | TLS 1.2 | ~562 bytes |
| BYPASS | TLS 1.3 | ~1893 bytes |

**Impact**: Different ClientHello sizes cause different TCP segmentation behavior

**Solution**: Configure TEST mode to use the same TLS library/version as BYPASS mode

### Verifying Parameter Application

Use the following checks in PCAP analysis:

```python
# Check TTL
for packet in fake_packets:
    assert packet.ip.ttl == 1, "TTL not applied"

# Check fooling (badseq)
for packet in fake_packets:
    # Sequence should be offset by 0x10000000
    assert packet.tcp.seq != real_packet.tcp.seq, "Sequence not modified"

# Check fragment count
assert len(real_packets) == 6, "Wrong fragment count"

# Check fake count
assert len(fake_packets) == 6, "Wrong fake count"
```

## Validation Tests

The strategy is validated by the following tests in `tests/test_nnmclub_strategy_validation.py`:

### Task 11.1: Test Complete Strategy
- `test_strategy_loads_from_domain_rules`: Verifies strategy loads from domain_rules.json
- `test_ttl_parameter_applied`: Verifies TTL=1 in all fake packets
- `test_fooling_badseq_applied`: Verifies fooling=badseq in all fake packets
- `test_split_count_6_fragments`: Verifies 6 real fragments created
- `test_fake_mode_per_fragment`: Verifies 6 fake packets created
- `test_disorder_reverse_applied`: Verifies segments are reversed
- `test_test_bypass_mode_parity`: Verifies TEST and BYPASS modes are identical

### Task 11.2: Document Behavior
- `test_document_strategy_behavior`: Generates detailed behavior documentation

### Task 11.3: Validate Effectiveness
- `test_strategy_produces_valid_segments`: Verifies segments are valid
- `test_fake_packets_have_correct_properties`: Verifies fake packet properties
- `test_strategy_vs_baseline_comparison`: Compares with baseline (no strategy)
- `test_complete_strategy_validation`: Complete end-to-end validation

## Running Validation

```bash
# Run all nnmclub.to validation tests
python -m pytest tests/test_nnmclub_strategy_validation.py -v

# Run with detailed output
python -m pytest tests/test_nnmclub_strategy_validation.py -v -s

# Run specific test class
python -m pytest tests/test_nnmclub_strategy_validation.py::TestNnmclubStrategyComplete -v
```

## Related Files

- `domain_rules.json`: Strategy configuration
- `tests/test_nnmclub_strategy_validation.py`: Validation tests
- `detailed_comparison_nnmclub.py`: PCAP comparison script
- `core/bypass/unified_attack_dispatcher.py`: Strategy application logic
- `core/strategy/normalizer.py`: Parameter normalization
- `core/strategy/combo_builder.py`: Recipe building

## Changelog

- **2025-11-28**: Initial documentation after bug fixes
  - TTL propagation fixed (was 128, now 1)
  - Fooling method preserved (badseq not replaced with badsum)
  - Split count implemented (6 fragments instead of 2)
  - Fake mode per_fragment implemented (6 fakes instead of 1)
  - Disorder applied in combo attacks
