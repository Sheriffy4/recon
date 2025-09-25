# PCAP Analysis Report
## Summary
- Total packets: 1637
- Total flows: 441
- Construction issues: 0
- Checksum issues: 399
- SNI issues: 0
- Sequence issues: 60

## Checksum Issues
- Invalid checksum (not intentionally corrupted)
  - Actual: 0x610D
  - Expected: 0x2585
- Invalid checksum (not intentionally corrupted)
  - Actual: 0x610D
  - Expected: 0x2585
- Invalid checksum (not intentionally corrupted)
  - Actual: 0x610D
  - Expected: 0x2585
- Invalid checksum (not intentionally corrupted)
  - Actual: 0x5F08
  - Expected: 0xFF6E
- Invalid checksum (not intentionally corrupted)
  - Actual: 0x610D
  - Expected: 0x2584
- Invalid checksum (not intentionally corrupted)
  - Actual: 0x5F08
  - Expected: 0xFF6D
- Invalid checksum (not intentionally corrupted)
  - Actual: 0x5F08
  - Expected: 0xFF6D
- Invalid checksum (not intentionally corrupted)
  - Actual: 0x5F08
  - Expected: 0xFF6D
- Invalid checksum (not intentionally corrupted)
  - Actual: 0x5F08
  - Expected: 0xFF6D
- Invalid checksum (not intentionally corrupted)
  - Actual: 0x5F08
  - Expected: 0xFF6D

## Recommendations
1. **Fix Checksum Corruption**: Ensure bad checksums are properly applied to fake packets
4. **Fix Sequence Numbers**: Align sequence number calculation with zapret