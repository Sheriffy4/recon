# Attack Validation - Quick Reference

## Quick Commands

```bash
# Run integration test
python validate_all_attacks_integration.py

# Generate report
python generate_final_integration_report.py

# View summary
cat integration_validation_report.json | jq '.summary'

# View issues
cat integration_validation_report.json | jq '.issues[:5]'
```

## Python API

```python
# Validate single PCAP
from core.packet_validator import PacketValidator

validator = PacketValidator()
result = validator.validate_attack(
    attack_name='fakeddisorder',
    params={'split_pos': 76, 'ttl': 3, 'fooling': ['badsum']},
    pcap_file='test.pcap'
)

# Validate all PCAPs
from validate_all_attacks_integration import IntegrationValidator

validator = IntegrationValidator()
results = validator.validate_all()
validator.print_summary()
```

## Validation Rules

| Aspect | Strict Mode | Lenient Mode |
|--------|-------------|--------------|
| Seq Numbers | Exact | ±10 or allow disorder |
| Checksums | Enforce all | Validate fake only |
| TTL | Exact value | Range (1-10 fake, 30-128 real) |
| Packet Count | Exact | Range (min-max) |

## Attack Types

| Attack | Expected Packets | Key Validation |
|--------|------------------|----------------|
| fake | 2 (fake + real) | TTL, checksum |
| split | 2 (part1 + part2) | Seq numbers |
| disorder | 2-3 (parts out of order) | Allow non-sequential |
| fakeddisorder | 3 (fake + 2 parts) | Overlapping seq, TTL |
| multisplit | 3+ (multiple parts) | Sequential seq |
| seqovl | 2+ (overlapping) | Allow overlap |

## Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| Too many packets | Background traffic | Enable filtering |
| Seq not sequential | Multiple connections | Use lenient mode |
| Bad checksums | Checksum offloading | Disable strict checksums |
| Wrong TTL | Hop decrements | Use TTL ranges |

## File Locations

```
recon/
├── validate_all_attacks_integration.py  # Integration test
├── fix_validation_issues.py             # Fix documentation
├── generate_final_integration_report.py # Report generator
├── ATTACK_VALIDATION_USER_GUIDE.md      # User guide
├── VALIDATION_PROCESS_DOCUMENTATION.md  # Process docs
├── integration_validation_report.json   # Raw results
└── final_integration_results/           # Reports
    ├── final_integration_report_*.md
    ├── final_integration_report_*.txt
    └── final_integration_report_*.json
```

## Modes

```python
# Strict mode (testing)
validator = PacketValidator(strict_mode=True)

# Lenient mode (production)
validator = PacketValidator(strict_mode=False)
```

## Filtering

```python
# Filter to attack packets only
attack_packets = validator.filter_attack_packets(
    packets=all_packets,
    attack_name='fakeddisorder'
)
```

## Grouping

```python
# Group by TCP connection
connections = validator.group_by_connection(packets)
for conn_key, conn_packets in connections.items():
    # Validate each connection separately
    result = validator.validate_connection(conn_packets, spec, params)
```

## Report Generation

```python
# Generate comprehensive report
from generate_final_integration_report import FinalReportGenerator

generator = FinalReportGenerator()
md_file, txt_file, json_file = generator.save_report()
```

## Troubleshooting

```python
# Enable debug logging
import logging
logging.basicConfig(level=logging.DEBUG)

# Verbose output
validator = PacketValidator(verbose=True)

# Check specific aspect
result = validator.validate_seq_numbers(packets, spec, params)
print(f"Passed: {result.passed}")
print(f"Message: {result.message}")
```

## Success Criteria

- ✅ 80%+ pass rate for real-world PCAPs
- ✅ <5% false positive rate
- ✅ <1% false negative rate
- ✅ 100% attack type coverage

## Documentation

- **User Guide:** `ATTACK_VALIDATION_USER_GUIDE.md`
- **Process Docs:** `VALIDATION_PROCESS_DOCUMENTATION.md`
- **Completion Report:** `TASK5_INTEGRATION_TESTING_COMPLETION_REPORT.md`
- **Summary:** `TASK5_SUMMARY.md`

## Support

- Check user guide for detailed examples
- See process documentation for workflow
- Review completion report for findings
- Read summary for quick overview

---

**Quick Reference Version:** 1.0  
**Last Updated:** 2025-10-05
