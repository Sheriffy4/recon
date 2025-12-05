# PCAP Validation Tool Usage Guide

## Overview

The `validate_pcap.py` tool validates PCAP captures against expected DPI bypass strategies defined in `domain_rules.json`. It provides detailed compliance reports, identifies issues, and suggests patches to update your strategy rules.

## Requirements

- Python 3.7+
- Scapy library
- Valid `domain_rules.json` file
- PCAP file to validate

## Basic Usage

```bash
python validate_pcap.py <pcap_file> <domain>
```

### Example

```bash
python validate_pcap.py capture.pcap youtube.com
```

## Command-Line Options

| Option | Description |
|--------|-------------|
| `pcap_file` | Path to PCAP file to validate (required) |
| `domain` | Domain name to validate against (required) |
| `--rules RULES` | Path to domain_rules.json file (default: domain_rules.json) |
| `--target-ip IP` | Target IP address to filter TCP streams |
| `--output FILE` | Save JSON report to file |
| `--verbose` | Enable verbose logging |

## Examples

### Basic Validation

```bash
python validate_pcap.py capture.pcap example.com
```

### With Custom Rules File

```bash
python validate_pcap.py capture.pcap example.com --rules custom_rules.json
```

### Filter by Target IP

```bash
python validate_pcap.py capture.pcap example.com --target-ip 1.2.3.4
```

### Save JSON Report

```bash
python validate_pcap.py capture.pcap example.com --output report.json
```

### Verbose Mode

```bash
python validate_pcap.py capture.pcap example.com --verbose
```

## Output

The tool provides a comprehensive report including:

### 1. Strategy Information
- Strategy type
- List of attacks
- Parameters

### 2. Detected Attacks
- Fake attack detection (with TTL, badsum/badseq info)
- Split attack detection (fragment count, split positions)
- Disorder attack detection (disorder type)

### 3. Attack Verdicts
- Shows which expected attacks were matched
- Identifies missing attacks

### 4. Issues Found
- Lists all compliance issues
- Provides specific details about mismatches

### 5. Proposed Patch
- JSON patch that can be applied to domain_rules.json
- Updates strategy to match detected attacks

### 6. Compliance Score
- Score out of maximum possible
- Percentage compliance
- Pass/Warn/Fail status

## Compliance Scoring

- **✅ PASS (90-100%)**: Excellent compliance
- **⚠️ WARN (70-89%)**: Acceptable compliance with issues
- **❌ FAIL (<70%)**: Poor compliance, review issues

## Exit Codes

- `0`: Success (compliance >= 70%)
- `1`: Failure (compliance < 70% or error)
- `130`: Interrupted by user

## JSON Report Format

When using `--output`, the tool saves a JSON report with the following structure:

```json
{
  "domain": "example.com",
  "expected_strategy": {
    "type": "fake",
    "attacks": ["fake", "split"],
    "params": {...},
    "metadata": {...}
  },
  "detected_attacks": {
    "fake": true,
    "fake_count": 1,
    "fake_ttl": 1.0,
    "split": true,
    "fragment_count": 2,
    ...
  },
  "score": 20,
  "max_score": 20,
  "compliance_percentage": 100.0,
  "issues": [],
  "verdicts": {
    "fake": true,
    "split": true
  },
  "proposed_patch": null
}
```

## Troubleshooting

### "PCAP file not found"
- Verify the PCAP file path is correct
- Use absolute path if relative path doesn't work

### "No strategy found for domain"
- Check if domain exists in domain_rules.json
- Tool will use default_strategy if available
- Add strategy to domain_rules.json first

### "No ClientHello found in PCAP"
- PCAP may not contain TLS handshake
- Verify PCAP was captured during connection establishment
- Check if target_ip filter is too restrictive

### "No TCP streams found"
- PCAP may be empty or corrupted
- Try without --target-ip filter
- Verify PCAP contains TCP traffic

## Integration with Workflow

This tool is part of the attack-application-parity workflow:

1. **Capture PCAP**: Run your DPI bypass with packet capture enabled
2. **Validate**: Use this tool to check compliance
3. **Review Issues**: Examine any mismatches
4. **Update Rules**: Apply proposed patch if needed
5. **Re-test**: Verify fixes work correctly

## Related Tools

- `deep_compare_testing_vs_production.py`: Compare testing vs production modes
- `cli.py`: Run DPI bypass in testing mode
- `recon_service.py`: Run DPI bypass in production mode

## Requirements Validation

This tool validates:
- **Requirement 3.6**: PCAP validation and compliance checking
- **Requirement 9.2**: Compliance reports with scores and patches
- **Requirement 9.5**: Detailed diagnostic output
