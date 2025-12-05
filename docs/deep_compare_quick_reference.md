# Deep Compare Script - Quick Reference

## Quick Start

```bash
python deep_compare_testing_vs_production.py \
  --testing-pcap log1.pcap \
  --production-pcap log2.pcap \
  --domain nnmclub.to \
  --target-ip 104.21.112.1
```

## What It Does

1. **Loads Strategy**: Finds the expected strategy for the domain from `domain_rules.json`
2. **Analyzes Testing PCAP**: Checks what attacks were actually applied in testing mode
3. **Analyzes Production PCAP**: Checks what attacks were actually applied in production mode
4. **Compares JA3**: Verifies TLS fingerprints match between modes
5. **Generates Report**: Shows compliance scores, issues, and proposed fixes

## Understanding the Output

### Compliance Score

```
Compliance Score: 80/100 (80.0%)
```

- **100%**: Perfect - all expected attacks detected with correct parameters
- **80-99%**: Good - all attacks present but some parameter mismatches
- **50-79%**: Poor - some attacks missing or incorrect
- **<50%**: Critical - major differences from expected strategy

### Detected Attacks

```
Detected Attacks:
  - Fake: True (count=1, ttl=1.0)
  - Split: True (fragments=6, near_sni=True)
  - Disorder: False (type=none)
```

- **Fake**: Low TTL decoy packets detected
- **Split**: Payload fragmentation detected
- **Disorder**: Out-of-order packet delivery detected

### Issues

```
⚠️ Issues:
  - Expected attack 'disorder' not detected in PCAP
  - TTL mismatch: expected 1, detected 2.0
```

Each issue explains what's wrong and what was expected.

### Proposed Patch

```json
{
  "domain": "example.com",
  "operation": "update",
  "path": "/domain_rules/example.com",
  "value": {
    "attacks": ["fake", "multisplit"],
    "params": {
      "ttl": 2,
      "split_count": 6
    }
  }
}
```

This patch can be applied to `domain_rules.json` to match what was actually detected.

## Common Scenarios

### Scenario 1: Testing and Production Match

```
📊 Compliance Summary:
  Testing:    100.0%
  Production: 100.0%
  Difference: 0.0%

✅ ОБА режима полностью соответствуют стратегии!
```

**Action**: None needed - everything works correctly!

### Scenario 2: Testing Missing Attacks

```
📊 Compliance Summary:
  Testing:    60.0%
  Production: 100.0%
  Difference: 40.0%

❌ TESTING режим НЕ полностью соответствует стратегии!
🚨 КРИТИЧНО: Режимы применяют стратегию ПО-РАЗНОМУ!
```

**Action**: Fix testing mode to apply all attacks correctly.

### Scenario 3: Both Modes Have Issues

```
📊 Compliance Summary:
  Testing:    80.0%
  Production: 80.0%
  Difference: 0.0%

⚠️ Оба режима имеют одинаковые проблемы - возможно проблема в стратегии
```

**Action**: Review the strategy definition in `domain_rules.json`.

### Scenario 4: JA3 Mismatch

```
⚠️ JA3 fingerprints differ - TLS stacks may behave differently
   This could cause DPI to react differently to the same attacks!
```

**Action**: Investigate why TLS stacks differ (different libraries, versions, etc.).

## Troubleshooting

### No Strategy Found

```
⚠️ No strategy found for example.com
```

**Fix**: Add strategy to `domain_rules.json` or ensure domain matching works.

### No ClientHello Found

```
❌ TESTING режим НЕ полностью соответствует стратегии!
   Проблемы:
     - No ClientHello found in PCAP
```

**Fix**: Ensure PCAP captures the TLS handshake. Check that:
- Target IP is correct
- HTTPS traffic is being captured
- Capture started before connection

### Script Takes Too Long

**Fix**: Use `--target-ip` to filter streams:

```bash
python deep_compare_testing_vs_production.py \
  --testing-pcap log1.pcap \
  --production-pcap log2.pcap \
  --domain nnmclub.to \
  --target-ip 104.21.112.1
```

## Advanced Usage

### Custom PCAP Files

```bash
python deep_compare_testing_vs_production.py \
  --testing-pcap /path/to/testing.pcap \
  --production-pcap /path/to/production.pcap \
  --domain example.com \
  --target-ip 1.2.3.4
```

### With Legacy Analysis

```bash
python deep_compare_testing_vs_production.py \
  --testing-pcap log1.pcap \
  --production-pcap log2.pcap \
  --domain nnmclub.to \
  --target-ip 104.21.112.1 \
  --legacy-analysis
```

This adds the old packet-by-packet analysis for detailed debugging.

## Integration with Workflow

1. **Capture Testing PCAP**:
   ```bash
   # Run testing mode and capture traffic
   python cli.py auto --domain nnmclub.to
   ```

2. **Capture Production PCAP**:
   ```bash
   # Run production service and capture traffic
   python recon_service.py
   ```

3. **Compare**:
   ```bash
   python deep_compare_testing_vs_production.py \
     --testing-pcap testing.pcap \
     --production-pcap production.pcap \
     --domain nnmclub.to
   ```

4. **Fix Issues**: Apply proposed patches or fix code

5. **Re-test**: Repeat until 100% compliance

## Key Metrics

- **Compliance Score**: Overall match percentage
- **Attack Detection**: Which attacks were found
- **Parameter Accuracy**: How well parameters match
- **JA3 Match**: Whether TLS stacks are identical

## Getting Help

```bash
python deep_compare_testing_vs_production.py --help
```

For detailed documentation, see `docs/deep_compare_updates.md`.
