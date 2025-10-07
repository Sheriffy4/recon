# Real Domain Testing - Quick Start Guide

## Overview

The Real Domain Testing system allows you to test DPI bypass attacks against real domains from your sites.txt file. It provides DNS resolution, parallel execution, PCAP capture, validation, and comprehensive reporting.

## Prerequisites

- Python 3.8+
- sites.txt file with domains to test
- Required Python packages (see requirements.txt)

## Basic Usage

### 1. Test with Specific Attacks

```bash
python test_real_domains.py --domains sites.txt --attacks fake split disorder
```

This will:
- Load domains from sites.txt
- Test each domain with fake, split, and disorder attacks
- Generate comprehensive reports

### 2. Test All Available Attacks

```bash
python test_real_domains.py --domains sites.txt --all-attacks
```

### 3. Parallel Execution (Faster)

```bash
python test_real_domains.py --domains sites.txt --attacks fake --parallel --workers 8
```

Use parallel execution for faster testing with multiple domains.

### 4. Fast Testing (No PCAP Validation)

```bash
python test_real_domains.py --domains sites.txt --attacks fake --no-validation --no-pcap
```

Skip PCAP capture and validation for quick testing.

## Advanced Usage

### Custom Attack Parameters

```bash
python test_real_domains.py --domains sites.txt --attacks fake --params fake:ttl=8
```

### Custom Output Directory

```bash
python test_real_domains.py --domains sites.txt --attacks fake --output-dir my_results/
```

### List Available Attacks

```bash
python test_real_domains.py --list-attacks
```

### Verbose Logging

```bash
python test_real_domains.py --domains sites.txt --attacks fake --verbose
```

## sites.txt Format

The system supports multiple formats:

```
# Plain domains
example.com
google.com

# URLs (protocol is stripped)
https://x.com
https://youtube.com

# Domains with ports (port is stripped)
example.com:443

# Comments
# This is a comment
example.com  # Inline comment

# Empty lines are ignored

```

## Output

### Console Output

The system provides:
- Progress bars during execution
- Real-time status updates
- Summary tables with statistics
- Per-domain and per-attack success rates

### Report Files

Generated in the output directory:
- `domain_test_report_TIMESTAMP.json` - Machine-readable JSON report
- `domain_test_report_TIMESTAMP.txt` - Human-readable text report

### JSON Report Structure

```json
{
  "total_domains": 31,
  "total_attacks": 1,
  "total_tests": 31,
  "successful_tests": 15,
  "failed_tests": 16,
  "success_rate": 48.4,
  "domains_tested": ["x.com", "youtube.com", ...],
  "attacks_tested": ["fake"],
  "domain_stats": {
    "x.com": {
      "total": 1,
      "successful": 1,
      "failed": 0
    }
  },
  "attack_stats": {
    "fake": {
      "total": 31,
      "successful": 15,
      "failed": 16
    }
  },
  "results": [...]
}
```

## Common Use Cases

### 1. Quick Test of Key Domains

```bash
# Create a small test file
echo "google.com" > test_domains.txt
echo "cloudflare.com" >> test_domains.txt

# Test quickly
python test_real_domains.py --domains test_domains.txt --attacks fake --no-pcap
```

### 2. Full Production Test

```bash
# Test all domains with all attacks, capture PCAPs, validate everything
python test_real_domains.py --domains sites.txt --all-attacks --parallel --workers 4
```

### 3. Regression Testing

```bash
# Test specific attacks that were working before
python test_real_domains.py --domains sites.txt --attacks fake split disorder --output-dir regression_test/
```

### 4. Performance Testing

```bash
# Test with maximum parallelism
python test_real_domains.py --domains sites.txt --attacks fake --parallel --workers 16 --no-validation
```

## Troubleshooting

### DNS Resolution Failures

If you see DNS resolution failures:
- Check your internet connection
- Verify the domain names are correct
- Increase DNS timeout: `--dns-timeout 10.0`

### Slow Execution

If testing is slow:
- Enable parallel execution: `--parallel --workers 8`
- Disable PCAP validation: `--no-validation`
- Disable PCAP capture: `--no-pcap`

### Attack Not Found Errors

If you see "Attack not found" errors:
- List available attacks: `--list-attacks`
- Check attack name spelling
- Ensure attack is registered in the attack registry

### Memory Issues

If you run out of memory with many domains:
- Reduce worker count: `--workers 2`
- Test in batches (split sites.txt into smaller files)
- Disable PCAP capture: `--no-pcap`

## Performance Tips

1. **Use Parallel Execution:** 3-4x speedup with `--parallel --workers 4`
2. **Skip Validation:** 2x speedup with `--no-validation`
3. **Skip PCAP Capture:** 5x speedup with `--no-pcap` (simulation mode)
4. **DNS Caching:** Automatic, but you can adjust TTL with `--dns-cache-ttl 7200`

## Integration with Other Tools

### Use with Baseline System

```bash
# Save baseline
python test_real_domains.py --domains sites.txt --attacks fake --save-baseline baseline_v1

# Compare with baseline later
python test_real_domains.py --domains sites.txt --attacks fake --compare-baseline baseline_v1
```

### Use with CI/CD

```bash
# Exit code 0 if success rate >= 50%, 1 otherwise
python test_real_domains.py --domains sites.txt --attacks fake
echo $?
```

## Examples

### Example 1: Test X.com with Multiple Attacks

```bash
echo "https://x.com" > x_test.txt
python test_real_domains.py --domains x_test.txt --attacks fake split disorder multisplit --parallel
```

### Example 2: Test YouTube Domains

```bash
cat > youtube_domains.txt << EOF
youtube.com
www.youtube.com
youtubei.googleapis.com
i.ytimg.com
EOF

python test_real_domains.py --domains youtube_domains.txt --attacks fake --output-dir youtube_results/
```

### Example 3: Full Production Test with All Features

```bash
python test_real_domains.py \
  --domains sites.txt \
  --all-attacks \
  --parallel \
  --workers 8 \
  --output-dir production_test_$(date +%Y%m%d) \
  --report-format both \
  --verbose
```

## Getting Help

```bash
# Show all options
python test_real_domains.py --help

# List available attacks
python test_real_domains.py --list-attacks
```

## Next Steps

After running tests:
1. Review the generated reports
2. Analyze per-domain and per-attack statistics
3. Identify failing attacks and domains
4. Adjust attack parameters if needed
5. Re-test with optimized parameters

## Support

For issues or questions:
- Check the logs in `domain_testing.log`
- Review the generated reports
- Enable verbose logging with `--verbose`
- Check the completion report: `PHASE5_REAL_DOMAIN_TESTING_COMPLETE.md`
