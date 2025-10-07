# DPI Fingerprinting Analysis Tool - Quick Start Guide

## Overview

The DPI Fingerprinting Analysis Tool systematically tests various bypass strategy parameters to identify which combinations successfully avoid RST packets from DPI systems.

## Quick Start

### Basic Usage

Test x.com with default settings (200 strategies):
```bash
python enhanced_find_rst_triggers_x_com.py --domain x.com
```

### Common Options

Test with limited strategies (faster):
```bash
python enhanced_find_rst_triggers_x_com.py --domain x.com --max-strategies 50
```

Save results to specific file:
```bash
python enhanced_find_rst_triggers_x_com.py --domain x.com --output x_com_analysis.json
```

Enable verbose logging:
```bash
python enhanced_find_rst_triggers_x_com.py --domain x.com --verbose
```

Adjust connection timeout:
```bash
python enhanced_find_rst_triggers_x_com.py --domain x.com --timeout 5.0
```

## What It Tests

### Parameters Tested

1. **Split Positions**: 1, 2, 3, 46, 50, 100
2. **TTL Values**: 1, 2, 3, 4
3. **AutoTTL Offsets**: 1, 2, 3
4. **Fooling Methods**: badseq, badsum, md5sig
5. **Overlap Sizes**: 0, 1, 2, 5
6. **Repeat Counts**: 1, 2, 3

### Priority Testing

The tool prioritizes testing the router-proven strategy first:
```
--dpi-desync=multidisorder 
--dpi-desync-autottl=2 
--dpi-desync-fooling=badseq 
--dpi-desync-split-pos=46 
--dpi-desync-split-seqovl=1 
--dpi-desync-repeats=2
```

## Understanding Results

### Console Output

```
================================================================================
DPI FINGERPRINTING ANALYSIS SUMMARY
================================================================================

Domain: x.com
Target IP: 172.66.0.227

Total strategies tested: 200
Successful: 15
Failed: 185
Success rate: 7.5%

Top 5 Working Strategies:

1. multidisorder autottl=2 badseq split_pos=46 seqovl=1 repeats=2
   Strategy: --dpi-desync=multidisorder --dpi-desync-autottl=2 ...
   Latency: 45.2ms
   RST count: 0

2. multidisorder ttl=2 badseq split_pos=46 seqovl=1 repeats=2
   Strategy: --dpi-desync=multidisorder --dpi-desync-ttl=2 ...
   Latency: 48.5ms
   RST count: 0

...
```

### JSON Report Structure

```json
{
  "metadata": {
    "domain": "x.com",
    "target_ip": "172.66.0.227",
    "start_time": "2025-10-06T14:30:00",
    "end_time": "2025-10-06T14:35:00",
    "duration_seconds": 300
  },
  "summary": {
    "tested_strategies": 200,
    "successful_strategies": 15,
    "failed_strategies": 185,
    "success_rate": 0.075,
    "average_latency_ms": 45.2
  },
  "successful_strategies": [...],
  "failed_strategies": [...],
  "top_5_strategies": [...],
  "router_tested_strategy": {...},
  "recommendations": [...]
}
```

## Interpreting Recommendations

### High Priority Recommendations

These are strategies that should be implemented immediately:

```json
{
  "priority": "HIGH",
  "title": "Best Performing Strategy",
  "strategy": "--dpi-desync=multidisorder --dpi-desync-autottl=2 ...",
  "description": "multidisorder autottl=2 badseq split_pos=46 seqovl=1 repeats=2",
  "success_rate": 1.0,
  "latency_ms": 45.0,
  "reason": "Highest success rate with lowest latency"
}
```

### Router-Tested Strategy Status

Check if the router-proven strategy works:

```json
{
  "priority": "HIGH",
  "title": "Router-Tested Strategy",
  "strategy": "...",
  "success_rate": 1.0,
  "reason": "Proven to work on router, should be prioritized"
}
```

## Common Scenarios

### Scenario 1: Router Strategy Works

If the router-tested strategy succeeds:
1. Use it as primary strategy in strategies.json
2. Select 2-3 backup strategies from top 5
3. Update service configuration
4. Test in production

### Scenario 2: Router Strategy Fails

If the router-tested strategy fails:
1. Review top 5 successful strategies
2. Select best performing alternative
3. Investigate why router strategy failed
4. Consider environment differences

### Scenario 3: No Strategies Work

If all strategies fail:
1. Check network connectivity
2. Verify domain is actually blocked
3. Test with different domains
4. Review DPI system behavior

### Scenario 4: Multiple Strategies Work

If many strategies succeed:
1. Choose strategy with lowest latency
2. Prefer autottl over fixed TTL
3. Consider simpler strategies first
4. Test stability over time

## Integration with Bypass Service

### Step 1: Run Analysis

```bash
python enhanced_find_rst_triggers_x_com.py --domain x.com --output x_com_analysis.json
```

### Step 2: Review Results

```bash
# View summary
cat x_com_analysis.json | jq '.summary'

# View top strategies
cat x_com_analysis.json | jq '.top_5_strategies'

# View recommendations
cat x_com_analysis.json | jq '.recommendations'
```

### Step 3: Update Configuration

Edit `strategies.json`:
```json
{
  "x.com": "--dpi-desync=multidisorder --dpi-desync-autottl=2 --dpi-desync-fooling=badseq --dpi-desync-split-pos=46 --dpi-desync-split-seqovl=1 --dpi-desync-repeats=2"
}
```

### Step 4: Test Service

```bash
# Start bypass service
python setup.py
# Select [2] Start bypass service

# Test x.com access in browser
# Monitor logs for success
```

## Troubleshooting

### Issue: All Tests Timeout

**Cause**: Network connectivity issues or firewall blocking

**Solution**:
- Check internet connection
- Verify domain resolves: `nslookup x.com`
- Try increasing timeout: `--timeout 30.0`
- Test with known-working domain first

### Issue: All Tests Fail with RST

**Cause**: DPI is blocking all attempts

**Solution**:
- This is expected behavior - tool is identifying what doesn't work
- Review successful strategies (if any)
- Consider testing different parameter ranges
- May need more advanced bypass techniques

### Issue: Inconsistent Results

**Cause**: DPI behavior varies over time

**Solution**:
- Run analysis multiple times
- Use `--test-count 5` to test each strategy multiple times
- Look for strategies with consistent success
- Consider time-of-day effects

### Issue: Tool Runs Too Slowly

**Cause**: Testing too many strategies

**Solution**:
- Reduce max strategies: `--max-strategies 50`
- Reduce timeout: `--timeout 5.0`
- Focus on priority strategies only
- Run in background for comprehensive analysis

## Advanced Usage

### Test Specific Parameter Ranges

Modify the tool to test custom parameter ranges:

```python
analyzer = DPIFingerprintAnalyzer("x.com")
analyzer.split_positions = [46, 50, 100]  # Only test these
analyzer.ttl_values = [1, 2]  # Only test these
configs = analyzer.generate_test_configs(max_configs=50)
```

### Batch Testing Multiple Domains

```bash
for domain in x.com twitter.com facebook.com; do
    python enhanced_find_rst_triggers_x_com.py --domain $domain --output ${domain}_analysis.json
done
```

### Automated Analysis Pipeline

```bash
#!/bin/bash
# Run analysis
python enhanced_find_rst_triggers_x_com.py --domain x.com --output analysis.json

# Extract best strategy
best_strategy=$(cat analysis.json | jq -r '.recommendations[0].strategy')

# Update configuration
echo "Best strategy: $best_strategy"

# Test in service
python test_strategy.py --strategy "$best_strategy"
```

## Performance Tips

1. **Start Small**: Use `--max-strategies 50` for quick tests
2. **Increase Gradually**: Expand to 200+ for comprehensive analysis
3. **Use Timeouts**: Set appropriate `--timeout` based on network
4. **Run Overnight**: Comprehensive analysis can take time
5. **Save Results**: Always use `--output` to preserve findings

## Best Practices

1. **Test Regularly**: DPI behavior can change over time
2. **Document Results**: Keep analysis reports for reference
3. **Compare Over Time**: Track which strategies stop working
4. **Share Findings**: Contribute successful strategies to community
5. **Validate in Production**: Always test selected strategies in real service

## Support

For issues or questions:
1. Check completion report: `TASK7_DPI_FINGERPRINTING_TOOL_COMPLETION_REPORT.md`
2. Review test results: `test_enhanced_find_rst_triggers_x_com.py`
3. Examine source code: `enhanced_find_rst_triggers_x_com.py`

## Related Documentation

- Task 7 Completion Report: `TASK7_DPI_FINGERPRINTING_TOOL_COMPLETION_REPORT.md`
- X.com Bypass Fix Design: `.kiro/specs/x-com-bypass-fix/design.md`
- X.com Bypass Fix Requirements: `.kiro/specs/x-com-bypass-fix/requirements.md`
- Strategy Parser Documentation: `core/strategy_parser_v2.py`

---

**Last Updated**: 2025-10-06  
**Tool Version**: 1.0  
**Status**: Production Ready
