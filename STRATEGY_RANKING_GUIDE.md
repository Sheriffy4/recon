# Strategy Ranking System Guide

## Overview

The strategy ranking system in `enhanced_find_rst_triggers.py` provides intelligent ranking of DPI bypass strategies based on multiple metrics, helping identify the most effective strategies for bypassing censorship.

## Ranking Methodology

### Composite Score Calculation

Each strategy receives a composite score based on:

```
Composite Score = (Success Rate × 100) - (Latency / 10)
```

**Components:**
- **Success Rate Score**: 0-100 points based on percentage of successful tests
- **Latency Penalty**: Latency in milliseconds divided by 10 (lower is better)

**Example:**
- Strategy with 95% success rate and 35ms latency: `(0.95 × 100) - (35 / 10) = 91.5`
- Strategy with 90% success rate and 45ms latency: `(0.90 × 100) - (45 / 10) = 85.5`

### Ranking Categories

Strategies are classified into four categories:

| Category | Criteria |
|----------|----------|
| **EXCELLENT** | Success Rate ≥ 90% AND Latency < 50ms |
| **GOOD** | Success Rate ≥ 70% AND Latency < 100ms |
| **FAIR** | Success Rate ≥ 50% |
| **POOR** | Success Rate < 50% |

### Reliability Assessment

Based on success rate:
- **HIGH**: Success rate ≥ 80%
- **MEDIUM**: Success rate ≥ 50%
- **LOW**: Success rate < 50%

### Performance Assessment

Based on average latency:
- **FAST**: Latency < 50ms
- **MODERATE**: Latency < 100ms
- **SLOW**: Latency ≥ 100ms

## Router-Tested Strategy Comparison

The ranking system can compare discovered strategies against a known router-tested strategy:

```python
router_tested_strategy = "--dpi-desync=multidisorder --dpi-desync-autottl=2 --dpi-desync-fooling=badseq --dpi-desync-repeats=2 --dpi-desync-split-pos=46 --dpi-desync-split-seqovl=1"
```

**Comparison Features:**
- Identifies if router-tested strategy appears in results
- Shows rank position of router-tested strategy
- Highlights matches with ⭐ marker
- Generates recommendations based on comparison

## Output Format

### Ranked Strategy Entry

```json
{
  "rank": 1,
  "strategy": "--dpi-desync=multidisorder --dpi-desync-ttl=2 ...",
  "description": "multidisorder ttl=2 badseq split_pos=46 seqovl=1 repeats=2",
  "success_rate": 0.95,
  "avg_latency_ms": 35.0,
  "rst_count": 1,
  "composite_score": 91.50,
  "rank_category": "EXCELLENT",
  "rank_details": {
    "success_score": 95.0,
    "latency_penalty": 3.5,
    "reliability": "HIGH",
    "performance": "FAST"
  },
  "matches_router_tested": false
}
```

### Ranking Details Summary

```json
{
  "ranking_details": {
    "total_ranked": 25,
    "excellent_count": 3,
    "good_count": 8,
    "fair_count": 10,
    "router_tested_match": true,
    "router_tested_rank": 2
  }
}
```

## Usage Examples

### Basic Ranking

```python
from enhanced_find_rst_triggers import DPIFingerprintAnalyzer

# Create analyzer
analyzer = DPIFingerprintAnalyzer(domain="x.com", test_count=3)

# Run analysis
report = analyzer.run_analysis(max_configs=100)

# Access ranked strategies
top_5 = report['top_5_strategies']
for strategy in top_5:
    print(f"Rank #{strategy['rank']}: {strategy['description']}")
    print(f"  Score: {strategy['composite_score']:.2f}")
    print(f"  Category: {strategy['rank_category']}")
```

### With Router Strategy Comparison

```python
# Successful strategies from analysis
successful_strategies = [...]

# Router-tested strategy
router_strategy = "--dpi-desync=multidisorder --dpi-desync-autottl=2 ..."

# Rank with comparison
ranked = analyzer.rank_strategies(successful_strategies, router_strategy)

# Check if router strategy is in top 5
router_in_top5 = any(s.get('matches_router_tested', False) for s in ranked[:5])
if router_in_top5:
    print("✓ Router-tested strategy validated in top 5")
```

### Command Line Usage

```bash
# Run analysis with ranking
python enhanced_find_rst_triggers.py --domain x.com --max-configs 100

# Output includes ranked strategies
# Top 5 Ranked Strategies:
#   ⭐ #1. multidisorder autottl=2 badseq split_pos=46 seqovl=1 repeats=2
#      Category: EXCELLENT, Score: 91.50
#      Success: 95.0%, Latency: 35.0ms
#      ⭐ Matches router-tested strategy
```

## Interpretation Guide

### Top Strategy Selection

**Choose the #1 ranked strategy when:**
- Composite score is significantly higher (>5 points) than alternatives
- Category is EXCELLENT or GOOD
- Reliability is HIGH

**Consider alternatives when:**
- Top strategy has MEDIUM reliability
- Multiple strategies have similar scores (within 2 points)
- Latency requirements are critical (choose FAST performance)

### Router Strategy Validation

**If router-tested strategy ranks in top 5:**
- ✓ Strategy is validated by testing
- Continue using with confidence
- Consider top-ranked alternatives for optimization

**If router-tested strategy ranks outside top 5:**
- Review why it underperformed
- Test top-ranked alternatives
- Consider network conditions may have changed

**If router-tested strategy not found:**
- May not have been tested in this run
- Increase `--max-configs` to test more combinations
- Manually test router strategy

## Recommendations System

The ranking system generates automatic recommendations:

### High Priority Recommendations

1. **Best Overall Strategy**
   - Highest composite score
   - Recommended for primary use

2. **Router Strategy Validation**
   - If router strategy is in top 5
   - Confirms effectiveness

### Medium Priority Recommendations

1. **Fastest Alternative**
   - Lowest latency strategy
   - For latency-sensitive applications

2. **Parameter Patterns**
   - Common effective parameters
   - Insights for optimization

## Advanced Features

### Parameter Pattern Analysis

The ranking system analyzes successful strategies to identify patterns:

```python
insights = analyzer._analyze_parameter_patterns(successful_strategies)
# Returns:
# - Most effective split position
# - Most effective TTL value
# - Most effective fooling method
```

### Strategy Normalization

Strategies are normalized for comparison:

```python
# Both are considered equivalent:
"--dpi-desync=multidisorder --dpi-desync-ttl=2 --dpi-desync-fooling=badseq"
"--dpi-desync-fooling=badseq --dpi-desync=multidisorder --dpi-desync-ttl=2"
```

## Best Practices

### Testing Configuration

1. **Test Count**: Use at least 3 tests per configuration for reliability
2. **Max Configs**: Start with 100, increase to 200+ for comprehensive analysis
3. **Target Selection**: Test against actual blocked domains

### Result Interpretation

1. **Focus on Top 5**: Top 5 strategies are most reliable
2. **Check Category**: Prefer EXCELLENT and GOOD categories
3. **Verify Reliability**: HIGH reliability strategies are more consistent
4. **Consider Latency**: Balance success rate with performance needs

### Strategy Deployment

1. **Test Top Strategy**: Deploy #1 ranked strategy first
2. **Have Fallbacks**: Keep top 3 strategies as alternatives
3. **Monitor Performance**: Track actual success rates in production
4. **Re-analyze Periodically**: DPI systems may change over time

## Troubleshooting

### No Strategies Ranked

**Possible causes:**
- All strategies failed (0% success rate)
- No successful tests completed

**Solutions:**
- Increase test count
- Expand parameter ranges
- Check network connectivity

### Router Strategy Not Found

**Possible causes:**
- Strategy not tested in current run
- Parameter combination not in test matrix

**Solutions:**
- Increase `--max-configs`
- Manually add router strategy to test matrix
- Check strategy string format

### Low Composite Scores

**Possible causes:**
- High latency network
- Aggressive DPI filtering
- Suboptimal parameters

**Solutions:**
- Focus on success rate over latency
- Test more parameter combinations
- Analyze failed strategies for patterns

## Integration with Other Tools

### With Intelligent Strategy Generator

```python
from core.strategy.intelligent_strategy_generator import IntelligentStrategyGenerator

# Generate intelligent strategies
generator = IntelligentStrategyGenerator()
strategies = await generator.generate_intelligent_strategies("x.com", count=10)

# Test and rank them
analyzer = DPIFingerprintAnalyzer(domain="x.com")
# ... run tests ...
ranked = analyzer.rank_strategies(successful_strategies)
```

### With Enhanced RST Analyzer

```python
from core.strategy.enhanced_rst_analyzer import EnhancedRSTAnalyzer

# Run enhanced analysis with ranking
analyzer = EnhancedRSTAnalyzer(
    recon_summary_file="recon_summary.json",
    pcap_file="out2.pcap"
)
results = await analyzer.run_enhanced_analysis(
    target_sites=["x.com"],
    max_strategies=10
)

# Access ranked strategies
ranked = results['ranked_strategies']
```

## Performance Metrics

### Typical Ranking Performance

- **Strategies Tested**: 100-200 configurations
- **Ranking Time**: < 1 second
- **Memory Usage**: < 50MB
- **Accuracy**: Based on test count (3+ tests recommended)

### Optimization Tips

1. **Parallel Testing**: Test multiple strategies concurrently
2. **Early Termination**: Stop testing after finding EXCELLENT strategies
3. **Caching**: Cache results for repeated analyses
4. **Filtering**: Pre-filter obviously ineffective combinations

## References

- Task 7.3: Implement strategy ranking
- Requirements: 4.6, 4.7
- Related: Task 7.1 (RST trigger analysis), Task 7.2 (RST detection)

## Version History

- **v1.0** (2025-10-06): Initial implementation
  - Composite score calculation
  - Category classification
  - Router strategy comparison
  - Top 5 ranking
