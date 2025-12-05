# Auto Strategy Discovery System

## Overview

The Auto Strategy Discovery system is an intelligent DPI bypass strategy finder that automatically discovers, tests, validates, and learns from successful strategies. It provides two modes of operation:

1. **Normal Mode**: Fast strategy discovery with minimal overhead
2. **Verification Mode**: Deep validation with PCAP analysis to ensure strategies are applied correctly

## Architecture

The system consists of several interconnected components:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    cli.py auto / cli.py auto -d sites.txt               │
└─────────────────────────────────┬───────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     AdaptiveEngine.find_best_strategy()                  │
├─────────────────────────────────────────────────────────────────────────┤
│  1. Check domain_rules.json (manual rules)                              │
│  2. Check adaptive_knowledge.json (learned strategies)                  │
│  3. Detect block type (ACTIVE_RST, PASSIVE_DROP, etc.)                  │
│  4. Prioritize by block_type + success_rate                             │
│  5. Test with ConnectionMetrics                                         │
│  6. Evaluate via StrategyEvaluator                                      │
│  7. Save to adaptive_knowledge.json                                     │
└─────────────────────────────────┬───────────────────────────────────────┘
                                  │
          ┌───────────────────────┼───────────────────────────────────────┐
          ▼                       ▼                                       ▼
┌──────────────────┐  ┌────────────────────┐  ┌───────────────────────────┐
│ domain_rules.json│  │ adaptive_knowledge │  │ StrategyValidator         │
│ (MANUAL)         │  │ .json (AUTO)       │  │ (PCAP vs LOG)             │
│ NOT MODIFIED     │  │                    │  │                           │
└──────────────────┘  └────────────────────┘  └───────────────────────────┘
```

## Core Components

### 1. ConnectionMetrics (`core/connection_metrics.py`)

Centralized metrics collection for all connection attempts.

**Key Fields:**
- `connect_time_ms`: TCP handshake duration
- `tls_time_ms`: TLS handshake duration
- `ttfb_ms`: Time to first byte
- `http_status`: HTTP response code
- `bytes_received`: Total bytes received
- `rst_received`: Whether RST packet was received
- `rst_timing_ms`: Timing of RST packet
- `timeout`: Whether connection timed out
- `block_type`: Classification of DPI block type

**Block Types:**
- `NONE`: No blocking detected
- `ACTIVE_RST`: RST packet within 100ms of ClientHello
- `PASSIVE_DROP`: Timeout after 10+ seconds
- `HTTP_BLOCK`: TLS succeeded but HTTP returned 403/451
- `IP_BLOCK`: No SYN-ACK received
- `UNKNOWN`: Unable to classify

**Example:**
```python
from core.connection_metrics import ConnectionMetrics, BlockType

metrics = ConnectionMetrics(
    connect_time_ms=45.2,
    tls_time_ms=120.5,
    ttfb_ms=180.3,
    http_status=200,
    bytes_received=5432,
    block_type=BlockType.NONE
)

if metrics.is_success():
    print("Connection successful!")
```

### 2. StrategyEvaluator (`core/strategy_evaluator.py`)

Single source of truth for evaluating strategy success/failure.

**Evaluation Logic:**
1. Timeout → `success=False`, `block_type=PASSIVE_DROP`
2. RST < 100ms → `success=False`, `block_type=ACTIVE_RST`
3. HTTP 200-499 → `success=True` (DPI bypassed)
4. HTTP 403/451 → `success=True`, `block_type=HTTP_BLOCK` (DPI bypassed, server blocked)
5. Bytes received → `success=True`
6. TLS completed → `success=True`, `confidence=0.8`

**Example:**
```python
from core.strategy_evaluator import StrategyEvaluator

evaluator = StrategyEvaluator()
result = evaluator.evaluate(metrics)

print(f"Success: {result.success}")
print(f"Block Type: {result.block_type}")
print(f"Reason: {result.reason}")
print(f"Confidence: {result.confidence}")
```

### 3. AdaptiveKnowledgeBase (`core/adaptive_knowledge.py`)

Automatic learning system that stores discovered strategies.

**Key Features:**
- Separate from manual `domain_rules.json`
- Tracks success/failure counts
- Records average connection times
- Identifies effective block types
- Supports wildcard patterns for CDN domains

**Data Structure:**
```json
{
  "example.com": {
    "strategies": [
      {
        "strategy_name": "fake_multisplit",
        "strategy_params": {
          "split_pos": 2,
          "split_count": 6,
          "fake_ttl": 1
        },
        "success_count": 25,
        "failure_count": 2,
        "last_success_ts": 1732800000.0,
        "avg_connect_ms": 250.5,
        "effective_against": ["active_rst", "passive_drop"],
        "verified": true,
        "verification_ts": 1732799000.0
      }
    ],
    "preferred_strategy": "fake_multisplit",
    "block_type": "active_rst"
  }
}
```

**Example:**
```python
from core.adaptive_knowledge import AdaptiveKnowledgeBase

kb = AdaptiveKnowledgeBase()

# Record successful strategy
kb.record_success(
    domain="example.com",
    strategy_name="fake_multisplit",
    strategy_params={"split_pos": 2, "split_count": 6},
    metrics=metrics
)

# Get strategies for domain
strategies = kb.get_strategies_for_domain(
    domain="example.com",
    block_type=BlockType.ACTIVE_RST
)
```

### 4. StrategyValidator (`core/strategy_validator.py`)

Validates that logged operations match actual PCAP data.

**Validation Process:**
1. Parse operation log (split, fake, disorder operations)
2. Analyze PCAP file for actual packet modifications
3. Compare expected vs actual operations
4. Generate detailed validation report

**Validation Statuses:**
- `VALID`: All operations match
- `INVALID`: Operations don't match
- `PARTIAL`: Some operations match
- `UNKNOWN`: Unable to validate

**Example:**
```python
from core.strategy_validator import StrategyValidator
from pathlib import Path

validator = StrategyValidator()
result = validator.validate_strategy(
    strategy_log=operation_log,
    pcap_file=Path("capture.pcap"),
    domain="example.com"
)

print(f"Status: {result.status}")
print(f"Missing: {result.missing_operations}")
print(f"Unexpected: {result.unexpected_operations}")
```

### 5. UnifiedPCAPAnalyzer (`core/pcap/unified_analyzer.py`)

Consolidated PCAP analyzer with byte-level packet inspection.

**Analysis Capabilities:**
- **ClientHello Detection**: Identifies TLS ClientHello by header (0x16 0x03)
- **Split Detection**: Determines split position by fragment size
- **Fake Packet Detection**: Finds packets with TTL < 20
- **Disorder Detection**: Analyzes sequence number ordering
- **Fooling Detection**: Verifies checksums for badsum/badseq

**Example:**
```python
from core.pcap.unified_analyzer import UnifiedPCAPAnalyzer
from pathlib import Path

analyzer = UnifiedPCAPAnalyzer()
result = analyzer.analyze(
    pcap_file=Path("capture.pcap"),
    domain="example.com"
)

print(f"ClientHello packets: {len(result.clienthello_packets)}")
print(f"Split detected: {result.split_info.detected}")
print(f"Fake packets: {len(result.fake_packets)}")
```

### 6. OperationLogger (`core/operation_logger.py`)

Logs all packet modification operations for validation.

**Logged Information:**
- Unique operation ID
- Operation type (split, fake, disorder, fooling)
- Parameters (split_pos, ttl, etc.)
- Segment/packet numbers
- Timestamps

**Example:**
```python
from core.operation_logger import OperationLogger

logger = OperationLogger()
logger.log_operation(
    operation_type="split",
    params={"position": 5, "count": 6},
    segment_ids=[1, 2, 3, 4, 5, 6]
)
```

## Usage

### Basic Auto Mode

Find a working strategy for a single domain:

```bash
python cli.py auto example.com
```

This will:
1. Check `domain_rules.json` for existing strategy
2. Check `adaptive_knowledge.json` for learned strategies
3. Test strategies in priority order
4. Save successful strategy to `adaptive_knowledge.json`

### Verification Mode

Run with deep PCAP validation:

```bash
python cli.py auto example.com --verify-with-pcap
```

This will:
1. Capture extended PCAP (5+ seconds)
2. Log all packet modification operations
3. Validate operations against PCAP
4. Mark strategy as `verified: true` if validation passes
5. Generate detailed validation report

**When to use verification mode:**
- Debugging strategy application issues
- Validating new attack implementations
- Ensuring strategies work as expected
- Building confidence in learned strategies

### Batch Mode

Test multiple domains from a file:

```bash
python cli.py auto -d sites.txt
```

This will:
1. Test each domain sequentially
2. Save all successful strategies to `adaptive_knowledge.json`
3. **NOT** modify `domain_rules.json`
4. Generate summary report with success/failure counts

**Summary Output:**
```
Batch Mode Summary:
  Total domains: 10
  Successful: 8
  Failed: 2
  
Per-domain results:
  ✓ example.com: fake_multisplit (250ms)
  ✓ test.org: disorder_multisplit (180ms)
  ✗ blocked.net: No working strategy found
```

### Promote Best Strategies

Save best strategies to manual rules:

```bash
python cli.py auto -d sites.txt --promote-best-to-rules
```

This will:
1. Run batch mode as normal
2. After completion, offer to save best strategies to `domain_rules.json`
3. Show preview of changes before applying
4. Require user confirmation

**Example Prompt:**
```
Found 8 successful strategies. Promote to domain_rules.json?

  example.com: fake_multisplit (success_rate: 92%, avg: 250ms)
  test.org: disorder_multisplit (success_rate: 88%, avg: 180ms)
  ...

Promote these strategies? [y/N]:
```

## Strategy Prioritization

The system uses intelligent prioritization to test strategies efficiently:

### Priority Order

1. **Manual Rules** (`domain_rules.json`)
   - Always tried first
   - User-configured strategies

2. **Verified Strategies** (`adaptive_knowledge.json`)
   - Strategies that passed PCAP validation
   - Sorted by:
     - Preferred strategy flag
     - Effective against current block type
     - Success rate (descending)
     - Average connection time (ascending)

3. **Unverified Strategies** (`adaptive_knowledge.json`)
   - Strategies that worked but not validated
   - Same sorting as verified strategies

4. **Generated Strategies**
   - Fallback to adaptive generation
   - Used when no known strategies work

### Wildcard Matching

For CDN domains (e.g., `rr1---sn-xxx.googlevideo.com`):
- Matches wildcard patterns (e.g., `*.googlevideo.com`)
- Returns strategies for wildcard pattern
- Useful for large CDN networks

**Example:**
```python
# Automatically matches *.googlevideo.com
strategies = kb.get_strategies_for_domain("rr1---sn-abc123.googlevideo.com")
```

## PCAP Capture Modes

### Normal Mode (Default)

Optimized for performance:
- Short capture duration (1-2 seconds)
- BPF filter by target IP and port 443
- Minimal system overhead
- Suitable for batch processing

### Verification Mode (`--verify-with-pcap`)

Extended capture for validation:
- Minimum 5 seconds capture duration
- 2-3 seconds post-capture delay
- Captures complete TLS handshake
- Includes application data
- Required for strategy validation

## Data Files

### domain_rules.json (Manual Rules)

**Location**: `data/domain_rules.json`

**Purpose**: User-configured strategies that should not be modified automatically

**Structure**:
```json
{
  "example.com": {
    "strategy": "fake_multisplit",
    "attacks": ["fake", "multisplit"],
    "params": {
      "split_pos": 2,
      "split_count": 6,
      "fake_ttl": 1
    }
  }
}
```

**Modification**: Only modified manually or with `--promote-best-to-rules` flag

### adaptive_knowledge.json (Learned Strategies)

**Location**: `data/adaptive_knowledge.json`

**Purpose**: Automatically discovered and learned strategies

**Structure**: See AdaptiveKnowledgeBase section above

**Modification**: Automatically updated during strategy discovery

### Operation Logs

**Location**: `logs/operations/`

**Purpose**: Detailed logs of packet modifications for validation

**Structure**:
```json
{
  "strategy_id": "uuid-123",
  "strategy_name": "fake_multisplit",
  "domain": "example.com",
  "timestamp": 1732800000.0,
  "operations": [
    {
      "type": "split",
      "params": {"position": 5, "count": 6},
      "segment_ids": [1, 2, 3, 4, 5, 6]
    },
    {
      "type": "fake",
      "params": {"ttl": 1, "count": 2},
      "packet_ids": [7, 8]
    }
  ]
}
```

## Integration with Existing Code

### AdaptiveEngine Integration

The new components integrate seamlessly with the existing `AdaptiveEngine`:

```python
# In core/adaptive_engine.py
from core.connection_metrics import ConnectionMetrics, BlockType
from core.strategy_evaluator import StrategyEvaluator
from core.adaptive_knowledge import AdaptiveKnowledgeBase

class AdaptiveEngine:
    def __init__(self):
        self.evaluator = StrategyEvaluator()
        self.knowledge_base = AdaptiveKnowledgeBase()
    
    def find_best_strategy(self, domain: str):
        # 1. Check domain_rules.json
        # 2. Check adaptive_knowledge.json
        # 3. Test strategies with ConnectionMetrics
        # 4. Evaluate with StrategyEvaluator
        # 5. Save to adaptive_knowledge.json
        pass
```

### CLI Integration

New flags added to `cli.py`:

```python
# Verification mode
parser.add_argument('--verify-with-pcap', action='store_true',
                   help='Enable PCAP validation mode')

# Promote to rules
parser.add_argument('--promote-best-to-rules', action='store_true',
                   help='Offer to save best strategies to domain_rules.json')
```

## Best Practices

### When to Use Verification Mode

✅ **Use verification mode when:**
- Debugging strategy application issues
- Validating new attack implementations
- Building initial knowledge base
- Investigating DPI behavior changes

❌ **Don't use verification mode when:**
- Running batch mode on many domains
- Performance is critical
- You trust existing strategies

### Managing Knowledge Bases

**domain_rules.json (Manual)**:
- Use for production-critical domains
- Manually curate and test
- Version control recommended
- Review before promoting from adaptive_knowledge.json

**adaptive_knowledge.json (Automatic)**:
- Let the system learn automatically
- Periodically review and promote best strategies
- Can be regenerated if corrupted
- Backup before major changes

### Batch Mode Tips

1. **Start Small**: Test with 5-10 domains first
2. **Review Results**: Check summary before promoting
3. **Use Verification Selectively**: Verify a few domains, not all
4. **Monitor Performance**: Watch for timeouts and failures
5. **Iterate**: Refine strategy generation based on results

## Troubleshooting

### Strategy Not Applied Correctly

**Symptoms**: Logs show strategy applied, but PCAP shows different

**Solution**:
```bash
python cli.py auto example.com --verify-with-pcap
```

Check validation report for discrepancies.

### Low Success Rate

**Symptoms**: Many strategies failing for a domain

**Solution**:
1. Check block type classification
2. Review effective_against field
3. Try verification mode to ensure strategies work
4. Consider DPI behavior changes

### Adaptive Knowledge Corruption

**Symptoms**: JSON parse errors, missing fields

**Solution**:
1. Check `data/adaptive_knowledge.json.backup`
2. Restore from backup
3. System will auto-backup on corruption detection

### PCAP Analysis Fails

**Symptoms**: Validation returns UNKNOWN status

**Solution**:
1. Ensure Scapy is installed: `pip install scapy`
2. Check PCAP file exists and is readable
3. Verify PCAP contains expected traffic
4. Check BPF filter settings

## Performance Considerations

### Memory Usage

- **Normal Mode**: ~50MB per domain
- **Verification Mode**: ~200MB per domain (PCAP storage)
- **Batch Mode**: Sequential processing, constant memory

### Disk Usage

- **Operation Logs**: ~10KB per test
- **PCAP Files**: ~500KB per capture (verification mode)
- **Knowledge Base**: ~1MB per 1000 domains

### Timing

- **Normal Mode**: 5-15 seconds per strategy test
- **Verification Mode**: 10-20 seconds per strategy test
- **Batch Mode**: Linear scaling with domain count

## API Reference

### ConnectionMetrics

```python
@dataclass
class ConnectionMetrics:
    connect_time_ms: float = 0.0
    tls_time_ms: float = 0.0
    ttfb_ms: float = 0.0
    total_time_ms: float = 0.0
    http_status: Optional[int] = None
    bytes_received: int = 0
    tls_completed: bool = False
    error: Optional[str] = None
    rst_received: bool = False
    rst_timing_ms: Optional[float] = None
    timeout: bool = False
    block_type: BlockType = BlockType.UNKNOWN
    timestamp: float = field(default_factory=time.time)
    
    def is_success(self) -> bool:
        """Check if connection was successful"""
        
    def detect_block_type(self) -> BlockType:
        """Detect type of DPI blocking"""
```

### StrategyEvaluator

```python
class StrategyEvaluator:
    def __init__(self, timeout_threshold_ms: int = 10000, 
                 rst_threshold_ms: int = 100):
        """Initialize evaluator with thresholds"""
    
    def evaluate(self, metrics: ConnectionMetrics) -> EvaluationResult:
        """Evaluate strategy success based on metrics"""

@dataclass
class EvaluationResult:
    success: bool
    block_type: BlockType
    reason: str
    confidence: float = 1.0
```

### AdaptiveKnowledgeBase

```python
class AdaptiveKnowledgeBase:
    def __init__(self, path: Optional[Path] = None):
        """Initialize knowledge base"""
    
    def record_success(self, domain: str, strategy_name: str,
                      strategy_params: Dict, metrics: ConnectionMetrics):
        """Record successful strategy"""
    
    def record_failure(self, domain: str, strategy_name: str,
                      strategy_params: Dict, metrics: ConnectionMetrics):
        """Record failed strategy"""
    
    def get_strategies_for_domain(self, domain: str,
                                  block_type: Optional[BlockType] = None) -> List[StrategyRecord]:
        """Get prioritized strategies for domain"""
    
    def get_prioritized_strategies(self, domain: str,
                                   block_type: Optional[BlockType] = None) -> List[StrategyRecord]:
        """Get strategies sorted by priority"""
    
    def save(self):
        """Save knowledge base to disk"""
    
    def load(self):
        """Load knowledge base from disk"""
```

### StrategyValidator

```python
class StrategyValidator:
    def validate_strategy(self, strategy_log: Dict, pcap_file: Path,
                         domain: str) -> ValidationResult:
        """Validate strategy against PCAP"""
    
    def generate_report(self) -> str:
        """Generate validation report"""

@dataclass
class ValidationResult:
    status: ValidationStatus
    strategy_name: str
    expected_operations: List[str]
    actual_operations: List[str]
    missing_operations: List[str]
    unexpected_operations: List[str]
    operation_details: Dict[str, Dict]
    message: str
```

### UnifiedPCAPAnalyzer

```python
class UnifiedPCAPAnalyzer:
    def analyze(self, pcap_file: Path, domain: str) -> PCAPAnalysisResult:
        """Analyze PCAP file"""
    
    def find_clienthello_packets(self, packets: List) -> List[ClientHelloInfo]:
        """Find ClientHello packets"""
    
    def detect_split(self, packets: List) -> Optional[SplitInfo]:
        """Detect split operations"""
    
    def detect_fake_packets(self, packets: List) -> List[FakePacketInfo]:
        """Detect fake packets"""
    
    def detect_disorder(self, packets: List) -> Optional[str]:
        """Detect disorder operations"""
    
    def detect_fooling(self, packets: List) -> List[str]:
        """Detect fooling modes"""
```

## Examples

### Example 1: Basic Strategy Discovery

```python
from core.adaptive_engine import AdaptiveEngine

engine = AdaptiveEngine()
result = engine.find_best_strategy("example.com")

if result.success:
    print(f"Found strategy: {result.strategy_name}")
    print(f"Parameters: {result.strategy_params}")
    print(f"Connection time: {result.metrics.total_time_ms}ms")
else:
    print(f"Failed: {result.reason}")
```

### Example 2: Verification Mode

```python
from core.adaptive_engine import AdaptiveEngine

engine = AdaptiveEngine(verify_with_pcap=True)
result = engine.find_best_strategy("example.com")

if result.validation_result.status == ValidationStatus.VALID:
    print("Strategy validated successfully!")
    print(f"All operations matched: {result.validation_result.expected_operations}")
else:
    print(f"Validation failed: {result.validation_result.message}")
    print(f"Missing: {result.validation_result.missing_operations}")
```

### Example 3: Batch Processing

```python
from core.adaptive_engine import AdaptiveEngine
from pathlib import Path

engine = AdaptiveEngine()
domains = Path("sites.txt").read_text().splitlines()

results = []
for domain in domains:
    result = engine.find_best_strategy(domain)
    results.append((domain, result))

# Generate summary
successful = [r for r in results if r[1].success]
failed = [r for r in results if not r[1].success]

print(f"Successful: {len(successful)}/{len(domains)}")
print(f"Failed: {len(failed)}/{len(domains)}")
```

### Example 4: Custom Evaluation

```python
from core.connection_metrics import ConnectionMetrics, BlockType
from core.strategy_evaluator import StrategyEvaluator

# Create custom metrics
metrics = ConnectionMetrics(
    connect_time_ms=50.0,
    tls_time_ms=150.0,
    ttfb_ms=200.0,
    http_status=200,
    bytes_received=5000,
    block_type=BlockType.NONE
)

# Evaluate
evaluator = StrategyEvaluator()
result = evaluator.evaluate(metrics)

print(f"Success: {result.success}")
print(f"Confidence: {result.confidence}")
```

## Future Enhancements

### Planned Features

1. **Machine Learning Integration**
   - Predict best strategy based on domain characteristics
   - Learn DPI patterns over time

2. **Distributed Knowledge Base**
   - Share strategies across multiple systems
   - Community-driven strategy database

3. **Real-time Adaptation**
   - Detect DPI changes automatically
   - Switch strategies on-the-fly

4. **Advanced Analytics**
   - Success rate trends over time
   - Block type distribution analysis
   - Performance optimization recommendations

### Contributing

To contribute to the Auto Strategy Discovery system:

1. Follow existing code patterns
2. Add property-based tests for new features
3. Update this documentation
4. Test with verification mode

## Related Documentation

- [Domain Rules Schema](domain_rules_schema.md)
- [Fake Mode Guide](fake_mode_guide.md)
- [Metrics System](metrics_system.md)
- [Payload Usage](payload_usage.md)
- [PCAP Validation Usage](validate_pcap_usage.md)

## Support

For issues or questions:
1. Check troubleshooting section above
2. Review validation reports
3. Enable debug logging: `--log-level DEBUG`
4. Check operation logs in `logs/operations/`
