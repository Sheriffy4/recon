# TTL Parameter Handling Guide

## Overview

This document provides comprehensive documentation for TTL (Time To Live) parameter handling in the Recon DPI bypass system. It serves as a reference for developers to understand, maintain, and troubleshoot TTL-related functionality.

## TTL Parameter Flow

### Complete Pipeline

```
CLI Input → Strategy Interpreter → Bypass Engine → Packet Injection
```

### Detailed Flow

1. **CLI Parsing** (`cli.py`)
   - User specifies: `--strategy "--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=64"`
   - Strategy string passed to `interpret_strategy()`

2. **Strategy Interpretation** (`core/strategy_interpreter.py`)
   - Parses `--dpi-desync-ttl=64` parameter
   - Converts string "64" to integer 64
   - Includes in params dictionary: `{"ttl": 64}`

3. **Bypass Engine** (`core/bypass_engine.py`)
   - Extracts TTL: `ttl = params.get("ttl")`
   - Applies fallback: `ttl = ttl if ttl else 1`
   - Passes to packet injection methods

4. **Packet Injection** (Various attack methods)
   - Uses TTL value in fake packet generation
   - Applies to both fake and real packet segments

## Parameter Mapping

### CLI to Internal Parameter Mapping

| CLI Parameter | Internal Parameter | Type | Range | Default |
|---------------|-------------------|------|-------|---------|
| `--dpi-desync-ttl=N` | `params["ttl"]` | int | 1-255 | 1 |
| `--dpi-desync-autottl=N` | `params["autottl"]` | int | 1-10 | None |

### Example Mappings

```python
# CLI: --dpi-desync-ttl=64
# Result: {"ttl": 64}

# CLI: --dpi-desync-ttl=64 --dpi-desync-autottl=2  
# Result: {"ttl": 64, "autottl": 2}
```

## Attack Type Compatibility

### TTL Support by Attack Type

| Attack Type | TTL Support | Default TTL | Notes |
|-------------|-------------|-------------|-------|
| `fake` | ✅ Full | 1 | Uses TTL for fake packets |
| `fakeddisorder` | ✅ Full | 1 | Uses TTL for fake packets and segments |
| `fake,fakeddisorder` | ✅ Full | 1 | Combined attack with TTL |

### Attack-Specific Behavior

```python
# Fake attack
"--dpi-desync=fake --dpi-desync-ttl=64"
# → Uses TTL=64 for fake packets only

# Fakeddisorder attack  
"--dpi-desync=fakeddisorder --dpi-desync-ttl=64"
# → Uses TTL=64 for fake packets and disordered segments

# Combined attack
"--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=64"
# → Uses TTL=64 for all fake packets and segments
```

## Common TTL Values

### Standard TTL Values

| TTL Value | Description | Use Case |
|-----------|-------------|----------|
| 1 | Minimum TTL | Local network testing |
| 4 | Very low TTL | Aggressive DPI bypass |
| 32 | Low TTL | Moderate DPI bypass |
| 64 | Standard TTL | Default for many systems |
| 128 | Windows default | Windows compatibility |
| 255 | Maximum TTL | Maximum hop count |

### Recommended Values

```bash
# For aggressive DPI bypass
--dpi-desync-ttl=1

# For balanced approach
--dpi-desync-ttl=64

# For maximum compatibility
--dpi-desync-ttl=128
```

## Zapret Compatibility

### Parameter Compatibility

Recon maintains full compatibility with original zapret TTL parameters:

```bash
# Zapret command
zapret --dpi-desync=fake,fakeddisorder --dpi-desync-ttl=64

# Equivalent recon command
python cli.py --strategy "--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=64"
```

### Behavior Compatibility

| Aspect | Zapret | Recon | Status |
|--------|--------|-------|--------|
| TTL parsing | ✅ | ✅ | Compatible |
| Default TTL | 1 | 1 | Compatible |
| TTL range | 1-255 | 1-255 | Compatible |
| Packet structure | ✅ | ✅ | Compatible |

## Troubleshooting Guide

### Common Issues

#### Issue 1: TTL=1 Used Instead of Specified TTL

**Symptoms:**
- Command specifies `--dpi-desync-ttl=64`
- PCAP analysis shows TTL=1 in packets
- Bypass effectiveness reduced

**Diagnosis:**
```python
# Test strategy parsing
from core.strategy_interpreter import interpret_strategy
result = interpret_strategy("--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=64")
print(f"Parsed TTL: {result['params'].get('ttl')}")
```

**Solutions:**
1. Verify strategy interpreter includes TTL in params
2. Check bypass engine parameter extraction
3. Ensure packet injection uses correct TTL

#### Issue 2: TTL Parameter Not Recognized

**Symptoms:**
- TTL parameter ignored in strategy parsing
- No TTL field in parsed parameters
- Default TTL=1 always used

**Diagnosis:**
```python
# Check parameter parsing
result = interpret_strategy("--dpi-desync=fake --dpi-desync-ttl=64")
print(f"All params: {result['params']}")
print(f"TTL present: {'ttl' in result['params']}")
```

**Solutions:**
1. Update strategy interpreter regex patterns
2. Add TTL parameter to parameter mapping
3. Test with different attack types

#### Issue 3: TTL Not Applied to Packets

**Symptoms:**
- TTL correctly parsed in strategy
- PCAP shows wrong TTL in actual packets
- Bypass engine logs show correct TTL

**Diagnosis:**
```python
# Check bypass engine TTL usage
ttl = params.get("ttl")
effective_ttl = ttl if ttl else 1
print(f"Extracted TTL: {ttl}")
print(f"Effective TTL: {effective_ttl}")
```

**Solutions:**
1. Verify packet injection methods receive TTL
2. Check packet builder TTL application
3. Ensure all attack methods use TTL parameter

### Debugging Commands

```bash
# Test TTL parsing
python -c "
from core.strategy_interpreter import interpret_strategy
result = interpret_strategy('--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=64')
print('TTL:', result['params'].get('ttl'))
"

# Test with different values
python -c "
from core.strategy_interpreter import interpret_strategy
for ttl in [1, 32, 64, 128, 255]:
    result = interpret_strategy(f'--dpi-desync=fake --dpi-desync-ttl={ttl}')
    print(f'TTL {ttl}: {result[\"params\"].get(\"ttl\")}')
"

# Test complex strategy
python -c "
from core.strategy_interpreter import interpret_strategy
strategy = '--dpi-desync=fake,fakeddisorder --dpi-desync-split-seqovl=1 --dpi-desync-autottl=2 --dpi-desync-fake-http=PAYLOADTLS --dpi-desync-fake-tls=PAYLOADTLS --dpi-desync-fooling=badseq,md5sig --dpi-desync-ttl=64'
result = interpret_strategy(strategy)
print('TTL:', result['params'].get('ttl'))
print('Type:', result['type'])
"
```

## Testing Guidelines

### Unit Testing

```python
def test_ttl_parameter_parsing():
    """Test TTL parameter parsing."""
    strategy = "--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=64"
    result = interpret_strategy(strategy)
    
    assert 'error' not in result
    assert result['params']['ttl'] == 64
    assert result['type'] == 'fakeddisorder'
```

### Integration Testing

```python
def test_ttl_end_to_end():
    """Test TTL parameter end-to-end."""
    # Test complete flow from CLI to packet injection
    # Verify TTL preservation through pipeline
    # Compare with zapret reference behavior
```

### Regression Testing

```python
def test_ttl_regression():
    """Test TTL regression scenarios."""
    # Test original failing command
    # Test common TTL values
    # Test edge cases and boundary conditions
```

## Performance Considerations

### TTL Impact on Performance

| TTL Value | Performance Impact | Bypass Effectiveness |
|-----------|-------------------|---------------------|
| 1 | Minimal | High (aggressive) |
| 32 | Low | Medium-High |
| 64 | Low | Medium |
| 128 | Minimal | Medium-Low |
| 255 | Minimal | Low (conservative) |

### Optimization Tips

1. **Use appropriate TTL values**
   - Lower TTL = more aggressive bypass
   - Higher TTL = better compatibility

2. **Combine with AutoTTL**
   ```bash
   --dpi-desync-ttl=64 --dpi-desync-autottl=2
   ```

3. **Test different values**
   - Start with TTL=64
   - Adjust based on success rate
   - Monitor packet loss

## Code Examples

### Strategy Interpreter Usage

```python
from core.strategy_interpreter import interpret_strategy

# Basic TTL parsing
strategy = "--dpi-desync=fake,fakeddisorder --dpi-desync-ttl=64"
result = interpret_strategy(strategy)
ttl = result['params']['ttl']  # 64

# Complex strategy with TTL
complex_strategy = """
--dpi-desync=fake,fakeddisorder 
--dpi-desync-split-seqovl=1 
--dpi-desync-autottl=2 
--dpi-desync-fake-http=PAYLOADTLS 
--dpi-desync-fake-tls=PAYLOADTLS 
--dpi-desync-fooling=badseq,md5sig 
--dpi-desync-ttl=64
""".replace('\n', ' ').strip()

result = interpret_strategy(complex_strategy)
params = result['params']
print(f"TTL: {params['ttl']}")
print(f"AutoTTL: {params['autottl']}")
print(f"Attack: {result['type']}")
```

### Bypass Engine Usage

```python
from core.bypass_engine import BypassEngine

# Extract TTL from parsed strategy
def apply_bypass(params):
    ttl = params.get("ttl")
    effective_ttl = ttl if ttl else 1
    
    # Use TTL in packet injection
    send_fake_packet(ttl=effective_ttl)
    
def send_fake_packet(ttl=1):
    # Apply TTL to packet
    packet.ttl = ttl
    # Send packet
```

## Future Development

### Planned Enhancements

1. **TTL Auto-Detection**
   - Automatic TTL optimization based on network conditions
   - Dynamic TTL adjustment during bypass

2. **Advanced TTL Strategies**
   - TTL randomization for stealth
   - TTL progression algorithms

3. **Enhanced Validation**
   - Real-time TTL validation
   - Network-aware TTL recommendations

### Contribution Guidelines

When modifying TTL-related code:

1. **Maintain Compatibility**
   - Preserve zapret parameter compatibility
   - Keep existing TTL behavior

2. **Add Tests**
   - Unit tests for new TTL features
   - Regression tests for bug fixes

3. **Update Documentation**
   - Update this guide for new features
   - Add examples for new use cases

4. **Performance Testing**
   - Benchmark TTL impact
   - Test with real blocked domains

## References

### Related Files

- `core/strategy_interpreter.py` - TTL parameter parsing
- `core/bypass_engine.py` - TTL parameter usage
- `tests/test_ttl_parameter_parsing.py` - TTL unit tests
- `tests/test_ttl_regression.py` - TTL regression tests

### External References

- [Original zapret documentation](https://github.com/bol-van/zapret)
- [TCP TTL field specification](https://tools.ietf.org/html/rfc791)
- [DPI bypass techniques](https://github.com/ValdikSS/GoodbyeDPI)

---

**Last Updated:** September 2, 2024  
**Version:** 1.0  
**Maintainer:** Recon Development Team