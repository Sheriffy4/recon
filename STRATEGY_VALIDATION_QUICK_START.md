# Strategy Validation - Quick Start Guide

## Overview

Strategy validation ensures that generated strategies are syntactically correct and use available attacks before execution.

## Quick Examples

### 1. Validate Generated Strategies

```python
from core.cli_validation_integration import validate_generated_strategies

# Your strategies
strategies = [
    {'type': 'fake_disorder', 'split_pos': 3, 'ttl': 4, 'fooling': ['badsum']},
    {'type': 'multisplit', 'split_count': 5, 'ttl': 4}
]

# Validate
result = validate_generated_strategies(strategies)

# Check result
if result['passed']:
    print(f"✓ All {result['total_strategies']} strategies are valid")
else:
    print(f"✗ Found {len(result['errors'])} errors")
    for error in result['errors']:
        print(f"  - {error}")
```

### 2. Validate Strategy String

```python
from core.cli_validation_integration import validate_strategy_string

# Zapret style
result = validate_strategy_string(
    "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-ttl=4"
)

# Function style
result = validate_strategy_string(
    "fake_disorder(split_pos=3, ttl=4, fooling=['badsum'])"
)

if result.passed:
    print(f"✓ Valid strategy: {result.strategy['type']}")
else:
    for error in result.errors:
        print(f"✗ {error}")
```

### 3. Quick Syntax Check

```python
from core.cli_validation_integration import check_strategy_syntax

result = check_strategy_syntax("fake_disorder(split_pos=3, ttl=4)")

if result['valid_syntax']:
    print(f"✓ Valid {result['syntax_type']} syntax")
    print(f"  Attack: {result['attack_type']}")
    print(f"  Params: {result['parameters']}")
```

### 4. Validate and Report (with Rich)

```python
from rich.console import Console
from core.cli_validation_integration import validate_and_report_strategies

console = Console()

strategies = [
    {'type': 'fake_disorder', 'split_pos': 3, 'ttl': 4},
    {'type': 'multisplit', 'split_count': 5}
]

# Validate and show formatted output
all_valid = validate_and_report_strategies(
    strategies,
    console=console,
    verbose=True
)
```

## Common Validation Errors

### Error: Attack Not Found

```
✗ Attack type 'invalid_attack' not found in registry
```

**Fix**: Use a registered attack type
```python
# Wrong
{'type': 'invalid_attack'}

# Correct
{'type': 'fake_disorder'}
```

### Error: Wrong Parameter Type

```
✗ Parameter 'fooling' has wrong type. Expected list, got str.
```

**Fix**: Use correct type
```python
# Wrong
{'fooling': 'badsum'}

# Correct
{'fooling': ['badsum']}
```

### Error: Parameter Out of Range

```
✗ Parameter 'ttl' value 999 is above maximum 255.
```

**Fix**: Use value within range
```python
# Wrong
{'ttl': 999}

# Correct
{'ttl': 4}
```

### Error: Invalid Parameter Value

```
✗ Parameter 'fooling' contains invalid value 'invalid_fooling'.
Allowed values: badsum, md5sig, badseq, hopbyhop, datanoack.
```

**Fix**: Use allowed values
```python
# Wrong
{'fooling': ['invalid_fooling']}

# Correct
{'fooling': ['badsum', 'md5sig']}
```

## Parameter Reference

### Common Parameters

| Parameter | Type | Range | Example |
|-----------|------|-------|---------|
| `ttl` | int | 1-255 | `4` |
| `split_pos` | int/str | 0-65535 or "midsld" | `3` |
| `split_count` | int | 1-100 | `5` |
| `split_seqovl` | int | 0-65535 | `20` |
| `fooling` | list | See below | `['badsum']` |
| `repeats` | int | 1-10 | `2` |

### Fooling Methods

Valid values for `fooling` parameter:
- `badsum` - Invalid TCP checksum
- `md5sig` - MD5 signature option
- `badseq` - Invalid sequence number
- `hopbyhop` - IPv6 hop-by-hop option
- `datanoack` - Data without ACK

## CLI Integration Example

```python
# In your CLI code after fingerprinting
if args.validate:
    from core.cli_validation_integration import validate_and_report_strategies
    
    # Validate generated strategies
    all_valid = validate_and_report_strategies(
        generated_strategies,
        console=console,
        verbose=args.verbose
    )
    
    # Handle validation failure
    if not all_valid:
        console.print("[yellow]⚠ Some strategies failed validation[/yellow]")
        
        # Ask user if they want to continue
        if not Confirm.ask("Continue with valid strategies only?"):
            sys.exit(1)
        
        # Filter to valid strategies only
        valid_strategies = [
            result.strategy 
            for result in validation_summary['results'] 
            if result.passed
        ]
        generated_strategies = valid_strategies
```

## Testing

Run the test suite:

```bash
cd recon
python test_strategy_validation_integration.py
```

Expected output:
```
======================================================================
✓ ALL TESTS PASSED
======================================================================
```

## Troubleshooting

### Issue: Validation is slow

**Solution**: Registry is cached after first load. Subsequent validations are fast.

### Issue: Unknown parameter warnings

**Solution**: These are warnings, not errors. The strategy will still work if the attack supports the parameter.

### Issue: Attack not found but it exists

**Solution**: Check attack name spelling and aliases. Use `get_supported_attacks()` to see all available attacks.

## More Information

- Full documentation: `docs/STRATEGY_VALIDATION_CLI_INTEGRATION.md`
- Completion report: `TASK_6.2_STRATEGY_VALIDATION_CLI_INTEGRATION_COMPLETE.md`
- Test suite: `test_strategy_validation_integration.py`

## Support

For issues or questions:
1. Check the full documentation
2. Run the test suite to verify installation
3. Review error messages carefully - they include helpful descriptions
4. Check parameter specifications in error messages
