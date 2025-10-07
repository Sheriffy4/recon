# StrategyParserV2 - Quick Start Guide

## Installation

No installation needed - files are already in place:
- `recon/core/strategy_parser_v2.py`
- `recon/core/strategy_parser_adapter.py`

## Basic Usage

### Parse a Strategy

```python
from core.strategy_parser_v2 import StrategyParserV2

parser = StrategyParserV2()

# Function-style
parsed = parser.parse("fake(ttl=1, fooling=['badsum'])")
print(parsed.attack_type)  # 'fake'
print(parsed.params)       # {'ttl': 1, 'fooling': ['badsum']}

# Zapret-style
parsed = parser.parse("--dpi-desync=fake --dpi-desync-ttl=1")
print(parsed.attack_type)  # 'fake'
print(parsed.params)       # {'ttl': 1}
```

### Validate Parameters

```python
from core.strategy_parser_v2 import parse_strategy

# Parse and validate in one call
parsed = parse_strategy("fake(ttl=1)", validate=True)

# This will raise ValueError
try:
    parsed = parse_strategy("fake(ttl=300)", validate=True)
except ValueError as e:
    print(f"Error: {e}")
```

### Use with Existing System

```python
from core.strategy_parser_adapter import StrategyParserAdapter

adapter = StrategyParserAdapter()

# Returns engine task format
result = adapter.interpret_strategy("fake(ttl=1)")
# {'type': 'fake', 'params': {'ttl': 1}}
```

## Supported Attacks

### Fake Attack
```python
# Function-style
"fake(ttl=1)"
"fake(ttl=1, fooling=['badsum'])"
"fake(ttl=1, fooling=['badsum', 'md5sig'], fake_sni='example.com')"

# Zapret-style
"--dpi-desync=fake --dpi-desync-ttl=1"
"--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-fooling=badsum"
```

### Split Attack
```python
# Function-style
"split(split_pos=1)"
"split(split_pos=76)"

# Zapret-style
"--dpi-desync=split --dpi-desync-split-pos=1"
```

### Disorder Attack
```python
# Function-style
"disorder(split_pos=2)"

# Zapret-style
"--dpi-desync=disorder --dpi-desync-split-pos=2"
```

### Fakeddisorder Attack
```python
# Function-style
"fakeddisorder(split_pos=76, overlap_size=336, ttl=3)"
"fakeddisorder(split_pos=76, ttl=3, fooling=['badsum', 'badseq'])"

# Zapret-style
"--dpi-desync=fake,disorder --dpi-desync-split-pos=76 --dpi-desync-ttl=3"
"--dpi-desync=fake,disorder --dpi-desync-split-pos=76 --dpi-desync-ttl=3 --dpi-desync-split-seqovl=336"
```

### Multisplit Attack
```python
# Function-style
"multisplit(split_count=5)"
"multisplit(split_count=5, ttl=64)"

# Zapret-style
"--dpi-desync=multisplit --dpi-desync-split-count=5"
```

### Multidisorder Attack
```python
# Function-style
"multidisorder(split_pos=3, ttl=1)"
```

## Parameter Types

### Integer
```python
"fake(ttl=1)"           # ttl = 1
"split(split_pos=76)"   # split_pos = 76
```

### String
```python
"fake(fake_sni='example.com')"  # fake_sni = 'example.com'
```

### List
```python
"fake(fooling=['badsum'])"                    # fooling = ['badsum']
"fake(fooling=['badsum', 'md5sig'])"          # fooling = ['badsum', 'md5sig']
```

### Boolean
```python
"fake(enabled=True)"   # enabled = True
"fake(enabled=False)"  # enabled = False
```

## Common Patterns

### Minimal Attack
```python
"fake(ttl=1)"
"split(split_pos=1)"
```

### With Fooling
```python
"fake(ttl=1, fooling=['badsum'])"
"fakeddisorder(split_pos=76, ttl=3, fooling=['badsum', 'badseq'])"
```

### Complex Attack
```python
"fakeddisorder(split_pos=76, overlap_size=336, ttl=3, fooling=['badsum', 'badseq'])"
```

## Error Handling

### Invalid Syntax
```python
try:
    parser.parse("invalid")
except ValueError as e:
    print(e)
    # Unknown syntax: invalid
    # Expected either:
    #   - Function-style: fake(ttl=1, fooling=['badsum'])
    #   - Zapret-style: --dpi-desync=fake --dpi-desync-ttl=1
```

### Missing Required Parameter
```python
try:
    parse_strategy("split()", validate=True)
except ValueError as e:
    print(e)
    # Validation failed for strategy 'split()':
    #   - Missing required parameter 'split_pos' for attack 'split'
```

### Out of Range
```python
try:
    parse_strategy("fake(ttl=300)", validate=True)
except ValueError as e:
    print(e)
    # Validation failed for strategy 'fake(ttl=300)':
    #   - Parameter 'ttl' value 300 is above maximum 255
```

## Testing

### Run Tests
```bash
cd recon

# Basic tests
python test_strategy_parser_v2.py

# Integration tests
python test_parser_integration.py

# Comprehensive tests
python test_all_attacks_parser.py
```

### Quick Test
```python
from core.strategy_parser_v2 import parse_strategy

# Test parsing
result = parse_strategy("fake(ttl=1, fooling=['badsum'])")
print(f"✓ Parsed: {result.attack_type}")
print(f"  Params: {result.params}")
```

## Integration

### Replace StrategyInterpreter

**Before:**
```python
from core.strategy_interpreter import StrategyInterpreter

interpreter = StrategyInterpreter()
result = interpreter.interpret_strategy(strategy_str)
```

**After:**
```python
from core.strategy_parser_adapter import StrategyParserAdapter

interpreter = StrategyParserAdapter()
result = interpreter.interpret_strategy(strategy_str)
```

### Function-Based Interface

```python
from core.strategy_parser_adapter import interpret_strategy

result = interpret_strategy("fake(ttl=1)")
```

## Tips

1. **Use function-style for readability:**
   ```python
   "fake(ttl=1, fooling=['badsum'])"  # Clear and concise
   ```

2. **Use zapret-style for compatibility:**
   ```python
   "--dpi-desync=fake --dpi-desync-ttl=1"  # Compatible with zapret
   ```

3. **Always validate in production:**
   ```python
   parsed = parse_strategy(strategy_str, validate=True)
   ```

4. **Check error messages:**
   ```python
   try:
       parsed = parse_strategy(strategy_str)
   except ValueError as e:
       print(f"Parse error: {e}")
   ```

## Troubleshooting

### Parser doesn't recognize syntax
- Check for typos in attack name
- Ensure parentheses are balanced
- Check parameter syntax (key=value)

### Validation fails
- Check parameter ranges (ttl: 1-255)
- Ensure required parameters are present
- Check parameter types (int, str, list)

### Integration issues
- Use StrategyParserAdapter for compatibility
- Check that result format matches expectations
- Verify backward compatibility with tests

## More Information

- Full documentation: `TASK1_STRATEGY_PARSER_V2_COMPLETION_REPORT.md`
- Design details: `.kiro/specs/attack-validation-suite/design.md`
- Requirements: `.kiro/specs/attack-validation-suite/requirements.md`
