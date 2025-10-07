# Parameter Validation Guide

## Overview

The StrategyParserV2 includes comprehensive parameter validation to ensure attack strategies are correctly specified before execution. This prevents runtime errors and provides clear feedback when parameters are invalid.

## Features

### 1. Required Parameter Validation

Each attack type has specific required parameters that must be present:

```python
# ✓ Valid - has required split_pos
parse_strategy("split(split_pos=1)")

# ✗ Invalid - missing required split_pos
parse_strategy("split()")
# Error: Missing required parameter 'split_pos' for attack 'split'
```

**Required Parameters by Attack:**
- `split`: `split_pos`
- `disorder`: `split_pos`
- `disorder2`: `split_pos`
- `multisplit`: `split_count`
- `multidisorder`: `split_pos`
- `fakeddisorder`: `split_pos`
- `seqovl`: `split_pos`, `overlap_size`
- `fake`: (none)

### 2. Parameter Type Validation

Parameters must be of the correct type:

```python
# ✓ Valid - ttl is int
parse_strategy("fake(ttl=1)")

# ✓ Valid - fooling is list
parse_strategy("fake(fooling=['badsum'])")

# ✓ Valid - fake_sni is string
parse_strategy("fake(fake_sni='example.com')")

# ✓ Valid - split_pos can be int or 'midsld'
parse_strategy("split(split_pos=1)")
parse_strategy("split(split_pos='midsld')")
```

**Parameter Types:**
- `ttl`, `autottl`, `fake_ttl`: `int`
- `split_pos`: `int` or `str` (only 'midsld' allowed)
- `split_count`: `int`
- `overlap_size`, `split_seqovl`: `int`
- `repeats`: `int`
- `fooling`: `list`
- `fake_sni`: `str`
- `enabled`: `bool`

### 3. Parameter Range Validation

Numeric parameters must be within valid ranges:

```python
# ✓ Valid - ttl in range [1, 255]
parse_strategy("fake(ttl=1)")
parse_strategy("fake(ttl=64)")
parse_strategy("fake(ttl=255)")

# ✗ Invalid - ttl out of range
parse_strategy("fake(ttl=0)")
# Error: Parameter 'ttl' value 0 is below minimum 1

parse_strategy("fake(ttl=300)")
# Error: Parameter 'ttl' value 300 is above maximum 255
```

**Parameter Ranges:**
- `ttl`, `autottl`, `fake_ttl`: 1-255
- `split_pos`: 0-65535 (or 'midsld')
- `split_count`: 1-100
- `overlap_size`, `split_seqovl`: 0-65535
- `repeats`: 1-10

### 4. List Value Validation

List parameters have allowed values:

```python
# ✓ Valid - all values are allowed
parse_strategy("fake(fooling=['badsum'])")
parse_strategy("fake(fooling=['badsum', 'md5sig'])")
parse_strategy("fake(fooling=['badseq', 'hopbyhop', 'datanoack'])")

# ✗ Invalid - contains invalid value
parse_strategy("fake(fooling=['invalid'])")
# Error: Parameter 'fooling' contains invalid value 'invalid'
```

**Allowed Values for `fooling`:**
- `badsum` - Corrupt TCP checksum
- `md5sig` - Add MD5 signature option
- `badseq` - Use bad sequence number
- `hopbyhop` - Add hop-by-hop option
- `datanoack` - Send data without ACK

### 5. Clear Error Messages

Validation errors provide detailed information:

```python
try:
    parse_strategy("split()")
except ValueError as e:
    print(e)
```

Output:
```
Validation failed for strategy 'split()':
  - Missing required parameter 'split_pos' for attack 'split'. 
    Description: Position to split packet (or "midsld")

Attack: split
Description: Split packet at specified position
Required parameters: split_pos
Optional parameters: ttl, fooling
```

## Usage

### Basic Usage

```python
from core.strategy_parser_v2 import parse_strategy

# Parse and validate (default)
parsed = parse_strategy("fake(ttl=1, fooling=['badsum'])")

# Parse without validation
parsed = parse_strategy("fake(ttl=1)", validate=False)
```

### Manual Validation

```python
from core.strategy_parser_v2 import StrategyParserV2, ParameterValidator

parser = StrategyParserV2()
validator = ParameterValidator()

# Parse
parsed = parser.parse("fake(ttl=1)")

# Validate
try:
    validator.validate(parsed)
    print("Valid!")
except ValueError as e:
    print(f"Invalid: {e}")
```

### Getting Parameter Info

```python
from core.strategy_parser_v2 import ParameterValidator

validator = ParameterValidator()

# Get attack info
attack_info = validator.get_attack_info('fake')
print(f"Required: {attack_info['required']}")
print(f"Optional: {attack_info['optional']}")
print(f"Description: {attack_info['description']}")

# Get parameter info
param_info = validator.get_parameter_info('ttl')
print(f"Type: {param_info['type']}")
print(f"Range: {param_info['min']}-{param_info['max']}")
print(f"Description: {param_info['description']}")
```

## Attack Specifications

### fake

Send fake packet with low TTL before real packet.

**Required:** None  
**Optional:** `ttl`, `fake_ttl`, `fooling`, `fake_sni`

```python
parse_strategy("fake(ttl=1)")
parse_strategy("fake(ttl=1, fooling=['badsum'])")
parse_strategy("fake(fake_sni='example.com', fooling=['md5sig'])")
```

### split

Split packet at specified position.

**Required:** `split_pos`  
**Optional:** `ttl`, `fooling`

```python
parse_strategy("split(split_pos=1)")
parse_strategy("split(split_pos=2, ttl=64)")
parse_strategy("split(split_pos='midsld')")
```

### disorder

Send packet fragments in disorder.

**Required:** `split_pos`  
**Optional:** `ttl`, `overlap_size`, `fooling`

```python
parse_strategy("disorder(split_pos=2)")
parse_strategy("disorder(split_pos=3, overlap_size=10)")
```

### multisplit

Split packet into multiple fragments.

**Required:** `split_count`  
**Optional:** `ttl`, `fooling`

```python
parse_strategy("multisplit(split_count=5)")
parse_strategy("multisplit(split_count=3, ttl=64)")
```

### fakeddisorder

Send fake packet, then real packets in disorder.

**Required:** `split_pos`  
**Optional:** `ttl`, `fake_ttl`, `overlap_size`, `fooling`, `fake_sni`

```python
parse_strategy("fakeddisorder(split_pos=76)")
parse_strategy("fakeddisorder(split_pos=76, overlap_size=336, ttl=3)")
parse_strategy("fakeddisorder(split_pos=76, ttl=1, fooling=['badsum'])")
```

### seqovl

Sequence overlap attack.

**Required:** `split_pos`, `overlap_size`  
**Optional:** `ttl`, `fooling`

```python
parse_strategy("seqovl(split_pos=5, overlap_size=100)")
parse_strategy("seqovl(split_pos=10, overlap_size=50, ttl=64)")
```

## Testing

Run the comprehensive validation test suite:

```bash
python test_parameter_validation.py
```

This tests:
- Required parameter validation
- Parameter type validation
- Parameter range validation
- List value validation
- Error message quality
- Validator info methods

## Implementation Details

### ParameterValidator Class

The `ParameterValidator` class contains:

1. **param_specs**: Dictionary of parameter specifications
   - Type requirements
   - Min/max ranges
   - Allowed values
   - Descriptions

2. **attack_requirements**: Dictionary of attack specifications
   - Required parameters
   - Optional parameters
   - Attack descriptions

3. **validate()**: Main validation method
   - Checks required parameters
   - Validates parameter types
   - Validates parameter ranges
   - Validates list values
   - Returns detailed error messages

4. **get_attack_info()**: Get attack specification
5. **get_parameter_info()**: Get parameter specification

### Validation Process

1. Parse strategy string
2. Check attack type is known
3. Validate required parameters present
4. Validate each parameter:
   - Check type matches specification
   - Check value is in valid range
   - Check list values are allowed
5. Generate warnings for unusual parameter combinations
6. Raise ValueError with detailed message if validation fails

## Benefits

1. **Early Error Detection**: Catch invalid parameters before execution
2. **Clear Feedback**: Detailed error messages explain what's wrong
3. **Type Safety**: Ensure parameters are correct types
4. **Range Safety**: Prevent out-of-range values
5. **Documentation**: Parameter specs serve as documentation
6. **Maintainability**: Easy to add new parameters and attacks

## Future Enhancements

Potential improvements:
- Cross-parameter validation (e.g., overlap_size < split_pos)
- Parameter dependency validation
- Custom validation rules per attack
- Validation warnings vs errors
- Auto-correction suggestions
