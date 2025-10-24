# Current Attack System Behavior Documentation

**Generated:** 2025-10-21  
**Purpose:** Document current behavior and parameter handling quirks before refactoring  
**Requirements:** 9.1, 9.4

## Overview

This document captures the current behavior of the attack dispatch system, including parameter handling quirks, special behaviors, and implementation details that need to be preserved or improved during refactoring.

## Attack Types and Current Behavior

### 1. fakeddisorder (Primary Attack)
**Current Implementation:** `core/bypass/techniques/primitives.py:apply_fakeddisorder()`

**Behavior:**
- Sends fake packet with low TTL, then real parts in reverse order
- Most complex attack with highest execution time (avg: 13.57ms)
- High variance in performance (std dev: 16.39ms, range: 5.21-121.18ms)

**Parameter Handling Quirks:**
- `split_pos` can be int, str, or list - if list, takes first element
- Special values: "cipher", "sni", "midsld" are auto-resolved
- `ttl` and `fake_ttl` are interchangeable parameters
- `fooling` and `fooling_methods` are aliases
- Accepts extra parameters like `overlap_size` but ignores them

**Current Issues:**
- Inconsistent parameter naming (`ttl` vs `fake_ttl`)
- Silent parameter conversion (list to single value)
- No validation of special position values in payload context

### 2. seqovl (Sequence Overlap)
**Current Implementation:** `core/bypass/techniques/primitives.py:apply_seqovl()`

**Behavior:**
- Sends fake packet with sequence overlap, then full real packet
- Moderate execution time (avg: 11.40ms)
- Requires both `split_pos` and `overlap_size`

**Parameter Handling Quirks:**
- Requires explicit `overlap_size` parameter
- `fake_ttl` parameter preferred over `ttl`
- `fooling_methods` parameter preferred over `fooling`

**Current Issues:**
- Parameter precedence not documented
- No validation that overlap_size < payload length

### 3. multidisorder (Multi-part Disorder)
**Current Implementation:** `core/bypass/techniques/primitives.py:apply_multidisorder()`

**Behavior:**
- Splits packet into multiple parts, sends in reverse order with fake packet
- Consistent performance (avg: 8.08ms, std dev: 2.65ms)

**Parameter Handling Quirks:**
- Can use either `positions` list or single `split_pos`
- If `split_pos` provided, generates multiple positions automatically
- Converts string split_pos to int, falls back to payload//2 on error

**Current Issues:**
- Automatic position generation logic not documented
- No validation of position values against payload length

### 4. disorder (Simple Disorder)
**Current Implementation:** `core/bypass/techniques/primitives.py:apply_disorder()`

**Behavior:**
- Fastest attack (avg: 1.75ms, most consistent performance)
- Simple two-part split in reverse order, no fake packet
- Has `disorder2` variant with `ack_first=True`

**Parameter Handling Quirks:**
- Clean implementation with minimal parameter conversion
- `ack_first` parameter controls TCP flag behavior

**Current Issues:**
- None identified - cleanest implementation

### 5. multisplit (Multi-part Split)
**Current Implementation:** `core/bypass/techniques/primitives.py:apply_multisplit()`

**Behavior:**
- Fast and consistent (avg: 2.23ms, std dev: 0.83ms)
- Splits packet into multiple parts, sends in order

**Parameter Handling Quirks:**
- Complex parameter resolution logic
- Can use `positions`, `split_pos`, or `split_count`
- Generates positions automatically if not provided
- Falls back to payload//2 for single position

**Current Issues:**
- Multiple parameter sources create confusion
- Automatic position generation not well documented

## Special Parameter Values

### split_pos Special Values
The system supports special string values for `split_pos`:

1. **"cipher"** - Finds TLS cipher suite position (typically 40-50 bytes in ClientHello)
2. **"sni"** - Finds Server Name Indication position in TLS handshake
3. **"midsld"** - Finds middle of second-level domain in HTTP Host header

**Current Implementation Issues:**
- Position finding logic in `attack_dispatcher.py` methods:
  - `_find_cipher_position()`
  - `_find_sni_position()`
  - `_find_midsld_position()`
- No fallback behavior if special position not found
- No validation that found position is within payload bounds

## Parameter Handling Patterns

### Common Parameter Aliases
- `ttl` ↔ `fake_ttl` (interchangeable)
- `fooling` ↔ `fooling_methods` (interchangeable)
- `positions` ↔ `split_pos` (for multi-attacks)

### Parameter Conversion Behaviors
1. **List to Single Value:** `split_pos=[10, 20]` → `split_pos=10`
2. **String to Int:** `split_pos="10"` → `split_pos=10`
3. **Special Value Resolution:** `split_pos="cipher"` → `split_pos=45` (example)
4. **Default Fallbacks:** Missing positions → `payload_length // 2`

### Validation Gaps
- No bounds checking for numeric positions
- No payload length validation for special positions
- Silent parameter conversion without warnings
- Inconsistent error handling across attacks

## Performance Characteristics

### Execution Time Baseline (50 iterations each)
| Attack | Avg (ms) | Std Dev (ms) | Min (ms) | Max (ms) |
|--------|----------|--------------|----------|----------|
| disorder | 1.75 | 0.89 | 0.89 | 4.40 |
| multisplit | 2.23 | 0.83 | 1.45 | 4.54 |
| multidisorder | 8.08 | 2.65 | 5.35 | 21.89 |
| seqovl | 11.40 | 14.38 | 5.51 | 101.46 |
| fakeddisorder | 13.57 | 16.39 | 5.21 | 121.18 |

### Memory Usage
- Baseline: 224.28 MB
- After 100 dispatches: 224.53 MB
- Memory increase: 0.25 MB (2.52 KB per dispatch)
- Throughput: 747 dispatches/second

### Success Rates
- All attacks: 100% success rate in mock environment
- Real-world success rates vary by target and DPI system

## Registry and Dispatch Behavior

### Attack Registry
- Global singleton pattern: `get_attack_registry()`
- Automatic discovery of external attacks in `core/bypass/attacks/`
- Built-in attacks registered from `primitives.py`
- Alias resolution: `fake_disorder` → `fakeddisorder`

### Dispatch Priority
1. **Advanced attacks** from `core/bypass/attacks/` (if available)
2. **Primitive attacks** from `primitives.py` (fallback)
3. **Error handling** with detailed logging

### Current Dispatch Issues
- Inconsistent parameter validation between advanced and primitive attacks
- No standardized error reporting format
- Advanced attacks may not be available (import failures)

## Known Quirks and Workarounds

### 1. Parameter Precedence
```python
# Current behavior - last parameter wins
params = {"ttl": 3, "fake_ttl": 5}  # fake_ttl=5 is used
```

### 2. List Parameter Handling
```python
# Current behavior - takes first element
params = {"split_pos": [10, 20, 30]}  # Uses split_pos=10
```

### 3. Special Position Fallbacks
```python
# Current behavior - no error if special position not found
params = {"split_pos": "cipher"}  # May fall back to payload//2
```

### 4. Silent Parameter Conversion
```python
# Current behavior - converts without warning
params = {"split_pos": "10"}  # Becomes split_pos=10 (int)
```

## Compatibility Requirements

### Zapret Compatibility
- Parameter names must match zapret conventions
- Special position values must work identically
- Fooling methods must be compatible

### Backward Compatibility
- All current parameter combinations must continue working
- Existing aliases must be preserved
- Default behaviors must remain unchanged

## Recommendations for Refactoring

### High Priority Issues
1. **Standardize parameter validation** across all attacks
2. **Document parameter precedence** rules clearly
3. **Add bounds checking** for all position parameters
4. **Implement proper error handling** for special position resolution

### Medium Priority Issues
1. **Reduce performance variance** in fakeddisorder and seqovl
2. **Standardize parameter naming** (choose ttl vs fake_ttl)
3. **Add parameter conversion warnings** for debugging

### Low Priority Issues
1. **Optimize memory usage** per dispatch
2. **Add performance monitoring** hooks
3. **Implement parameter validation caching**

## Testing Requirements

### Regression Testing
- All current parameter combinations must pass
- Performance must not degrade significantly
- Memory usage must not increase substantially

### New Testing
- Bounds checking for all position parameters
- Special position resolution in various payload types
- Error handling for invalid parameters

---

**Note:** This documentation captures the current state as of 2025-10-21. Any changes during refactoring should be documented and validated against this baseline.