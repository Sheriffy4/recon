# Split and Disorder Strategy Fix - Summary

## Problem

User-defined strategies `split` and `disorder` were **parsed correctly** but **NOT TESTED**. Instead, they were replaced with `unknown` strategy.

## Root Cause

The issue was in **three different places** in the strategy processing chain:

1. **Missing aliases** in `alias_map.py`
2. **Missing handler** in `strategy_interpreter.py`
3. **Incorrect conversion** in `hybrid_engine.py`

## Solution

### Fix #1: alias_map.py

Added missing aliases:

```python
_ALIAS_MAP = {
    # ... existing aliases ...
    "split": "split",
    "disorder": "disorder",
    "tcp_split": "split",
    "tcp_disorder": "disorder",
}
```

### Fix #2: strategy_interpreter.py

Added handler for `DPIMethod.DISORDER`:

```python
elif DPIMethod.DISORDER in strategy.methods:
    attack_type = "disorder"
    params = {'split_pos': strategy.split_pos}
```

### Fix #3: hybrid_engine.py

Updated `_translate_zapret_to_engine_task()`:

```python
elif 'split' in desync:
    task_type = 'split'
elif 'disorder' in desync or 'disorder2' in desync:
    task_type = 'disorder'  # Not fakeddisorder!
```

## Test Results

All unit tests passed (3/3):
- ✅ Alias normalization
- ✅ Strategy parsing
- ✅ Engine task conversion

## Files Changed

1. `recon/core/bypass/attacks/alias_map.py`
2. `recon/core/strategy_interpreter.py`
3. `recon/core/hybrid_engine.py`

## Testing

Run unit tests:
```bash
python test_split_disorder_fix.py
```

Run real-world tests:
```bash
python cli.py x.com --strategy "--dpi-desync=split --dpi-desync-split-pos=3" --pcap split.pcap
python cli.py x.com --strategy "--dpi-desync=disorder --dpi-desync-split-pos=3" --pcap disorder.pcap
```

## Status

✅ **FIXED AND TESTED**

Date: 2025-10-03
