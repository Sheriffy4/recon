# Task 4: Dictionary Format Fix

## Issue

After implementing Task 4 (AutoTTL), the `interpret_strategy()` method was returning an `AttackTask` dataclass object instead of a dictionary. This caused errors in code that expected a dictionary and tried to call `.get()` on the result:

```
Error parsing strategy: 'AttackTask' object has no attribute 'get'
```

## Root Cause

The `interpret_strategy()` method was refactored to return an `AttackTask` dataclass for better type safety, but existing code (like `hybrid_engine.py`) expected a dictionary format with `type` and `params` keys.

## Solution

Renamed the methods to maintain backward compatibility:

1. **`interpret_strategy()`** - Now returns a dictionary (backward compatible)
2. **`interpret_strategy_as_task()`** - Returns an `AttackTask` object (new method)

This ensures existing code continues to work while providing a new method for code that wants the typed `AttackTask` object.

## Changes Made

### File: `recon/core/strategy_interpreter.py`

**Before:**
```python
def interpret_strategy(self, strategy_str: str) -> Optional[AttackTask]:
    # Returns AttackTask object
    ...
```

**After:**
```python
def interpret_strategy(self, strategy_str: str) -> Optional[Dict[str, Any]]:
    """Returns dictionary for backward compatibility."""
    attack_task = self.interpret_strategy_as_task(strategy_str)
    if not attack_task:
        return None
    
    # Convert AttackTask to dict format
    params = {...}
    return {'type': attack_task.attack_type, 'params': params}

def interpret_strategy_as_task(self, strategy_str: str) -> Optional[AttackTask]:
    """Returns AttackTask object."""
    # Original implementation moved here
    ...
```

## Verification

Created test file `test_strategy_interpreter_dict_fix.py` to verify:

```python
result = interpreter.interpret_strategy(strategy_str)
assert isinstance(result, dict)
assert 'type' in result
assert 'params' in result
assert result.get('type') == 'multidisorder'
assert result.get('params', {}).get('autottl') == 1
```

**Test Result:** ✅ All tests passed

## Impact

- ✅ Backward compatibility maintained
- ✅ Existing code works without changes
- ✅ New code can use `interpret_strategy_as_task()` for typed objects
- ✅ AutoTTL functionality preserved
- ✅ No breaking changes

## Example Usage

### For existing code (dict format):
```python
interpreter = StrategyInterpreter()
strategy_dict = interpreter.interpret_strategy(strategy_str)
attack_type = strategy_dict.get('type')
params = strategy_dict.get('params', {})
autottl = params.get('autottl')
```

### For new code (typed format):
```python
interpreter = StrategyInterpreter()
attack_task = interpreter.interpret_strategy_as_task(strategy_str)
attack_type = attack_task.attack_type
autottl = attack_task.autottl
```

## Status

✅ **FIXED** - Dictionary format compatibility restored while maintaining AutoTTL functionality.

---

**Date:** 2025-10-06  
**Related Task:** Task 4 - Implement AutoTTL Calculation
