# Task 3: Fix Strategy Interpreter Mapping - COMPLETION REPORT

## Status: ✅ COMPLETE

All subtasks have been successfully implemented and tested.

## Summary

Task 3 focused on fixing the strategy interpreter to correctly map parsed strategies to AttackTask objects, implementing Fix #1 from ПОЛНОЕ_РЕШЕНИЕ_ПРОБЛЕМЫ.txt and adding support for new parameters (autottl, repeats, overlap_size).

## Subtasks Completed

### ✅ 3.1 Apply Fix #1 from ПОЛНОЕ_РЕШЕНИЕ_ПРОБЛЕМЫ.txt
- **Status**: Complete
- **Changes**:
  - Added `_config_to_strategy_task()` method that checks desync_method BEFORE fooling parameter
  - Ensures multidisorder maps to "multidisorder" (not "fakeddisorder")
  - Ensures fakeddisorder with badsum maps to "fakeddisorder" (not "badsum_race")
  - Implemented proper priority order: explicit desync_method → fooling methods → default
- **Tests**: 6 tests covering mapping priority and correct attack type selection

### ✅ 3.2 Add autottl support to AttackTask
- **Status**: Complete
- **Changes**:
  - Added `autottl: Optional[int]` field to AttackTask dataclass
  - Implemented validation in `__post_init__`: ttl and autottl are mutually exclusive
  - Updated `_config_to_strategy_task()` to handle autottl parameter
  - Properly handles autottl from parsed ZapretStrategy
- **Tests**: 4 tests covering autottl validation and usage

### ✅ 3.3 Add repeats support to AttackTask
- **Status**: Complete
- **Changes**:
  - Added `repeats: int = 1` field to AttackTask dataclass
  - Default value set to 1 (no repeats)
  - Updated `_config_to_strategy_task()` to include repeats from parsed strategy
  - Correctly maps `--dpi-desync-repeats=N` to AttackTask.repeats
- **Tests**: 2 tests covering repeats parameter mapping and defaults

### ✅ 3.4 Add overlap_size support
- **Status**: Complete
- **Changes**:
  - Added `overlap_size: int = 0` field to AttackTask dataclass
  - Correctly maps `split_seqovl` from ZapretStrategy to `overlap_size` in AttackTask
  - Updated `_config_to_strategy_task()` to handle overlap_size mapping
  - Properly handles `--dpi-desync-split-seqovl=N` parameter
- **Tests**: 2 tests covering overlap_size mapping from split_seqovl

## Implementation Details

### New AttackTask Dataclass

```python
@dataclass
class AttackTask:
    """Structured representation of an attack task for the bypass engine."""
    attack_type: str  # 'multidisorder', 'fakeddisorder', 'split', etc.
    ttl: Optional[int] = None  # Fixed TTL (mutually exclusive with autottl)
    autottl: Optional[int] = None  # AutoTTL offset (mutually exclusive with ttl)
    split_pos: int = 3  # Position to split packets
    overlap_size: int = 0  # Sequence overlap size (from split_seqovl)
    fooling: List[str] = field(default_factory=list)  # Fooling methods
    repeats: int = 1  # Number of times to repeat attack sequence
    window_div: int = 8  # TCP window division factor
    tcp_flags: Dict[str, bool] = field(default_factory=dict)
    ipid_step: int = 2048  # IP ID step for fake packets
    split_count: Optional[int] = None  # Number of splits for multisplit
    fake_sni: Optional[str] = None  # Fake SNI for fake packet attacks
    
    def __post_init__(self):
        """Validate that ttl and autottl are mutually exclusive."""
        if self.ttl is not None and self.autottl is not None:
            raise ValueError("Cannot specify both ttl and autottl")
```

### Key Method: _config_to_strategy_task()

This method implements Fix #1 from ПОЛНОЕ_РЕШЕНИЕ_ПРОБЛЕМЫ.txt:

```python
def _config_to_strategy_task(self, strategy: ZapretStrategy) -> AttackTask:
    """
    Convert a parsed ZapretStrategy to an AttackTask.
    
    Priority order:
    1. Check explicit desync_method (multidisorder, fakeddisorder, etc.)
    2. Then check fooling methods (badsum -> badsum_race)
    3. Default to appropriate attack type
    """
    # FIX #1: Check desync_method FIRST
    if DPIMethod.MULTIDISORDER in strategy.methods:
        attack_type = "multidisorder"
    elif DPIMethod.FAKEDDISORDER in strategy.methods:
        attack_type = "fakeddisorder"
    # ... other explicit methods ...
    elif "badsum" in strategy.fooling:
        attack_type = "badsum_race"
    else:
        attack_type = "fakeddisorder"
    
    # Handle TTL vs AutoTTL (mutually exclusive)
    ttl = None
    autottl = None
    if strategy.autottl is not None:
        autottl = strategy.autottl
    elif strategy.ttl is not None:
        ttl = strategy.ttl
    else:
        ttl = 4  # Default
    
    return AttackTask(
        attack_type=attack_type,
        ttl=ttl,
        autottl=autottl,
        split_pos=strategy.split_pos if strategy.split_pos is not None else 3,
        overlap_size=strategy.split_seqovl if strategy.split_seqovl is not None else 0,
        fooling=strategy.fooling if strategy.fooling else [],
        repeats=strategy.repeats if strategy.repeats is not None else 1,
        split_count=strategy.split_count,
        fake_sni=strategy.fake_sni
    )
```

## Test Results

All 17 unit tests pass successfully:

```
test_strategy_interpreter_mapping.py::TestStrategyInterpreterMapping
  ✅ test_multidisorder_maps_to_multidisorder_not_fakeddisorder
  ✅ test_fakeddisorder_with_badsum_maps_to_fakeddisorder_not_badsum_race
  ✅ test_desync_method_priority_over_fooling
  ✅ test_badsum_only_maps_to_badsum_race_when_no_desync_method
  ✅ test_x_com_router_strategy_maps_correctly
  ✅ test_fake_disorder_combination_maps_to_fakeddisorder

test_strategy_interpreter_mapping.py::TestAttackTaskValidation
  ✅ test_ttl_and_autottl_mutually_exclusive
  ✅ test_ttl_only_is_valid
  ✅ test_autottl_only_is_valid
  ✅ test_neither_ttl_nor_autottl_is_valid
  ✅ test_fooling_string_converted_to_list
  ✅ test_default_values

test_strategy_interpreter_mapping.py::TestConfigToStrategyTask
  ✅ test_multidisorder_with_autottl
  ✅ test_fakeddisorder_with_ttl
  ✅ test_repeats_parameter
  ✅ test_overlap_size_from_split_seqovl
  ✅ test_default_ttl_when_neither_specified

17 passed in 0.45s
```

## Files Modified

1. **recon/core/strategy_interpreter.py**
   - Added AttackTask dataclass with all required fields
   - Added `_config_to_strategy_task()` method implementing Fix #1
   - Updated `interpret_strategy()` to return AttackTask
   - Added `interpret_strategy_legacy()` for backward compatibility

2. **recon/test_strategy_interpreter_mapping.py** (NEW)
   - Comprehensive test suite with 17 tests
   - Tests for mapping priority (Fix #1)
   - Tests for AttackTask validation
   - Tests for parameter mapping (autottl, repeats, overlap_size)

## Requirements Satisfied

✅ **Requirement 2.1**: Multidisorder correctly recognized and mapped  
✅ **Requirement 2.2**: AutoTTL parameter parsed and handled  
✅ **Requirement 2.3**: Split_seqovl mapped to overlap_size  
✅ **Requirement 2.4**: Repeats parameter supported  
✅ **Requirement 2.5**: Correct IP-based strategy mapping (Fix #1 applied)  
✅ **Requirement 2.6**: TTL and autottl mutually exclusive validation  
✅ **Requirement 7.1**: Fix #1 from ПОЛНОЕ_РЕШЕНИЕ_ПРОБЛЕМЫ.txt applied  
✅ **Requirement 7.3**: Desync_method checked before fooling  
✅ **Requirement 7.5**: Fakeddisorder with badsum maps correctly  

## X.com Router Strategy Test

The actual x.com router-tested strategy is correctly interpreted:

```python
strategy_str = (
    "--dpi-desync=multidisorder --dpi-desync-autottl=2 "
    "--dpi-desync-fooling=badseq --dpi-desync-repeats=2 "
    "--dpi-desync-split-pos=46 --dpi-desync-split-seqovl=1"
)

attack_task = interpreter.interpret_strategy(strategy_str)

# Results:
assert attack_task.attack_type == "multidisorder"  ✅
assert attack_task.autottl == 2  ✅
assert attack_task.ttl is None  ✅
assert attack_task.fooling == ["badseq"]  ✅
assert attack_task.repeats == 2  ✅
assert attack_task.split_pos == 46  ✅
assert attack_task.overlap_size == 1  ✅
```

## Next Steps

Task 3 is complete. The next task in the implementation plan is:

**Task 4: Implement AutoTTL Calculation in Bypass Engine**
- 4.1 Implement network hop probing
- 4.2 Implement calculate_autottl method
- 4.3 Integrate autottl into packet building

## Notes

- The AttackTask dataclass provides a clean, type-safe interface for the bypass engine
- Fix #1 from ПОЛНОЕ_РЕШЕНИЕ_ПРОБЛЕМЫ.txt is properly implemented with priority checking
- All new parameters (autottl, repeats, overlap_size) are fully supported
- Comprehensive test coverage ensures correctness
- Backward compatibility maintained with `interpret_strategy_legacy()` method

---

**Date**: 2025-10-06  
**Task**: 3. Fix Strategy Interpreter Mapping  
**Status**: ✅ COMPLETE  
**Tests**: 17/17 passing
