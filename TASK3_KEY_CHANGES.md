# Task 3: Key Code Changes

## AttackTask Dataclass (NEW)

```python
@dataclass
class AttackTask:
    """Structured representation of an attack task for the bypass engine."""
    attack_type: str  # 'multidisorder', 'fakeddisorder', 'split', etc.
    ttl: Optional[int] = None  # Fixed TTL (mutually exclusive with autottl)
    autottl: Optional[int] = None  # AutoTTL offset (mutually exclusive with ttl)
    split_pos: int = 3
    overlap_size: int = 0  # From split_seqovl
    fooling: List[str] = field(default_factory=list)
    repeats: int = 1  # NEW: Number of attack repeats
    window_div: int = 8
    tcp_flags: Dict[str, bool] = field(default_factory=dict)
    ipid_step: int = 2048
    split_count: Optional[int] = None
    fake_sni: Optional[str] = None
    
    def __post_init__(self):
        """Validate that ttl and autottl are mutually exclusive."""
        if self.ttl is not None and self.autottl is not None:
            raise ValueError("Cannot specify both ttl and autottl")
```

## _config_to_strategy_task() Method (NEW)

This implements Fix #1 from ПОЛНОЕ_РЕШЕНИЕ_ПРОБЛЕМЫ.txt:

```python
def _config_to_strategy_task(self, strategy: ZapretStrategy) -> AttackTask:
    """
    Convert a parsed ZapretStrategy to an AttackTask.
    
    FIX #1: Check desync_method BEFORE fooling parameter.
    """
    # Priority 1: Explicit desync method
    if DPIMethod.MULTIDISORDER in strategy.methods:
        attack_type = "multidisorder"
    elif DPIMethod.FAKEDDISORDER in strategy.methods:
        attack_type = "fakeddisorder"
    elif DPIMethod.DISORDER2 in strategy.methods:
        attack_type = "disorder2"
    elif DPIMethod.DISORDER in strategy.methods:
        attack_type = "disorder"
    elif DPIMethod.MULTISPLIT in strategy.methods:
        attack_type = "multisplit"
    elif DPIMethod.SPLIT in strategy.methods:
        attack_type = "split"
    elif DPIMethod.FAKE in strategy.methods:
        attack_type = "fake"
    # Priority 2: Check fooling only if no explicit desync method
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
        ttl = 4
    
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

## Updated interpret_strategy() Method

```python
def interpret_strategy(self, strategy_str: str) -> Optional[AttackTask]:
    """
    Main entry point to interpret a strategy and convert it to an AttackTask.
    
    Returns:
        AttackTask object ready for execution, or None if parsing fails
    """
    strategy = self.parse_strategy(strategy_str)
    
    # X.COM FAKEDDISORDER FIX
    if DPIMethod.FAKEDDISORDER in strategy.methods:
        if strategy.ttl is None or strategy.ttl > 10:
            strategy.ttl = 3
        if strategy.split_pos is None:
            strategy.split_pos = 3
        if strategy.split_seqovl is None:
            strategy.split_seqovl = 336
        if not strategy.fooling:
            strategy.fooling = ["badsum", "badseq"]
    
    if not self.validate_strategy(strategy):
        return None

    # Convert to AttackTask using the new method
    try:
        attack_task = self._config_to_strategy_task(strategy)
        self.logger.info(f"✅ Strategy interpreted: {attack_task.attack_type} "
                       f"(ttl={attack_task.ttl}, autottl={attack_task.autottl}, "
                       f"split_pos={attack_task.split_pos}, repeats={attack_task.repeats})")
        return attack_task
    except ValueError as e:
        self.logger.error(f"Failed to create AttackTask: {e}")
        return None
```

## Example Usage

```python
from core.strategy_interpreter import StrategyInterpreter

interpreter = StrategyInterpreter()

# X.com router-tested strategy
strategy_str = (
    "--dpi-desync=multidisorder --dpi-desync-autottl=2 "
    "--dpi-desync-fooling=badseq --dpi-desync-repeats=2 "
    "--dpi-desync-split-pos=46 --dpi-desync-split-seqovl=1"
)

attack_task = interpreter.interpret_strategy(strategy_str)

# Result:
# AttackTask(
#     attack_type='multidisorder',
#     ttl=None,
#     autottl=2,
#     split_pos=46,
#     overlap_size=1,
#     fooling=['badseq'],
#     repeats=2,
#     ...
# )
```

## Key Improvements

1. **Type Safety**: AttackTask provides a structured, type-safe interface
2. **Fix #1 Applied**: Correct priority order prevents mapping bugs
3. **New Parameters**: Full support for autottl, repeats, overlap_size
4. **Validation**: Mutual exclusivity of ttl/autottl enforced
5. **Logging**: Comprehensive logging of interpreted parameters
6. **Backward Compatibility**: Legacy dict format still available

## Testing

All functionality is covered by 17 unit tests:
- Mapping priority tests (Fix #1)
- AttackTask validation tests
- Parameter mapping tests
- X.com strategy integration test

```bash
python -m pytest recon/test_strategy_interpreter_mapping.py -v
# Result: 17 passed
```
