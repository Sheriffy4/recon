# Strategy Loader Package

Modular components for loading, parsing, normalizing, and validating DPI bypass strategies.

## Architecture

This package was extracted from a 1932-line god class (`UnifiedStrategyLoader`) to improve maintainability and reduce complexity.

## Modules

### Core Modules

- **`registry_integration.py`** (~236 LOC)
  - AttackRegistry integration
  - Hardcoded attacks fallback
  - Registry instance management

- **`param_normalizer.py`** (~377 LOC)
  - Parameter normalization and transformation
  - Special parameter handling (fooling, split_pos, etc.)
  - Attack-specific parameter defaults

- **`strategy_validator.py`** (~938 LOC)
  - Strategy validation logic
  - Attack combination validation
  - Parameter value validation
  - Attack-specific requirements

### Parsing Modules

- **`format_detection.py`** (~75 LOC)
  - Strategy format detection (zapret, function, colon, etc.)
  - Format priority handling

- **`parsing_utils.py`** (~98 LOC)
  - Low-level parsing utilities
  - Smart split, value parsing, list parsing

- **`strategy_parsers.py`** (~613 LOC)
  - Format-specific parsers
  - Zapret, function, colon, semicolon, comma-separated formats

### Helper Modules

- **`file_operations.py`** (~343 LOC)
  - File I/O operations
  - JSON serialization/deserialization
  - Strategy persistence

- **`registry_helpers.py`** (~289 LOC)
  - Registry query methods
  - Attack metadata retrieval
  - Attack handler access

- **`strategy_helpers.py`** (~196 LOC)
  - Miscellaneous utilities
  - Strategy name sanitization
  - Forced override creation
  - Dictionary normalization

## Public API

Import from `core.unified_strategy_loader`:

```python
from core.unified_strategy_loader import (
    UnifiedStrategyLoader,
    NormalizedStrategy,
    StrategyLoadError,
    StrategyValidationError,
    load_strategy,
    create_forced_override,
    load_strategies_from_file,
)
```

## Usage Example

```python
from core.unified_strategy_loader import UnifiedStrategyLoader

# Create loader
loader = UnifiedStrategyLoader(debug=True)

# Load strategy from string
strategy = loader.load_strategy("fakeddisorder")

# Load strategy from dict
strategy = loader.load_strategy({
    "type": "split",
    "params": {"split_pos": 3}
})

# Validate strategy
loader.validate_strategy(strategy)

# Create forced override
override = loader.create_forced_override(strategy)
```

## Refactoring History

- **Step 1-8**: Extracted functionality from god class into focused modules
- **Step 9**: Created package structure with proper documentation
- **Result**: Reduced main file from 1932 → 749 lines (61.2% reduction)

## Design Principles

1. **Single Responsibility**: Each module has one clear purpose
2. **No Circular Dependencies**: Careful import management
3. **Backward Compatibility**: All public APIs preserved
4. **Type Safety**: TYPE_CHECKING guards for circular imports
5. **Testability**: Pure functions where possible

## Testing

```bash
# Import validation
python -c "from core.unified_strategy_loader import UnifiedStrategyLoader; print('OK')"

# Full test suite
python -m pytest tests/ -v
```

## Version

- **Version**: 2.0.0
- **Author**: DPI Bypass Team
