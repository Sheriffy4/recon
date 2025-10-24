# Design Document: Attack System Refactoring

## Overview

This design document outlines the technical approach for refactoring the DPI bypass attack system to eliminate duplicates, consolidate registries, and optimize attack logic. The refactoring will transform a fragmented system with multiple duplicate implementations into a clean, unified architecture with a single source of truth for each attack.

### Goals

1. **Eliminate Duplicates**: Remove all duplicate attack implementations, keeping only canonical versions
2. **Unified Registry**: Consolidate multiple registry systems into a single, authoritative registry
3. **Optimized Logic**: Ensure canonical implementations use the most effective algorithms and parameters
4. **Clean Imports**: Provide clear, predictable import paths for all attacks
5. **Backward Compatibility**: Maintain existing functionality while improving structure

### Current State Analysis

**Identified Duplicates:**
- `fake_disorder_attack.py` (3 versions in `core/bypass/attacks/tcp/`)
  - `fake_disorder_attack.py`
  - `fake_disorder_attack_fixed.py`
  - `fake_disorder_attack_original.py`
- Disorder family implementations scattered across:
  - `core/bypass/techniques/primitives.py` (canonical)
  - `core/bypass/attacks/tcp/`
  - `core/bypass/attacks/reference/`

**Multiple Registries:**
- `core/bypass/attacks/attack_registry.py` (primary)
- `core/bypass/attacks/registry.py`
- `core/bypass/attacks/modern_registry.py`
- `core/bypass/techniques/registry.py`
- `core/integration/advanced_attack_registry.py`

**Canonical Attack Location:**
- Expert guidance: `core/bypass/techniques/primitives.py` contains canonical implementations
- All disorder family attacks (disorder, disorder2, multidisorder, fakeddisorder, multisplit, split, seqovl, fake) should derive from primitives

## Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Attack System                             │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────────────────────────────────────────────┐  │
│  │         Unified Attack Registry                       │  │
│  │  - Single source of truth for all attacks            │  │
│  │  - Deduplication logic                                │  │
│  │  - Priority-based registration                        │  │
│  │  - Metadata management                                │  │
│  └──────────────────────────────────────────────────────┘  │
│                          ▲ (Registers)                       │
│                          │                                   │
│  ┌───────────────────────┴──────────────────────────────┐  │
│  │         Attack Implementations                        │  │
│  │  ┌──────────────────┐      ┌──────────────────────┐ │  │
│  │  │  Core Attacks    │      │  External Attacks    │ │  │
│  │  │  (primitives.py) │      │  (attack modules)    │ │  │
│  │  │  Priority: CORE  │      │  Priority: NORMAL    │ │  │
│  │  └──────────────────┘      └──────────────────────┘ │  │
│  └────────────────────────────────────────────────────────┘│
│                          │ (Provides Handlers)               │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐  │
│  │         Attack Dispatcher & Execution Layer           │  │
│  │  - Resolves strategy to canonical attack             │  │
│  │  - Calls appropriate handler from Registry           │  │
│  │  - Normalizes parameters (split_pos → positions)     │  │
│  │  - Uses BypassTechniques (primitives) for execution  │  │
│  │  - Validates AttackContext                            │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### Component Architecture

#### 1. Attack Dispatcher

**Location**: `core/bypass/engine/attack_dispatcher.py`

**Responsibilities:**
- Resolve strategy strings to canonical attack names
- Normalize parameters before passing to handlers
- Call appropriate attack handler from registry
- Validate AttackContext
- Handle parameter conversion (e.g., split_pos → positions)

**Key Classes:**

```python
class AttackDispatcher:
    """Dispatches attack execution requests to appropriate handlers."""
    
    def __init__(self, registry: AttackRegistry):
        self.registry = registry
        self.parameter_normalizer = ParameterNormalizer()
        
    def dispatch(
        self,
        attack_name: str,
        context: AttackContext,
        **params
    ) -> AttackResult:
        """
        Dispatch attack execution.
        
        1. Resolve attack name (handle aliases)
        2. Normalize parameters
        3. Validate context and parameters
        4. Get handler from registry
        5. Execute attack
        6. Return result
        """
        
    def resolve_strategy(
        self,
        strategy: str
    ) -> List[Tuple[str, Dict[str, Any]]]:
        """
        Resolve zapret-style strategy to attack sequence.
        
        Example: "fake,disorder" → [("fakeddisorder", {...})]
        """

class ParameterNormalizer:
    """Normalizes attack parameters to unified format."""
    
    def normalize(
        self,
        attack_type: str,
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Normalize parameters for attack.
        
        Examples:
        - split_pos: 3 → positions: [3]
        - split_pos: [1, 5] → positions: [1, 5]
        - overlap_size: 336 → overlap_size: 336 (no change)
        """

class AttackContext:
    """Unified context for all attacks."""
    
    payload: bytes
    dst_ip: str
    dst_port: int
    protocol: str  # "tcp", "udp", "tls", "http"
    connection_id: str
    metadata: Dict[str, Any]
```

#### 2. Unified Attack Registry

**Location**: `core/bypass/attacks/attack_registry.py` (consolidated)

**Responsibilities:**
- Maintain single registry of all attacks
- Prevent duplicate registrations
- Provide priority-based registration (core > external)
- Validate attack metadata and parameters
- Resolve attack aliases to canonical names

**Key Classes:**

```python
class AttackRegistry:
    """Unified registry for all DPI bypass attacks."""
    
    def __init__(self):
        self.attacks: Dict[str, AttackEntry] = {}
        self._aliases: Dict[str, str] = {}
        self._registration_order: List[str] = []
        
    def register_attack(
        self, 
        attack_type: str,
        handler: Callable,
        metadata: AttackMetadata,
        priority: RegistrationPriority = RegistrationPriority.NORMAL
    ) -> RegistrationResult:
        """Register attack with deduplication and priority handling."""
        
    def get_attack_handler(self, attack_type: str) -> Optional[Callable]:
        """Get handler for attack, resolving aliases."""
        
    def validate_parameters(
        self, 
        attack_type: str, 
        params: Dict[str, Any]
    ) -> ValidationResult:
        """Validate parameters for specific attack."""

class RegistrationPriority(Enum):
    """Priority levels for attack registration."""
    CORE = 100      # From primitives.py
    HIGH = 75       # Verified effective implementations
    NORMAL = 50     # Standard external attacks
    LOW = 25        # Experimental attacks
    
class AttackEntry:
    """Entry in attack registry."""
    handler: Callable
    metadata: AttackMetadata
    priority: RegistrationPriority
    source_module: str
    registration_time: datetime
```

#### 3. Core Attack Primitives

**Location**: `core/bypass/techniques/primitives.py` (enhanced)

**Responsibilities:**
- Provide canonical implementations of all core attacks
- Implement shared helper functions for attack families
- Use optimized parameters based on effectiveness data
- Serve as single source of truth for attack logic
- Support implementation promotion mechanism

**Enhanced Structure:**

```python
class BypassTechniques:
    """Canonical implementations of DPI bypass techniques."""
    
    # Shared helpers for disorder family
    @staticmethod
    def _split_payload(
        payload: bytes,
        split_pos: int,
        validate: bool = True
    ) -> Tuple[bytes, bytes]:
        """Shared payload splitting logic for all disorder attacks."""
        
    @staticmethod
    def _create_segment_options(
        is_fake: bool,
        ttl: int,
        fooling_methods: List[str],
        **kwargs
    ) -> Dict[str, Any]:
        """Shared segment options creation for all attacks."""
    
    # Implementation promotion mechanism
    @staticmethod
    def promote_implementation(
        attack_name: str, 
        new_handler: Callable,
        reason: str,
        performance_data: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Allows promoting a more advanced implementation from an external module
        to become the canonical handler for a core attack type.
        
        This should be used sparingly and only after thorough testing and
        validation that the new implementation is more effective.
        
        Args:
            attack_name: Name of the attack to promote
            new_handler: New handler function to use
            reason: Justification for promotion (e.g., "30% better success rate on x.com")
            performance_data: Optional performance metrics supporting the promotion
            
        Returns:
            True if promotion successful, False otherwise
        """
    
    # Canonical attack implementations
    @staticmethod
    def apply_fakeddisorder(
        payload: bytes,
        split_pos: int = 3,  # Optimized default
        fake_ttl: int = 3,   # Optimized default
        fooling_methods: List[str] = None,
        **kwargs
    ) -> List[Tuple[bytes, int, dict]]:
        """
        Canonical fakeddisorder implementation.
        
        Key optimization: Fake packet contains FULL payload (critical for x.com).
        """
        
    @staticmethod
    def apply_seqovl(
        payload: bytes,
        split_pos: int,
        overlap_size: int,
        fake_ttl: int = 3,
        fooling_methods: List[str] = None
    ) -> List[Tuple[bytes, int, dict]]:
        """
        Canonical seqovl implementation.
        
        Key optimization: Correct overlap calculation, real packet intact.
        """
        
    @staticmethod
    def apply_disorder(
        payload: bytes,
        split_pos: int,
        ack_first: bool = False
    ) -> List[Tuple[bytes, int, dict]]:
        """Canonical simple disorder implementation."""
        
    @staticmethod
    def apply_multidisorder(
        payload: bytes,
        positions: List[int],
        fooling: List[str] = None,
        fake_ttl: int = 3
    ) -> List[Tuple[bytes, int, dict]]:
        """Canonical multidisorder implementation."""
```

#### 3.1. Unified Attack Context and Parameters

**Purpose**: Standardize how all attacks receive and process parameters.

**Unified Parameter Names:**
- `positions: List[int]` - Always use for splitting positions (even single position)
- `ttl: int` - Time to live for packets
- `fake_ttl: int` - TTL specifically for fake packets
- `fooling_methods: List[str]` - Methods to fool DPI
- `overlap_size: int` - Size of sequence overlap

**Parameter Normalization Rules:**

```python
# Old style (deprecated but supported)
split_pos: 3 → positions: [3]
split_pos: [1, 5] → positions: [1, 5]

# New style (canonical)
positions: [3]  # Always a list
positions: [1, 5, 10]  # Multiple positions
```

**AttackDispatcher Responsibility:**
The AttackDispatcher normalizes all incoming parameters before passing them to handlers. This means:
- Attack handlers always receive parameters in canonical format
- Backward compatibility is maintained at the dispatcher level
- New attacks only need to support canonical format

**Benefits:**
- Simplified attack implementation
- Consistent parameter handling
- Easier to add new attacks
- Clear migration path for old code

#### 4. Attack Registration System

**Registration Flow:**

```
1. System Initialization
   ↓
2. Register Core Attacks (primitives.py)
   - Priority: CORE
   - Cannot be overridden by lower priority
   ↓
3. Discover External Attack Modules
   - Scan core/bypass/attacks/ for modules
   - Strategy: Eager loading (default) or Lazy loading (optional)
   - With lazy loading, registry stores module paths, and imports 
     a module only when an attack from it is first requested
   - Skip excluded files
   ↓
4. Register External Attacks
   - Priority: NORMAL/LOW
   - Deduplicate against core
   - Can promote to CORE with explicit approval
   ↓
5. Validate Registry
   - Check for conflicts
   - Verify all handlers
   - Log registration summary
```

**Deduplication Logic:**

```python
def _handle_duplicate_registration(
    self,
    attack_type: str,
    new_entry: AttackEntry,
    existing_entry: AttackEntry
) -> RegistrationResult:
    """Handle duplicate attack registration based on priority."""
    
    if new_entry.priority > existing_entry.priority:
        # Higher priority wins
        self.attacks[attack_type] = new_entry
        return RegistrationResult(
            success=True,
            action="replaced",
            message=f"Replaced {attack_type} with higher priority version"
        )
    elif new_entry.priority == existing_entry.priority:
        # Same priority - keep first, warn
        return RegistrationResult(
            success=False,
            action="skipped",
            message=f"Skipped duplicate {attack_type} (same priority)"
        )
    else:
        # Lower priority - skip
        return RegistrationResult(
            success=False,
            action="skipped",
            message=f"Skipped {attack_type} (lower priority)"
        )
```

## Components and Interfaces

### 1. Attack Registry Interface

```python
class IAttackRegistry(Protocol):
    """Interface for attack registry."""
    
    def register_attack(
        self,
        attack_type: str,
        handler: Callable,
        metadata: AttackMetadata,
        priority: RegistrationPriority = RegistrationPriority.NORMAL
    ) -> RegistrationResult:
        """Register a new attack."""
        ...
    
    def get_attack_handler(self, attack_type: str) -> Optional[Callable]:
        """Get handler for attack type."""
        ...
    
    def list_attacks(
        self,
        category: Optional[str] = None,
        priority: Optional[RegistrationPriority] = None
    ) -> List[str]:
        """List registered attacks."""
        ...
    
    def validate_parameters(
        self,
        attack_type: str,
        params: Dict[str, Any]
    ) -> ValidationResult:
        """Validate attack parameters."""
        ...
```

### 2. Attack Handler Interface

```python
class IAttackHandler(Protocol):
    """Interface for attack handlers."""
    
    def __call__(
        self,
        techniques: BypassTechniques,
        payload: bytes,
        **params
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """
        Execute attack and return segments.
        
        Returns:
            List of (data, offset, options) tuples for each segment.
        """
        ...
```

### 3. Attack Metadata

```python
@dataclass
class AttackMetadata:
    """Metadata for an attack."""
    name: str
    description: str
    required_params: List[str]
    optional_params: Dict[str, Any]
    aliases: List[str]
    category: str
    effectiveness_score: Optional[float] = None  # From performance data
    recommended_params: Optional[Dict[str, Any]] = None  # Optimized defaults
```

## Data Models

### Attack Entry Model

```python
@dataclass
class AttackEntry:
    """Complete entry for a registered attack."""
    attack_type: str
    handler: Callable
    metadata: AttackMetadata
    priority: RegistrationPriority
    source_module: str
    registration_time: datetime
    is_canonical: bool
    is_alias_of: Optional[str] = None  # Points to canonical attack if this is an alias
    performance_data: Optional[Dict[str, Any]] = None
    promotion_history: List[Dict[str, Any]] = field(default_factory=list)  # Track promotions
```

### Registration Result Model

```python
@dataclass
class RegistrationResult:
    """Result of attack registration attempt."""
    success: bool
    action: str  # "registered", "replaced", "skipped"
    message: str
    attack_type: Optional[str] = None
    conflicts: List[str] = field(default_factory=list)
```

### Validation Result Model

```python
@dataclass
class ValidationResult:
    """Result of parameter validation."""
    is_valid: bool
    error_message: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    normalized_params: Optional[Dict[str, Any]] = None
```

## Error Handling

### Error Hierarchy

```python
class AttackRegistryError(Exception):
    """Base exception for registry errors."""
    pass

class DuplicateAttackError(AttackRegistryError):
    """Raised when duplicate attack registration is attempted."""
    pass

class InvalidAttackError(AttackRegistryError):
    """Raised when attack validation fails."""
    pass

class AttackNotFoundError(AttackRegistryError):
    """Raised when requested attack is not found."""
    pass

class ParameterValidationError(AttackRegistryError):
    """Raised when parameter validation fails."""
    pass
```

### Error Handling Strategy

1. **Registration Errors**: Log warning, continue with other registrations
2. **Validation Errors**: Return ValidationResult with detailed error info
3. **Runtime Errors**: Propagate to caller with context
4. **Critical Errors**: Log error, raise exception

## Testing Strategy

### Unit Tests

**Test Coverage:**
- Attack registry operations (register, get, list, validate)
- Deduplication logic with various priority combinations
- Parameter validation for all attack types
- Alias resolution
- Error handling

**Test Files:**
- `tests/test_attack_registry.py` (update existing)
- `tests/test_attack_primitives.py` (new)
- `tests/test_attack_deduplication.py` (new)

### Integration Tests

**Test Scenarios:**
- Full system initialization with all attacks
- Attack execution with various parameter combinations
- Registry behavior with duplicate registrations
- Import structure and backward compatibility

**Test Files:**
- `tests/test_attack_integration.py` (update existing)
- `tests/test_attack_refactoring.py` (new)

### Performance Tests

**Metrics to Track:**
- Attack execution time (before vs after)
- Registry lookup performance
- Memory usage
- Attack effectiveness (success rate)

**Test Files:**
- `tests/test_attack_performance.py` (new)

### Test Data

**Baseline Performance Report:**
```json
{
  "timestamp": "2025-10-21T00:00:00Z",
  "attacks": {
    "fakeddisorder": {
      "execution_time_ms": 1.5,
      "success_rate": 0.85,
      "memory_kb": 128
    },
    "disorder": {
      "execution_time_ms": 0.8,
      "success_rate": 0.75,
      "memory_kb": 64
    }
  }
}
```

## Migration Strategy

### Phase 1: Analysis and Preparation

1. **Scan Codebase**
   - Identify all attack implementations
   - Map duplicates to canonical versions
   - Analyze unique functionality in duplicates

2. **Create Mapping**
   - Document old → new import paths
   - Identify breaking changes
   - Plan backward compatibility shims

3. **Baseline Performance**
   - Run performance tests
   - Generate baseline report
   - Document current behavior

### Phase 2: Registry Consolidation

1. **Enhance Primary Registry**
   - Add priority system
   - Implement deduplication
   - Add performance tracking

2. **Migrate Registry Functions**
   - Move unique functions from other registries
   - Update imports
   - Add deprecation warnings

3. **Remove Old Registries**
   - Delete `registry.py`
   - Delete `modern_registry.py`
   - Update all imports

### Phase 3: Attack Consolidation

1. **Enhance Primitives**
   - Add shared helper functions
   - Optimize canonical implementations
   - Add comprehensive docstrings

2. **Merge Unique Functionality**
   - Extract unique features from duplicates
   - Add to canonical implementations
   - Create tests for merged features

3. **Remove Duplicates**
   - Delete duplicate attack files
   - Update imports
   - Verify no broken references

### Phase 4: Validation and Testing

1. **Run Test Suite**
   - Execute all unit tests
   - Execute all integration tests
   - Compare performance metrics

2. **Validate Functionality**
   - Test all attack types
   - Verify parameter handling
   - Check error handling

3. **Performance Comparison**
   - Generate new performance report
   - Compare with baseline
   - Investigate any regressions

### Phase 5: Documentation and Cleanup

1. **Update Documentation**
   - Create migration guide
   - Update API reference
   - Document new import structure

2. **Code Cleanup**
   - Remove deprecated code
   - Clean up imports
   - Update comments

3. **Final Validation**
   - Run full test suite
   - Verify all documentation
   - Check for any remaining issues

## File Structure Changes

### Before Refactoring

```
core/bypass/
├── attacks/
│   ├── __init__.py
│   ├── attack_registry.py
│   ├── registry.py              # DUPLICATE
│   ├── modern_registry.py       # DUPLICATE
│   ├── tcp/
│   │   ├── fake_disorder_attack.py          # DUPLICATE
│   │   ├── fake_disorder_attack_fixed.py    # DUPLICATE
│   │   └── fake_disorder_attack_original.py # DUPLICATE
│   └── reference/
│       └── faked_disorder_attack.py         # DUPLICATE
└── techniques/
    ├── primitives.py            # CANONICAL
    └── registry.py              # DUPLICATE
```

### After Refactoring

```
core/bypass/
├── attacks/
│   ├── __init__.py              # Updated imports
│   ├── attack_registry.py       # Consolidated registry
│   ├── tcp/
│   │   └── [other tcp attacks]  # Duplicates removed
│   └── reference/
│       └── [reference attacks]  # Duplicates removed
└── techniques/
    └── primitives.py            # Enhanced canonical implementations
```

## Import Structure

### New Import Patterns

```python
# Primary imports - for all users
from core.bypass.attacks import (
    get_attack_registry,
    register_attack,
    AttackMetadata,
    ValidationResult
)

# Get attack handler
registry = get_attack_registry()
handler = registry.get_attack_handler("fakeddisorder")

# Direct access to primitives (advanced users)
from core.bypass.techniques.primitives import BypassTechniques
techniques = BypassTechniques()
segments = techniques.apply_fakeddisorder(payload, split_pos=3, fake_ttl=3)
```

### Backward Compatibility

```python
# Deprecated imports (with warnings)
from core.bypass.attacks.registry import AttackRegistry  # → attack_registry
from core.bypass.attacks.modern_registry import ModernRegistry  # → attack_registry

# Deprecated attack imports (with warnings)
from core.bypass.attacks.tcp.fake_disorder_attack import FakeDisorderAttack  # → primitives
```

## Performance Considerations

### Optimization Targets

1. **Registry Lookup**: O(1) hash-based lookup
2. **Attack Execution**: Minimize overhead, optimize hot paths
3. **Memory Usage**: Reduce duplicate code, share common structures
4. **Initialization Time**: 
   - Eager loading (default): < 100ms for all attacks
   - Lazy loading (optional): < 10ms initial, load on demand
5. **Parameter Normalization**: < 0.05ms overhead per attack

### Performance Metrics

**Target Improvements:**
- Registry lookup: < 0.1ms
- Attack execution overhead: < 5% of total time
- Memory reduction: 30-40% (from duplicate removal)
- Initialization time: < 100ms

## Security Considerations

### Attack Validation

1. **Parameter Sanitization**: Validate all user inputs
2. **Type Checking**: Enforce strict type requirements
3. **Range Validation**: Check numeric parameters are within valid ranges
4. **Injection Prevention**: Sanitize string parameters

### Registry Security

1. **Priority Enforcement**: Prevent low-priority attacks from overriding core attacks
2. **Source Verification**: Track attack source modules
3. **Audit Logging**: Log all registration attempts
4. **Access Control**: Restrict registry modification after initialization

## Monitoring and Observability

### Logging Strategy

```python
# Registration logging
logger.info(f"Registered attack '{attack_type}' from {source_module} with priority {priority}")
logger.warning(f"Skipped duplicate attack '{attack_type}' (lower priority)")
logger.error(f"Failed to register attack '{attack_type}': {error}")

# Execution logging
logger.debug(f"Executing attack '{attack_type}' with params: {params}")
logger.info(f"Attack '{attack_type}' completed: {len(segments)} segments")
```

### Metrics Collection

```python
# Registry metrics
- total_attacks_registered
- duplicate_registrations_skipped
- registration_failures

# Execution metrics
- attack_execution_count
- attack_execution_time
- attack_success_rate
- attack_failure_count
```

## Rollback Plan

### Rollback Triggers

1. Test failures > 5%
2. Performance regression > 20%
3. Critical functionality broken
4. Unresolvable conflicts

### Rollback Procedure

1. **Revert Code Changes**
   - Git revert to pre-refactoring commit
   - Restore deleted files from backup

2. **Restore Configuration**
   - Restore old import structure
   - Re-enable deprecated registries

3. **Validate Rollback**
   - Run test suite
   - Verify functionality
   - Check performance

4. **Document Issues**
   - Record rollback reason
   - Document problems encountered
   - Plan remediation

## Success Criteria

### Functional Requirements

- ✅ All attacks work correctly after refactoring
- ✅ No duplicate attack implementations remain
- ✅ Single unified registry in use
- ✅ All tests pass
- ✅ No broken imports

### Performance Requirements

- ✅ No performance regression > 5%
- ✅ Memory usage reduced by 20%+
- ✅ Registry lookup < 0.1ms
- ✅ Initialization time < 100ms

### Quality Requirements

- ✅ Code coverage ≥ 80%
- ✅ All attacks have comprehensive tests
- ✅ Documentation complete and accurate
- ✅ Migration guide available
- ✅ No critical issues in production

## Timeline and Milestones

### Estimated Timeline: 2-3 weeks

**Week 1: Analysis and Preparation**
- Day 1-2: Codebase analysis and mapping
- Day 3-4: Baseline performance testing
- Day 5: Design review and approval

**Week 2: Implementation**
- Day 1-2: Registry consolidation
- Day 3-4: Attack consolidation
- Day 5: Testing and validation

**Week 3: Finalization**
- Day 1-2: Documentation
- Day 3-4: Final testing and fixes
- Day 5: Deployment and monitoring

## Dependencies

### Internal Dependencies

- `core/bypass/techniques/primitives.py` - Canonical attack implementations
- `core/bypass/attacks/metadata.py` - Attack metadata definitions
- `core/bypass/attacks/base.py` - Base attack classes

### External Dependencies

- None (all changes are internal to the bypass system)

## Risks and Mitigation

### Risk 1: Breaking Existing Code

**Mitigation:**
- Maintain backward compatibility shims
- Provide clear migration guide
- Gradual deprecation warnings

### Risk 2: Performance Regression

**Mitigation:**
- Comprehensive performance testing
- Baseline comparison
- Rollback plan ready

### Risk 3: Lost Functionality

**Mitigation:**
- Thorough analysis of duplicates
- Merge unique features before deletion
- Comprehensive test coverage

### Risk 4: Registry Conflicts

**Mitigation:**
- Priority-based registration
- Clear conflict resolution rules
- Detailed logging

## Future Enhancements

### Post-Refactoring Improvements

1. **Lazy Loading System**: 
   - Implement full lazy loading for external attacks
   - Reduce startup time for large attack libraries (target: < 10ms)
   - Cache loaded modules for performance
   - Provide configuration option to choose eager vs lazy loading

2. **Implementation Promotion Workflow**:
   - Automated testing framework for promoted implementations
   - Performance comparison reports (before/after metrics)
   - Approval process for core attack changes
   - Rollback mechanism for failed promotions
   - Documentation of promotion history

3. **Dynamic Attack Loading**: 
   - Plugin system for external attacks
   - Hot-reload capability for development
   - Sandboxed execution for untrusted attacks

4. **Performance Profiling**: 
   - Built-in profiling for attack optimization
   - Real-time performance dashboards
   - Automatic detection of performance regressions

5. **Attack Composition**: 
   - Combine multiple attacks into strategies
   - Strategy optimization based on target characteristics
   - A/B testing framework for strategy comparison

6. **Machine Learning**: 
   - Use ML to select optimal attacks per target
   - Learn from success/failure patterns
   - Adaptive attack selection

7. **Distributed Registry**: 
   - Support for distributed attack execution
   - Load balancing across multiple nodes
   - Centralized registry with local caching

8. **Parameter Validation DSL**: 
   - Domain-specific language for parameter validation rules
   - Declarative validation specifications
   - Auto-generated validation documentation
