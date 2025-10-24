# Attack System Duplicate Mapping

This document maps all duplicate attack implementations to their canonical versions and documents unique functionality found in duplicates.

## Analysis Summary

**Analysis Date**: October 21, 2025  
**Total Duplicates Found**: 7 files  
**Canonical Location**: `core/bypass/techniques/primitives.py`  

## Disorder Attack Implementations

### Canonical Implementation
- **Location**: `core/bypass/techniques/primitives.py`
- **Class**: `BypassTechniques`
- **Methods**: 
  - `apply_fakeddisorder()` - Main fake disorder attack
  - `apply_disorder()` - Simple disorder without fake packet
  - `apply_multidisorder()` - Multiple position disorder
  - `apply_seqovl()` - Sequence overlap attack
  - `apply_multisplit()` - Multiple split attack
  - `apply_fake_packet_race()` - Simple fake packet race

### Duplicate Files Found

#### 1. `core/bypass/attacks/tcp/fake_disorder_attack.py`
- **Status**: DUPLICATE - Remove
- **Registration**: `@register_attack("fake_fakeddisorder")`
- **Unique Features**:
  - Zapret-compatible fake payload generation
  - TLS ClientHello fake payload templates
  - HTTP fake payload templates
  - AutoTTL testing functionality (TTL range 1-N)
  - Comprehensive parameter validation
  - Split position handling for special values ("sni", "cipher", "midsld")
- **Key Differences from Canonical**:
  - More sophisticated fake payload generation
  - Better parameter normalization
  - Enhanced error handling and logging
  - Zapret compatibility features

#### 2. `core/bypass/attacks/tcp/fake_disorder_attack_fixed.py`
- **Status**: DUPLICATE - Remove
- **Registration**: `@register_attack("fake_fakeddisorder_fixed")`
- **Unique Features**:
  - Similar to above but with different default parameters
  - TTL=1 vs TTL=3 in the other version
  - Different split_pos defaults (76 vs 3)
  - Enhanced sequence overlap logic
- **Key Differences from Canonical**:
  - Different parameter defaults optimized for specific scenarios
  - More detailed logging and debugging information

#### 3. `core/bypass/attacks/tcp/fake_disorder_attack_original.py`
- **Status**: DUPLICATE - Remove (Truncated in analysis)
- **Registration**: `@register_attack("fake_fakeddisorder")`
- **Unique Features** (from visible portion):
  - Comprehensive zapret parameter support
  - Advanced fooling methods configuration
  - Fake payload template selection system
  - AutoTTL testing with effectiveness evaluation
  - Support for multiple fake payload types (HTTP, TLS, QUIC, etc.)
- **Key Differences from Canonical**:
  - Much more comprehensive parameter support
  - Advanced configuration system
  - Better zapret compatibility

#### 4. `core/bypass/attacks/reference/faked_disorder_attack.py`
- **Status**: DUPLICATE - Remove
- **Registration**: None (reference implementation)
- **Unique Features**:
  - Segments-based architecture
  - Deceptive fake payload generation
  - Protocol-specific fake payload creation
  - Effectiveness estimation methods
  - Context validation
- **Key Differences from Canonical**:
  - Different architecture (segments vs direct execution)
  - More sophisticated fake payload generation
  - Better payload analysis and protocol detection

## Registry System Duplicates

### Canonical Registry
- **Location**: `core/bypass/attacks/attack_registry.py`
- **Class**: `AttackRegistry`
- **Features**: 
  - Comprehensive attack registration
  - Parameter validation
  - Metadata management
  - Alias support
  - External attack discovery

### Duplicate Registry Files

#### 1. `core/bypass/attacks/registry.py`
- **Status**: DUPLICATE - Remove
- **Purpose**: Backward compatibility wrapper
- **Functionality**: Simple imports from `attack_registry.py`
- **Unique Features**: None (pure wrapper)

#### 2. `core/bypass/attacks/modern_registry.py`
- **Status**: DUPLICATE - Remove
- **Purpose**: Modern registry alias
- **Functionality**: Aliases for `attack_registry.py` functions
- **Unique Features**: `ModernAttackRegistry` alias class

#### 3. `core/bypass/techniques/registry.py`
- **Status**: DUPLICATE - Remove
- **Class**: `TechniqueRegistry`
- **Unique Features**:
  - Decorator-based registration system
  - Category-based organization
  - Protocol support validation
  - Signature-based technique lookup
- **Key Differences from Canonical**:
  - Different registration approach (decorators vs direct calls)
  - More sophisticated categorization system
  - Better protocol handling

#### 4. `core/integration/advanced_attack_registry.py`
- **Status**: DUPLICATE - Remove
- **Class**: `AdvancedAttackRegistry`
- **Unique Features**:
  - DPI signature-based attack selection
  - Protocol-specific attack mapping
  - Attack lifecycle management
  - Sophistication level matching
  - Statistics and monitoring
- **Key Differences from Canonical**:
  - More advanced attack selection logic
  - Better integration with DPI detection
  - Enhanced monitoring and statistics

## Mapping Table

| Duplicate File | Canonical Method | Action | Unique Features to Preserve |
|---|---|---|---|
| `fake_disorder_attack.py` | `apply_fakeddisorder()` | Remove | Zapret fake payload generation, AutoTTL testing |
| `fake_disorder_attack_fixed.py` | `apply_fakeddisorder()` | Remove | Parameter optimization, enhanced logging |
| `fake_disorder_attack_original.py` | `apply_fakeddisorder()` | Remove | Comprehensive zapret compatibility |
| `faked_disorder_attack.py` | `apply_fakeddisorder()` | Remove | Segments architecture, protocol detection |
| `registry.py` | `AttackRegistry` | Remove | None (pure wrapper) |
| `modern_registry.py` | `AttackRegistry` | Remove | None (alias only) |
| `techniques/registry.py` | `AttackRegistry` | Remove | Decorator registration, categorization |
| `advanced_attack_registry.py` | `AttackRegistry` | Remove | DPI signature mapping, sophistication matching |

## Unique Functionality Analysis

### Features to Merge into Canonical Implementation

#### 1. Enhanced Fake Payload Generation
**Source**: `fake_disorder_attack.py`, `faked_disorder_attack.py`
**Description**: 
- TLS ClientHello template generation
- HTTP request template generation
- Protocol-specific payload detection
- Deceptive payload modification

**Recommendation**: Add to `BypassTechniques.apply_fakeddisorder()` as optional enhanced mode

#### 2. AutoTTL Testing
**Source**: `fake_disorder_attack.py`, `fake_disorder_attack_original.py`
**Description**:
- Automatic TTL range testing (1 to N)
- Effectiveness evaluation per TTL
- Optimal TTL selection
- Minimal delay between tests

**Recommendation**: Add as optional parameter to canonical implementation

#### 3. Advanced Parameter Handling
**Source**: Multiple duplicate files
**Description**:
- Special position values ("sni", "cipher", "midsld")
- Parameter normalization and validation
- Zapret-compatible parameter mapping
- Enhanced error handling

**Recommendation**: Integrate into `AttackRegistry` parameter validation

#### 4. Registry Enhancement Features
**Source**: `techniques/registry.py`, `advanced_attack_registry.py`
**Description**:
- Decorator-based registration
- Category-based organization
- DPI signature mapping
- Protocol-specific selection
- Attack lifecycle management

**Recommendation**: Enhance canonical `AttackRegistry` with these features

### Features Not to Preserve

#### 1. Duplicate Architecture Patterns
- Multiple ways to achieve the same result
- Inconsistent parameter naming
- Different return value formats

#### 2. Redundant Configuration Systems
- Multiple configuration classes for same functionality
- Overlapping parameter sets
- Inconsistent default values

#### 3. Compatibility Wrappers
- Simple import redirections
- Alias-only classes
- Backward compatibility shims (will be replaced with proper migration)

## Implementation Priority

### High Priority (Core Functionality)
1. **Fake Payload Enhancement**: Merge advanced fake payload generation
2. **Parameter Normalization**: Integrate comprehensive parameter handling
3. **AutoTTL Support**: Add automatic TTL testing capability

### Medium Priority (Registry Features)
1. **Enhanced Registration**: Add decorator support and categorization
2. **DPI Signature Mapping**: Integrate signature-based attack selection
3. **Protocol Support**: Add protocol-specific attack filtering

### Low Priority (Nice to Have)
1. **Statistics and Monitoring**: Add attack execution statistics
2. **Lifecycle Management**: Add attack enable/disable functionality
3. **Advanced Validation**: Enhanced parameter validation with warnings

## Migration Strategy

### Phase 1: Preserve Unique Features
1. Extract unique functionality from duplicates
2. Create enhancement methods in canonical implementation
3. Add comprehensive tests for merged features

### Phase 2: Update Imports
1. Update all imports to use canonical registry
2. Add deprecation warnings to duplicate files
3. Provide migration guide for external code

### Phase 3: Remove Duplicates
1. Delete duplicate attack files
2. Delete duplicate registry files
3. Verify no broken imports remain

### Phase 4: Validation
1. Run comprehensive test suite
2. Verify all functionality preserved
3. Performance comparison with baseline

## Risk Assessment

### Low Risk
- Removing pure wrapper files (`registry.py`, `modern_registry.py`)
- Removing reference implementations (`faked_disorder_attack.py`)

### Medium Risk
- Merging complex fake payload generation logic
- Integrating AutoTTL testing functionality
- Removing advanced registry features

### High Risk
- Removing comprehensive zapret compatibility features
- Changing parameter handling behavior
- Modifying core attack execution logic

## Validation Checklist

- [ ] All unique features identified and documented
- [ ] Migration plan created for each unique feature
- [ ] Test cases written for merged functionality
- [ ] Performance impact assessed
- [ ] Backward compatibility plan established
- [ ] Import update strategy defined
- [ ] Rollback plan prepared

## Notes

1. **Zapret Compatibility**: The duplicate files contain significant zapret compatibility features that should be carefully preserved during migration.

2. **Parameter Handling**: Multiple approaches to parameter normalization exist - the most comprehensive should be adopted.

3. **Testing Requirements**: Enhanced testing will be needed to ensure all merged functionality works correctly.

4. **Performance Considerations**: Some duplicate implementations may have performance optimizations that should be preserved.

5. **Documentation Updates**: All API documentation will need updates to reflect the unified interface.
## At
tack Registration Conflicts Analysis

### Registration Conflict Summary

**Analysis Date**: October 21, 2025  
**Total Conflicts Found**: 3 major conflicts  
**Conflict Type**: Multiple registrations of same attack name  

### Identified Registration Conflicts

#### 1. `fake_fakeddisorder` Name Conflict
**Conflict**: Two different files register the same attack name
- **File 1**: `core/bypass/attacks/tcp/fake_disorder_attack.py`
  - Registration: `@register_attack("fake_fakeddisorder")`
  - Class: `FixedFakeDisorderAttack`
- **File 2**: `core/bypass/attacks/tcp/fake_disorder_attack_original.py`
  - Registration: `@register_attack("fake_fakeddisorder")`
  - Class: `FakeDisorderAttack`

**Impact**: Last registered implementation overwrites the first
**Resolution**: Remove duplicates, keep canonical implementation in primitives

#### 2. `fake_disorder` vs `fakeddisorder` Alias Conflict
**Conflict**: Overlapping functionality with different names
- **Canonical**: `fakeddisorder` (in primitives.py via AttackRegistry)
  - Aliases: `["fake_disorder", "fakedisorder"]`
- **External**: `fake_disorder` (in tcp_fragmentation.py)
  - Registration: `@register_attack("fake_disorder")`
  - Class: `FakeDisorderAttack`

**Impact**: Confusion between canonical and external implementations
**Resolution**: Remove external registration, ensure alias mapping works

#### 3. Registry Priority Conflicts
**Conflict**: No priority system for registration order
- **Current Behavior**: Last registration wins (overwrites previous)
- **Problem**: External attacks can overwrite core attacks
- **Missing**: Priority-based registration system

### Registration Order Analysis

#### Current Registration Flow
1. **Core Attacks** (from `AttackRegistry._register_builtin_attacks()`)
   - `fakeddisorder` → `apply_fakeddisorder()` handler
   - `disorder` → `apply_disorder()` handler
   - `multidisorder` → `apply_multidisorder()` handler
   - `seqovl` → `apply_seqovl()` handler
   - `multisplit` → `apply_multisplit()` handler
   - `split` → `apply_multisplit()` with single position
   - `fake` → `apply_fake_packet_race()` handler

2. **External Attacks** (from `AttackRegistry._register_external_attacks()`)
   - Scans `core/bypass/attacks/*.py` files
   - Registers classes with `@register_attack` decorator
   - **Problem**: Can overwrite core attacks if same name used

3. **Module Import Order** (affects final registration)
   - Order depends on filesystem iteration
   - Non-deterministic on some systems
   - Last import wins in case of conflicts

### Specific Conflicts Found

#### A. Duplicate `fake_fakeddisorder` Registrations
```python
# File 1: fake_disorder_attack.py
@register_attack("fake_fakeddisorder")
class FixedFakeDisorderAttack(BaseAttack):
    # Implementation A

# File 2: fake_disorder_attack_original.py  
@register_attack("fake_fakeddisorder")
class FakeDisorderAttack(BaseAttack):
    # Implementation B - OVERWRITES Implementation A
```

#### B. Canonical vs External `fake_disorder`
```python
# Canonical (via AttackRegistry)
self.register_attack(
    "fakeddisorder",
    self._create_fakeddisorder_handler(),
    AttackMetadata(
        aliases=["fake_disorder", "fakedisorder"],  # Alias mapping
        # ...
    )
)

# External (tcp_fragmentation.py)
@register_attack("fake_disorder")
class FakeDisorderAttack(BaseTCPFragmentationAttack):
    # CONFLICTS with alias mapping
```

#### C. Missing Priority System
```python
# Current: No priority handling
def register_attack(self, attack_type: str, handler: Callable, metadata: AttackMetadata):
    if attack_type in self.attacks:
        logger.warning(f"Attack type '{attack_type}' already registered, overwriting")
        # PROBLEM: Always overwrites, no priority check
    
    self.attacks[attack_type] = {'handler': handler, 'metadata': metadata}
```

### Impact Assessment

#### High Impact Conflicts
1. **`fake_fakeddisorder` Duplicate**: Two different implementations compete
2. **Core vs External Priority**: External attacks can overwrite core functionality
3. **Non-deterministic Behavior**: Registration order depends on filesystem

#### Medium Impact Conflicts  
1. **Alias Confusion**: `fake_disorder` exists both as alias and direct registration
2. **Test Inconsistencies**: Tests expect specific implementations but get others
3. **Documentation Mismatch**: Docs reference attacks that may be overwritten

#### Low Impact Conflicts
1. **Logging Noise**: Warning messages about overwrites
2. **Development Confusion**: Unclear which implementation is active
3. **Debugging Difficulty**: Hard to trace which attack is actually running

### Resolution Strategy

#### Phase 1: Immediate Fixes
1. **Remove Duplicate Registrations**
   - Delete `fake_disorder_attack.py` 
   - Delete `fake_disorder_attack_original.py`
   - Delete `fake_disorder_attack_fixed.py`

2. **Fix External Conflicts**
   - Remove `@register_attack("fake_disorder")` from `tcp_fragmentation.py`
   - Ensure aliases work correctly for `fakeddisorder`

#### Phase 2: Priority System Implementation
1. **Add Registration Priority Enum**
   ```python
   class RegistrationPriority(Enum):
       CORE = 100      # Primitives.py attacks
       HIGH = 75       # Verified effective attacks  
       NORMAL = 50     # Standard external attacks
       LOW = 25        # Experimental attacks
   ```

2. **Update Registration Logic**
   ```python
   def register_attack(self, attack_type: str, handler: Callable, 
                      metadata: AttackMetadata, 
                      priority: RegistrationPriority = RegistrationPriority.NORMAL):
       if attack_type in self.attacks:
           existing_priority = self.attacks[attack_type].get('priority', RegistrationPriority.NORMAL)
           if priority <= existing_priority:
               logger.warning(f"Skipping {attack_type}: lower priority than existing")
               return
           logger.info(f"Replacing {attack_type}: higher priority")
       
       self.attacks[attack_type] = {
           'handler': handler, 
           'metadata': metadata,
           'priority': priority
       }
   ```

3. **Set Core Attack Priorities**
   - All primitives.py attacks: `RegistrationPriority.CORE`
   - External attacks: `RegistrationPriority.NORMAL` (default)

#### Phase 3: Validation and Testing
1. **Registration Order Tests**
   - Test that core attacks cannot be overwritten
   - Test that higher priority attacks replace lower priority
   - Test deterministic behavior regardless of import order

2. **Alias Resolution Tests**
   - Test that all aliases resolve to correct canonical attacks
   - Test that no conflicts exist between aliases and direct registrations

3. **Integration Tests**
   - Test that attack execution uses correct implementation
   - Test that all expected attacks are available
   - Test that no duplicate functionality exists

### Prevention Measures

#### 1. Registration Validation
- Check for name conflicts during registration
- Validate that aliases don't conflict with direct registrations
- Warn about potential overwrites

#### 2. Naming Conventions
- Core attacks: Use simple names (`fakeddisorder`, `disorder`, etc.)
- External attacks: Use prefixed names (`tcp_advanced_split`, `tls_record_split`)
- Aliases: Document clearly in metadata

#### 3. Documentation Standards
- Maintain registry of all attack names and aliases
- Document priority levels and when to use each
- Provide migration guide for conflicting names

### Testing Requirements

#### Unit Tests
- Test priority-based registration
- Test alias resolution
- Test conflict detection and handling

#### Integration Tests  
- Test full attack execution flow
- Test that correct implementations are used
- Test backward compatibility

#### Performance Tests
- Ensure priority checking doesn't impact performance
- Test registration time with many attacks
- Validate memory usage

### Migration Checklist

- [ ] Identify all registration conflicts
- [ ] Remove duplicate attack files
- [ ] Implement priority system
- [ ] Update core attack registrations with CORE priority
- [ ] Fix alias conflicts
- [ ] Update tests for new behavior
- [ ] Validate no functionality lost
- [ ] Update documentation

### Risk Mitigation

#### Rollback Plan
- Keep backup of current registry behavior
- Implement feature flag for priority system
- Provide compatibility mode for old behavior

#### Validation Steps
- Compare attack availability before/after changes
- Verify all tests pass with new system
- Check that performance is not degraded

#### Communication Plan
- Document all changes in migration guide
- Provide examples of new registration patterns
- Update API documentation