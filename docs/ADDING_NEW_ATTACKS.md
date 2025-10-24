# Adding New Attacks: Developer Guide

## 🎯 Overview

This guide provides step-by-step instructions for adding new DPI bypass attacks to the refactored system. The new architecture features a unified registry with priority-based registration, parameter normalization, and standardized attack interfaces.

## 🏗️ Attack Development Process

### 1. Planning Phase

#### Understand Your Attack
- **Attack Type**: What DPI technique does it bypass?
- **Protocol Level**: TCP, TLS, HTTP, DNS, etc.
- **Parameters**: What configuration does it need?
- **Category**: Which category does it belong to?
- **Priority**: What registration priority should it have?

#### Choose Attack Category

```python
from core.bypass.attacks.metadata import AttackCategories

# Available categories:
AttackCategories.SPLIT      # Packet splitting attacks
AttackCategories.DISORDER   # Packet reordering attacks  
AttackCategories.FAKE       # Fake packet attacks
AttackCategories.RACE       # Race condition attacks
AttackCategories.OVERLAP    # Sequence overlap attacks
AttackCategories.FRAGMENT   # Fragmentation attacks
AttackCategories.TIMING     # Timing-based attacks
AttackCategories.DNS        # DNS-based attacks
AttackCategories.CUSTOM     # Custom attacks
```

## 🎯 Priority System Usage Guide

The refactored attack system uses a priority-based registration system to ensure that the most effective and reliable implementations are used while preventing accidental overwrites of proven attacks.

### Priority Levels

```python
from core.bypass.attacks.metadata import RegistrationPriority

# Priority levels (higher values override lower):
RegistrationPriority.CORE = 100    # Canonical implementations (primitives.py)
RegistrationPriority.HIGH = 75     # Verified effective implementations
RegistrationPriority.NORMAL = 50   # Standard external attacks
RegistrationPriority.LOW = 25      # Experimental attacks
```

### When to Use Each Priority Level

#### CORE Priority (100) - Reserved for Canonical Implementations
- **Usage**: Only for canonical implementations in `core/bypass/techniques/primitives.py`
- **Characteristics**: 
  - Cannot be overridden by any other priority
  - Represents the "single source of truth" for each attack type
  - Optimized for performance and effectiveness
  - Thoroughly tested and validated

```python
# Example: Core implementation (in primitives.py)
@register_attack(
    name="fakeddisorder",
    category=AttackCategories.TCP,
    priority=RegistrationPriority.CORE,  # Highest priority
    required_params=["split_pos"],
    optional_params={"fake_ttl": 3, "fooling_methods": ["badsum"]}
)
class CanonicalFakeDisorderAttack(BaseAttack):
    """Canonical fakeddisorder implementation from primitives.py"""
    # This cannot be replaced by any external implementation
```

**When NOT to use CORE:**
- External attack modules (outside primitives.py)
- Experimental implementations
- User-contributed attacks
- Temporary or testing implementations

#### HIGH Priority (75) - Verified Effective Implementations
- **Usage**: For proven, highly effective attacks with performance data
- **Characteristics**:
  - Can replace NORMAL and LOW priority attacks
  - Cannot replace CORE priority attacks
  - Requires evidence of effectiveness (performance metrics, success rates)
  - Should have comprehensive testing

```python
# Example: High-priority attack with proven effectiveness
@register_attack(
    name="advanced_tcp_split",
    category=AttackCategories.TCP,
    priority=RegistrationPriority.HIGH,  # High priority due to proven effectiveness
    required_params=["positions"],
    optional_params={"adaptive_timing": True, "success_rate_threshold": 0.95}
)
class AdvancedTCPSplitAttack(BaseAttack):
    """
    Advanced TCP splitting with 95%+ success rate against modern DPI.
    
    Performance data:
    - Success rate: 97.3% across 1000+ domains
    - Average latency: 1.2ms
    - Effective against Roskomnadzor, Great Firewall, etc.
    """
    # Implementation with proven effectiveness
```

**When to use HIGH:**
- Attack has documented success rates > 90%
- Performance benchmarks show significant improvement
- Extensive real-world testing completed
- Community validation and feedback incorporated
- Replaces less effective NORMAL priority implementations

#### NORMAL Priority (50) - Standard External Attacks
- **Usage**: Default for most external attacks and standard implementations
- **Characteristics**:
  - Can replace LOW priority attacks
  - Cannot replace HIGH or CORE priority attacks
  - Standard level for community contributions
  - Reasonable testing expected but not extensive validation required

```python
# Example: Standard external attack
@register_attack(
    name="custom_disorder_attack",
    category=AttackCategories.TCP,
    priority=RegistrationPriority.NORMAL,  # Default priority
    required_params=["split_positions"],
    optional_params={"randomize_order": False}
)
class CustomDisorderAttack(BaseAttack):
    """Custom disorder attack with configurable split positions."""
    # Standard implementation for general use
```

**When to use NORMAL:**
- New external attack implementations
- Community-contributed attacks
- Standard variations of existing techniques
- Production-ready but not extensively validated attacks
- Default choice when unsure about priority level

#### LOW Priority (25) - Experimental Attacks
- **Usage**: For experimental, untested, or proof-of-concept attacks
- **Characteristics**:
  - Can be replaced by any higher priority attack
  - Suitable for research and development
  - May have limited testing or unknown effectiveness
  - Good for prototyping new techniques

```python
# Example: Experimental attack
@register_attack(
    name="experimental_quantum_evasion",
    category=AttackCategories.CUSTOM,
    priority=RegistrationPriority.LOW,  # Experimental priority
    required_params=["quantum_params"],
    optional_params={"experimental_mode": True}
)
class ExperimentalQuantumEvasionAttack(BaseAttack):
    """
    Experimental quantum-inspired evasion technique.
    
    WARNING: This is experimental and may not work reliably.
    """
    # Experimental implementation
```

**When to use LOW:**
- Proof-of-concept implementations
- Research prototypes
- Untested new techniques
- Temporary implementations during development
- Attacks with unknown effectiveness

### Priority Conflict Resolution

The registry automatically handles priority conflicts:

```python
# Scenario 1: Higher priority replaces lower priority
@register_attack("test_attack", priority=RegistrationPriority.NORMAL)
class NormalAttack(BaseAttack): pass

@register_attack("test_attack", priority=RegistrationPriority.HIGH)  
class HighAttack(BaseAttack): pass
# Result: HighAttack replaces NormalAttack

# Scenario 2: Lower priority is skipped
@register_attack("test_attack", priority=RegistrationPriority.HIGH)
class HighAttack(BaseAttack): pass

@register_attack("test_attack", priority=RegistrationPriority.NORMAL)
class NormalAttack(BaseAttack): pass
# Result: NormalAttack registration is skipped, HighAttack remains

# Scenario 3: CORE priority cannot be replaced
@register_attack("core_attack", priority=RegistrationPriority.CORE)
class CoreAttack(BaseAttack): pass

@register_attack("core_attack", priority=RegistrationPriority.HIGH)
class HighAttack(BaseAttack): pass
# Result: HighAttack registration is skipped, CoreAttack remains
```

### Implementation Promotion Process

The system supports promoting effective implementations to higher priorities:

#### Step 1: Implement with LOW Priority
```python
@register_attack(
    name="new_technique",
    priority=RegistrationPriority.LOW,  # Start experimental
    required_params=["technique_params"]
)
class NewTechniqueAttack(BaseAttack):
    """New experimental technique."""
    pass
```

#### Step 2: Gather Performance Data
```python
# After testing and validation
performance_data = {
    "success_rate": 0.94,
    "average_latency_ms": 1.1,
    "tested_domains": 500,
    "effective_against": ["dpi_system_a", "dpi_system_b"]
}
```

#### Step 3: Promote to Higher Priority
```python
@register_attack(
    name="new_technique",
    priority=RegistrationPriority.HIGH,  # Promoted after validation
    required_params=["technique_params"],
    optional_params={"validated": True}
)
class ValidatedNewTechniqueAttack(BaseAttack):
    """
    New technique - now validated and promoted to HIGH priority.
    
    Performance data:
    - Success rate: 94%
    - Average latency: 1.1ms
    - Tested on 500+ domains
    """
    pass
```

### Priority Best Practices

#### 1. Start Conservative
```python
# Always start with LOW or NORMAL priority for new attacks
@register_attack("my_new_attack", priority=RegistrationPriority.LOW)
class MyNewAttack(BaseAttack):
    """Start with low priority until proven effective."""
    pass
```

#### 2. Document Justification for HIGH Priority
```python
@register_attack(
    name="proven_attack",
    priority=RegistrationPriority.HIGH,
    # Document why HIGH priority is justified
)
class ProvenAttack(BaseAttack):
    """
    HIGH PRIORITY JUSTIFICATION:
    - Success rate: 96.7% (tested on 1000+ domains)
    - Outperforms existing NORMAL priority implementations by 15%
    - Validated against 5 different DPI systems
    - Community tested for 3 months
    - Performance benchmarks available in /docs/performance/
    """
    pass
```

#### 3. Never Use CORE Outside Primitives
```python
# WRONG - Don't use CORE priority in external modules
@register_attack("external_attack", priority=RegistrationPriority.CORE)  # ❌
class ExternalAttack(BaseAttack): pass

# CORRECT - Use appropriate priority for external modules
@register_attack("external_attack", priority=RegistrationPriority.NORMAL)  # ✅
class ExternalAttack(BaseAttack): pass
```

#### 4. Handle Registration Results
```python
@register_attack(
    name="my_attack",
    priority=RegistrationPriority.NORMAL
)
class MyAttack(BaseAttack):
    pass

# The decorator automatically logs registration results:
# INFO: Successfully registered my_attack with NORMAL priority
# WARNING: Skipped my_attack registration (lower priority than existing HIGH)
# INFO: Replaced my_attack with higher priority implementation
```

### Priority System Monitoring

You can check registration results and priority conflicts:

```python
from core.bypass.attacks.attack_registry import get_attack_registry

registry = get_attack_registry()

# Check current attack priority
entry = registry.get_attack_entry("my_attack")
if entry:
    print(f"Attack priority: {entry.priority}")
    print(f"Registration time: {entry.registration_time}")
    print(f"Source module: {entry.source_module}")

# List attacks by priority
high_priority_attacks = registry.list_attacks_by_priority(RegistrationPriority.HIGH)
print(f"High priority attacks: {high_priority_attacks}")

# Check for conflicts
conflicts = registry.get_registration_conflicts()
for conflict in conflicts:
    print(f"Conflict: {conflict.attack_type} - {conflict.message}")
```

### Common Priority Scenarios

#### Scenario 1: Community Contribution
```python
# Community member contributes new attack
@register_attack(
    name="community_split_attack",
    priority=RegistrationPriority.NORMAL,  # Standard for community contributions
    required_params=["split_method"]
)
class CommunitySplitAttack(BaseAttack):
    """Community-contributed split attack."""
    pass
```

#### Scenario 2: Research Prototype
```python
# Researcher testing new concept
@register_attack(
    name="research_prototype",
    priority=RegistrationPriority.LOW,  # Experimental priority
    required_params=["research_params"]
)
class ResearchPrototypeAttack(BaseAttack):
    """Research prototype - experimental only."""
    pass
```

#### Scenario 3: Production Optimization
```python
# Optimized version of existing attack
@register_attack(
    name="existing_attack",
    priority=RegistrationPriority.HIGH,  # Higher priority to replace existing
    required_params=["optimized_params"]
)
class OptimizedAttack(BaseAttack):
    """
    Optimized version with 20% better performance.
    Replaces existing NORMAL priority implementation.
    """
    pass
```

### Priority System Summary

| Priority | Value | Use Case | Can Replace | Can Be Replaced By |
|----------|-------|----------|-------------|-------------------|
| **CORE** | 100 | Canonical implementations (primitives.py) | All lower priorities | None |
| **HIGH** | 75 | Proven effective implementations | NORMAL, LOW | CORE only |
| **NORMAL** | 50 | Standard external attacks | LOW only | CORE, HIGH |
| **LOW** | 25 | Experimental/untested attacks | None | All higher priorities |

**Key Rules:**
1. **CORE priority is reserved** for canonical implementations in `primitives.py`
2. **Higher priority always wins** in registration conflicts
3. **Equal priority registrations are skipped** (first registration wins)
4. **All registration actions are logged** for transparency
5. **Priority should reflect implementation maturity** and proven effectiveness

**Decision Tree for Priority Selection:**
```
Is this in primitives.py? → YES → Use CORE
                         ↓ NO
Do you have extensive performance data (>90% success rate, >1000 tests)? → YES → Use HIGH
                                                                         ↓ NO
Is this a standard, tested implementation? → YES → Use NORMAL
                                          ↓ NO
Is this experimental or untested? → YES → Use LOW
```

### 2. Implementation Phase

#### Option A: Simple Attack (Recommended)

For most attacks, implement as a static method in `BypassTechniques`:

```python
# In core/bypass/techniques/primitives.py

@staticmethod
def apply_my_attack(payload: bytes, 
                   my_param: int,
                   optional_param: str = "default",
                   **kwargs) -> List[Tuple[bytes, int, Dict[str, Any]]]:
    """
    My custom DPI bypass attack.
    
    Args:
        payload: Packet payload data
        my_param: Required parameter description
        optional_param: Optional parameter description
        **kwargs: Additional parameters
        
    Returns:
        List of (data, offset, options) tuples for packet transmission
    """
    # Validate input
    if len(payload) < 2:
        return [(payload, 0, {"is_fake": False, "tcp_flags": 0x18})]
    
    # Implement your attack logic here
    part1 = payload[:my_param]
    part2 = payload[my_param:]
    
    # Return segments with metadata
    return [
        (part1, 0, {"is_fake": False, "tcp_flags": 0x18}),
        (part2, my_param, {"is_fake": False, "tcp_flags": 0x18})
    ]
```

**Parameter Normalization Requirements:**

Your attack should expect parameters in **canonical format** after normalization:

```python
# Canonical parameter formats (what your attack receives):
positions: List[int]        # Always a list, even for single position
ttl: int                   # Time to live value
fake_ttl: int              # TTL specifically for fake packets  
fooling_methods: List[str] # List of fooling methods
overlap_size: int          # Size of sequence overlap

# The AttackDispatcher automatically converts these formats:
# split_pos: 3 → positions: [3]
# split_pos: [1, 5] → positions: [1, 5] 
# ttl: 3 → fake_ttl: 3 (for fakeddisorder attacks)
# fooling: "badsum" → fooling_methods: ["badsum"]
# Special values: "sni" → positions: [43] (resolved automatically)
```

## 🔄 Parameter Normalization System

The refactored system includes a comprehensive parameter normalization system that automatically converts various parameter formats to canonical ones.

### Supported Parameter Conversions

#### 1. Alias Resolution
```python
# Old parameter names → Canonical names
ttl → fake_ttl                    # For fakeddisorder attacks
fooling → fooling_methods         # Fooling method standardization
overlap_size → split_seqovl       # Zapret compatibility
```

#### 2. Format Standardization
```python
# Position parameters
split_pos: 3 → positions: [3]           # Single position to list
split_pos: [1, 5] → positions: [1, 5]   # List format preserved
split_count: 5 → positions: [calculated] # Generate positions from count

# Fooling methods
fooling: "badsum" → fooling_methods: ["badsum"]
fooling: ["badsum", "badseq"] → fooling_methods: ["badsum", "badseq"]
```

#### 3. Special Value Resolution
```python
# Special position values (resolved based on payload analysis)
positions: ["sni"] → positions: [43]        # TLS SNI extension position
positions: ["cipher"] → positions: [11]     # TLS cipher suites position
positions: ["midsld"] → positions: [calc]   # Middle of second-level domain
```

#### 4. Type Conversion
```python
# String to numeric conversion
split_pos: "3" → positions: [3]
fake_ttl: "5" → fake_ttl: 5
overlap_size: "10" → overlap_size: 10
```

### Validation and Warnings

The normalization system provides detailed feedback:

```python
# Example ValidationResult from parameter normalization
ValidationResult(
    is_valid=True,
    warnings=[
        "Converted alias 'ttl' to 'fake_ttl': 3",
        "Converted single position to list: split_pos=3 → positions=[3]",
        "Resolved special value 'sni' to position: 43"
    ],
    normalized_params={
        "positions": [3],
        "fake_ttl": 3,
        "fooling_methods": ["badsum", "badseq"]
    },
    transformations=[
        "Alias resolution: ttl=3 → fake_ttl=3",
        "Format standardization: split_pos=3 → positions=[3]"
    ]
)
```

### Attack Implementation Guidelines

When implementing your attack, expect normalized parameters:

```python
def apply_my_attack(payload: bytes,
                   positions: List[int],           # Always list format
                   fake_ttl: int = 3,             # Canonical TTL name
                   fooling_methods: List[str] = None,  # Always list format
                   overlap_size: int = 0,         # Canonical overlap name
                   **kwargs) -> List[Tuple[bytes, int, Dict[str, Any]]]:
    """
    Attack implementation expecting normalized parameters.
    
    All parameter conversion is handled by ParameterNormalizer before
    your attack is called, so you can focus on the attack logic.
    """
    if fooling_methods is None:
        fooling_methods = ["badsum", "badseq"]
    
    # Your attack logic here with normalized parameters
    segments = []
    # ... implementation
    return segments
```

## 🏗️ BaseAttack Interface Requirements

All attacks must inherit from `BaseAttack` and implement the required abstract properties and methods. The interface enforces standardization and enables automatic registration with complete metadata.

### Required Abstract Properties

Every attack class **must** implement these abstract properties:

#### 1. `name` Property
```python
@property
@abstractmethod
def name(self) -> str:
    """Unique name for this attack."""
    pass

# Example implementation:
@property
def name(self) -> str:
    return "my_custom_attack"
```

#### 2. `category` Property
```python
@property
@abstractmethod
def category(self) -> str:
    """Attack category from AttackCategories."""
    pass

# Example implementation:
@property
def category(self) -> str:
    return AttackCategories.TCP  # Must be from AttackCategories.ALL
```

#### 3. `required_params` Property
```python
@property
@abstractmethod
def required_params(self) -> List[str]:
    """List of required parameter names."""
    pass

# Example implementation:
@property
def required_params(self) -> List[str]:
    return ["positions", "target_protocol"]  # Parameters that must be provided
```

#### 4. `optional_params` Property
```python
@property
@abstractmethod
def optional_params(self) -> Dict[str, Any]:
    """Dictionary of optional parameters with default values."""
    pass

# Example implementation:
@property
def optional_params(self) -> Dict[str, Any]:
    return {
        "fake_ttl": 3,
        "fooling_methods": ["badsum", "badseq"],
        "delay_ms": 0
    }
```

#### 5. `execute` Method
```python
@abstractmethod
def execute(self, context: AttackContext) -> AttackResult:
    """Execute the attack with the given context."""
    pass

# Example implementation:
def execute(self, context: AttackContext) -> AttackResult:
    # Extract normalized parameters
    positions = context.params.get("positions", [3])
    fake_ttl = context.params.get("fake_ttl", 3)
    
    # Implement attack logic
    segments = self._create_attack_segments(context.payload, positions, fake_ttl)
    
    # Return standardized result
    return AttackResultHelper.create_segments_result(
        technique_used=self.name,
        segments=segments
    )
```

### Optional Properties (Can be Overridden)

#### 1. `description` Property
```python
@property
def description(self) -> str:
    """Human-readable description of the attack."""
    return f"{self.name} attack"  # Default implementation

# Custom implementation:
@property
def description(self) -> str:
    return "Advanced TCP segmentation attack with fake packet injection"
```

#### 2. `aliases` Property
```python
@property
def aliases(self) -> List[str]:
    """List of alternative names for this attack."""
    return []  # Default: no aliases

# Custom implementation:
@property
def aliases(self) -> List[str]:
    return ["tcp_split", "segment_attack", "split_advanced"]
```

#### 3. `supported_protocols` Property
```python
@property
def supported_protocols(self) -> List[str]:
    """List of supported protocols."""
    return ["tcp"]  # Default: TCP only

# Custom implementation:
@property
def supported_protocols(self) -> List[str]:
    return ["tcp", "udp", "tls"]
```

### Complete BaseAttack Implementation Example

```python
from typing import List, Dict, Any
from core.bypass.attacks.base import BaseAttack, AttackContext, AttackResult
from core.bypass.attacks.metadata import AttackCategories
from core.bypass.attacks.attack_registry import register_attack

@register_attack(
    name="example_segmentation_attack",
    category=AttackCategories.TCP,
    priority=RegistrationPriority.NORMAL,
    required_params=["positions"],
    optional_params={
        "fake_ttl": 3,
        "fooling_methods": ["badsum", "badseq"],
        "max_segments": 10
    },
    aliases=["example_attack", "seg_attack"]
)
class ExampleSegmentationAttack(BaseAttack):
    """
    Example TCP segmentation attack that demonstrates proper BaseAttack implementation.
    
    This attack splits the payload at specified positions and sends segments
    with optional fake packet injection and TTL manipulation.
    """
    
    # Required abstract properties
    @property
    def name(self) -> str:
        return "example_segmentation_attack"
    
    @property
    def category(self) -> str:
        return AttackCategories.TCP
    
    @property
    def required_params(self) -> List[str]:
        return ["positions"]
    
    @property
    def optional_params(self) -> Dict[str, Any]:
        return {
            "fake_ttl": 3,
            "fooling_methods": ["badsum", "badseq"],
            "max_segments": 10
        }
    
    # Optional properties (customized)
    @property
    def description(self) -> str:
        return "TCP segmentation attack with fake packet injection"
    
    @property
    def aliases(self) -> List[str]:
        return ["example_attack", "seg_attack"]
    
    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp", "tls"]
    
    # Required abstract method
    def execute(self, context: AttackContext) -> AttackResult:
        """Execute the segmentation attack."""
        try:
            # Extract and validate parameters (already normalized by dispatcher)
            positions = context.params.get("positions", [3])
            fake_ttl = context.params.get("fake_ttl", 3)
            fooling_methods = context.params.get("fooling_methods", ["badsum"])
            max_segments = context.params.get("max_segments", 10)
            
            # Validate parameters
            if not positions:
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message="positions parameter cannot be empty"
                )
            
            if len(positions) > max_segments:
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message=f"Too many positions: {len(positions)} > {max_segments}"
                )
            
            # Create attack segments
            segments = self._create_segments(
                context.payload, positions, fake_ttl, fooling_methods
            )
            
            # Return success result with segments
            return AttackResultHelper.create_segments_result(
                technique_used=self.name,
                segments=segments,
                metadata={
                    "positions_used": positions,
                    "fake_ttl": fake_ttl,
                    "fooling_methods": fooling_methods,
                    "segment_count": len(segments)
                }
            )
            
        except Exception as e:
            self.logger.error(f"Attack execution failed: {e}")
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                technique_used=self.name
            )
    
    def _create_segments(self, payload: bytes, positions: List[int], 
                        fake_ttl: int, fooling_methods: List[str]) -> List[SegmentTuple]:
        """Create segments for the attack."""
        segments = []
        last_pos = 0
        
        for i, pos in enumerate(sorted(positions)):
            if pos <= last_pos or pos >= len(payload):
                continue
                
            # Create real segment
            segment_data = payload[last_pos:pos]
            segment_options = {
                "ttl": None,  # Use default TTL for real segments
                "bad_checksum": False
            }
            segments.append((segment_data, last_pos, segment_options))
            
            # Create fake segment (if not last)
            if i < len(positions) - 1:
                fake_options = {
                    "ttl": fake_ttl,
                    "bad_checksum": "badsum" in fooling_methods,
                    "bad_seq": "badseq" in fooling_methods
                }
                # Fake segment with same data but different options
                segments.append((segment_data, last_pos, fake_options))
            
            last_pos = pos
        
        # Add final segment if needed
        if last_pos < len(payload):
            final_segment = payload[last_pos:]
            segments.append((final_segment, last_pos, {"ttl": None, "bad_checksum": False}))
        
        return segments
```

### Interface Validation

The `BaseAttack` class automatically validates implementations using `__init_subclass__`:

```python
class MyInvalidAttack(BaseAttack):
    # Missing required properties - will raise TypeError
    pass

# TypeError: Attack class MyInvalidAttack must implement all required abstract properties: 
# ['name', 'category', 'required_params', 'optional_params']
```

### Validation Rules

1. **Property Types**: All properties must return correct types
   - `name`: non-empty string
   - `category`: valid AttackCategories value
   - `required_params`: list of strings
   - `optional_params`: dictionary

2. **Category Validation**: Category must be from `AttackCategories.ALL`

3. **Parameter Consistency**: Parameters in decorator must match class properties

4. **Method Signatures**: `execute` method must accept `AttackContext` and return `AttackResult`

### Common Implementation Patterns

#### Pattern 1: Simple Segmentation Attack
```python
class SimpleSegmentationAttack(BaseAttack):
    """Simple payload segmentation."""
    
    @property
    def required_params(self) -> List[str]:
        return ["positions"]
    
    def execute(self, context: AttackContext) -> AttackResult:
        positions = context.params["positions"]
        segments = self._split_payload(context.payload, positions)
        return AttackResultHelper.create_segments_result(self.name, segments)
```

#### Pattern 2: Stateful Attack
```python
class StatefulAttack(BaseAttack):
    """Attack that maintains connection state."""
    
    def __init__(self):
        super().__init__()
        self.connection_states = {}
    
    def execute(self, context: AttackContext) -> AttackResult:
        conn_id = context.connection_id
        state = self.connection_states.get(conn_id, {})
        
        # Use state in attack logic
        result = self._execute_with_state(context, state)
        
        # Update state
        self.connection_states[conn_id] = state
        return result
```

#### Pattern 3: Protocol-Specific Attack
```python
class TLSSpecificAttack(BaseAttack):
    """Attack specific to TLS protocol."""
    
    @property
    def category(self) -> str:
        return AttackCategories.TLS
    
    @property
    def supported_protocols(self) -> List[str]:
        return ["tls"]
    
    def execute(self, context: AttackContext) -> AttackResult:
        if context.protocol != "tls":
            return AttackResult(
                status=AttackStatus.INVALID_PARAMS,
                error_message="This attack only supports TLS protocol"
            )
        # TLS-specific implementation
```

### 3. Registration Phase

#### New Standardized Registration Process

The refactored system uses a unified registry with priority-based registration and a standardized `@register_attack` decorator. This decorator provides automatic registration with complete metadata validation.

#### Option A: Standardized Decorator Registration (Recommended)

Use the enhanced `@register_attack` decorator with complete metadata:

```python
# In your attack module (e.g., core/bypass/attacks/my_category/my_attack.py)

from core.bypass.attacks.base import BaseAttack
from core.bypass.attacks.metadata import AttackCategories, RegistrationPriority
from core.bypass.attacks.attack_registry import register_attack

@register_attack(
    name="my_advanced_attack",
    category=AttackCategories.TCP,
    priority=RegistrationPriority.NORMAL,
    required_params=["positions"],
    optional_params={
        "fake_ttl": 3,
        "fooling_methods": ["badsum", "badseq"]
    },
    aliases=["my_attack", "advanced_attack"]
)
class MyAdvancedAttack(BaseAttack):
    """
    My advanced DPI bypass attack.
    
    This attack implements a sophisticated technique that...
    """
    
    @property
    def name(self) -> str:
        return "my_advanced_attack"
    
    @property
    def category(self) -> str:
        return AttackCategories.TCP
    
    @property
    def required_params(self) -> List[str]:
        return ["positions"]
    
    @property
    def optional_params(self) -> Dict[str, Any]:
        return {
            "fake_ttl": 3,
            "fooling_methods": ["badsum", "badseq"]
        }
    
    def execute(self, context: AttackContext) -> AttackResult:
        """Execute the attack with normalized parameters."""
        positions = context.params.get("positions", [3])
        fake_ttl = context.params.get("fake_ttl", 3)
        fooling_methods = context.params.get("fooling_methods", ["badsum"])
        
        # Your attack implementation here
        segments = self._create_segments(context.payload, positions, fake_ttl, fooling_methods)
        
        return AttackResultHelper.create_segments_result(
            technique_used=self.name,
            segments=segments
        )
    
    def _create_segments(self, payload: bytes, positions: List[int], 
                        fake_ttl: int, fooling_methods: List[str]) -> List[SegmentTuple]:
        """Create segments for the attack."""
        # Implementation details...
        segments = []
        # ... segment creation logic
        return segments
```

#### Option B: Simple Decorator Registration

For simpler cases, use the decorator with minimal parameters:

```python
@register_attack("my_simple_attack")
class MySimpleAttack(BaseAttack):
    """Simple attack with automatic metadata extraction."""
    
    @property
    def name(self) -> str:
        return "my_simple_attack"
    
    @property
    def category(self) -> str:
        return AttackCategories.TCP
    
    @property
    def required_params(self) -> List[str]:
        return ["split_pos"]
    
    @property
    def optional_params(self) -> Dict[str, Any]:
        return {"ttl": 3}
    
    def execute(self, context: AttackContext) -> AttackResult:
        # Implementation...
        pass
```

#### Option C: Parameterless Decorator Registration

For automatic name detection from class name:

```python
@register_attack  # Uses class name automatically
class AutoNamedAttack(BaseAttack):
    """Attack with automatic name detection."""
    
    @property
    def name(self) -> str:
        return "auto_named_attack"  # Derived from class name
    
    # ... rest of implementation
```

#### Manual Registration (Legacy Support)

For backward compatibility, manual registration is still supported:

```python
# In core/bypass/attacks/attack_registry.py

def _register_builtin_attacks(self):
    """Register all built-in attacks."""
    
    # ... existing registrations ...
    
    # Add your attack with priority
    result = self.register_attack(
        attack_type="my_attack",
        handler=lambda techniques, payload, **params: techniques.apply_my_attack(payload, **params),
        metadata=AttackMetadata(
            name="My Attack",
            description="Description of my attack",
            category=AttackCategories.TCP,
            required_params=["my_param"],
            optional_params={"optional_param": "default"},
            aliases=["my_alias"]
        ),
        priority=RegistrationPriority.NORMAL  # Specify priority
    )
    
    # Check registration result
    if not result.success:
        logger.warning(f"Failed to register my_attack: {result.message}")
```

#### Decorator Registration Patterns

The `@register_attack` decorator supports multiple usage patterns:

**1. Full Metadata Declaration (Recommended):**
```python
@register_attack(
    name="comprehensive_attack",
    category=AttackCategories.TCP,
    priority=RegistrationPriority.HIGH,
    required_params=["positions", "target_protocol"],
    optional_params={
        "fake_ttl": 3,
        "fooling_methods": ["badsum", "badseq"],
        "delay_ms": 0,
        "max_segments": 10
    },
    aliases=["comp_attack", "comprehensive"]
)
class ComprehensiveAttack(BaseAttack):
    # Implementation...
```

**2. Minimal Declaration:**
```python
@register_attack("simple_attack")
class SimpleAttack(BaseAttack):
    # Metadata extracted from class properties
```

**3. Automatic Name Detection:**
```python
@register_attack
class MyCustomAttack(BaseAttack):
    # Name becomes "my_custom_attack" automatically
```

**4. Priority-Based Registration:**
```python
@register_attack(
    name="high_priority_attack",
    priority=RegistrationPriority.HIGH  # Will replace NORMAL priority attacks
)
class HighPriorityAttack(BaseAttack):
    # Implementation...
```

#### Registration with Deduplication Handling

The registry automatically handles duplicate registrations based on priority:

```python
# Higher priority attack replaces lower priority
@register_attack(
    name="existing_attack",
    priority=RegistrationPriority.HIGH  # Will replace NORMAL priority
)
class ImprovedAttack(BaseAttack):
    # Better implementation
    pass

# The decorator will automatically:
# 1. Check existing registration priority
# 2. Replace if new priority is higher
# 3. Skip if new priority is lower or equal
# 4. Log the action taken
```

#### Decorator Validation and Error Handling

The decorator performs comprehensive validation:

```python
@register_attack(
    name="validated_attack",
    category=AttackCategories.TCP,  # Must be valid category
    required_params=["positions"],   # Must be list of strings
    optional_params={"ttl": 3}      # Must be dict with defaults
)
class ValidatedAttack(BaseAttack):
    # If validation fails, registration is skipped with detailed error message
    pass
```

**Common Validation Errors:**
- Invalid category (not in AttackCategories.ALL)
- Missing required abstract properties in BaseAttack
- Incorrect parameter types (required_params not list, optional_params not dict)
- Empty or invalid attack name
- Priority conflicts with existing registrations

#### Manual Registration (External Modules)

```python
# In your external module
from core.bypass.attacks.attack_registry import get_attack_registry
from core.bypass.attacks.metadata import AttackMetadata, RegistrationPriority, AttackCategories

# Get the global registry
registry = get_attack_registry()

# Register your attack
result = registry.register_attack(
    attack_type="my_external_attack",
    handler=MyAttack().execute,
    metadata=AttackMetadata(
        name="My External Attack",
        description="External attack implementation",
        category=AttackCategories.CUSTOM,
        required_params=["param1"],
        optional_params={"param2": "default"},
        aliases=["external_attack"]
    ),
    priority=RegistrationPriority.NORMAL
)

# Handle registration result
if result.success:
    logger.info(f"Successfully registered: {result.message}")
else:
    logger.error(f"Registration failed: {result.message}")
```

### 4. Testing Phase

#### Create Unit Tests

```python
# In tests/test_my_attack.py

import pytest
from core.bypass.techniques.primitives import BypassTechniques
from core.bypass.engine.attack_dispatcher import AttackDispatcher
from core.bypass.attacks.attack_registry import get_attack_registry

class TestMyAttack:
    
    def setup_method(self):
        self.techniques = BypassTechniques()
        self.registry = get_attack_registry()
        self.dispatcher = AttackDispatcher(self.techniques, self.registry)
    
    def test_my_attack_basic(self):
        """Test basic functionality of my attack."""
        payload = b"test_payload_data"
        params = {"my_param": 5}
        
        # Test through dispatcher (includes parameter normalization)
        result = self.dispatcher.dispatch_attack("my_attack", params, payload, {})
        
        assert result.status == "success"
        assert len(result.segments) == 2  # Expected number of segments
        assert result.segments[0][0] == b"test_"  # First part
        assert result.segments[1][0] == b"payload_data"  # Second part
    
    def test_my_attack_parameter_normalization(self):
        """Test parameter normalization."""
        payload = b"test_payload_data"
        
        # Test that old-style parameters are normalized
        params_old = {"split_pos": 5}  # Old format
        params_new = {"positions": [5]}  # New format
        
        result_old = self.dispatcher.dispatch_attack("my_attack", params_old, payload, {})
        result_new = self.dispatcher.dispatch_attack("my_attack", params_new, payload, {})
        
        # Should produce same results after normalization
        assert result_old.segments == result_new.segments
    
    def test_my_attack_special_values(self):
        """Test special parameter value resolution."""
        payload = b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n"
        
        # Test special value resolution
        params = {"positions": ["sni"]}  # Special value
        result = self.dispatcher.dispatch_attack("my_attack", params, payload, {})
        
        assert result.status == "success"
        # SNI position should be resolved to actual position
    
    def test_my_attack_edge_cases(self):
        """Test edge cases."""
        # Empty payload
        result = self.dispatcher.dispatch_attack("my_attack", {"my_param": 1}, b"", {})
        assert result.status in ["success", "warning"]  # Should handle gracefully
        
        # Large parameter
        result = self.dispatcher.dispatch_attack("my_attack", {"my_param": 1000}, b"small", {})
        assert result.status in ["success", "warning"]  # Should handle gracefully
    
    def test_my_attack_parameter_validation(self):
        """Test parameter validation through registry."""
        # Valid parameters
        result = self.registry.validate_parameters("my_attack", {"my_param": 5})
        assert result.is_valid
        
        # Missing required parameter
        result = self.registry.validate_parameters("my_attack", {})
        assert not result.is_valid
        assert "my_param" in result.error_message
        
        # Invalid parameter type
        result = self.registry.validate_parameters("my_attack", {"my_param": "invalid"})
        assert not result.is_valid
    
    def test_my_attack_registration(self):
        """Test attack registration and priority handling."""
        # Check that attack is registered
        handler = self.registry.get_attack_handler("my_attack")
        assert handler is not None
        
        # Check aliases work
        for alias in ["my_alias"]:
            alias_handler = self.registry.get_attack_handler(alias)
            assert alias_handler is not None
        
        # Check metadata
        attacks = self.registry.list_attacks()
        assert "my_attack" in attacks
```

#### Integration Tests

```python
# In tests/test_integration.py

def test_my_attack_integration(self):
    """Test my attack in full system integration."""
    from core.bypass.engine.base_engine import WindowsBypassEngine
    
    engine = WindowsBypassEngine(config)
    packet = create_test_packet()
    strategy = {
        "type": "my_attack",
        "params": {"my_param": 3}
    }
    
    with patch('pydivert.WinDivert') as mock_divert:
        engine.apply_bypass(packet, mock_divert, strategy)
        
    # Verify expected behavior
    assert mock_divert.send.call_count == 2  # Expected packet count
```

### 5. Documentation Phase

#### Update Attack Documentation

```python
# Add to docs/API_REFERENCE.md

## My Attack

**Type**: `my_attack`  
**Category**: Split  
**Aliases**: `my_alias`

### Description
Detailed description of what the attack does and how it bypasses DPI.

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `my_param` | int | Yes | - | Description of parameter |
| `optional_param` | str | No | "default" | Description of optional parameter |

### Example Usage

```python
recipe = dispatcher.dispatch_attack(
    "my_attack",
    {"my_param": 5, "optional_param": "custom"},
    b"test_payload",
    {}
)
```

### Behavior
- Splits payload at position `my_param`
- Sends first part, then second part
- Uses standard TCP flags
```

## 🔧 Advanced Features

### Parameter Normalization System

The new system includes automatic parameter normalization through `ParameterNormalizer`:

```python
# The dispatcher automatically handles these conversions:

# 1. Alias resolution
ttl: 3 → fake_ttl: 3  # For fakeddisorder attacks
fooling: "badsum" → fooling_methods: ["badsum"]

# 2. Format standardization  
split_pos: 3 → positions: [3]  # Single position to list
split_pos: [1, 5] → positions: [1, 5]  # Already list format

# 3. Special value resolution (automatic)
positions: ["sni"] → positions: [43]  # TLS SNI position
positions: ["cipher"] → positions: [11]  # TLS cipher position  
positions: ["midsld"] → positions: [calculated]  # Middle of domain

# 4. Type conversion
split_pos: "3" → positions: [3]  # String to int conversion
ttl: "5" → fake_ttl: 5  # String to int conversion
```

### Custom Parameter Resolution

If you need custom parameter resolution, implement it in your attack:

```python
def _resolve_custom_parameter(self, param_value: str, payload: bytes) -> int:
    """Resolve custom parameter values."""
    if param_value == "my_special_value":
        # Custom logic to determine position
        return self._find_special_position(payload)
    return int(param_value)
```

### Advanced Priority Usage

#### Dynamic Priority Assignment
```python
# Assign priority based on performance metrics
def get_attack_priority(success_rate: float, test_count: int) -> RegistrationPriority:
    """Determine appropriate priority based on performance data."""
    if test_count < 100:
        return RegistrationPriority.LOW  # Insufficient testing
    elif success_rate >= 0.95 and test_count >= 1000:
        return RegistrationPriority.HIGH  # Proven effectiveness
    elif success_rate >= 0.80:
        return RegistrationPriority.NORMAL  # Standard effectiveness
    else:
        return RegistrationPriority.LOW  # Below standard

# Use dynamic priority
performance_data = get_performance_metrics("my_attack")
priority = get_attack_priority(performance_data.success_rate, performance_data.test_count)

@register_attack(
    name="my_attack",
    priority=priority,  # Dynamic priority based on performance
    required_params=["positions"]
)
class MyAttack(BaseAttack):
    pass
```

#### Priority-Based Feature Flags
```python
@register_attack(
    name="feature_flagged_attack",
    priority=RegistrationPriority.HIGH if ENABLE_ADVANCED_FEATURES else RegistrationPriority.LOW,
    required_params=["positions"]
)
class FeatureFlaggedAttack(BaseAttack):
    """Attack with priority based on feature flags."""
    pass
```

#### Conditional Registration
```python
# Register only if conditions are met
if has_required_dependencies() and performance_meets_threshold():
    @register_attack(
        name="conditional_attack",
        priority=RegistrationPriority.HIGH,
        required_params=["advanced_params"]
    )
    class ConditionalAttack(BaseAttack):
        """Attack registered only when conditions are met."""
        pass
else:
    logger.info("Skipping conditional_attack registration - requirements not met")
```

### State Management

```python
class StatefulAttack:
    def __init__(self):
        self.connection_state = {}
    
    def execute(self, payload: bytes, connection_id: str, **params):
        # Use connection state
        state = self.connection_state.get(connection_id, {})
        
        # Update state based on attack
        state['packet_count'] = state.get('packet_count', 0) + 1
        self.connection_state[connection_id] = state
        
        # Execute attack with state awareness
        return self._execute_with_state(payload, state, params)
```

### Performance Optimization

```python
from functools import lru_cache

class OptimizedAttack:
    @lru_cache(maxsize=128)
    def _expensive_calculation(self, payload_hash: int, param: int) -> int:
        """Cache expensive calculations."""
        # Expensive operation here
        return result
    
    def execute(self, payload: bytes, **params):
        # Use cached calculation
        result = self._expensive_calculation(hash(payload), params['param'])
        return self._generate_segments(payload, result)
```

## 📊 Best Practices

### 1. Parameter Validation

With the new system, parameter validation is handled by the registry, but you should still validate in your attack:

```python
def apply_my_attack(payload: bytes, positions: List[int], **kwargs):
    # Parameters are already normalized by ParameterNormalizer
    # But still validate for safety
    if not isinstance(positions, list):
        raise ValueError(f"positions must be list, got {type(positions)}")
    
    if not positions:
        raise ValueError("positions cannot be empty")
    
    for pos in positions:
        if not isinstance(pos, int):
            raise ValueError(f"position must be int, got {type(pos)}")
        if pos < 1 or pos >= len(payload):
            raise ValueError(f"position {pos} out of range for payload length {len(payload)}")
    
    # Continue with implementation
```

### 2. Registration Best Practices

```python
# Always specify complete metadata
metadata = AttackMetadata(
    name="Descriptive Attack Name",
    description="Detailed description of DPI bypass mechanism and effectiveness",
    category=AttackCategories.APPROPRIATE_CATEGORY,
    required_params=["positions"],  # Use canonical parameter names
    optional_params={
        "fake_ttl": 3,  # Use canonical names with good defaults
        "fooling_methods": ["badsum", "badseq"]
    },
    aliases=["alternative_name", "short_name"]
)

# Register with appropriate priority
result = registry.register_attack(
    attack_type="my_attack",
    handler=handler,
    metadata=metadata,
    priority=RegistrationPriority.NORMAL  # Choose appropriate priority
)

# Always check registration result
if not result.success:
    logger.error(f"Failed to register attack: {result.message}")
    if result.conflicts:
        logger.error(f"Conflicts: {result.conflicts}")
```

### 2. Error Handling

```python
def apply_my_attack(payload: bytes, **params):
    try:
        # Attack implementation
        return segments
    except Exception as e:
        # Log error and return safe fallback
        logger.error(f"My attack failed: {e}")
        return [(payload, 0, {"is_fake": False, "tcp_flags": 0x18})]
```

### 3. Logging

```python
import logging

logger = logging.getLogger(__name__)

def apply_my_attack(payload: bytes, **params):
    logger.debug(f"Executing my_attack with params: {params}")
    
    segments = generate_segments(payload, params)
    
    logger.info(f"✅ My attack generated {len(segments)} segments")
    return segments
```

### 4. Metadata Completeness

Use canonical parameter names in metadata for consistency:

```python
AttackMetadata(
    name="Descriptive Attack Name",
    description="Detailed description including DPI bypass mechanism and effectiveness data",
    category=AttackCategories.APPROPRIATE_CATEGORY,
    required_params=["positions"],  # Use canonical names
    optional_params={
        "fake_ttl": 3,  # Canonical TTL parameter name
        "fooling_methods": ["badsum", "badseq"],  # Canonical fooling parameter
        "overlap_size": 0  # Canonical overlap parameter
    },
    aliases=["alternative_name", "short_name"]
)
```

### 5. Parameter Normalization Compliance

Design your attack to work with normalized parameters:

```python
def apply_my_attack(payload: bytes, 
                   positions: List[int],  # Always expect list format
                   fake_ttl: int = 3,     # Use canonical parameter names
                   fooling_methods: List[str] = None,  # Always expect list
                   **kwargs) -> List[Tuple[bytes, int, Dict[str, Any]]]:
    """
    Attack implementation that expects normalized parameters.
    
    The AttackDispatcher will automatically convert:
    - split_pos: 3 → positions: [3]
    - ttl: 3 → fake_ttl: 3
    - fooling: "badsum" → fooling_methods: ["badsum"]
    - Special values: "sni" → positions: [43]
    """
    if fooling_methods is None:
        fooling_methods = ["badsum", "badseq"]
    
    # Your attack logic here - parameters are already normalized
    segments = []
    for pos in positions:
        # Process each position
        part1 = payload[:pos]
        part2 = payload[pos:]
        
        segments.extend([
            (part1, 0, {"is_fake": False, "tcp_flags": 0x18}),
            (part2, pos, {"is_fake": False, "tcp_flags": 0x18})
        ])
    
    return segments
```

## 🧪 Testing Checklist

### Unit Tests
- [ ] Basic functionality with normalized parameters
- [ ] Parameter normalization (old format → new format)
- [ ] Special value resolution ("sni", "cipher", "midsld")
- [ ] Edge cases (empty payload, large parameters)
- [ ] Parameter validation through registry
- [ ] Error handling (malformed input)
- [ ] Performance with large payloads

### Registration Tests
- [ ] Successful registration with correct priority
- [ ] Duplicate registration handling
- [ ] Alias resolution
- [ ] Metadata validation
- [ ] Priority conflict resolution

### Integration Tests
- [ ] Full system integration through AttackDispatcher
- [ ] CLI integration with new registry
- [ ] Strategy loading and resolution
- [ ] Network transmission simulation
- [ ] Backward compatibility with old parameter formats

### Manual Testing
- [ ] Real network testing
- [ ] DPI bypass effectiveness
- [ ] Performance benchmarking vs baseline
- [ ] Compatibility with existing strategies
- [ ] Parameter normalization in real scenarios

## 📈 Performance Guidelines

### Optimization Tips
1. **Minimize allocations** in hot paths
2. **Cache expensive calculations** when possible
3. **Use efficient data structures** for large payloads
4. **Avoid unnecessary copying** of payload data
5. **Profile performance** with realistic workloads

### Performance Targets
- **Dispatch time**: < 1ms for simple attacks
- **Memory usage**: < 2x payload size
- **CPU usage**: < 10% overhead vs direct transmission

## 🔒 Security Considerations

### Input Validation
- Validate all parameters thoroughly
- Prevent integer overflow/underflow
- Check array bounds carefully
- Sanitize string inputs

### Resource Limits
- Limit maximum payload size
- Prevent excessive memory allocation
- Implement timeouts for long operations
- Rate limit attack execution

## 📞 Getting Help

### Resources
- **Architecture Documentation**: `docs/ARCHITECTURE.md`
- **API Reference**: `docs/API_REFERENCE.md`
- **Migration Guide**: `.kiro/specs/attack-refactoring/MIGRATION_GUIDE.md`
- **Module Inventory**: `docs/MODULE_INVENTORY.md`
- **Existing Tests**: `tests/test_attack_*.py`

### Code Review Process
1. Create feature branch
2. Implement attack with tests following new standards
3. Ensure parameter normalization compliance
4. Test registration with appropriate priority
5. Update documentation
6. Submit pull request
7. Address review feedback
8. Merge after approval

### Common Issues

#### Registration Issues
- **Registration not working**: Check metadata format and priority
- **Duplicate registration**: Check if higher priority attack exists
- **Alias conflicts**: Verify alias names don't conflict with existing attacks

#### Parameter Issues  
- **Parameters not normalized**: Use canonical parameter names in metadata
- **Special values not resolved**: Ensure ParameterNormalizer handles your special values
- **Type conversion errors**: Check parameter type validation in metadata

#### Testing Issues
- **Tests failing**: Check return value format matches expected segments
- **Parameter tests failing**: Test both old and new parameter formats
- **Integration tests failing**: Verify attack works through AttackDispatcher

#### Performance Issues
- **Slow registration**: Check if lazy loading is enabled for external attacks
- **Parameter normalization overhead**: Profile normalization performance
- **Attack execution slow**: Profile and optimize hot paths

### Migration from Old System

If migrating an existing attack:

1. **Update parameter names** to canonical format
2. **Add priority** to registration
3. **Update tests** to use new registry and dispatcher
4. **Check metadata completeness** with new required fields
5. **Test parameter normalization** with old parameter formats

---

**Guide Version**: 2.0 (Refactored System)  
**Last Updated**: October 2025  
**Next Review**: When architecture changes  
**Maintainer**: DPI Bypass Team