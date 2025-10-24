# API Reference: Attack System Refactoring

## Overview

This document provides comprehensive API documentation for the refactored DPI bypass attack system. The system consists of four main components that work together to provide unified attack registration, parameter normalization, and execution with proper context management.

## Core Components

### 1. AttackDispatcher

**Location**: `core/bypass/engine/attack_dispatcher.py`

The central component responsible for routing attacks to their proper handlers, normalizing parameters, resolving special parameter values, and supporting zapret-style strategy resolution.

#### Class: `AttackDispatcher`

```python
class AttackDispatcher:
    def __init__(self, techniques: BypassTechniques, attack_registry: AttackRegistry = None)
```

**Parameters:**
- `techniques`: Instance of BypassTechniques for executing attacks (backward compatibility)
- `attack_registry`: Attack registry instance (uses global registry if None)

#### Methods

##### `dispatch_attack()`

```python
def dispatch_attack(self, 
                   task_type: str, 
                   params: Dict[str, Any], 
                   payload: bytes, 
                   packet_info: Dict[str, Any]) -> List[Tuple[bytes, int, Dict[str, Any]]]
```

Dispatches an attack to the proper handler with two-tier architecture (advanced attacks first, primitives fallback).

**Parameters:**
- `task_type`: Attack type identifier or zapret-style strategy (e.g., "fake,disorder")
- `params`: Attack parameters dictionary
- `payload`: Packet payload data
- `packet_info`: Packet information (src_addr, dst_addr, src_port, dst_port)

**Returns:**
- List of tuples `(data, offset, options)` for packet transmission

**Raises:**
- `ValueError`: If attack type is unknown or parameters are invalid
- `RuntimeError`: If attack execution fails

**Example:**
```python
dispatcher = AttackDispatcher(techniques)

# Single attack
recipe = dispatcher.dispatch_attack(
    "fakeddisorder",
    {"split_pos": 3, "ttl": 3},
    b"test_payload",
    {"src_addr": "192.168.1.1", "dst_addr": "1.1.1.1"}
)

# Zapret-style strategy
recipe = dispatcher.dispatch_attack(
    "fake,disorder",  # Resolves to fakeddisorder
    {"split_pos": "sni", "ttl": 3},
    tls_clienthello_payload,
    packet_info
)
```

##### `resolve_strategy()`

```python
def resolve_strategy(self, strategy: str) -> List[Tuple[str, Dict[str, Any]]]
```

Resolves zapret-style strategy strings to attack sequences.

**Parameters:**
- `strategy`: Zapret-style strategy string (e.g., "fake,disorder", "split:split_pos=10")

**Returns:**
- List of tuples `(attack_name, params)` for execution

**Supported Strategy Formats:**
- Simple: `"fake"`, `"disorder"`, `"split"`
- Combined: `"fake,disorder"` → `"fakeddisorder"`
- With parameters: `"fake:ttl=3"`, `"disorder:split_pos=sni"`
- Complex: `"fake:ttl=3,disorder:split_pos=10"`

##### `get_attack_info()`

```python
def get_attack_info(self, attack_type: str) -> Dict[str, Any]
```

Gets comprehensive information about an attack.

**Parameters:**
- `attack_type`: Attack type or alias

**Returns:**
- Dictionary with attack information (canonical_name, aliases, metadata, availability)

##### `list_available_attacks()`

```python
def list_available_attacks(self, category: Optional[str] = None) -> List[Dict[str, Any]]
```

Lists all available attacks with their information.

**Parameters:**
- `category`: Optional category filter

**Returns:**
- List of attack information dictionaries

##### `validate_attack_parameters()`

```python
def validate_attack_parameters(self, attack_type: str, params: Dict[str, Any]) -> ValidationResult
```

Validates parameters for an attack through the registry.

#### Factory Function

```python
def create_attack_dispatcher(techniques: BypassTechniques) -> AttackDispatcher
```

Convenience function for creating AttackDispatcher instances.

---

### 2. AttackRegistry

**Location**: `core/bypass/attacks/attack_registry.py`

Centralized registry for all available attacks with priority-based registration, deduplication, metadata management, and parameter validation.

#### Class: `AttackRegistry`

```python
class AttackRegistry:
    def __init__(self, lazy_loading: bool = False)
```

Initializes registry and registers all available attacks.

**Parameters:**
- `lazy_loading`: If True, external attacks are loaded on demand

#### Methods

##### `register_attack()`

```python
def register_attack(self, 
                   attack_type: str, 
                   handler: Callable, 
                   metadata: AttackMetadata,
                   priority: RegistrationPriority = RegistrationPriority.NORMAL) -> RegistrationResult
```

Registers a new attack in the registry with priority-based deduplication.

**Parameters:**
- `attack_type`: Unique attack type identifier
- `handler`: Attack handler function with signature `handler(context: AttackContext) -> List[Tuple]`
- `metadata`: Attack metadata object
- `priority`: Registration priority (CORE, HIGH, NORMAL, LOW)

**Returns:**
- RegistrationResult with success status and conflict information

##### `get_attack_handler()`

```python
def get_attack_handler(self, attack_type: str) -> Optional[Callable]
```

Returns handler for specified attack type with lazy loading support.

**Parameters:**
- `attack_type`: Attack type or alias

**Returns:**
- Handler function or None if not found

##### `get_attack_metadata()`

```python
def get_attack_metadata(self, attack_type: str) -> Optional[AttackMetadata]
```

Returns metadata for specified attack type with lazy loading support.

**Parameters:**
- `attack_type`: Attack type or alias

**Returns:**
- AttackMetadata object or None if not found

##### `validate_parameters()`

```python
def validate_parameters(self, attack_type: str, params: Dict[str, Any]) -> ValidationResult
```

Validates parameters for specified attack type with comprehensive checking.

**Parameters:**
- `attack_type`: Attack type
- `params`: Parameters dictionary to validate

**Returns:**
- ValidationResult object with validation status, errors, and warnings

##### `list_attacks()`

```python
def list_attacks(self, category: Optional[str] = None, enabled_only: bool = False) -> List[str]
```

Returns list of all registered attacks.

**Parameters:**
- `category`: Optional category filter
- `enabled_only`: Filter only enabled attacks (for compatibility)

**Returns:**
- List of attack type strings

##### `get_canonical_name()`

```python
def get_canonical_name(self, attack_name: str) -> str
```

Returns canonical name for an attack, resolving aliases.

**Parameters:**
- `attack_name`: Attack name or alias

**Returns:**
- Canonical attack name

##### `promote_implementation()`

```python
def promote_implementation(self,
                         attack_type: str,
                         new_handler: Callable,
                         new_metadata: AttackMetadata,
                         reason: str,
                         performance_data: Optional[Dict[str, Any]] = None,
                         require_confirmation: bool = True) -> RegistrationResult
```

Promotes a new implementation to replace an existing attack.

**Parameters:**
- `attack_type`: Attack type to promote
- `new_handler`: New handler function
- `new_metadata`: New metadata
- `reason`: Justification for promotion
- `performance_data`: Optional performance metrics
- `require_confirmation`: Require confirmation for CORE attacks

**Returns:**
- RegistrationResult with promotion status

##### `validate_registry_integrity()`

```python
def validate_registry_integrity(self) -> Dict[str, Any]
```

Validates registry integrity and identifies conflicts.

**Returns:**
- Dictionary with validation results, issues, warnings, and statistics

#### Global Functions

```python
def get_attack_registry(lazy_loading: Optional[bool] = None) -> AttackRegistry
```

Returns global AttackRegistry instance (singleton pattern).

```python
def configure_lazy_loading(enabled: bool) -> None
```

Configures global lazy loading setting (must be called before first registry use).

```python
def register_attack(attack_type_or_class, handler: Callable = None, metadata: AttackMetadata = None, priority: RegistrationPriority = RegistrationPriority.NORMAL)
```

Convenience function/decorator for registering attacks in global registry.

```python
def get_attack_handler(attack_type: str) -> Optional[Callable]
```

Convenience function for getting attack handlers from global registry.

```python
def validate_attack_parameters(attack_type: str, params: Dict[str, Any]) -> ValidationResult
```

Convenience function for parameter validation.

---

### 3. AttackContext

**Location**: `core/bypass/attacks/base.py`

Unified context object that contains all necessary information for attack execution, including TCP session management and packet construction details.

#### Class: `AttackContext`

```python
@dataclass
class AttackContext:
    dst_ip: str
    dst_port: int
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    domain: Optional[str] = None
    payload: bytes = b""
    raw_packet: Optional[bytes] = None
    protocol: str = "tcp"
    # TCP session fields
    tcp_seq: int = 0
    tcp_ack: int = 0
    tcp_flags: int = 24  # PSH,ACK
    tcp_window_size: int = 65535
    tcp_urgent_pointer: int = 0
    tcp_options: bytes = b""
    # Context fields
    connection_id: str = ""
    packet_id: int = 0
    session_established: bool = False
    params: Dict[str, Any] = field(default_factory=dict)
    timeout: float = 5.0
    engine_type: str = "local"
    debug: bool = False
```

**Key Attributes:**
- `dst_ip`, `dst_port`: Target destination
- `src_ip`, `src_port`: Source address (optional)
- `payload`: Packet payload data
- `tcp_seq`, `tcp_ack`: TCP sequence numbers
- `tcp_flags`: TCP flags (integer representation)
- `params`: Attack-specific parameters
- `connection_id`: Unique connection identifier

#### Methods

##### `copy()`

```python
def copy(self) -> "AttackContext"
```

Creates a shallow copy of the context for safe reuse.

##### `get_next_seq()`

```python
def get_next_seq(self, payload_len: int) -> int
```

Calculates next sequence number after sending payload.

##### `advance_seq()`

```python
def advance_seq(self, payload_len: int) -> None
```

Advances TCP sequence number after sending payload.

##### `set_tcp_flags()`

```python
def set_tcp_flags(self, flags: Union[int, str]) -> None
```

Sets TCP flags from integer (0x18) or string ("PSH,ACK") representation.

##### `get_tcp_flags_string()`

```python
def get_tcp_flags_string(self) -> str
```

Returns TCP flags as human-readable string (e.g., "PSH,ACK").

##### `create_connection_id()`

```python
def create_connection_id(self) -> str
```

Creates unique connection identifier string.

##### `validate_tcp_session()`

```python
def validate_tcp_session(self) -> bool
```

Validates that TCP session information is consistent.

##### `to_dict()`

```python
def to_dict(self) -> Dict[str, Any]
```

Converts context to dictionary for logging/debugging.

#### Factory Methods

```python
@classmethod
def from_compat(cls, **kwargs) -> "AttackContext"
```

Creates AttackContext from legacy parameter formats (target_ip → dst_ip).

---

### 4. Metadata Classes

**Location**: `core/bypass/attacks/metadata.py`

Data classes and constants for attack metadata management, registration priorities, and validation results.

#### Class: `AttackMetadata`

```python
@dataclass
class AttackMetadata:
    name: str
    description: str
    required_params: List[str]
    optional_params: Dict[str, Any]
    aliases: List[str]
    category: str
```

**Attributes:**
- `name`: Human-readable attack name
- `description`: Detailed description of attack behavior
- `required_params`: List of required parameter names
- `optional_params`: Dictionary of optional parameters with default values
- `aliases`: List of alternative names for the attack
- `category`: Attack category (from AttackCategories)

#### Class: `RegistrationPriority`

Priority levels for attack registration:

```python
class RegistrationPriority(Enum):
    CORE = 100      # From primitives.py (highest priority)
    HIGH = 75       # Verified effective implementations
    NORMAL = 50     # Standard external attacks
    LOW = 25        # Experimental attacks
```

#### Class: `AttackCategories`

Constants for attack categories:

```python
class AttackCategories:
    SPLIT = "split"          # Packet splitting attacks
    DISORDER = "disorder"    # Packet reordering attacks
    FAKE = "fake"           # Fake packet attacks
    RACE = "race"           # Race condition attacks
    OVERLAP = "overlap"     # Sequence overlap attacks
    FRAGMENT = "fragment"   # Fragmentation attacks
    TIMING = "timing"       # Timing-based attacks
    CUSTOM = "custom"       # Custom attacks
    ALL = [...]            # List of all categories
```

#### Class: `ValidationResult`

```python
@dataclass
class ValidationResult:
    is_valid: bool
    error_message: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    normalized_params: Optional[Dict[str, Any]] = None
    transformations: List[str] = field(default_factory=list)
```

**Methods:**
- `add_warning(message: str)`: Adds warning to result
- `add_transformation(old_value, new_value, reason)`: Documents parameter transformation

#### Class: `RegistrationResult`

```python
@dataclass
class RegistrationResult:
    success: bool
    action: str  # "registered", "replaced", "skipped"
    message: str
    attack_type: Optional[str] = None
    conflicts: List[str] = field(default_factory=list)
    previous_priority: Optional[RegistrationPriority] = None
    new_priority: Optional[RegistrationPriority] = None
```

#### Class: `AttackEntry`

Internal registry entry for attacks:

```python
@dataclass
class AttackEntry:
    attack_type: str
    handler: Callable
    metadata: AttackMetadata
    priority: RegistrationPriority
    source_module: str
    registration_time: datetime
    is_canonical: bool
    is_alias_of: Optional[str] = None
    promotion_history: List[Dict[str, Any]] = field(default_factory=list)
    performance_data: Dict[str, Any] = field(default_factory=dict)
```

#### Class: `SpecialParameterValues`

Special parameter values that require resolution:

```python
class SpecialParameterValues:
    CIPHER = "cipher"    # TLS cipher suite position
    SNI = "sni"         # Server Name Indication position
    MIDSLD = "midsld"   # Middle of second-level domain
    ALL = [...]         # List of all special values
```

#### Class: `FoolingMethods`

DPI evasion methods:

```python
class FoolingMethods:
    BADSUM = "badsum"       # Bad checksum
    BADSEQ = "badseq"       # Bad sequence number
    BADACK = "badack"       # Bad acknowledgment number
    DATANOACK = "datanoack" # Data without ACK flag
    HOPBYHOP = "hopbyhop"   # IPv6 Hop-by-Hop header
    MD5SIG = "md5sig"       # MD5 signature fooling
    ALL = [...]             # List of all methods
```

#### Factory Function

```python
def create_attack_metadata(name: str,
                          description: str,
                          category: str,
                          required_params: List[str] = None,
                          optional_params: Dict[str, Any] = None,
                          aliases: List[str] = None) -> AttackMetadata
```

Convenience function for creating AttackMetadata instances.

---

### 5. BypassTechniques

**Location**: `core/bypass/techniques/primitives.py`

Core attack implementation methods used by the dispatch system. Contains canonical implementations of all DPI bypass techniques with optimized parameters and shared helper functions.

#### Class: `BypassTechniques`

Static methods for implementing various DPI bypass attacks. All methods return segment tuples for orchestrated execution.

##### Core Attack Methods

###### `apply_fakeddisorder()`

```python
@staticmethod
def apply_fakeddisorder(payload: bytes,
                       split_pos: int,
                       fake_ttl: int,
                       fooling_methods: Optional[List[str]] = None,
                       **kwargs) -> List[Tuple[bytes, int, dict]]
```

Canonical fakeddisorder implementation: sends fake packet with low TTL, then real parts in reverse order.

**Key Optimization:** Fake packet contains FULL payload (critical for sites like x.com).

**Parameters:**
- `payload`: Packet payload data
- `split_pos`: Position to split the payload (int, str, or special value)
- `fake_ttl`: TTL value for fake packet (default: 3)
- `fooling_methods`: List of DPI evasion methods (default: ["badsum"])

**Returns:**
- List of segments: `[(fake_payload, 0, opts_fake), (part2, split_pos, opts_real), (part1, 0, opts_real)]`

**Special Values for split_pos:**
- `"sni"`: TLS Server Name Indication position
- `"cipher"`: TLS cipher suite position  
- `"midsld"`: Middle of second-level domain

###### `apply_seqovl()`

```python
@staticmethod
def apply_seqovl(payload: bytes,
                split_pos: int,
                overlap_size: int,
                fake_ttl: int,
                fooling_methods: Optional[List[str]] = None) -> List[Tuple[bytes, int, dict]]
```

Canonical seqovl implementation: sends fake packet with sequence overlap, then full real packet.

**Key Optimization:** Correct overlap calculation, real packet remains intact.

**Parameters:**
- `payload`: Packet payload data
- `split_pos`: Position for overlap calculation
- `overlap_size`: Size of sequence overlap
- `fake_ttl`: TTL value for fake packet (default: 3)
- `fooling_methods`: List of DPI evasion methods (default: ["badsum"])

**Returns:**
- List of segments: `[(overlap_part, calculated_offset, opts_fake), (real_full, 0, opts_real)]`

###### `apply_multidisorder()`

```python
@staticmethod
def apply_multidisorder(payload: bytes,
                       positions: List[int],
                       fooling: Optional[List[str]] = None,
                       fake_ttl: int = 3) -> List[Tuple[bytes, int, dict]]
```

Canonical multidisorder implementation: cuts payload into multiple fragments, sends small fake packet, then real fragments in reverse order.

**Simplified Parameter Handling:** Only accepts `positions: List[int]` (canonical format). ParameterNormalizer converts other formats.

**Parameters:**
- `payload`: Packet payload data
- `positions`: List of split positions (canonical format)
- `fooling`: List of DPI evasion methods (default: ["badsum"])
- `fake_ttl`: TTL value for fake packet (default: 3)

**Returns:**
- List of segments with fake packet first, then real fragments in reverse order

**Parameter Conversion Examples:**
- `split_pos: 3` → `positions: [3]` (done by ParameterNormalizer)
- `split_count: 5` → `positions: [calculated 5 positions]` (done by ParameterNormalizer)

###### `apply_disorder()`

```python
@staticmethod
def apply_disorder(payload: bytes,
                  split_pos: int,
                  ack_first: bool = False) -> List[Tuple[bytes, int, dict]]
```

Canonical simple disorder implementation without fake packet.

**Parameters:**
- `payload`: Packet payload data
- `split_pos`: Position to split the payload
- `ack_first`: Whether to send ACK flag first (default: False)

**Returns:**
- List of segments: `[(part2, split_pos, opts_first), (part1, 0, opts_real)]`

###### `apply_multisplit()`

```python
@staticmethod
def apply_multisplit(payload: bytes,
                    positions: List[int],
                    fooling: Optional[List[str]] = None) -> List[Tuple[bytes, int, dict]]
```

Canonical multi-split implementation with optional delays and badsum racing.

**Parameters:**
- `payload`: Packet payload data
- `positions`: List of split positions
- `fooling`: List of DPI evasion methods (default: ["badsum"])

**Returns:**
- List of segments split at specified positions with optional delays

###### `apply_fake_packet_race()`

```python
@staticmethod
def apply_fake_packet_race(payload: bytes,
                          ttl: int = 3,
                          fooling: List[str] = None) -> List[Tuple[bytes, int, dict]]
```

Canonical race condition implementation: fake packet + original.

**Parameters:**
- `payload`: Packet payload data
- `ttl`: TTL value for fake packet (default: 3)
- `fooling`: List of DPI evasion methods (default: ["badsum"])

**Returns:**
- List of segments: `[(payload, 0, opts_fake), (payload, 0, opts_real)]`

##### Shared Helper Functions

###### `_split_payload()`

```python
@staticmethod
def _split_payload(payload: bytes, split_pos: int, validate: bool = True) -> Tuple[bytes, bytes]
```

Shared payload splitting logic for all disorder family attacks.

###### `_create_segment_options()`

```python
@staticmethod
def _create_segment_options(is_fake: bool, ttl: int, fooling_methods: List[str], **kwargs) -> Dict[str, Any]
```

Shared segment options creation for all attacks.

###### `_normalize_positions()`

```python
@staticmethod
def _normalize_positions(positions: Union[int, str, List], payload_len: int) -> List[int]
```

Converts various position formats to List[int] with special value resolution.

##### Implementation Promotion

###### `promote_implementation()`

```python
@staticmethod
def promote_implementation(attack_name: str, 
                         new_handler: Callable,
                         reason: str,
                         performance_data: Optional[Dict[str, Any]] = None) -> bool
```

Allows promoting a more advanced implementation from an external module to become the canonical handler.

**Parameters:**
- `attack_name`: Name of the attack to promote
- `new_handler`: New handler function to use
- `reason`: Justification for promotion (e.g., "30% better success rate on x.com")
- `performance_data`: Optional performance metrics supporting the promotion

**Returns:**
- True if promotion successful, False otherwise

##### Utility Methods

###### `apply_tlsrec_split()`

```python
@staticmethod
def apply_tlsrec_split(payload: bytes, split_pos: int = 5) -> bytes
```

Splits TLS record at specified position.

###### `apply_wssize_limit()`

```python
@staticmethod
def apply_wssize_limit(payload: bytes, window_size: int = 1) -> List[Tuple[bytes, int, dict]]
```

Limits window size by splitting payload into small chunks.

###### `apply_badsum_fooling()`

```python
@staticmethod
def apply_badsum_fooling(packet_data: bytearray) -> bytearray
```

Corrupts TCP checksum for DPI evasion.

###### `apply_md5sig_fooling()`

```python
@staticmethod
def apply_md5sig_fooling(packet_data: bytearray) -> bytearray
```

Applies MD5 signature fooling to packet.

---

## Registered Attack Types

The system automatically registers the following attack types with priority-based registration:

| Attack Type | Priority | Required Params | Optional Params | Category | Description |
|-------------|----------|----------------|-----------------|----------|-------------|
| `fakeddisorder` | CORE | `split_pos` | `ttl`, `fake_ttl`, `fooling`, `fooling_methods` | `fake` | Fake packet + real parts in reverse order |
| `seqovl` | CORE | `split_pos`, `overlap_size` | `fake_ttl`, `fooling_methods` | `overlap` | Sequence overlap with fake packet |
| `multidisorder` | CORE | - | `positions`, `split_pos`, `fake_ttl`, `fooling` | `disorder` | Multiple fragments in reverse order |
| `disorder` | CORE | `split_pos` | `ack_first` | `disorder` | Simple reordering without fake packet |
| `disorder2` | CORE | `split_pos` | - | `disorder` | Disorder with ACK flag first |
| `multisplit` | CORE | - | `positions`, `split_pos`, `split_count`, `fooling` | `split` | Multiple packet splitting |
| `split` | CORE | `split_pos` | `fooling` | `split` | Simple packet splitting |
| `fake` | CORE | `ttl` | `fooling`, `fake_data` | `race` | Race condition with fake packet |

### Attack Aliases

Each attack type supports multiple aliases for compatibility:

- `fakeddisorder`: `fake_disorder`, `fakedisorder`
- `seqovl`: `seq_overlap`, `overlap`
- `multidisorder`: `multi_disorder`
- `disorder`: `simple_disorder`
- `disorder2`: `disorder_ack`
- `multisplit`: `multi_split`
- `split`: `simple_split`
- `fake`: `fake_race`, `race`

### Registration Priorities

- **CORE (100)**: Built-in attacks from primitives.py (highest priority, cannot be overridden by lower priorities)
- **HIGH (75)**: Verified effective implementations
- **NORMAL (50)**: Standard external attacks
- **LOW (25)**: Experimental attacks

### Parameter Normalization

The system automatically normalizes parameters before passing them to handlers:

**Alias Resolution:**
- `ttl` → `fake_ttl` (for fakeddisorder)
- `fooling` → `fooling_methods`
- `overlap_size` → `split_seqovl` (for zapret compatibility)

**Type Conversion:**
- String numbers: `"10"` → `10`
- Single values to lists: `3` → `[3]` (for positions)
- List extraction: `[1, 5]` → `1` (with warning for split_pos)

**Special Value Resolution:**
- `"sni"` → TLS SNI position (typically 43)
- `"cipher"` → TLS cipher suite position (typically 11)
- `"midsld"` → Middle of second-level domain (calculated from payload)

---

## Usage Examples

### Basic Attack Dispatch

```python
from core.bypass.engine.attack_dispatcher import create_attack_dispatcher
from core.bypass.techniques.primitives import BypassTechniques

# Create dispatcher
techniques = BypassTechniques()
dispatcher = create_attack_dispatcher(techniques)

# Dispatch single attack
recipe = dispatcher.dispatch_attack(
    "fakeddisorder",
    {"split_pos": 3, "ttl": 3, "fooling": ["badsum"]},
    b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    {"src_addr": "192.168.1.1", "dst_addr": "93.184.216.34", "src_port": 12345, "dst_port": 80}
)

# Recipe contains: [(fake_payload, 0, opts), (part2, 3, opts), (part1, 0, opts)]
```

### Zapret-Style Strategy Resolution

```python
# Simple strategy
recipe = dispatcher.dispatch_attack(
    "fake,disorder",  # Resolves to fakeddisorder
    {"split_pos": "sni", "ttl": 3},
    tls_clienthello_payload,
    packet_info
)

# Strategy with parameters
recipe = dispatcher.dispatch_attack(
    "fake:ttl=3,disorder:split_pos=10",
    {},
    payload,
    packet_info
)

# Manual strategy resolution
strategy_attacks = dispatcher.resolve_strategy("fake:ttl=3,split:split_pos=sni")
# Returns: [("fake", {"ttl": 3}), ("split", {"split_pos": "sni"})]
```

### Parameter Validation and Normalization

```python
from core.bypass.attacks.attack_registry import validate_attack_parameters

# Validate parameters with detailed feedback
result = validate_attack_parameters("seqovl", {
    "split_pos": 5,
    "overlap_size": 20,
    "fake_ttl": 3
})

if result.is_valid:
    print("Parameters are valid")
    if result.warnings:
        for warning in result.warnings:
            print(f"Warning: {warning}")
else:
    print(f"Validation error: {result.error_message}")

# Check parameter transformations
if result.transformations:
    for transformation in result.transformations:
        print(f"Transformation: {transformation}")
```

### AttackContext Usage

```python
from core.bypass.attacks.base import AttackContext

# Create attack context
context = AttackContext(
    dst_ip="93.184.216.34",
    dst_port=443,
    src_ip="192.168.1.1", 
    src_port=12345,
    payload=tls_clienthello_payload,
    params={"split_pos": "sni", "ttl": 3}
)

# Use context with registry handler
registry = get_attack_registry()
handler = registry.get_attack_handler("fakeddisorder")
segments = handler(context)

# TCP session management
context.set_tcp_flags("PSH,ACK")
next_seq = context.get_next_seq(len(payload))
context.advance_seq(len(payload))
```

### Custom Attack Registration

```python
from core.bypass.attacks.attack_registry import register_attack
from core.bypass.attacks.metadata import AttackMetadata, AttackCategories, RegistrationPriority

def my_custom_attack(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
    """Custom attack implementation."""
    payload = context.payload
    split_pos = context.params.get('split_pos', len(payload) // 2)
    
    # Split payload and create segments
    part1 = payload[:split_pos]
    part2 = payload[split_pos:]
    
    return [
        (part2, split_pos, {"tcp_flags": 0x18}),  # Second part first
        (part1, 0, {"tcp_flags": 0x18})           # First part second
    ]

# Register with metadata
metadata = AttackMetadata(
    name="My Custom Attack",
    description="Custom DPI bypass attack with payload reordering",
    required_params=["split_pos"],
    optional_params={"custom_param": "default_value"},
    aliases=["my_attack", "custom"],
    category=AttackCategories.CUSTOM
)

result = register_attack("custom_attack", my_custom_attack, metadata, RegistrationPriority.NORMAL)
print(f"Registration result: {result.message}")
```

### Registry Management and Inspection

```python
from core.bypass.attacks.attack_registry import get_attack_registry, configure_lazy_loading

# Configure lazy loading before first use
configure_lazy_loading(True)

registry = get_attack_registry()

# List all attacks with filtering
all_attacks = registry.list_attacks()
fake_attacks = registry.list_attacks(category="fake")
print(f"Available attacks: {all_attacks}")
print(f"Fake attacks: {fake_attacks}")

# Get comprehensive attack information
attack_info = registry.get_attack_metadata("fakeddisorder")
print(f"Attack: {attack_info.name}")
print(f"Description: {attack_info.description}")
print(f"Required params: {attack_info.required_params}")
print(f"Optional params: {attack_info.optional_params}")
print(f"Aliases: {attack_info.aliases}")

# Check registry integrity
integrity_report = registry.validate_registry_integrity()
print(f"Registry valid: {integrity_report['is_valid']}")
if integrity_report['issues']:
    print(f"Issues found: {integrity_report['issues']}")

# Get registration statistics
stats = registry.get_priority_statistics()
print(f"Total attacks: {stats['total_attacks']}")
print(f"Core attacks: {len(stats['core_attacks'])}")
print(f"External attacks: {len(stats['external_attacks'])}")
```

### Attack Dispatcher Information

```python
# Get attack information through dispatcher
attack_info = dispatcher.get_attack_info("fakeddisorder")
print(f"Canonical name: {attack_info['canonical_name']}")
print(f"Is alias: {attack_info['is_alias']}")
print(f"All names: {attack_info['all_names']}")

# List available attacks with details
available_attacks = dispatcher.list_available_attacks(category="fake")
for attack in available_attacks:
    print(f"Attack: {attack['canonical_name']}")
    print(f"  Aliases: {attack['aliases']}")
    print(f"  Available: {attack['is_available']}")
```

### Implementation Promotion

```python
from core.bypass.techniques.primitives import BypassTechniques

def improved_fakeddisorder(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
    """Improved fakeddisorder with better performance."""
    # Implementation with 30% better success rate
    # ... improved logic ...
    pass

# Promote implementation
registry = get_attack_registry()
result = registry.promote_implementation(
    "fakeddisorder",
    improved_fakeddisorder,
    metadata,  # Updated metadata
    "30% better success rate on x.com based on testing",
    performance_data={"improvement_percent": 30, "test_cases": 1000, "success_rate": 0.95}
)

if result.success:
    print(f"Promotion successful: {result.message}")
else:
    print(f"Promotion failed: {result.message}")
```

---

## Error Handling

### Exception Hierarchy

```python
# Registry-specific exceptions
class AttackRegistryError(Exception): pass
class DuplicateAttackError(AttackRegistryError): pass
class InvalidAttackError(AttackRegistryError): pass
class AttackNotFoundError(AttackRegistryError): pass
class ParameterValidationError(AttackRegistryError): pass
```

### Common Exceptions

- `ValueError`: Invalid attack type, parameters, or strategy format
- `RuntimeError`: Attack execution failure or critical system error
- `ImportError`: Missing dependencies for advanced attacks
- `AttackNotFoundError`: Requested attack not found in registry
- `ParameterValidationError`: Parameter validation failed

### Validation Error Details

The system provides comprehensive validation feedback:

```python
# Parameter validation with detailed feedback
result = validate_attack_parameters("seqovl", {"split_pos": "invalid"})
if not result.is_valid:
    print(f"Error: {result.error_message}")
    # "Invalid split_pos value: invalid. Must be int or one of ['cipher', 'sni', 'midsld']"

# Missing required parameters
result = validate_attack_parameters("fakeddisorder", {})
# result.error_message: "Missing required parameter 'split_pos' for attack 'fakeddisorder'"

# Parameter transformation warnings
result = validate_attack_parameters("multisplit", {"split_pos": [1, 5, 10]})
if result.warnings:
    for warning in result.warnings:
        print(f"Warning: {warning}")
    # "Converted list 'split_pos' [1, 5, 10] to first element: 1"
```

### Registry Error Handling

```python
# Registration conflicts
result = registry.register_attack("existing_attack", handler, metadata)
if not result.success:
    print(f"Registration failed: {result.message}")
    print(f"Conflicts: {result.conflicts}")

# Attack not found with suggestions
try:
    handler = registry.get_attack_handler("unknown_attack")
except ValueError as e:
    print(e)
    # "Unknown attack type 'unknown_attack'. Did you mean one of: fakeddisorder, disorder, multidisorder?"
```

### Dispatcher Error Handling

```python
# Strategy resolution errors
try:
    attacks = dispatcher.resolve_strategy("invalid:strategy:format")
except ValueError as e:
    print(f"Strategy error: {e}")

# Attack execution errors with context
try:
    recipe = dispatcher.dispatch_attack("fakeddisorder", {}, payload, packet_info)
except ValueError as e:
    print(f"Dispatch error: {e}")
except RuntimeError as e:
    print(f"Execution error: {e}")
```

### Logging

All components use structured logging with appropriate levels:

**INFO Level:**
- Successful attack dispatch with timing
- Registry initialization and statistics
- Strategy resolution results
- Implementation promotions

**WARNING Level:**
- Parameter normalization warnings
- Registry conflicts and skipped registrations
- Fallback to primitive attacks
- Performance regressions

**ERROR Level:**
- Attack execution failures
- Parameter validation errors
- Registry integrity issues
- Import/loading failures

**DEBUG Level:**
- Detailed parameter transformations
- Internal attack routing decisions
- TCP session state changes
- Performance timing breakdowns

**Example Log Output:**
```
INFO: 🎯 Advanced attack 'fakeddisorder' executed successfully!
INFO: ⏱️ Timing: advanced_execution=0.003s, total=0.005s
INFO: 📦 Generated 3 segments
WARNING: ⚠️ Parameter warnings for 'multisplit': 1 warnings
WARNING:   ⚠️ Converted list 'split_pos' [3, 5] to first element: 3
DEBUG: 🔧 Parameter transformations for 'fakeddisorder': 2 changes
DEBUG:   📋 Resolved special value 'sni' to position: 43
DEBUG:   📋 Converted alias 'ttl' to 'fake_ttl': 3
```

---

## Performance Considerations

### Execution Time Monitoring

The AttackDispatcher automatically measures and logs execution time with detailed breakdowns:

```
INFO: 🎯 Advanced attack 'fakeddisorder' executed successfully!
INFO: ⏱️ Timing: advanced_execution=0.003s, total=0.005s
INFO: 📦 Generated 3 segments
DEBUG: ⏱️ Parameter normalization completed in 0.0004s
DEBUG: ✅ Handler found for 'fakeddisorder' in 0.0001s
DEBUG: ✅ Registry validation completed in 0.0002s
```

### Memory Usage

- **Registry Singleton**: Attack registry initialized once and reused globally
- **Lazy Loading**: External attacks loaded on-demand to reduce startup memory
- **Context Copying**: AttackContext.copy() creates shallow copies for safe reuse
- **Segment Generation**: Attack handlers generate segments on-demand without caching
- **Parameter Normalization**: Lightweight validation with minimal memory overhead

### Performance Optimizations

**Registry Level:**
- Priority-based registration prevents unnecessary duplicate processing
- Alias resolution cached for fast lookups
- Lazy loading reduces startup time for large attack collections

**Dispatcher Level:**
- Two-tier architecture: advanced attacks first, primitives fallback
- Parameter normalization cached per attack type
- Special value resolution optimized for TLS payloads

**Attack Implementation:**
- Shared helper functions reduce code duplication
- Optimized defaults based on effectiveness data
- Minimal object creation in hot paths

### Optimization Tips

1. **Reuse Components**: Create AttackDispatcher once and reuse for multiple attacks
2. **Use Global Functions**: For simple operations, use global registry functions
3. **Early Validation**: Validate parameters before expensive operations
4. **Cache Contexts**: Reuse AttackContext.copy() for similar attacks
5. **Lazy Loading**: Enable lazy loading for applications with many external attacks
6. **Batch Operations**: Process multiple attacks in sequence to amortize setup costs

### Performance Targets

Based on current behavior analysis:

- **fakeddisorder**: ~0.0012ms average, <0.0005ms std dev (target)
- **seqovl**: ~0.0013ms average, <0.0005ms std dev (target)
- **Parameter normalization**: <0.0005ms per attack
- **Registry lookup**: <0.0001ms per attack
- **Strategy resolution**: <0.001ms for complex strategies

### Monitoring and Profiling

```python
# Enable detailed timing logs
import logging
logging.getLogger('core.bypass.engine.attack_dispatcher').setLevel(logging.DEBUG)

# Get performance statistics
registry = get_attack_registry()
stats = registry.get_priority_statistics()
print(f"Registry performance: {stats}")

# Monitor lazy loading efficiency
lazy_stats = registry.get_lazy_loading_stats()
print(f"Lazy loading stats: {lazy_stats}")
```

---

## Thread Safety

### Thread-Safe Components

- **AttackRegistry**: Thread-safe for read operations (get_attack_handler, validate_parameters, list_attacks)
- **Global Registry Functions**: Thread-safe for all operations
- **BypassTechniques**: All static methods are thread-safe
- **Parameter Validation**: Stateless validation is thread-safe
- **AttackContext**: Immutable after creation, safe for concurrent read access

### Thread-Unsafe Components

- **AttackDispatcher**: Instances should not be shared between threads (create per-thread)
- **Registry Registration**: Concurrent registration operations may cause conflicts
- **AttackContext Modification**: Mutable operations (advance_seq, set_tcp_flags) are not thread-safe

### Best Practices

```python
import threading
from core.bypass.engine.attack_dispatcher import create_attack_dispatcher
from core.bypass.techniques.primitives import BypassTechniques

# Thread-safe: Global registry access
def worker_thread():
    registry = get_attack_registry()  # Safe
    handler = registry.get_attack_handler("fakeddisorder")  # Safe
    
    # Create per-thread dispatcher
    techniques = BypassTechniques()
    dispatcher = create_attack_dispatcher(techniques)  # Per-thread instance
    
    # Use immutable context
    context = AttackContext(dst_ip="1.1.1.1", dst_port=443, payload=b"data")
    segments = handler(context)  # Safe

# Thread-unsafe: Shared dispatcher
shared_dispatcher = create_attack_dispatcher(BypassTechniques())  # DON'T SHARE

def unsafe_worker():
    # This is NOT thread-safe
    shared_dispatcher.dispatch_attack(...)  # Potential race conditions
```

### Concurrent Registration

```python
# Safe: Use locks for concurrent registration
import threading

registration_lock = threading.Lock()

def register_attack_safely(attack_type, handler, metadata):
    with registration_lock:
        return register_attack(attack_type, handler, metadata)
```

---

## Backward Compatibility

The refactored system maintains full backward compatibility while providing enhanced functionality:

### Attack Types
- **All existing attack types continue to work**: fakeddisorder, seqovl, multidisorder, etc.
- **Legacy aliases supported**: fake_disorder → fakeddisorder, seq_overlap → seqovl
- **Parameter formats preserved**: Existing parameter names and formats work unchanged
- **Return value compatibility**: All handlers return the same segment tuple format

### Parameter Handling
- **Automatic normalization**: Legacy parameter names automatically converted
- **Type flexibility**: Accepts int, str, or list formats for positions
- **Special values**: "sni", "cipher", "midsld" continue to work as before
- **Default values**: Preserved from original implementations

### API Compatibility
```python
# Old style - still works
from core.bypass.techniques.primitives import BypassTechniques
techniques = BypassTechniques()
segments = techniques.apply_fakeddisorder(payload, split_pos=3, fake_ttl=3)

# New style - enhanced functionality
from core.bypass.engine.attack_dispatcher import create_attack_dispatcher
dispatcher = create_attack_dispatcher(techniques)
segments = dispatcher.dispatch_attack("fakeddisorder", {"split_pos": 3, "ttl": 3}, payload, packet_info)
```

### Migration Support
- **Gradual migration**: Can use old and new APIs simultaneously
- **Deprecation warnings**: Old import paths show warnings but continue working
- **Configuration compatibility**: Existing config files work without changes
- **Legacy context**: Old parameter formats automatically converted to AttackContext

### Import Compatibility
```python
# Deprecated but supported imports (with warnings)
from core.bypass.attacks.registry import AttackRegistry  # → attack_registry
from core.bypass.attacks.modern_registry import ModernRegistry  # → attack_registry

# Legacy attack imports (with warnings)  
from core.bypass.attacks.tcp.fake_disorder_attack import FakeDisorderAttack  # → primitives
```

---

## Migration Guide

### From Old Dispatch System

**Replace centralized dispatch logic:**

```python
# Old way - monolithic dispatch
if task_type in ("fakeddisorder", "multidisorder", "disorder", "disorder2", "seqovl"):
    recipe = self.techniques.apply_fakeddisorder(...)
elif task_type == "multisplit":
    recipe = self.techniques.apply_multisplit(...)
# ... many more conditions

# New way - unified dispatcher
recipe = self.attack_dispatcher.dispatch_attack(task_type, params, payload, packet_info)
```

**Update parameter handling:**

```python
# Old way - manual parameter resolution
if split_pos == "sni":
    split_pos = self._find_sni_position(payload)
elif split_pos == "cipher":
    split_pos = self._find_cipher_position(payload)

# New way - automatic resolution
# Just pass "sni" or "cipher" - dispatcher handles resolution automatically
params = {"split_pos": "sni", "ttl": 3}
```

**Modernize attack registration:**

```python
# Old way - manual registration
attack_handlers = {
    "fakeddisorder": self.techniques.apply_fakeddisorder,
    "seqovl": self.techniques.apply_seqovl,
}

# New way - automatic registration with metadata
@register_attack("my_attack")
class MyAttack:
    def execute(self, context: AttackContext):
        return [(context.payload, 0, {})]
```

### Adding New Attacks

**Method 1: Class-based registration (recommended)**

```python
from core.bypass.attacks.base import AttackContext
from core.bypass.attacks.attack_registry import register_attack
from core.bypass.attacks.metadata import AttackCategories

@register_attack("my_new_attack")
class MyNewAttack:
    name = "My New Attack"
    category = AttackCategories.CUSTOM
    required_params = ["split_pos"]
    optional_params = {"ttl": 3}
    aliases = ["my_attack", "new_attack"]
    
    def execute(self, context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        # Implementation here
        payload = context.payload
        split_pos = context.params.get('split_pos', len(payload) // 2)
        
        part1 = payload[:split_pos]
        part2 = payload[split_pos:]
        
        return [
            (part1, 0, {"tcp_flags": 0x18}),
            (part2, split_pos, {"tcp_flags": 0x18})
        ]
```

**Method 2: Function-based registration**

```python
from core.bypass.attacks.attack_registry import register_attack
from core.bypass.attacks.metadata import AttackMetadata, AttackCategories, RegistrationPriority

def my_attack_handler(context: AttackContext) -> List[Tuple[bytes, int, Dict[str, Any]]]:
    # Implementation
    return [(context.payload, 0, {})]

metadata = AttackMetadata(
    name="My Attack",
    description="Custom attack implementation",
    required_params=["param1"],
    optional_params={"param2": "default"},
    aliases=["my_attack"],
    category=AttackCategories.CUSTOM
)

register_attack("my_attack", my_attack_handler, metadata, RegistrationPriority.NORMAL)
```

**Method 3: Extending primitives (for core attacks)**

```python
# Add to BypassTechniques class in primitives.py
class BypassTechniques:
    @staticmethod
    def apply_my_technique(payload: bytes, **params) -> List[Tuple[bytes, int, dict]]:
        # Core implementation
        return [(payload, 0, {})]

# Register in attack_registry.py _register_builtin_attacks()
self.register_attack(
    "my_technique",
    self._create_primitives_handler("apply_my_technique"),
    AttackMetadata(...),
    priority=RegistrationPriority.CORE
)
```

### Configuration Migration

**Update configuration files:**

```python
# Old config format
attack_config = {
    "fakeddisorder": {"split_pos": 3, "ttl": 3},
    "seqovl": {"split_pos": 5, "overlap_size": 10}
}

# New config format (same structure, enhanced validation)
attack_config = {
    "fakeddisorder": {"split_pos": "sni", "ttl": 3},  # Special values supported
    "seqovl": {"split_pos": 5, "overlap_size": 10},
    "strategy": "fake,disorder"  # Zapret-style strategies supported
}
```

### Testing Migration

**Update test cases:**

```python
# Old test style
def test_fakeddisorder():
    techniques = BypassTechniques()
    result = techniques.apply_fakeddisorder(payload, 3, 3, ["badsum"])
    assert len(result) == 3

# New test style
def test_fakeddisorder_dispatcher():
    dispatcher = create_attack_dispatcher(BypassTechniques())
    result = dispatcher.dispatch_attack(
        "fakeddisorder", 
        {"split_pos": 3, "ttl": 3}, 
        payload, 
        packet_info
    )
    assert len(result) == 3
    
def test_fakeddisorder_context():
    context = AttackContext(
        dst_ip="1.1.1.1", 
        dst_port=443, 
        payload=payload,
        params={"split_pos": 3, "ttl": 3}
    )
    registry = get_attack_registry()
    handler = registry.get_attack_handler("fakeddisorder")
    result = handler(context)
    assert len(result) == 3
```

---

## Testing

### Unit Tests

**Registry Testing:**
- `tests/test_attack_registry.py`: Registry functionality, priority system, deduplication
- `tests/test_attack_deduplication.py`: Duplicate registration scenarios and conflict resolution
- `tests/test_attack_primitives.py`: Canonical implementations and shared helpers

**Dispatcher Testing:**
- `tests/test_attack_dispatcher.py`: Dispatch logic, parameter normalization, strategy resolution
- `tests/test_parameter_normalizer.py`: Parameter validation and transformation

**Integration Testing:**
- `tests/test_attack_integration.py`: Full attack execution flow
- `tests/test_attack_functionality_validation.py`: End-to-end attack validation
- `tests/test_merged_fakeddisorder_features.py`: Unified implementation testing

### Test Examples

**Registry Testing:**
```python
def test_priority_based_registration():
    registry = AttackRegistry()
    
    # Register NORMAL priority attack
    result1 = registry.register_attack("test", handler1, metadata1, RegistrationPriority.NORMAL)
    assert result1.success
    
    # Try to register CORE priority attack (should replace)
    result2 = registry.register_attack("test", handler2, metadata2, RegistrationPriority.CORE)
    assert result2.success
    assert result2.action == "replaced"
    
    # Verify CORE handler is active
    assert registry.get_attack_handler("test") == handler2

def test_parameter_validation():
    registry = AttackRegistry()
    
    # Valid parameters
    result = registry.validate_parameters("fakeddisorder", {"split_pos": 3, "ttl": 3})
    assert result.is_valid
    
    # Invalid parameters
    result = registry.validate_parameters("fakeddisorder", {"split_pos": "invalid"})
    assert not result.is_valid
    assert "Invalid split_pos value" in result.error_message
```

**Dispatcher Testing:**
```python
def test_strategy_resolution():
    dispatcher = create_attack_dispatcher(BypassTechniques())
    
    # Simple strategy
    attacks = dispatcher.resolve_strategy("fake,disorder")
    assert len(attacks) == 1
    assert attacks[0][0] == "fakeddisorder"
    
    # Strategy with parameters
    attacks = dispatcher.resolve_strategy("fake:ttl=3,disorder:split_pos=10")
    assert attacks[0][1]["ttl"] == 3
    assert attacks[0][1]["split_pos"] == 10

def test_special_parameter_resolution():
    dispatcher = create_attack_dispatcher(BypassTechniques())
    
    # TLS ClientHello payload with SNI
    tls_payload = create_tls_clienthello_with_sni("example.com")
    
    result = dispatcher.dispatch_attack(
        "fakeddisorder",
        {"split_pos": "sni", "ttl": 3},
        tls_payload,
        {"src_addr": "1.1.1.1", "dst_addr": "2.2.2.2"}
    )
    
    # Verify SNI position was resolved correctly
    assert len(result) == 3  # fake + part2 + part1
```

**Performance Testing:**
```python
def test_attack_performance():
    dispatcher = create_attack_dispatcher(BypassTechniques())
    payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    
    # Measure execution time
    start_time = time.time()
    for _ in range(1000):
        result = dispatcher.dispatch_attack(
            "fakeddisorder",
            {"split_pos": 3, "ttl": 3},
            payload,
            {"src_addr": "1.1.1.1", "dst_addr": "2.2.2.2"}
        )
    execution_time = time.time() - start_time
    
    # Performance target: < 1ms average per attack
    avg_time_ms = (execution_time / 1000) * 1000
    assert avg_time_ms < 1.0, f"Average execution time {avg_time_ms:.3f}ms exceeds 1ms target"
```

### Test Coverage

The system maintains comprehensive test coverage:

- **Registry**: >95% coverage including edge cases, conflicts, lazy loading
- **Dispatcher**: >90% coverage including strategy resolution, parameter normalization
- **Primitives**: >85% coverage of all canonical implementations
- **Integration**: End-to-end scenarios covering real-world usage patterns
- **Performance**: Regression testing against baseline metrics

### Running Tests

```bash
# Run all tests
pytest tests/

# Run specific test categories
pytest tests/test_attack_registry.py -v
pytest tests/test_attack_dispatcher.py -v
pytest tests/test_attack_integration.py -v

# Run with coverage
pytest tests/ --cov=core.bypass --cov-report=html

# Run performance tests
pytest tests/test_performance.py -v --benchmark-only
```