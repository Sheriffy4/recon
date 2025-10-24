# Attack Standardization Guide

This guide provides comprehensive standards for implementing DPI bypass attacks in the unified attack system. It covers metadata requirements, parameter normalization standards, and implementation best practices.

## Table of Contents

1. [Metadata Requirements](#metadata-requirements)
2. [Parameter Normalization Standards](#parameter-normalization-standards)
3. [Attack Implementation Checklist](#attack-implementation-checklist)
4. [Quality Assurance Guidelines](#quality-assurance-guidelines)

---

## Metadata Requirements

All attacks must provide complete metadata through the `AttackMetadata` class. This metadata is used for registration, validation, documentation generation, and system integration.

### Required Metadata Fields

#### 1. `name` (str) - REQUIRED
- **Purpose**: Human-readable attack name
- **Format**: Descriptive name in plain English
- **Example**: `"TCP Window Manipulation"`
- **Validation**: Cannot be empty

#### 2. `description` (str) - REQUIRED  
- **Purpose**: Detailed explanation of how the attack works
- **Format**: 1-3 sentences describing the technique and its purpose
- **Example**: `"Manipulates TCP window size in packet headers to confuse DPI systems tracking flow control"`
- **Validation**: Cannot be empty

#### 3. `required_params` (List[str]) - REQUIRED
- **Purpose**: List of mandatory parameters that must be provided
- **Format**: List of parameter names as strings
- **Example**: `["split_pos", "target_domain"]`
- **Validation**: Must be a list (can be empty)

#### 4. `optional_params` (Dict[str, Any]) - REQUIRED
- **Purpose**: Dictionary of optional parameters with their default values
- **Format**: Parameter name → default value mapping
- **Example**: `{"ttl": 3, "fooling_methods": ["badsum"], "window_size": 2048}`
- **Validation**: Must be a dictionary (can be empty)

#### 5. `aliases` (List[str]) - REQUIRED
- **Purpose**: Alternative names for the attack (for backward compatibility)
- **Format**: List of alternative names as strings
- **Example**: `["window_manipulation", "tcp_window", "win_manip"]`
- **Validation**: Must be a list (can be empty)

#### 6. `category` (str) - REQUIRED
- **Purpose**: Attack classification for organization and filtering
- **Format**: Must be one of the predefined categories from `AttackCategories`
- **Example**: `AttackCategories.TCP`
- **Validation**: Must be a valid category from `AttackCategories.ALL`

### Attack Categories

Use **primary categories** for new attacks (recommended):

| Category | Description | Use Cases |
|----------|-------------|-----------|
| `AttackCategories.TCP` | TCP-level attacks | Splitting, reordering, window manipulation, sequence manipulation |
| `AttackCategories.IP` | IP-level attacks | Fragmentation, TTL manipulation, IP options |
| `AttackCategories.TLS` | TLS-specific attacks | SNI manipulation, record fragmentation, extension manipulation |
| `AttackCategories.HTTP` | HTTP-level attacks | Header manipulation, chunking, method changes |
| `AttackCategories.PAYLOAD` | Payload-level attacks | Encryption, obfuscation, steganography, padding |
| `AttackCategories.TUNNELING` | Protocol tunneling | DNS tunneling, HTTP tunneling, WebSocket tunnels |
| `AttackCategories.COMBO` | Combination attacks | Multiple techniques combined |
| `AttackCategories.TIMING` | Timing-based attacks | Delays, burst patterns, jitter injection |
| `AttackCategories.CUSTOM` | Custom/specialized | Unique or experimental techniques |

**Legacy categories** (deprecated but supported):
- `SPLIT`, `DISORDER`, `FAKE`, `RACE`, `OVERLAP`, `FRAGMENT`, `DNS`

### Metadata Validation Rules

1. **Non-empty strings**: `name` and `description` cannot be empty
2. **Correct types**: All fields must match their expected types
3. **Valid category**: Category must exist in `AttackCategories.ALL`
4. **Parameter consistency**: Parameters referenced in code must be declared in metadata
5. **Alias uniqueness**: Aliases should not conflict with existing attack names

### Example Complete Metadata

```python
metadata = AttackMetadata(
    name="TCP Window Manipulation",
    description="Manipulates TCP window size in packet headers to confuse DPI systems tracking flow control",
    required_params=[],
    optional_params={
        "window_size": 2048,
        "split_pos": None,
        "min_window": 256
    },
    aliases=["window_manipulation", "tcp_window", "win_manip"],
    category=AttackCategories.TCP
)
```

---

## Parameter Normalization Standards

The parameter normalization system ensures consistent parameter handling across all attacks. All parameters are normalized by the `ParameterNormalizer` before being passed to attack handlers. This provides a unified interface while maintaining backward compatibility.

### Core Principles

1. **Canonical Format**: All attacks receive parameters in a standardized format
2. **Backward Compatibility**: Legacy parameter names are supported through aliases
3. **Type Safety**: All parameters are validated and converted to correct types
4. **Transparency**: All transformations are logged and reported
5. **Fail-Safe**: Invalid parameters generate clear error messages

### Parameter Naming Conventions

#### Standard Parameter Names (Canonical Format)

Use these standardized parameter names for new attacks:

| Parameter | Type | Description | Example Values | Validation Rules |
|-----------|------|-------------|----------------|------------------|
| `positions` | `List[int]` | Split positions (canonical format) | `[3, 10, 20]` | All values 1 ≤ pos < payload_len |
| `split_pos` | `int` | Single split position (legacy, normalized to positions) | `3` | 1 ≤ pos < payload_len |
| `ttl` | `int` | Time To Live for packets | `64` | 1 ≤ ttl ≤ 255 |
| `fake_ttl` | `int` | TTL specifically for fake packets | `3` | 1 ≤ ttl ≤ 255 |
| `fooling_methods` | `List[str]` | Methods to fool DPI | `["badsum", "badseq"]` | All values in FoolingMethods.ALL |
| `overlap_size` | `int` | Size of sequence overlap | `10` | 0 ≤ size ≤ payload_len |
| `window_size` | `int` | TCP window size | `2048` | 1 ≤ size ≤ 65535 |
| `chunk_size` | `int` | Size of payload chunks | `100` | 1 ≤ size ≤ payload_len |
| `delay_ms` | `float` | Delay in milliseconds | `10.5` | delay_ms ≥ 0 |
| `ip_id` | `int` | IP identification field | `12345` | 0 ≤ id ≤ 65535 |
| `urgent_pointer` | `int` | TCP urgent pointer | `10` | 0 ≤ pointer ≤ 65535 |
| `padding_size` | `int` | Size of padding to add | `100` | 0 ≤ size ≤ 1024 |
| `noise_size` | `int` | Size of random noise | `50` | 0 ≤ size ≤ 1024 |

#### Parameter Aliases (Backward Compatibility)

The system supports parameter aliases to maintain compatibility with existing code:

| Alias | Canonical Name | Context | Transformation |
|-------|----------------|---------|----------------|
| `ttl` | `fake_ttl` | Fakeddisorder attacks | Direct rename |
| `fooling` | `fooling_methods` | All attacks using fooling | String → List[str] |
| `split_seqovl` | `overlap_size` | Zapret compatibility | Direct rename |
| `split_count` | `positions` | Multisplit attacks | Generate N positions |
| `ack_first` | `reverse_order` | Disorder attacks | Direct rename |
| `bad_checksum` | `fooling_methods` | Legacy attacks | Add "badsum" to list |

#### Parameter Categories by Attack Type

Different attack types use different parameter sets:

**TCP Splitting Attacks** (`split`, `multisplit`):
- `positions: List[int]` - Where to split the payload
- `fooling_methods: List[str]` - How to fool DPI on fake packets
- `fake_ttl: int` - TTL for fake packets

**TCP Disorder Attacks** (`disorder`, `multidisorder`, `fakeddisorder`):
- `positions: List[int]` - Split positions
- `fake_ttl: int` - TTL for fake packets
- `fooling_methods: List[str]` - Fooling methods
- `reverse_order: bool` - Send segments in reverse order

**TCP Overlap Attacks** (`seqovl`):
- `split_pos: int` - Where to split
- `overlap_size: int` - How much to overlap
- `fake_ttl: int` - TTL for fake packets

**IP-Level Attacks**:
- `ttl: int` - IP Time To Live
- `ip_id: int` - IP identification field
- `fragment_size: int` - Fragment size for fragmentation

**TLS Attacks**:
- `sni_value: str` - Server Name Indication value
- `alpn_protocols: List[str]` - ALPN protocol list
- `cipher_suites: List[int]` - Cipher suite list

**Payload Attacks**:
- `padding_size: int` - Amount of padding to add
- `noise_size: int` - Amount of random noise
- `encryption_key: bytes` - Key for payload encryption

### Type Conversion Rules

The parameter normalizer applies these conversion rules automatically:

#### 1. String to Integer
```python
# Input: "10"
# Output: 10
# Validation: Must be valid integer, within allowed range
# Error: ValueError if not convertible or out of range
```

#### 2. String to Float
```python
# Input: "10.5"
# Output: 10.5
# Validation: Must be valid float, non-negative for delays
# Error: ValueError if not convertible or negative (for delays)
```

#### 3. Single Value to List
```python
# Input: 3
# Output: [3]
# Use case: split_pos → positions
# Note: Always generates a list for consistency
```

#### 4. String to List
```python
# Input: "badsum"
# Output: ["badsum"]
# Use case: fooling → fooling_methods
# Note: Handles comma-separated strings: "badsum,badseq" → ["badsum", "badseq"]
```

#### 5. List Element Extraction (with warning)
```python
# Input: [3, 5, 10]
# Output: 3 (first element)
# Warning: "Extracted first element from list parameter 'split_pos': [3, 5, 10] → 3"
# Use case: Legacy code passing lists to single-value parameters
```

#### 6. Boolean Conversion
```python
# Input: "true", "1", 1, True
# Output: True
# Input: "false", "0", 0, False, None, ""
# Output: False
# Use case: String flags from configuration files
```

#### 7. Bytes Conversion
```python
# Input: "hello" (string)
# Output: b"hello" (bytes)
# Input: [72, 101, 108, 108, 111] (list of ints)
# Output: b"hello" (bytes)
# Use case: Payload data from various sources
```

### Special Value Resolution

Some parameters accept special string values that are resolved to numeric positions based on payload analysis:

| Special Value | Resolution | Context | Requirements |
|---------------|------------|---------|--------------|
| `"sni"` | `43` | TLS SNI extension position | TLS ClientHello payload |
| `"cipher"` | `11` | TLS cipher suites position | TLS ClientHello payload |
| `"midsld"` | `payload_len // 2` | Middle of payload | Any payload |
| `"random"` | `random.randint(1, payload_len-1)` | Random position | Any payload |
| `"quarter"` | `payload_len // 4` | First quarter of payload | Any payload |
| `"three_quarter"` | `3 * payload_len // 4` | Three quarters through payload | Any payload |

#### Special Value Resolution Process

1. **Check if value is special**: Compare against `SpecialParameterValues.ALL`
2. **Validate context**: Ensure payload is suitable for the special value
3. **Calculate position**: Apply the resolution formula
4. **Validate result**: Ensure calculated position is within bounds
5. **Log transformation**: Record the resolution for debugging

#### Example Special Value Usage

```python
# Configuration
params = {
    "split_pos": "sni",  # Will resolve to 43 for TLS
    "positions": ["quarter", "midsld", "three_quarter"]  # Multiple special values
}

# After normalization (assuming 200-byte payload)
normalized = {
    "positions": [50, 100, 150]  # quarter=50, midsld=100, three_quarter=150
}

# Transformation log
transformations = [
    "Resolved special value 'quarter' to position: 50",
    "Resolved special value 'midsld' to position: 100", 
    "Resolved special value 'three_quarter' to position: 150"
]
```

### Parameter Validation Rules

The normalizer applies comprehensive validation to ensure parameter safety and correctness:

#### 1. Range Validation

| Parameter Type | Valid Range | Error Condition |
|----------------|-------------|-----------------|
| **TTL values** | 1-255 | Outside IP TTL range |
| **Split positions** | 1 to payload_len-1 | Cannot split at start/end |
| **Overlap size** | 0 to payload_len | Cannot overlap more than payload |
| **Window size** | 1-65535 | Outside TCP window range |
| **Port numbers** | 1-65535 | Outside valid port range |
| **IP ID** | 0-65535 | Outside 16-bit range |
| **Delays** | ≥ 0 | Negative delays not allowed |
| **Sizes** | ≥ 0 | Negative sizes not allowed |

#### 2. List Validation

| List Type | Validation Rules | Error Conditions |
|-----------|------------------|------------------|
| **Positions** | All values within payload bounds, no duplicates | Position ≥ payload_len or ≤ 0 |
| **Fooling methods** | All values from `FoolingMethods.ALL` | Unknown fooling method |
| **ALPN protocols** | Valid protocol strings | Empty or invalid protocol |
| **Cipher suites** | Valid cipher suite IDs | Invalid cipher suite ID |

#### 3. Type Validation

| Expected Type | Accepted Inputs | Conversion | Error Conditions |
|---------------|-----------------|------------|------------------|
| **int** | int, str, float | int(value) | Non-numeric string |
| **float** | int, str, float | float(value) | Non-numeric string |
| **bool** | bool, int, str | bool(value) | N/A (always succeeds) |
| **List[int]** | List, int, str | [int(x) for x in value] | Non-numeric elements |
| **List[str]** | List, str | [str(x) for x in value] | N/A (always succeeds) |
| **bytes** | bytes, str, List[int] | bytes(value) | Invalid byte values |

#### 4. Logical Validation

Beyond type and range checks, the normalizer performs logical validation:

```python
# Example logical validations
def validate_split_positions(positions: List[int], payload_len: int) -> List[str]:
    """Validate split positions make logical sense."""
    errors = []
    
    # Check for duplicates
    if len(positions) != len(set(positions)):
        errors.append("Duplicate positions not allowed")
    
    # Check ordering (optional warning)
    if positions != sorted(positions):
        warnings.append("Positions not in ascending order")
    
    # Check minimum distance between positions
    for i in range(len(positions) - 1):
        if positions[i+1] - positions[i] < 2:
            warnings.append(f"Positions {positions[i]} and {positions[i+1]} too close")
    
    return errors

def validate_overlap_parameters(split_pos: int, overlap_size: int, payload_len: int) -> List[str]:
    """Validate overlap parameters make sense together."""
    errors = []
    
    if split_pos + overlap_size > payload_len:
        errors.append("Overlap extends beyond payload end")
    
    if overlap_size > split_pos:
        errors.append("Overlap larger than first segment")
    
    return errors
```

### Normalization Process

The `ParameterNormalizer` processes parameters through a multi-stage pipeline:

#### Stage 1: Preprocessing
1. **Copy parameters**: Create working copy to avoid modifying original
2. **Log input**: Record original parameters for debugging
3. **Initialize tracking**: Set up warning and transformation lists

#### Stage 2: Alias Resolution
1. **Resolve aliases** (`ttl` → `fake_ttl`, `fooling` → `fooling_methods`)
2. **Log transformations**: Record each alias resolution
3. **Remove old keys**: Clean up aliased parameter names

#### Stage 3: Type Conversion
1. **Convert types** (string "10" → int 10, "badsum" → ["badsum"])
2. **Handle lists** (extract first element with warning if needed)
3. **Validate conversions**: Ensure all conversions succeeded
4. **Log conversions**: Record type changes

#### Stage 4: Special Value Resolution
1. **Identify special values** ("sni", "cipher", "midsld", etc.)
2. **Resolve to positions** (based on payload analysis)
3. **Validate resolved positions** (ensure within bounds)
4. **Log resolutions**: Record special value transformations

#### Stage 5: Validation
1. **Range validation** (check all numeric ranges)
2. **List validation** (check list contents and constraints)
3. **Logical validation** (check parameter combinations make sense)
4. **Collect errors**: Gather all validation failures

#### Stage 6: Canonical Format Conversion
1. **Convert to canonical format** (split_pos → positions)
2. **Apply attack-specific rules** (different rules per attack type)
3. **Final validation** (ensure canonical format is correct)
4. **Generate result**: Create ValidationResult with normalized parameters

#### Error Handling Strategy

```python
class ValidationResult:
    """Result of parameter normalization with detailed feedback."""
    
    def __init__(self):
        self.is_valid = True
        self.normalized_params = {}
        self.warnings = []
        self.transformations = []
        self.error_message = None
    
    def add_warning(self, message: str):
        """Add a non-critical warning."""
        self.warnings.append(message)
    
    def add_transformation(self, old_value: Any, new_value: Any, reason: str):
        """Record a parameter transformation."""
        transformation = f"{reason}: {old_value} → {new_value}"
        self.transformations.append(transformation)
        self.add_warning(transformation)
    
    def add_error(self, message: str):
        """Add a critical error that prevents execution."""
        self.is_valid = False
        self.error_message = message
```

### Example Normalization

```python
# Input parameters
params = {
    "split_pos": "sni",
    "ttl": [3, 5],  # Should be single value
    "fooling": "badsum"
}

# After normalization
normalized = {
    "positions": [43],  # sni resolved to 43
    "fake_ttl": 3,      # ttl alias resolved, first element extracted
    "fooling_methods": ["badsum"]  # fooling alias resolved
}

# Warnings generated
warnings = [
    "Resolved special value 'sni' to position: 43",
    "Extracted first element from list parameter 'ttl': [3, 5] → 3",
    "Converted alias 'ttl' to 'fake_ttl': 3",
    "Converted alias 'fooling' to 'fooling_methods': ['badsum']"
]
```

---

## Attack Implementation Checklist

This checklist ensures that new attacks meet all requirements and integrate properly with the system.

### Phase 1: Planning and Design

#### 1.1 Attack Concept
- [ ] **Define attack purpose**: What DPI technique does this bypass?
- [ ] **Research effectiveness**: Is this technique proven to work?
- [ ] **Check for duplicates**: Does a similar attack already exist?
- [ ] **Determine category**: Which `AttackCategories` category fits best?

#### 1.2 Parameter Design
- [ ] **Identify required parameters**: What parameters are absolutely necessary?
- [ ] **Define optional parameters**: What parameters have sensible defaults?
- [ ] **Choose parameter names**: Use standardized names from the conventions
- [ ] **Set default values**: Choose effective defaults based on research

### Phase 2: Implementation

#### 2.1 Class Structure
- [ ] **Inherit from BaseAttack**: Use `BaseAttack` as the base class
- [ ] **Implement required properties**: `name`, `category`, `required_params`, `optional_params`
- [ ] **Add docstring**: Provide clear class-level documentation
- [ ] **Handle abstract methods**: Implement all required abstract methods

#### 2.2 Attack Logic
- [ ] **Implement execute() method**: Main attack execution logic
- [ ] **Handle AttackContext**: Process the context parameter correctly
- [ ] **Return AttackResult**: Use proper result structure
- [ ] **Error handling**: Catch and handle exceptions gracefully
- [ ] **Logging**: Add appropriate log messages

#### 2.3 Registration
- [ ] **Use @register_attack decorator**: Apply with complete metadata
- [ ] **Set appropriate priority**: Use `RegistrationPriority.NORMAL` for new attacks
- [ ] **Define aliases**: Include common alternative names
- [ ] **Add description**: Provide clear, concise description

### Phase 3: Testing

#### 3.1 Unit Tests
- [ ] **Test parameter validation**: Verify required/optional parameter handling
- [ ] **Test execution**: Verify attack executes without errors
- [ ] **Test edge cases**: Handle empty payloads, invalid parameters
- [ ] **Test error conditions**: Verify proper error handling

#### 3.2 Integration Tests
- [ ] **Test registration**: Verify attack registers correctly
- [ ] **Test dispatcher integration**: Verify works with AttackDispatcher
- [ ] **Test parameter normalization**: Verify parameters are normalized correctly
- [ ] **Test alias resolution**: Verify aliases work correctly

#### 3.3 Performance Tests
- [ ] **Measure execution time**: Ensure reasonable performance
- [ ] **Test with various payload sizes**: Verify scalability
- [ ] **Memory usage**: Check for memory leaks or excessive usage

### Phase 4: Documentation

#### 4.1 Code Documentation
- [ ] **Class docstring**: Explain what the attack does and how
- [ ] **Method docstrings**: Document all public methods
- [ ] **Parameter documentation**: Explain all parameters in docstrings
- [ ] **Example usage**: Provide usage examples in docstrings

#### 4.2 External Documentation
- [ ] **Update attack list**: Add to attack documentation
- [ ] **Add to examples**: Create usage examples if needed
- [ ] **Update migration guide**: If replacing existing attack

### Phase 5: Quality Assurance

#### 5.1 Code Quality
- [ ] **Follow naming conventions**: Use consistent naming
- [ ] **Code formatting**: Run code formatter (black/autopep8)
- [ ] **Linting**: Fix all linting issues
- [ ] **Type hints**: Add type hints where appropriate

#### 5.2 Security Review
- [ ] **Input validation**: Validate all input parameters
- [ ] **Resource limits**: Prevent resource exhaustion
- [ ] **Error information**: Don't leak sensitive information in errors

#### 5.3 Compatibility
- [ ] **Backward compatibility**: Don't break existing interfaces
- [ ] **Cross-platform**: Test on different operating systems if relevant
- [ ] **Python version**: Ensure compatibility with supported Python versions

### Example Implementation Template

```python
"""
Example attack implementation following standardization guidelines.
"""

import logging
from typing import List

from .attack_registry import register_attack, RegistrationPriority
from .metadata import AttackCategories
from .base import AttackContext, AttackResult, AttackStatus, BaseAttack

LOG = logging.getLogger(__name__)


@register_attack(
    name="example_attack",
    category=AttackCategories.TCP,
    priority=RegistrationPriority.NORMAL,
    required_params=["target_param"],
    optional_params={"optional_param": 10, "flag": False},
    aliases=["example", "ex_attack"],
    description="Example attack demonstrating standardization guidelines"
)
class ExampleAttack(BaseAttack):
    """
    Example attack that demonstrates proper implementation.
    
    This attack shows how to:
    - Inherit from BaseAttack
    - Implement required properties
    - Handle parameters correctly
    - Return proper results
    """

    @property
    def name(self) -> str:
        return "example_attack"

    @property
    def category(self) -> str:
        return AttackCategories.TCP

    @property
    def required_params(self) -> List[str]:
        return ["target_param"]

    @property
    def optional_params(self) -> dict:
        return {"optional_param": 10, "flag": False}

    def execute(self, context: AttackContext) -> AttackResult:
        """
        Execute the example attack.
        
        Args:
            context: Attack execution context with payload and parameters
            
        Returns:
            AttackResult with execution status and results
        """
        import time
        
        start_time = time.time()
        
        try:
            # Extract parameters (already normalized by dispatcher)
            target_param = context.params["target_param"]
            optional_param = context.params.get("optional_param", 10)
            flag = context.params.get("flag", False)
            
            # Validate parameters
            if target_param <= 0:
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message="target_param must be positive",
                    technique_used=self.name
                )
            
            # Implement attack logic
            segments = self._create_segments(context, target_param, optional_param, flag)
            
            # Return success result
            result = AttackResult(
                status=AttackStatus.SUCCESS,
                technique_used=self.name,
                packets_sent=len(segments),
                bytes_sent=sum(len(s[0]) for s in segments),
                processing_time_ms=(time.time() - start_time) * 1000,
            )
            result.segments = segments
            
            return result
            
        except Exception as e:
            LOG.error(f"Example attack failed: {e}")
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                technique_used=self.name,
            )
    
    def _create_segments(self, context: AttackContext, target_param: int, 
                        optional_param: int, flag: bool) -> List[tuple]:
        """
        Create attack segments based on parameters.
        
        Args:
            context: Attack context
            target_param: Required parameter
            optional_param: Optional parameter
            flag: Boolean flag
            
        Returns:
            List of (payload, offset, options) tuples
        """
        # Example implementation
        if flag:
            # Split payload at target_param position
            part1 = context.payload[:target_param]
            part2 = context.payload[target_param:]
            
            return [
                (part1, 0, {"flags": 0x10}),
                (part2, len(part1), {"flags": 0x18})
            ]
        else:
            # Send as single segment
            return [(context.payload, 0, {"flags": 0x18})]
```

This template demonstrates all the key requirements and best practices for implementing standardized attacks.

---

## Quality Assurance Guidelines

This section provides comprehensive quality assurance guidelines to ensure all attacks meet high standards for reliability, performance, and maintainability.

### Code Quality Standards

#### 1. Code Style and Formatting

**Required Standards:**
- [ ] **PEP 8 compliance**: Follow Python style guidelines
- [ ] **Consistent naming**: Use snake_case for functions/variables, PascalCase for classes
- [ ] **Line length**: Maximum 88 characters (Black formatter standard)
- [ ] **Import organization**: Standard library, third-party, local imports (separated by blank lines)
- [ ] **Docstring format**: Use Google-style docstrings consistently

**Automated Tools:**
```bash
# Format code
black your_attack_file.py

# Check style
flake8 your_attack_file.py

# Sort imports
isort your_attack_file.py

# Type checking
mypy your_attack_file.py
```

#### 2. Documentation Requirements

**Class Documentation:**
```python
class YourAttack(BaseAttack):
    """
    Brief one-line description of what this attack does.
    
    Longer description explaining:
    - How the attack works
    - What DPI techniques it bypasses
    - When to use this attack
    - Any limitations or considerations
    
    Examples:
        Basic usage:
        >>> attack = YourAttack()
        >>> result = attack.execute(context)
        
        With custom parameters:
        >>> context.params = {"param1": value1, "param2": value2}
        >>> result = attack.execute(context)
    
    Attributes:
        name: Canonical attack name
        category: Attack category
        required_params: List of required parameters
        optional_params: Dict of optional parameters with defaults
    """
```

**Method Documentation:**
```python
def execute(self, context: AttackContext) -> AttackResult:
    """
    Execute the attack with given context.
    
    Args:
        context: Attack execution context containing:
            - payload: bytes to be processed
            - params: attack parameters (already normalized)
            - dst_ip, dst_port: target information
            - other context fields as needed
    
    Returns:
        AttackResult containing:
            - status: SUCCESS, FAILURE, ERROR, etc.
            - technique_used: name of technique used
            - packets_sent: number of packets generated
            - bytes_sent: total bytes in all packets
            - processing_time_ms: execution time
            - segments: list of (payload, offset, options) tuples
    
    Raises:
        ValueError: If required parameters are missing or invalid
        RuntimeError: If attack execution fails due to system issues
    
    Examples:
        >>> context = AttackContext(payload=b"test", params={"split_pos": 2})
        >>> result = attack.execute(context)
        >>> assert result.status == AttackStatus.SUCCESS
    """
```

#### 3. Type Hints and Validation

**Required Type Hints:**
```python
from typing import List, Dict, Any, Optional, Union, Tuple

class YourAttack(BaseAttack):
    def execute(self, context: AttackContext) -> AttackResult:
        """Method with proper type hints."""
        pass
    
    def _helper_method(self, data: bytes, positions: List[int]) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Helper method with complete type annotations."""
        pass
```

**Parameter Validation:**
```python
def execute(self, context: AttackContext) -> AttackResult:
    # Validate required parameters exist
    required = self.required_params
    missing = [p for p in required if p not in context.params]
    if missing:
        return AttackResult(
            status=AttackStatus.INVALID_PARAMS,
            error_message=f"Missing required parameters: {missing}",
            technique_used=self.name
        )
    
    # Validate parameter types and ranges
    try:
        param_value = int(context.params["numeric_param"])
        if not (1 <= param_value <= 100):
            raise ValueError(f"Parameter must be 1-100, got {param_value}")
    except (ValueError, TypeError) as e:
        return AttackResult(
            status=AttackStatus.INVALID_PARAMS,
            error_message=f"Invalid parameter: {e}",
            technique_used=self.name
        )
```

### Testing Standards

#### 1. Unit Test Requirements

**Test Coverage:**
- [ ] **Parameter validation**: Test all required/optional parameters
- [ ] **Edge cases**: Empty payloads, boundary values, invalid inputs
- [ ] **Error handling**: Test all error conditions and exceptions
- [ ] **Success cases**: Test normal execution with various inputs
- [ ] **Performance**: Basic performance regression tests

**Test Structure:**
```python
import pytest
from unittest.mock import Mock, patch

class TestYourAttack:
    """Test suite for YourAttack class."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.attack = YourAttack()
        self.context = AttackContext(
            dst_ip="192.168.1.1",
            dst_port=443,
            payload=b"test payload data"
        )
    
    def test_execute_success(self):
        """Test successful attack execution."""
        self.context.params = {"required_param": "value"}
        result = self.attack.execute(self.context)
        
        assert result.status == AttackStatus.SUCCESS
        assert result.technique_used == self.attack.name
        assert result.packets_sent > 0
        assert len(result.segments) > 0
    
    def test_execute_missing_required_param(self):
        """Test execution with missing required parameter."""
        # Don't set required parameters
        result = self.attack.execute(self.context)
        
        assert result.status == AttackStatus.INVALID_PARAMS
        assert "Missing required parameters" in result.error_message
    
    def test_execute_invalid_param_type(self):
        """Test execution with invalid parameter type."""
        self.context.params = {"numeric_param": "not_a_number"}
        result = self.attack.execute(self.context)
        
        assert result.status == AttackStatus.INVALID_PARAMS
        assert "Invalid parameter" in result.error_message
    
    def test_execute_empty_payload(self):
        """Test execution with empty payload."""
        self.context.payload = b""
        self.context.params = {"required_param": "value"}
        result = self.attack.execute(self.context)
        
        # Should handle gracefully - either success with empty result
        # or appropriate error status
        assert result.status in [AttackStatus.SUCCESS, AttackStatus.INVALID_PARAMS]
    
    @pytest.mark.parametrize("payload_size", [1, 10, 100, 1000, 10000])
    def test_execute_various_payload_sizes(self, payload_size):
        """Test execution with various payload sizes."""
        self.context.payload = b"x" * payload_size
        self.context.params = {"required_param": "value"}
        result = self.attack.execute(self.context)
        
        assert result.status == AttackStatus.SUCCESS
        assert result.bytes_sent >= payload_size
    
    def test_performance_regression(self):
        """Test that execution time is within acceptable limits."""
        import time
        
        self.context.params = {"required_param": "value"}
        
        # Warm up
        self.attack.execute(self.context)
        
        # Measure execution time
        start_time = time.time()
        result = self.attack.execute(self.context)
        execution_time = time.time() - start_time
        
        assert result.status == AttackStatus.SUCCESS
        assert execution_time < 0.1  # Should complete within 100ms
        assert result.processing_time_ms < 100
```

#### 2. Integration Test Requirements

**Registry Integration:**
```python
def test_attack_registration():
    """Test that attack registers correctly in the registry."""
    from core.bypass.attacks.attack_registry import get_attack_registry
    
    registry = get_attack_registry()
    
    # Check attack is registered
    assert "your_attack_name" in registry.attacks
    
    # Check metadata is correct
    entry = registry.attacks["your_attack_name"]
    assert entry.metadata.name == "Your Attack Name"
    assert entry.metadata.category == AttackCategories.TCP
    
    # Check aliases work
    for alias in entry.metadata.aliases:
        assert registry.resolve_alias(alias) == "your_attack_name"

def test_dispatcher_integration():
    """Test that attack works with AttackDispatcher."""
    from core.bypass.engine.attack_dispatcher import AttackDispatcher
    from core.bypass.attacks.attack_registry import get_attack_registry
    
    registry = get_attack_registry()
    dispatcher = AttackDispatcher(registry)
    
    context = AttackContext(
        dst_ip="192.168.1.1",
        dst_port=443,
        payload=b"test payload"
    )
    
    # Test direct dispatch
    result = dispatcher.dispatch("your_attack_name", context, required_param="value")
    assert result.status == AttackStatus.SUCCESS
    
    # Test alias dispatch
    result = dispatcher.dispatch("your_attack_alias", context, required_param="value")
    assert result.status == AttackStatus.SUCCESS
```

### Performance Standards

#### 1. Execution Time Requirements

| Payload Size | Maximum Execution Time | Target Time |
|--------------|------------------------|-------------|
| < 1KB | 10ms | 1ms |
| 1KB - 10KB | 50ms | 5ms |
| 10KB - 100KB | 200ms | 20ms |
| > 100KB | 1000ms | 100ms |

#### 2. Memory Usage Requirements

- **Maximum memory overhead**: 2x payload size
- **No memory leaks**: Memory usage should return to baseline after execution
- **Efficient data structures**: Use appropriate data structures for the task

#### 3. Performance Testing

```python
import psutil
import time
import gc

def test_memory_usage():
    """Test memory usage stays within limits."""
    process = psutil.Process()
    
    # Baseline memory
    gc.collect()
    baseline_memory = process.memory_info().rss
    
    # Execute attack multiple times
    attack = YourAttack()
    context = AttackContext(payload=b"x" * 10000)  # 10KB payload
    
    for _ in range(100):
        result = attack.execute(context)
        assert result.status == AttackStatus.SUCCESS
    
    # Check memory after execution
    gc.collect()
    final_memory = process.memory_info().rss
    memory_increase = final_memory - baseline_memory
    
    # Should not increase by more than 2x payload size
    assert memory_increase < 20000  # 20KB for 10KB payload

def test_execution_time_scaling():
    """Test that execution time scales reasonably with payload size."""
    attack = YourAttack()
    
    times = []
    sizes = [100, 1000, 10000, 100000]
    
    for size in sizes:
        context = AttackContext(payload=b"x" * size)
        
        start_time = time.time()
        result = attack.execute(context)
        execution_time = time.time() - start_time
        
        assert result.status == AttackStatus.SUCCESS
        times.append(execution_time)
    
    # Execution time should scale sub-linearly (better than O(n))
    # This is a rough check - adjust based on your attack's complexity
    for i in range(1, len(times)):
        time_ratio = times[i] / times[i-1]
        size_ratio = sizes[i] / sizes[i-1]
        assert time_ratio < size_ratio * 2  # Allow some overhead
```

### Security and Safety Standards

#### 1. Input Validation

- [ ] **Validate all inputs**: Never trust input parameters
- [ ] **Sanitize strings**: Prevent injection attacks
- [ ] **Limit resource usage**: Prevent DoS through resource exhaustion
- [ ] **Handle edge cases**: Empty inputs, very large inputs, malformed data

#### 2. Error Handling

- [ ] **Don't leak sensitive information**: Error messages should not reveal system details
- [ ] **Graceful degradation**: Fail safely without crashing
- [ ] **Proper logging**: Log errors for debugging without exposing sensitive data
- [ ] **Resource cleanup**: Always clean up resources in finally blocks

#### 3. Thread Safety

- [ ] **Stateless design**: Avoid shared mutable state
- [ ] **Thread-safe operations**: Use thread-safe data structures if needed
- [ ] **No global state**: Avoid global variables that could cause race conditions

### Deployment Readiness Checklist

#### Pre-Deployment Validation

- [ ] **All tests pass**: Unit tests, integration tests, performance tests
- [ ] **Code review completed**: At least one other developer has reviewed the code
- [ ] **Documentation complete**: All public methods and classes documented
- [ ] **Performance validated**: Meets performance requirements
- [ ] **Security review**: No security vulnerabilities identified
- [ ] **Backward compatibility**: Doesn't break existing functionality
- [ ] **Configuration tested**: Works with various configuration options

#### Post-Deployment Monitoring

- [ ] **Monitoring setup**: Metrics and logging configured
- [ ] **Error tracking**: Error rates and types monitored
- [ ] **Performance tracking**: Execution times and resource usage tracked
- [ ] **Usage analytics**: Track which attacks are used most frequently
- [ ] **Feedback collection**: Mechanism for collecting user feedback

This comprehensive quality assurance framework ensures that all attacks meet high standards for production use.