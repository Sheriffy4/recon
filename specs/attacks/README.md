# Attack Specifications

This directory contains YAML specifications for all DPI bypass attacks. These specifications define expected behavior, validation rules, test variations, and error cases for each attack.

## Purpose

Attack specifications serve multiple purposes:

1. **Documentation** - Clear, structured documentation of how each attack works
2. **Validation** - Automated validation of attack implementations against expected behavior
3. **Testing** - Comprehensive test variations and error cases for each attack
4. **Parameter Validation** - Type checking and range validation for attack parameters

## Specification Format

Each attack specification is a YAML file with the following structure:

```yaml
name: attack_name
aliases: [alias1, alias2]
description: Brief description of the attack
category: attack_category

parameters:
  - name: param_name
    type: int|float|str|bool|list[type]
    default: default_value
    required: true|false
    description: Parameter description
    min: minimum_value (optional)
    max: maximum_value (optional)
    allowed_values: [value1, value2] (optional)

expected_packets:
  count: number_of_packets
  order:
    - packet_index: 0
      name: packet_name
      properties:
        ttl: expected_ttl
        seq: expected_sequence
        # ... other properties

validation_rules:
  category_name:
    - rule: "validation expression"
      description: "What this rule validates"
      severity: critical|error|warning|info

test_variations:
  variation_name:
    description: "Test variation description"
    params:
      param1: value1
      param2: value2

error_cases:
  case_name:
    description: "Error case description"
    params:
      param1: invalid_value
    expected_error: "Expected error message"

notes:
  - Additional notes about the attack
```

## Available Attacks

### TCP Manipulation Attacks

#### fake
- **File**: `fake.yaml`
- **Description**: Send fake packet with low TTL before real packet
- **Parameters**: ttl, fake_ttl, fooling, fake_sni, fake_http, fake_tls
- **Expected Packets**: 2 (fake + real)
- **Key Validation**: Fake packet must have low TTL and same sequence number as real packet

#### fakeddisorder
- **File**: `fakeddisorder.yaml`
- **Description**: Send fake packet with low TTL, then real packets in disorder
- **Parameters**: split_pos, split_seqovl, ttl, fake_ttl, autottl, fooling, fake_http, fake_tls
- **Expected Packets**: 3 (fake + 2 real in disorder)
- **Key Validation**: Fake seq must equal first real part seq, real packets sent out-of-order

#### seqovl
- **File**: `seqovl.yaml`
- **Description**: Create overlapping TCP sequence numbers
- **Parameters**: split_pos, overlap_size, overlap_pattern
- **Expected Packets**: 2 (with overlapping sequences)
- **Key Validation**: Second packet sequence overlaps with first packet

### TCP Fragmentation Attacks

#### split
- **File**: `split.yaml`
- **Description**: Split packet at specified position
- **Parameters**: split_pos, split_position
- **Expected Packets**: 2 (first part + second part)
- **Key Validation**: Combined payload equals original, correct sequence numbers

#### disorder
- **File**: `disorder.yaml`
- **Description**: Send packet segments in out-of-order sequence
- **Parameters**: split_pos, disorder_delay_ms
- **Expected Packets**: 2 (sent in reverse order)
- **Key Validation**: Packets sent out-of-order but with correct sequence numbers

#### multisplit
- **File**: `multisplit.yaml`
- **Description**: Split packet into multiple segments
- **Parameters**: split_positions, num_splits, segment_size
- **Expected Packets**: Multiple (based on split positions)
- **Key Validation**: All segments have sequential sequence numbers

#### multidisorder
- **File**: `multidisorder.yaml`
- **Description**: Split packet into multiple segments and send out-of-order
- **Parameters**: split_positions, num_splits, disorder_pattern, custom_order
- **Expected Packets**: Multiple (sent in disordered sequence)
- **Key Validation**: Packets sent out-of-order with correct sequence numbers

#### simple_fragment
- **File**: `simple_fragment.yaml`
- **Description**: Basic TCP fragmentation that splits packets into equal-sized segments
- **Parameters**: fragment_size, max_fragments, fragment_delay_ms
- **Expected Packets**: Multiple (based on fragment_size)
- **Key Validation**: All fragments have sequential sequence numbers and valid checksums

#### window_manipulation
- **File**: `window_manipulation.yaml`
- **Description**: Manipulates TCP window size to confuse DPI flow tracking
- **Parameters**: window_size, window_scale, window_pattern, restore_window
- **Expected Packets**: 1 or 2 (depending on restore_window)
- **Key Validation**: Window size correctly set, optional restore packet sent

#### tcp_options_modification
- **File**: `tcp_options_modification.yaml`
- **Description**: Modifies or adds TCP options to confuse DPI header parsing
- **Parameters**: add_options, remove_options, modify_options, add_padding, padding_size, corrupt_options
- **Expected Packets**: 1 (with modified TCP options)
- **Key Validation**: TCP options correctly added/removed/modified, header length valid

## Usage

### Loading Specifications

```python
from core.attack_spec_loader import get_spec_loader

# Get spec loader instance
loader = get_spec_loader()

# Load a specific attack spec
spec = loader.load_spec('fake')

# Load all specs
all_specs = loader.load_all_specs()
```

### Validating Parameters

```python
# Validate parameters against spec
params = {'ttl': 1, 'fooling': ['badsum']}
errors = loader.validate_parameters('fake', params)

if errors:
    print(f"Invalid parameters: {errors}")
else:
    print("Parameters valid")
```

### Getting Validation Rules

```python
# Get all validation rules for an attack
rules = loader.get_validation_rules('fake')

# Get rules for specific category
seq_rules = loader.get_validation_rules('fake', 'sequence_numbers')
```

### Getting Test Variations

```python
# Get test variations for an attack
variations = loader.get_test_variations('fake')

for name, variation in variations.items():
    print(f"{name}: {variation.description}")
    print(f"  Params: {variation.params}")
```

### Using with PacketValidator

```python
from core.packet_validator import PacketValidator

validator = PacketValidator(debug_mode=True)

# Validate attack using spec
result = validator.validate_attack_with_spec(
    attack_name='fake',
    params={'ttl': 1, 'fooling': ['badsum']},
    pcap_file='test_fake.pcap'
)

if result.passed:
    print("Validation passed!")
else:
    print(f"Validation failed: {result.error}")
    for detail in result.get_critical_issues():
        print(f"  - {detail.message}")
```

## Validation Rule Categories

### sequence_numbers
Rules for validating TCP sequence numbers:
- Fake packets must have same sequence as real packets
- Real packets must have sequential sequence numbers
- Overlap calculations must be correct

### checksum
Rules for validating TCP checksums:
- Fake packets with badsum fooling must have bad checksum
- Real packets must have valid checksum
- WinDivert checksum recalculation detection

### ttl
Rules for validating TTL values:
- Fake packets must have specified low TTL
- Real packets should have default system TTL (64 or 128)
- TTL parameter validation

### packet_count
Rules for validating packet counts:
- Correct number of packets generated
- No missing or extra packets

### packet_order
Rules for validating packet order:
- Packets sent in correct order (or disorder for disorder attacks)
- Fake packets sent before real packets
- Disorder patterns correctly implemented

### payload
Rules for validating payload:
- Combined payload equals original
- Payload split at correct positions
- Overlap data correct

## Test Variations

Each attack includes multiple test variations:

- **minimal**: Minimal parameters for basic functionality
- **with_badsum**: With bad checksum fooling
- **with_overlap**: With sequence overlap (where applicable)
- **high_ttl**: With higher TTL values
- **custom_params**: With custom parameter combinations

## Error Cases

Each attack includes error cases to test parameter validation:

- **missing_required**: Missing required parameters
- **invalid_range**: Parameters outside valid range
- **invalid_type**: Parameters with wrong type
- **invalid_values**: Parameters with invalid values

## Adding New Attack Specs

To add a new attack specification:

1. Create a new YAML file in this directory: `attack_name.yaml`
2. Follow the specification format above
3. Define all parameters with types and validation rules
4. Specify expected packet structure
5. Add validation rules for all critical aspects
6. Include test variations and error cases
7. Test the spec using `test_spec_validation.py`

Example:

```bash
cd recon
python test_spec_validation.py
```

## Validation Severity Levels

- **critical**: Must pass for attack to be considered valid
- **error**: Significant issue that should be fixed
- **warning**: Minor issue or best practice violation
- **info**: Informational message

## Notes

- All sequence numbers are relative to original_seq
- TTL values: 1-3 are most effective for fake packets
- Fooling methods: badsum, md5sig, badseq
- Default TTL for real packets: 64 (Linux) or 128 (Windows)
- Overlap sizes: Common values are 10, 336 bytes
- Split positions: Common values are 1, 3, 76 (SNI position in TLS)

## Testing

Run the spec validation test suite:

```bash
cd recon
python test_spec_validation.py
```

This will:
- Load all attack specifications
- Validate parameter definitions
- Test validation rules
- Display test variations
- Show error cases
- Verify integration with PacketValidator

## References

- [Attack Validation Suite Design](../../.kiro/specs/attack-validation-suite/design.md)
- [Attack Validation Suite Requirements](../../.kiro/specs/attack-validation-suite/requirements.md)
- [Attack Validation Suite Tasks](../../.kiro/specs/attack-validation-suite/tasks.md)
