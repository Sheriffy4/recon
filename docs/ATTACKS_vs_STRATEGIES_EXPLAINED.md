# Attacks vs Strategies in DPI Bypass System

## Overview

Understanding the distinction between attacks and strategies is crucial for effectively using and developing the DPI bypass system. While these concepts are related, they serve different purposes in the bypass process.

## Attacks

### Definition
**Attacks** are the fundamental, atomic techniques used to bypass DPI systems. They represent specific methods of manipulating network packets to evade detection.

### Characteristics
- **Atomic**: Single, specific technique
- **Implementation-focused**: Direct packet manipulation methods
- **Reusable**: Can be combined in different ways
- **Technology-specific**: Target specific DPI detection mechanisms

### Examples of Attacks
1. **fakedisorder**: Sends TCP segments out of order
2. **multisplit**: Splits packets at multiple positions
3. **multidisorder**: Splits and reorders multiple packet segments
4. **seqovl**: Overlaps TCP sequence numbers
5. **badsum_race**: Uses bad TCP checksums to create race conditions
6. **md5sig_race**: Uses MD5 signature fooling techniques

### Implementation
Attacks are implemented as individual classes in the attack registry:
```python
# Example attack implementation
class FakeDisorderAttack(BaseAttack):
    name = "fakedisorder"
    category = AttackCategory.TCP_FRAGMENTATION
    
    def apply(self, packet, context):
        # Implementation of the fakedisorder technique
        split_pos = context.params.get("split_pos", 3)
        # ... packet manipulation logic
        return AttackResult(status=AttackStatus.SUCCESS, modified_packets=segments)
```

## Strategies

### Definition
**Strategies** are high-level plans that combine one or more attacks in a specific sequence or configuration to achieve bypass goals.

### Characteristics
- **Composite**: Combination of multiple attacks or attack parameters
- **Context-aware**: Adapted to specific DPI characteristics
- **Configurable**: Parameterized for different scenarios
- **Goal-oriented**: Designed to achieve specific bypass objectives

### Examples of Strategies
1. **Simple Strategy**: `--dpi-desync=fake,disorder --dpi-desync-split-pos=3`
2. **Complex Strategy**: `--dpi-desync=multidisorder --dpi-desync-split-pos=1,5,10 --dpi-desync-ttl=4`
3. **Combo Strategy**: `--dpi-desync=fake,split --dpi-desync-split-pos=5 --dpi-desync-fooling=badseq`

### Implementation
Strategies are defined as structured configurations:
```python
# Example strategy definition
strategy = {
    "name": "multidisorder_with_ttl",
    "params": {
        "type": "multidisorder",
        "positions": [1, 5, 10],
        "ttl": 4
    },
    "estimated_score": 0.75,
    "reason": "Effective against stateful DPI with packet reordering tolerance"
}
```

## Relationship Between Attacks and Strategies

### Composition
```
Strategy = Attack(s) + Parameters + Context
```

A strategy combines:
- One or more attack techniques
- Specific parameter values
- Environmental context (target DPI characteristics)

### Example Relationship
```
Strategy: "multidisorder(positions=[1,5,10])"
├── Attack: "multidisorder"
├── Parameters: positions=[1,5,10]
└── Context: Target DPI tolerates packet reordering
```

## When Are Attacks Applied?

### Strategy Execution Flow
1. **Strategy Selection**: Choose the most appropriate strategy based on fingerprint analysis
2. **Attack Resolution**: Identify which attacks are needed for the strategy
3. **Parameter Mapping**: Map strategy parameters to attack parameters
4. **Attack Execution**: Execute each attack in sequence with specified parameters
5. **Result Aggregation**: Combine results from all attacks in the strategy

### Example Execution Flow
```
1. Strategy Selected: --dpi-desync=multidisorder --dpi-desync-split-pos=1,5,10
2. Attack Resolved: multidisorder attack
3. Parameters Mapped: split positions = [1,5,10]
4. Attack Executed: Apply multidisorder to TLS ClientHello packet
5. Result: Segments sent in reordered sequence [10,5,1]
```

## System Architecture

### Attack Registry
- Central repository of all available attacks
- Provides attack discovery and instantiation
- Manages attack metadata and categories

### Strategy Manager
- Generates and manages strategies
- Maps strategies to attack sequences
- Optimizes strategy selection based on context

### Bypass Engine
- Executes strategies by applying attacks
- Handles packet interception and modification
- Manages attack coordination and timing

## Practical Implications

### For Developers
- **Attacks**: Implement specific packet manipulation techniques
- **Strategies**: Design combinations of attacks for specific scenarios

### For Users
- **Attacks**: Generally not used directly, but understanding helps with troubleshooting
- **Strategies**: Selected and applied to bypass specific DPI systems

### For System Designers
- **Modularity**: Attacks provide reusable building blocks
- **Flexibility**: Strategies allow for complex, adaptive bypass approaches
- **Maintainability**: Clear separation between attack implementation and strategy design

## Conclusion

Understanding the distinction between attacks and strategies is essential for effective DPI bypass:

- **Attacks** are the fundamental building blocks - the "how" of packet manipulation
- **Strategies** are the high-level plans - the "what" and "when" of applying attacks
- The system combines both to create effective, adaptive bypass solutions

This architecture allows for both powerful, pre-defined strategies and flexible, adaptive approaches based on real-time DPI analysis.