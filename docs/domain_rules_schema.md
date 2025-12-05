# domain_rules.json Schema Documentation

## Overview

The `domain_rules.json` file defines DPI bypass strategies for specific domains. It supports exact domain matching, wildcard patterns, parent domain fallback, and a default strategy for unmatched domains.

## File Structure

```json
{
  "version": "1.0",
  "last_updated": "ISO-8601 timestamp",
  "domain_rules": {
    "domain.com": { /* strategy */ },
    "*.example.com": { /* wildcard strategy */ }
  },
  "default_strategy": { /* fallback strategy */ }
}
```

## Strategy Object Schema

Each strategy consists of three main sections:

### 1. Attack Configuration

```json
{
  "type": "legacy_attack_type",
  "attacks": ["attack1", "attack2", "attack3"],
  "params": { /* attack parameters */ },
  "metadata": { /* strategy metadata */ }
}
```

#### Field Priority: `attacks` over `type`

**IMPORTANT**: The `attacks` field has **priority** over the `type` field.

- **`attacks`** (array of strings, **source of truth**): List of attacks to apply in order
- **`type`** (string, **legacy field**): Ignored when `attacks` is present

**Why this matters:**
- Old strategies may only have `type` field
- New strategies use `attacks` field for combo attacks
- System always uses `attacks` if present, ignoring `type`

**Example:**
```json
{
  "type": "fake",
  "attacks": ["fake", "multisplit", "disorder"]
}
```
In this case, the system applies: fake + multisplit + disorder (NOT just "fake")

### 2. Attack Types

Available attack types:

- **`fake`**: Send decoy packet with low TTL to confuse DPI
- **`split`**: Fragment payload into 2 parts
- **`multisplit`**: Fragment payload into multiple parts (3+)
- **`disorder`**: Send packets out of order

### 3. Parameters

Common parameters for all attacks:

```json
{
  "params": {
    "no_fallbacks": true,
    "forced": true
  }
}
```

#### Fake Attack Parameters

```json
{
  "ttl": 1,              // TTL for fake packet (1-3)
  "fooling": "badseq",   // Method: "badseq", "badsum", "none"
  "repeats": 1           // Number of fake packets
}
```

#### Split/Multisplit Parameters

```json
{
  "split_pos": 2,        // Position: number or "sni"
  "split_count": 6       // Number of fragments (2 for split, 3+ for multisplit)
}
```

**split_pos values:**
- **Numeric** (e.g., `2`, `3`): Split at byte position N from start
- **`"sni"`**: Split near SNI offset (±8 bytes) in TLS ClientHello

#### Disorder Parameters

```json
{
  "disorder_method": "reverse"  // Method: "reverse", "random"
}
```

### 4. Metadata

```json
{
  "metadata": {
    "source": "adaptive_engine_cli",
    "discovered_at": "2025-11-18T13:23:47.006191",
    "success_rate": 100.0,
    "attack_count": 2,
    "validation_status": "validated",
    "validated_at": "2025-11-18T13:23:47.006191",
    "needs_revalidation": false
  }
}
```

## Domain Matching Rules

The system uses a **priority-based fallback** mechanism:

### 1. Exact Match (Highest Priority)

```json
{
  "domain_rules": {
    "youtube.com": { /* exact match strategy */ }
  }
}
```

Matches: `youtube.com` exactly

### 2. Wildcard Match

```json
{
  "domain_rules": {
    "*.youtube.com": { /* wildcard strategy */ }
  }
}
```

Matches: `www.youtube.com`, `m.youtube.com`, `any.subdomain.youtube.com`
Does NOT match: `youtube.com` (use exact match for that)

### 3. Parent Domain Match

If no exact or wildcard match found, system checks parent domains:

- For `sub.example.com` → checks `example.com`
- For `deep.sub.example.com` → checks `sub.example.com`, then `example.com`

### 4. Default Strategy (Lowest Priority)

```json
{
  "default_strategy": {
    "type": "disorder",
    "attacks": ["disorder"],
    "params": { /* default params */ }
  }
}
```

Used when no other rule matches.

### Matching Priority Example

Given these rules:
```json
{
  "domain_rules": {
    "youtube.com": { "attacks": ["fake"] },
    "*.youtube.com": { "attacks": ["split"] },
    "google.com": { "attacks": ["disorder"] }
  },
  "default_strategy": { "attacks": ["disorder"] }
}
```

Matching results:
- `youtube.com` → **exact match** → `["fake"]`
- `www.youtube.com` → **wildcard match** → `["split"]`
- `m.youtube.com` → **wildcard match** → `["split"]`
- `google.com` → **exact match** → `["disorder"]`
- `mail.google.com` → **parent match** → `["disorder"]`
- `example.com` → **default strategy** → `["disorder"]`

## Combo Attack Examples

### Example 1: Fake + Multisplit

```json
{
  "type": "fake",
  "attacks": ["fake", "multisplit"],
  "params": {
    "ttl": 1,
    "fooling": "badseq",
    "split_pos": 3,
    "split_count": 8,
    "no_fallbacks": true,
    "forced": true
  }
}
```

**Effect**: Sends 1 fake packet with TTL=1, then splits real payload into 8 fragments starting at position 3.

### Example 2: Fake + Disorder + Split

```json
{
  "type": "fake",
  "attacks": ["fake", "disorder", "split"],
  "params": {
    "ttl": 1,
    "fooling": "badseq",
    "split_pos": 3,
    "split_count": 2,
    "disorder_method": "reverse",
    "no_fallbacks": true,
    "forced": true
  }
}
```

**Effect**: 
1. Sends fake packet with TTL=1
2. Splits payload into 2 fragments at position 3
3. Sends fragments in reverse order

### Example 3: Disorder + Multisplit

```json
{
  "type": "disorder",
  "attacks": ["disorder", "multisplit"],
  "params": {
    "split_pos": 2,
    "split_count": 6,
    "disorder_method": "reverse",
    "no_fallbacks": true,
    "forced": true
  }
}
```

**Effect**: Splits payload into 6 fragments at position 2, then sends them in reverse order.

### Example 4: Split with SNI Position

```json
{
  "type": "split",
  "attacks": ["split"],
  "params": {
    "split_pos": "sni",
    "split_count": 2,
    "no_fallbacks": true,
    "forced": true
  }
}
```

**Effect**: Splits payload near the SNI (Server Name Indication) field in TLS ClientHello, within ±8 bytes of SNI offset.

### Example 5: Fake with Badsum

```json
{
  "type": "fake",
  "attacks": ["fake"],
  "params": {
    "ttl": 3,
    "fooling": "badsum",
    "repeats": 1,
    "no_fallbacks": true,
    "forced": true
  }
}
```

**Effect**: Sends 1 fake packet with TTL=3 and corrupted TCP checksum.

## Attack Application Order

When multiple attacks are specified, they are applied in this order:

1. **Fake** packets (sent first with low TTL)
2. **Split/Multisplit** (fragment the real payload)
3. **Disorder** (reorder the fragments)

This order is enforced by the system regardless of the order in the `attacks` array.

## Validation and Compliance

### needs_revalidation Flag

```json
{
  "metadata": {
    "needs_revalidation": true,
    "failure_count": 14,
    "last_failure_time": "2025-11-21T11:11:06.465476",
    "last_failure_reason": "Strategy failed with 6 retransmissions"
  }
}
```

When `needs_revalidation: true`, the strategy should be retested as it has failed recently.

### Validation Status

```json
{
  "metadata": {
    "validation_status": "validated",
    "validated_at": "2025-11-18T13:23:47.006191"
  }
}
```

Possible values:
- `"validated"`: Strategy confirmed working
- `"pending"`: Awaiting validation
- `"failed"`: Strategy not working

## Migration from Legacy Format

### Old Format (type only)

```json
{
  "type": "fake",
  "params": { "ttl": 1, "fooling": "badseq" }
}
```

### New Format (attacks field)

```json
{
  "type": "fake",
  "attacks": ["fake"],
  "params": { "ttl": 1, "fooling": "badseq" }
}
```

**Migration rule**: If only `type` exists, create `attacks` array with single element matching `type`.

## Best Practices

1. **Always use `attacks` field** for new strategies
2. **Keep `type` for backward compatibility** but don't rely on it
3. **Use wildcard rules** for subdomains that share the same strategy
4. **Set `needs_revalidation: false`** after confirming strategy works
5. **Document rationale** in metadata for complex combos
6. **Use `split_pos: "sni"`** for TLS-aware splitting
7. **Test combos** before deploying to production

## Common Patterns

### Pattern 1: Aggressive Combo for Stubborn DPI

```json
{
  "attacks": ["fake", "disorder", "multisplit"],
  "params": {
    "ttl": 1,
    "fooling": "badseq",
    "split_pos": 2,
    "split_count": 6,
    "disorder_method": "reverse"
  }
}
```

### Pattern 2: Lightweight Split

```json
{
  "attacks": ["split"],
  "params": {
    "split_pos": 3,
    "split_count": 2
  }
}
```

### Pattern 3: SNI-Aware Splitting

```json
{
  "attacks": ["split"],
  "params": {
    "split_pos": "sni",
    "split_count": 2
  }
}
```

## Troubleshooting

### Strategy Not Applied

**Check:**
1. Is `attacks` field present? (It overrides `type`)
2. Is domain matching correctly? (Check exact → wildcard → parent → default)
3. Are parameters valid? (e.g., `split_count >= 2`)

### Combo Not Working

**Check:**
1. Are attacks compatible? (Some combos may conflict)
2. Is attack order correct? (System enforces: fake → split → disorder)
3. Are all required parameters present? (e.g., `ttl` for fake, `split_pos` for split)

### Validation Failures

**Check:**
1. Is `needs_revalidation: true`? (Strategy may be outdated)
2. Check `failure_count` and `last_failure_reason`
3. Try simpler strategy first, then add complexity

## See Also

- [PCAP Validation Tool](validate_pcap_usage.md)
- [Deep Compare Tool](deep_compare_quick_reference.md)
- Strategy Loader: `core/strategy/loader.py`
- Combo Builder: `core/strategy/combo_builder.py`
