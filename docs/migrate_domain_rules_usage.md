# Domain Rules Migration Script

## Overview

The `migrate_domain_rules.py` script ensures all rules in `domain_rules.json` have the `attacks` field, which is the source of truth for attack application (Requirements 5.3, 5.5).

## Background

In the legacy format, strategies used the `type` field to specify attacks. The new format uses the `attacks` field as a list, allowing for combo attacks. This migration script:

1. Reads existing `domain_rules.json`
2. For each rule, ensures `attacks` field exists
3. If only `type` exists, creates `attacks` with appropriate elements
4. Validates all rules with StrategyLoader
5. Creates a backup of the original file
6. Writes updated `domain_rules.json`

## Usage

### Basic Usage

```bash
# Perform migration (creates backup automatically)
python migrate_domain_rules.py

# Dry run (preview changes without writing)
python migrate_domain_rules.py --dry-run

# Specify custom rules file
python migrate_domain_rules.py --rules-path /path/to/domain_rules.json
```

### Command Line Options

- `--rules-path PATH`: Path to domain_rules.json file (default: `domain_rules.json`)
- `--dry-run`: Perform migration without writing changes (useful for preview)

## Migration Logic

### Simple Types

For simple attack types, the migration creates a single-element list:

```json
// Before
{
  "type": "fake",
  "params": {...}
}

// After
{
  "type": "fake",
  "attacks": ["fake"],
  "params": {...},
  "metadata": {
    "migrated_at": "2025-11-27T...",
    "migration_note": "Auto-migrated from type='fake'"
  }
}
```

### Compound Types

For compound types, the migration parses them into multiple attacks:

```json
// Before
{
  "type": "fakeddisorder",
  "params": {...}
}

// After
{
  "type": "fakeddisorder",
  "attacks": ["fake", "disorder"],
  "params": {...},
  "metadata": {
    "migrated_at": "2025-11-27T...",
    "migration_note": "Auto-migrated from type='fakeddisorder'"
  }
}
```

Supported compound types:
- `fakeddisorder` → `["fake", "disorder"]`
- `disorder_short_ttl_decoy` → `["disorder"]`

### Already Migrated Rules

Rules that already have the `attacks` field are left unchanged:

```json
{
  "type": "fake",
  "attacks": ["fake", "disorder", "split"],
  "params": {...}
}
// No changes made
```

## Validation

After migration, all rules are validated using `StrategyLoader.validate_strategy()`:

- **Errors**: Rules with validation errors will cause migration to abort
- **Warnings**: Rules with warnings are migrated but warnings are logged

Common warnings:
- Missing `disorder_method` parameter for disorder attacks
- Type/attacks field mismatch (attacks field takes priority)

## Backup and Rollback

### Automatic Backup

The script automatically creates two backups:

1. **Timestamped backup**: `domain_rules.json.backup_YYYYMMDD_HHMMSS`
2. **Simple backup**: `domain_rules.json.backup` (for easy rollback)

### Rollback

To rollback to the original file:

```bash
# Windows
copy domain_rules.json.backup domain_rules.json

# Linux/Mac
cp domain_rules.json.backup domain_rules.json
```

## Output

The script provides detailed output:

```
======================================================================
🚀 Starting domain_rules.json migration
======================================================================

📊 Found 37 domain rules

🔄 Migrating rules...
  ✅ example.com: Migrated type='fake' → attacks=['fake']
  example.com: Already has attacks field

🔄 Migrating default_strategy...
  ✅ default_strategy: Migrated type='disorder' → attacks=['disorder']

🔍 Validating migrated rules...
  ⚠️ www.youtube.com: Validation warnings
     Warning: disorder attack should have 'disorder_method' parameter

✅ Updated domain_rules.json

======================================================================
📊 Migration Statistics
======================================================================
Total rules:           37
Already migrated:      35
Newly migrated:        2
Validation errors:     0
Validation warnings:   1
======================================================================

✅ Migration completed successfully!
💾 Backup saved to: domain_rules.json.backup
💡 To rollback: cp domain_rules.json.backup domain_rules.json
```

## Exit Codes

- `0`: Migration successful
- `1`: Migration failed (validation errors, file errors, etc.)

## Examples

### Example 1: Dry Run

Preview what would be migrated without making changes:

```bash
python migrate_domain_rules.py --dry-run
```

### Example 2: Migrate Production File

Migrate the production domain_rules.json:

```bash
python migrate_domain_rules.py
```

### Example 3: Migrate Custom File

Migrate a custom rules file:

```bash
python migrate_domain_rules.py --rules-path config/custom_rules.json
```

## Integration with StrategyLoader

After migration, the `StrategyLoader` will:

1. Use the `attacks` field as the source of truth
2. Ignore the `type` field if `attacks` is present
3. Apply all attacks in the `attacks` list in order

See `core/strategy/loader.py` for implementation details.

## Troubleshooting

### Migration Fails with Validation Errors

If migration fails due to validation errors:

1. Review the error messages in the output
2. Fix the issues in `domain_rules.json` manually
3. Run migration again

### Backup Not Created

If backup creation fails:

1. Check file permissions
2. Ensure sufficient disk space
3. Check if file is locked by another process

### Rules Not Migrated

If some rules are not migrated:

1. Check if they already have `attacks` field
2. Review the migration statistics output
3. Use `--dry-run` to preview changes

## Related Documentation

- [Domain Rules Schema](domain_rules_schema.md)
- [Strategy Loader](../core/strategy/loader.py)
- [Attack Application Parity Spec](../.kiro/specs/attack-application-parity/)
