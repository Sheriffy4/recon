"""
Unit tests for migrate_domain_rules.py script.

Tests the migration of domain_rules.json to ensure all rules have attacks field.
"""

import json
import tempfile
from pathlib import Path

import pytest

from migrate_domain_rules import DomainRulesMigrator


class TestDomainRulesMigrator:
    """Test suite for DomainRulesMigrator."""
    
    def test_migrate_rule_with_only_type(self):
        """Test migrating a rule that only has type field."""
        migrator = DomainRulesMigrator()
        
        rule_data = {
            "type": "fake",
            "params": {
                "ttl": 1,
                "fooling": "badseq"
            },
            "metadata": {}
        }
        
        migrated = migrator.migrate_rule("test.com", rule_data)
        
        assert "attacks" in migrated
        assert migrated["attacks"] == ["fake"]
        assert "migrated_at" in migrated["metadata"]
        assert "migration_note" in migrated["metadata"]
    
    def test_migrate_rule_already_has_attacks(self):
        """Test migrating a rule that already has attacks field."""
        migrator = DomainRulesMigrator()
        
        rule_data = {
            "type": "fake",
            "attacks": ["fake", "disorder"],
            "params": {
                "ttl": 1,
                "fooling": "badseq"
            },
            "metadata": {}
        }
        
        migrated = migrator.migrate_rule("test.com", rule_data)
        
        assert migrated["attacks"] == ["fake", "disorder"]
        assert "migrated_at" not in migrated["metadata"]
    
    def test_parse_compound_type_fakeddisorder(self):
        """Test parsing compound type fakeddisorder."""
        migrator = DomainRulesMigrator()
        
        attacks = migrator._parse_type_to_attacks("fakeddisorder")
        
        assert attacks == ["fake", "disorder"]
    
    def test_parse_compound_type_disorder_short_ttl_decoy(self):
        """Test parsing compound type disorder_short_ttl_decoy."""
        migrator = DomainRulesMigrator()
        
        attacks = migrator._parse_type_to_attacks("disorder_short_ttl_decoy")
        
        assert attacks == ["disorder"]
    
    def test_parse_simple_type(self):
        """Test parsing simple type."""
        migrator = DomainRulesMigrator()
        
        attacks = migrator._parse_type_to_attacks("split")
        
        assert attacks == ["split"]
    
    def test_migrate_full_file(self):
        """Test migrating a complete domain_rules.json file."""
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            test_data = {
                "version": "1.0",
                "last_updated": "2025-01-01T00:00:00",
                "domain_rules": {
                    "example.com": {
                        "type": "fake",
                        "params": {
                            "ttl": 1,
                            "fooling": "badseq"
                        },
                        "metadata": {}
                    },
                    "test.com": {
                        "type": "split",
                        "attacks": ["split"],
                        "params": {
                            "split_pos": 2
                        },
                        "metadata": {}
                    },
                    "compound.com": {
                        "type": "fakeddisorder",
                        "params": {
                            "ttl": 1,
                            "fooling": "badseq",
                            "disorder_method": "reverse"
                        },
                        "metadata": {}
                    }
                },
                "default_strategy": {
                    "type": "disorder",
                    "params": {
                        "disorder_method": "reverse"
                    }
                }
            }
            json.dump(test_data, f)
            temp_path = f.name
        
        try:
            # Create migrator
            migrator = DomainRulesMigrator(temp_path)
            
            # Perform migration
            success = migrator.migrate(dry_run=False)
            
            assert success
            assert migrator.migration_stats['total_rules'] == 3
            # example.com, compound.com, and default_strategy need migration
            assert migrator.migration_stats['migrated_rules'] == 3
            # Only test.com already has attacks field
            assert migrator.migration_stats['already_migrated'] == 1
            
            # Read migrated file
            with open(temp_path, 'r') as f:
                migrated_data = json.load(f)
            
            # Check example.com was migrated
            assert "attacks" in migrated_data['domain_rules']['example.com']
            assert migrated_data['domain_rules']['example.com']['attacks'] == ["fake"]
            
            # Check test.com unchanged
            assert migrated_data['domain_rules']['test.com']['attacks'] == ["split"]
            
            # Check compound.com was migrated correctly
            assert "attacks" in migrated_data['domain_rules']['compound.com']
            assert migrated_data['domain_rules']['compound.com']['attacks'] == ["fake", "disorder"]
            
            # Check default_strategy was migrated
            assert "attacks" in migrated_data['default_strategy']
            assert migrated_data['default_strategy']['attacks'] == ["disorder"]
            
            # Check backup was created
            backup_path = Path(temp_path).with_suffix('.json.backup')
            assert backup_path.exists()
            
        finally:
            # Cleanup
            Path(temp_path).unlink(missing_ok=True)
            Path(temp_path).with_suffix('.json.backup').unlink(missing_ok=True)
            # Clean up timestamped backups
            for backup in Path(temp_path).parent.glob(f"{Path(temp_path).stem}.json.backup_*"):
                backup.unlink(missing_ok=True)
    
    def test_validate_rules_with_errors(self):
        """Test validation catches rules with errors."""
        # Create temporary file with invalid rule
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            test_data = {
                "version": "1.0",
                "domain_rules": {
                    "invalid.com": {
                        "type": "",
                        "attacks": [],  # Empty attacks list is invalid
                        "params": {},
                        "metadata": {}
                    }
                }
            }
            json.dump(test_data, f)
            temp_path = f.name
        
        try:
            migrator = DomainRulesMigrator(temp_path)
            
            # Load data
            with open(temp_path, 'r') as f:
                data = json.load(f)
            
            # Validate should fail
            is_valid = migrator.validate_rules(data)
            
            assert not is_valid
            assert migrator.migration_stats['validation_errors'] > 0
            
        finally:
            Path(temp_path).unlink(missing_ok=True)
    
    def test_create_backup(self):
        """Test backup creation."""
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            test_data = {"version": "1.0", "domain_rules": {}}
            json.dump(test_data, f)
            temp_path = f.name
        
        try:
            migrator = DomainRulesMigrator(temp_path)
            
            # Create backup
            success = migrator.create_backup()
            
            assert success
            assert migrator.backup_path.exists()
            
            # Check backup content matches original
            with open(temp_path, 'r') as f:
                original = json.load(f)
            with open(migrator.backup_path, 'r') as f:
                backup = json.load(f)
            
            assert original == backup
            
        finally:
            Path(temp_path).unlink(missing_ok=True)
            Path(temp_path).with_suffix('.json.backup').unlink(missing_ok=True)
            # Clean up timestamped backups
            for backup in Path(temp_path).parent.glob(f"{Path(temp_path).stem}.json.backup_*"):
                backup.unlink(missing_ok=True)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
