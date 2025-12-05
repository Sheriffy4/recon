#!/usr/bin/env python3
"""
Migration script for domain_rules.json to ensure all rules have "attacks" field.

This script:
1. Reads existing domain_rules.json
2. For each rule, ensures "attacks" field exists
3. If only "type" exists, creates "attacks" with single element
4. Validates all rules with StrategyLoader
5. Creates a backup of the original file
6. Writes updated domain_rules.json

Requirements: 5.3, 5.5
"""

import json
import logging
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from core.strategy.loader import StrategyLoader, Strategy

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DomainRulesMigrator:
    """Migrates domain_rules.json to ensure all rules have attacks field."""
    
    def __init__(self, rules_path: str = "domain_rules.json"):
        """
        Initialize migrator.
        
        Args:
            rules_path: Path to domain_rules.json file
        """
        self.rules_path = Path(rules_path)
        self.backup_path = self.rules_path.with_suffix('.json.backup')
        self.loader = StrategyLoader(str(rules_path))
        self.migration_stats = {
            'total_rules': 0,
            'migrated_rules': 0,
            'already_migrated': 0,
            'validation_errors': 0,
            'validation_warnings': 0
        }
    
    def create_backup(self) -> bool:
        """
        Create backup of original domain_rules.json.
        
        Returns:
            True if backup was successful, False otherwise
        """
        try:
            if not self.rules_path.exists():
                logger.error(f"Rules file not found: {self.rules_path}")
                return False
            
            # Create timestamped backup
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_path = self.rules_path.with_suffix(f'.json.backup_{timestamp}')
            
            shutil.copy2(self.rules_path, backup_path)
            logger.info(f"✅ Created backup: {backup_path}")
            
            # Also create a simple .backup file for easy rollback
            shutil.copy2(self.rules_path, self.backup_path)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to create backup: {e}")
            return False
    
    def migrate_rule(self, domain: str, rule_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Migrate a single rule to ensure it has attacks field.
        
        Args:
            domain: Domain name
            rule_data: Rule data dictionary
            
        Returns:
            Migrated rule data
        """
        # Check if attacks field exists
        if 'attacks' in rule_data and rule_data['attacks']:
            self.migration_stats['already_migrated'] += 1
            logger.debug(f"  {domain}: Already has attacks field")
            return rule_data
        
        # If only type exists, create attacks with single element
        if 'type' in rule_data and rule_data['type']:
            rule_type = rule_data['type']
            
            # Create attacks list from type
            # Handle compound types like "fakeddisorder" or "disorder_short_ttl_decoy"
            attacks = self._parse_type_to_attacks(rule_type)
            
            rule_data['attacks'] = attacks
            self.migration_stats['migrated_rules'] += 1
            
            logger.info(f"  ✅ {domain}: Migrated type='{rule_type}' → attacks={attacks}")
            
            # Update metadata
            if 'metadata' not in rule_data:
                rule_data['metadata'] = {}
            
            rule_data['metadata']['migrated_at'] = datetime.now().isoformat()
            rule_data['metadata']['migration_note'] = f"Auto-migrated from type='{rule_type}'"
            
        else:
            # No type and no attacks - this is an error
            logger.warning(f"  ⚠️ {domain}: No type or attacks field found")
            rule_data['attacks'] = []
        
        return rule_data
    
    def _parse_type_to_attacks(self, rule_type: str) -> List[str]:
        """
        Parse type field into attacks list.
        
        Handles compound types like:
        - "fakeddisorder" → ["fake", "disorder"]
        - "disorder_short_ttl_decoy" → ["disorder"]
        
        Args:
            rule_type: Type string
            
        Returns:
            List of attack names
        """
        # Known compound types
        compound_types = {
            'fakeddisorder': ['fake', 'disorder'],
            'disorder_short_ttl_decoy': ['disorder'],
        }
        
        if rule_type in compound_types:
            return compound_types[rule_type]
        
        # Single attack type
        return [rule_type]
    
    def validate_rules(self, data: Dict[str, Any]) -> bool:
        """
        Validate all rules using StrategyLoader.
        
        Args:
            data: Complete domain_rules.json data
            
        Returns:
            True if all rules are valid, False otherwise
        """
        logger.info("\n🔍 Validating migrated rules...")
        
        all_valid = True
        domain_rules = data.get('domain_rules', {})
        
        for domain, rule_data in domain_rules.items():
            try:
                # Parse strategy
                strategy = Strategy(
                    type=rule_data.get('type', ''),
                    attacks=rule_data.get('attacks', []),
                    params=rule_data.get('params', {}),
                    metadata=rule_data.get('metadata', {})
                )
                
                # Validate
                result = self.loader.validate_strategy(strategy)
                
                if not result.valid:
                    logger.error(f"  ❌ {domain}: Validation failed")
                    for error in result.errors:
                        logger.error(f"     Error: {error}")
                    self.migration_stats['validation_errors'] += 1
                    all_valid = False
                
                if result.warnings:
                    logger.warning(f"  ⚠️ {domain}: Validation warnings")
                    for warning in result.warnings:
                        logger.warning(f"     Warning: {warning}")
                    self.migration_stats['validation_warnings'] += 1
                
            except Exception as e:
                logger.error(f"  ❌ {domain}: Failed to validate: {e}")
                self.migration_stats['validation_errors'] += 1
                all_valid = False
        
        # Validate default strategy
        if 'default_strategy' in data:
            try:
                strategy = Strategy(
                    type=data['default_strategy'].get('type', ''),
                    attacks=data['default_strategy'].get('attacks', []),
                    params=data['default_strategy'].get('params', {}),
                    metadata=data['default_strategy'].get('metadata', {})
                )
                
                result = self.loader.validate_strategy(strategy)
                
                if not result.valid:
                    logger.error(f"  ❌ default_strategy: Validation failed")
                    for error in result.errors:
                        logger.error(f"     Error: {error}")
                    all_valid = False
                
                if result.warnings:
                    logger.warning(f"  ⚠️ default_strategy: Validation warnings")
                    for warning in result.warnings:
                        logger.warning(f"     Warning: {warning}")
                
            except Exception as e:
                logger.error(f"  ❌ default_strategy: Failed to validate: {e}")
                all_valid = False
        
        return all_valid
    
    def migrate(self, dry_run: bool = False) -> bool:
        """
        Perform migration of domain_rules.json.
        
        Args:
            dry_run: If True, don't write changes to file
            
        Returns:
            True if migration was successful, False otherwise
        """
        logger.info("=" * 70)
        logger.info("🚀 Starting domain_rules.json migration")
        logger.info("=" * 70)
        
        try:
            # Load current rules
            if not self.rules_path.exists():
                logger.error(f"Rules file not found: {self.rules_path}")
                return False
            
            with open(self.rules_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Get domain rules
            domain_rules = data.get('domain_rules', {})
            self.migration_stats['total_rules'] = len(domain_rules)
            
            logger.info(f"\n📊 Found {len(domain_rules)} domain rules")
            
            # Migrate each rule
            logger.info("\n🔄 Migrating rules...")
            for domain, rule_data in domain_rules.items():
                domain_rules[domain] = self.migrate_rule(domain, rule_data)
            
            # Migrate default strategy
            if 'default_strategy' in data:
                logger.info("\n🔄 Migrating default_strategy...")
                data['default_strategy'] = self.migrate_rule('default_strategy', data['default_strategy'])
            
            # Update last_updated timestamp
            data['last_updated'] = datetime.now().isoformat()
            
            # Validate all rules
            if not self.validate_rules(data):
                logger.error("\n❌ Validation failed. Migration aborted.")
                return False
            
            # Write updated rules
            if not dry_run:
                # Create backup first
                if not self.create_backup():
                    logger.error("Failed to create backup. Migration aborted.")
                    return False
                
                # Write updated file
                with open(self.rules_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                
                logger.info(f"\n✅ Updated {self.rules_path}")
            else:
                logger.info("\n🔍 DRY RUN - No changes written to file")
            
            # Print statistics
            self.print_statistics()
            
            return True
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in {self.rules_path}: {e}")
            return False
        except Exception as e:
            logger.error(f"Migration failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def print_statistics(self):
        """Print migration statistics."""
        logger.info("\n" + "=" * 70)
        logger.info("📊 Migration Statistics")
        logger.info("=" * 70)
        logger.info(f"Total rules:           {self.migration_stats['total_rules']}")
        logger.info(f"Already migrated:      {self.migration_stats['already_migrated']}")
        logger.info(f"Newly migrated:        {self.migration_stats['migrated_rules']}")
        logger.info(f"Validation errors:     {self.migration_stats['validation_errors']}")
        logger.info(f"Validation warnings:   {self.migration_stats['validation_warnings']}")
        logger.info("=" * 70)


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Migrate domain_rules.json to ensure all rules have attacks field'
    )
    parser.add_argument(
        '--rules-path',
        default='domain_rules.json',
        help='Path to domain_rules.json file (default: domain_rules.json)'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Perform migration without writing changes'
    )
    
    args = parser.parse_args()
    
    # Create migrator
    migrator = DomainRulesMigrator(args.rules_path)
    
    # Perform migration
    success = migrator.migrate(dry_run=args.dry_run)
    
    if success:
        logger.info("\n✅ Migration completed successfully!")
        if not args.dry_run:
            logger.info(f"💾 Backup saved to: {migrator.backup_path}")
            logger.info(f"💡 To rollback: cp {migrator.backup_path} {migrator.rules_path}")
        sys.exit(0)
    else:
        logger.error("\n❌ Migration failed!")
        sys.exit(1)


if __name__ == '__main__':
    main()
