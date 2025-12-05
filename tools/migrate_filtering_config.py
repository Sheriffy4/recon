#!/usr/bin/env python3
# recon/tools/migrate_filtering_config.py

"""
Configuration Migration Tool for Runtime Packet Filtering

This tool helps migrate existing IP-based filtering configurations
to the new domain-based runtime filtering system.

Usage:
    python tools/migrate_filtering_config.py --file config.json
    python tools/migrate_filtering_config.py --directory config/
    python tools/migrate_filtering_config.py --validate config.json
    python tools/migrate_filtering_config.py --rollback backup_path config.json
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import List, Dict, Any

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.bypass.filtering.migration import ConfigurationMigrator, MigrationStatus, BackwardCompatibilityLayer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
LOG = logging.getLogger("MigrationTool")


def migrate_file(file_path: str, dry_run: bool = False) -> bool:
    """
    Migrate a single configuration file.
    
    Args:
        file_path: Path to the configuration file
        dry_run: If True, only analyze without making changes
        
    Returns:
        True if migration was successful, False otherwise
    """
    migrator = ConfigurationMigrator()
    
    if dry_run:
        LOG.info(f"DRY RUN: Analyzing {file_path}")
        
        # Load and analyze configuration
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            
            # Check if migration is needed
            if migrator._is_filter_config(config_data):
                LOG.info("  → Detected filter configuration")
                if 'target_ips' in config_data:
                    LOG.info("  → Contains IP-based filtering (migration needed)")
                else:
                    LOG.info("  → Already uses domain-based filtering")
            elif migrator._is_subdomain_config(config_data):
                LOG.info("  → Detected subdomain configuration")
                if 'runtime_filtering' not in config_data:
                    LOG.info("  → Missing runtime filtering section (migration needed)")
                else:
                    LOG.info("  → Already has runtime filtering section")
            elif migrator._is_engine_config(config_data):
                LOG.info("  → Detected engine configuration")
                if 'runtime_filtering' not in config_data:
                    LOG.info("  → Missing runtime filtering section (migration needed)")
                else:
                    LOG.info("  → Already has runtime filtering section")
            else:
                LOG.info("  → Unknown configuration format (runtime filtering will be added)")
            
            return True
            
        except Exception as e:
            LOG.error(f"Failed to analyze {file_path}: {e}")
            return False
    
    else:
        LOG.info(f"Migrating {file_path}")
        
        result = migrator.migrate_config_file(file_path)
        
        if result.status == MigrationStatus.COMPLETED:
            LOG.info(f"  ✓ {result.message}")
            if result.backup_path:
                LOG.info(f"  → Backup created: {result.backup_path}")
            return True
        else:
            LOG.error(f"  ✗ {result.message}")
            for error in result.errors:
                LOG.error(f"    - {error}")
            return False


def migrate_directory(directory_path: str, pattern: str = "*.json", dry_run: bool = False) -> bool:
    """
    Migrate all configuration files in a directory.
    
    Args:
        directory_path: Path to the directory
        pattern: File pattern to match
        dry_run: If True, only analyze without making changes
        
    Returns:
        True if all migrations were successful, False otherwise
    """
    migrator = ConfigurationMigrator()
    
    if dry_run:
        LOG.info(f"DRY RUN: Analyzing directory {directory_path}")
        
        config_path = Path(directory_path)
        config_files = list(config_path.glob(pattern))
        
        if not config_files:
            LOG.info(f"No files found matching pattern: {pattern}")
            return True
        
        success = True
        for config_file in config_files:
            if not migrate_file(str(config_file), dry_run=True):
                success = False
        
        return success
    
    else:
        LOG.info(f"Migrating directory {directory_path}")
        
        result = migrator.migrate_directory(directory_path, pattern)
        
        if result.status == MigrationStatus.COMPLETED:
            LOG.info(f"  ✓ {result.message}")
            for config_file in result.migrated_configs:
                LOG.info(f"    - {config_file}")
            return True
        else:
            LOG.error(f"  ✗ {result.message}")
            for error in result.errors:
                LOG.error(f"    - {error}")
            return False


def validate_migration(file_path: str) -> bool:
    """
    Validate a migrated configuration file.
    
    Args:
        file_path: Path to the configuration file
        
    Returns:
        True if validation passed, False otherwise
    """
    migrator = ConfigurationMigrator()
    
    LOG.info(f"Validating {file_path}")
    
    is_valid, errors = migrator.validate_migration(file_path)
    
    if is_valid:
        LOG.info("  ✓ Configuration is valid")
        return True
    else:
        LOG.error("  ✗ Configuration validation failed")
        for error in errors:
            LOG.error(f"    - {error}")
        return False


def rollback_migration(backup_path: str, target_path: str) -> bool:
    """
    Rollback a migration by restoring from backup.
    
    Args:
        backup_path: Path to the backup file
        target_path: Path where to restore the backup
        
    Returns:
        True if rollback was successful, False otherwise
    """
    migrator = ConfigurationMigrator()
    
    LOG.info(f"Rolling back {target_path} from {backup_path}")
    
    result = migrator.rollback_migration(backup_path, target_path)
    
    if result.status == MigrationStatus.ROLLED_BACK:
        LOG.info(f"  ✓ {result.message}")
        return True
    else:
        LOG.error(f"  ✗ {result.message}")
        for error in result.errors:
            LOG.error(f"    - {error}")
        return False


def show_migration_guide():
    """Display migration guide and best practices."""
    guide = """
MIGRATION GUIDE: IP-based to Runtime Packet Filtering

This tool helps migrate your existing configurations to use the new runtime
packet filtering system. Here's what you need to know:

WHAT CHANGES:
- IP-based filtering → Domain-based filtering
- Pre-resolved IPs → Runtime packet inspection
- WinDivert IP filters → Simple port-based filters + application logic

MIGRATION PROCESS:
1. Backup: Original configurations are automatically backed up
2. Convert: IP addresses are mapped to domain patterns where possible
3. Enhance: Runtime filtering settings are added
4. Validate: Migrated configurations are validated for correctness

MANUAL REVIEW NEEDED:
- IP addresses that cannot be automatically mapped to domains
- Custom filtering logic that may need adjustment
- Performance settings that may need tuning

BEST PRACTICES:
1. Run with --dry-run first to see what will change
2. Test migrated configurations in a development environment
3. Keep backups until you're confident the migration is successful
4. Use --validate to check migrated configurations

EXAMPLES:
  # Analyze a single file
  python tools/migrate_filtering_config.py --file config.json --dry-run
  
  # Migrate a single file
  python tools/migrate_filtering_config.py --file config.json
  
  # Migrate all JSON files in a directory
  python tools/migrate_filtering_config.py --directory config/
  
  # Validate a migrated configuration
  python tools/migrate_filtering_config.py --validate config.json
  
  # Rollback if needed
  python tools/migrate_filtering_config.py --rollback backup_file.json config.json

TROUBLESHOOTING:
- If migration fails, check the error messages for specific issues
- Use --validate to identify configuration problems
- Use --rollback to restore from backup if needed
- Check logs for detailed error information

For more information, see the runtime filtering documentation.
"""
    print(guide)


def main():
    """Main entry point for the migration tool."""
    parser = argparse.ArgumentParser(
        description="Migrate filtering configurations to runtime packet filtering",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Use --help-guide for detailed migration information"
    )
    
    # Main actions
    parser.add_argument('--file', '-f', help='Migrate a single configuration file')
    parser.add_argument('--directory', '-d', help='Migrate all files in a directory')
    parser.add_argument('--validate', '-v', help='Validate a migrated configuration file')
    parser.add_argument('--rollback', '-r', nargs=2, metavar=('BACKUP', 'TARGET'),
                       help='Rollback migration (backup_path target_path)')
    
    # Options
    parser.add_argument('--pattern', '-p', default='*.json',
                       help='File pattern for directory migration (default: *.json)')
    parser.add_argument('--dry-run', '-n', action='store_true',
                       help='Analyze configurations without making changes')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose logging')
    parser.add_argument('--help-guide', action='store_true',
                       help='Show detailed migration guide')
    
    args = parser.parse_args()
    
    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Show migration guide
    if args.help_guide:
        show_migration_guide()
        return 0
    
    # Validate arguments
    action_count = sum([
        bool(args.file),
        bool(args.directory),
        bool(args.validate),
        bool(args.rollback)
    ])
    
    if action_count == 0:
        parser.error("Must specify one action: --file, --directory, --validate, or --rollback")
    elif action_count > 1:
        parser.error("Can only specify one action at a time")
    
    # Execute requested action
    success = False
    
    try:
        if args.file:
            success = migrate_file(args.file, args.dry_run)
        elif args.directory:
            success = migrate_directory(args.directory, args.pattern, args.dry_run)
        elif args.validate:
            success = validate_migration(args.validate)
        elif args.rollback:
            backup_path, target_path = args.rollback
            success = rollback_migration(backup_path, target_path)
        
        if success:
            LOG.info("Operation completed successfully")
            return 0
        else:
            LOG.error("Operation failed")
            return 1
            
    except KeyboardInterrupt:
        LOG.info("Operation cancelled by user")
        return 1
    except Exception as e:
        LOG.error(f"Unexpected error: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())