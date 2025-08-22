"""
Main configuration management interface for bypass engine.
"""
import json
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime
from recon.core.bypass.config.config_models import PoolConfiguration, ConfigurationVersion, MigrationResult, StrategyPool, BypassStrategy
from recon.core.bypass.config.config_migrator import ConfigurationMigrator
from recon.core.bypass.config.config_validator import ConfigurationValidator, ValidationError
from recon.core.bypass.config.backup_manager import BackupManager

class ConfigurationManager:
    """Main interface for configuration management."""

    def __init__(self, config_dir: str='config', backup_dir: str='config_backups'):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True)
        self.migrator = ConfigurationMigrator()
        self.validator = ConfigurationValidator()
        self.backup_manager = BackupManager(backup_dir)
        self.default_config_path = self.config_dir / 'pool_config.json'
        self.legacy_config_path = self.config_dir / 'best_strategy.json'

    def load_configuration(self, config_path: Optional[str]=None) -> PoolConfiguration:
        """
        Load configuration from file.

        Args:
            config_path: Path to configuration file (uses default if not provided)

        Returns:
            PoolConfiguration object
        """
        if config_path is None:
            config_path = str(self.default_config_path)
        config_path = Path(config_path)
        if not config_path.exists():
            if self.legacy_config_path.exists():
                print(f'Legacy configuration found, migrating to {config_path}')
                migration_result = self.migrate_legacy_configuration(str(self.legacy_config_path), str(config_path))
                if not migration_result.success:
                    raise RuntimeError(f'Migration failed: {migration_result.errors}')
            else:
                return self._create_default_configuration()
        with open(config_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        config = PoolConfiguration.from_dict(data)
        validation_errors = self.validator.validate_configuration(config)
        error_count = len([e for e in validation_errors if e.level == 'error'])
        if error_count > 0:
            print(f'Warning: Configuration has {error_count} validation errors')
            for error in validation_errors:
                if error.level == 'error':
                    print(f'  {error}')
        return config

    def save_configuration(self, config: PoolConfiguration, config_path: Optional[str]=None, create_backup: bool=True) -> None:
        """
        Save configuration to file.

        Args:
            config: Configuration to save
            config_path: Path to save configuration (uses default if not provided)
            create_backup: Whether to create backup of existing file
        """
        if config_path is None:
            config_path = str(self.default_config_path)
        config_path = Path(config_path)
        validation_errors = self.validator.validate_configuration(config)
        error_count = len([e for e in validation_errors if e.level == 'error'])
        if error_count > 0:
            raise ValueError(f'Configuration has {error_count} validation errors')
        if create_backup and config_path.exists():
            backup_id = self.backup_manager.create_backup(str(config_path), f'Auto-backup before save at {datetime.now().isoformat()}')
            print(f'Created backup: {backup_id}')
        config.updated_at = datetime.now()
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, 'w', encoding='utf-8') as f:
            f.write(config.to_json())

    def migrate_legacy_configuration(self, legacy_path: str, target_path: Optional[str]=None) -> MigrationResult:
        """
        Migrate legacy configuration to new format.

        Args:
            legacy_path: Path to legacy configuration
            target_path: Path for migrated configuration

        Returns:
            Migration result
        """
        backup_id = self.backup_manager.create_backup(legacy_path, 'Backup before migration to pool format', ConfigurationVersion.LEGACY_V1)
        result = self.migrator.migrate_legacy_to_pool(legacy_path, target_path)
        result.backup_path = backup_id
        return result

    def validate_configuration_file(self, config_path: str) -> List[ValidationError]:
        """
        Validate configuration file.

        Args:
            config_path: Path to configuration file

        Returns:
            List of validation errors
        """
        return self.validator.validate_file(config_path)

    def get_validation_report(self, config_path: str) -> Dict[str, Any]:
        """
        Get detailed validation report for configuration.

        Args:
            config_path: Path to configuration file

        Returns:
            Validation report
        """
        errors = self.validate_configuration_file(config_path)
        summary = self.validator.get_validation_summary(errors)
        return {'summary': summary, 'errors': [str(e) for e in errors if e.level == 'error'], 'warnings': [str(e) for e in errors if e.level == 'warning'], 'info': [str(e) for e in errors if e.level == 'info']}

    def create_pool(self, pool_id: str, name: str, strategy: BypassStrategy, description: str='', domains: Optional[List[str]]=None) -> StrategyPool:
        """
        Create new strategy pool.

        Args:
            pool_id: Unique pool identifier
            name: Human-readable pool name
            strategy: Bypass strategy for the pool
            description: Pool description
            domains: List of domains for the pool

        Returns:
            Created strategy pool
        """
        return StrategyPool(id=pool_id, name=name, description=description, strategy=strategy, domains=domains or [], priority=1)

    def add_pool_to_configuration(self, config: PoolConfiguration, pool: StrategyPool) -> None:
        """
        Add pool to configuration.

        Args:
            config: Configuration to modify
            pool: Pool to add
        """
        existing_ids = {p.id for p in config.pools}
        if pool.id in existing_ids:
            raise ValueError(f"Pool ID '{pool.id}' already exists")
        config.pools.append(pool)
        config.updated_at = datetime.now()

    def remove_pool_from_configuration(self, config: PoolConfiguration, pool_id: str) -> None:
        """
        Remove pool from configuration.

        Args:
            config: Configuration to modify
            pool_id: ID of pool to remove
        """
        config.pools = [p for p in config.pools if p.id != pool_id]
        if config.default_pool == pool_id:
            config.default_pool = config.pools[0].id if config.pools else None
        config.updated_at = datetime.now()

    def get_pool_by_id(self, config: PoolConfiguration, pool_id: str) -> Optional[StrategyPool]:
        """
        Get pool by ID.

        Args:
            config: Configuration to search
            pool_id: Pool ID to find

        Returns:
            Strategy pool or None if not found
        """
        for pool in config.pools:
            if pool.id == pool_id:
                return pool
        return None

    def update_pool_strategy(self, config: PoolConfiguration, pool_id: str, strategy: BypassStrategy) -> None:
        """
        Update strategy for a pool.

        Args:
            config: Configuration to modify
            pool_id: ID of pool to update
            strategy: New strategy
        """
        pool = self.get_pool_by_id(config, pool_id)
        if not pool:
            raise ValueError(f"Pool '{pool_id}' not found")
        pool.strategy = strategy
        pool.updated_at = datetime.now()
        config.updated_at = datetime.now()

    def _create_default_configuration(self) -> PoolConfiguration:
        """Create default configuration."""
        default_strategy = BypassStrategy(id='default_strategy', name='Default Bypass Strategy', attacks=['tcp_fragmentation', 'http_host_case'], parameters={'split_pos': 2, 'split_count': 2}, target_ports=[80, 443])
        default_pool = StrategyPool(id='default', name='Default Pool', description='Default strategy pool for all domains', strategy=default_strategy, domains=['*'], priority=1)
        fallback_strategy = BypassStrategy(id='fallback', name='Fallback Strategy', attacks=['tcp_fragmentation'], parameters={'split_pos': 1}, target_ports=[443])
        return PoolConfiguration(version=ConfigurationVersion.POOL_V1, pools=[default_pool], default_pool='default', fallback_strategy=fallback_strategy, metadata={'created_by': 'ConfigurationManager', 'description': 'Default configuration created automatically'})

    def export_configuration(self, config: PoolConfiguration, export_path: str, format: str='json') -> None:
        """
        Export configuration to file.

        Args:
            config: Configuration to export
            export_path: Path for exported file
            format: Export format ('json' or 'yaml')
        """
        export_path = Path(export_path)
        export_path.parent.mkdir(parents=True, exist_ok=True)
        if format.lower() == 'json':
            with open(export_path, 'w', encoding='utf-8') as f:
                f.write(config.to_json())
        else:
            raise ValueError(f'Unsupported export format: {format}')

    def import_configuration(self, import_path: str) -> PoolConfiguration:
        """
        Import configuration from file.

        Args:
            import_path: Path to configuration file to import

        Returns:
            Imported configuration
        """
        import_path = Path(import_path)
        if not import_path.exists():
            raise FileNotFoundError(f'Import file not found: {import_path}')
        with open(import_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        config = PoolConfiguration.from_dict(data)
        validation_errors = self.validator.validate_configuration(config)
        error_count = len([e for e in validation_errors if e.level == 'error'])
        if error_count > 0:
            raise ValueError(f'Imported configuration has {error_count} validation errors')
        return config

    def get_configuration_info(self, config_path: Optional[str]=None) -> Dict[str, Any]:
        """
        Get information about configuration file.

        Args:
            config_path: Path to configuration file

        Returns:
            Configuration information
        """
        if config_path is None:
            config_path = str(self.default_config_path)
        config_path = Path(config_path)
        info = {'path': str(config_path.absolute()), 'exists': config_path.exists(), 'size': 0, 'modified': None, 'version': None, 'pools': 0, 'domains': 0}
        if config_path.exists():
            stat = config_path.stat()
            info['size'] = stat.st_size
            info['modified'] = datetime.fromtimestamp(stat.st_mtime).isoformat()
            try:
                config = self.load_configuration(str(config_path))
                info['version'] = config.version.value
                info['pools'] = len(config.pools)
                info['domains'] = sum((len(pool.domains) for pool in config.pools))
            except Exception as e:
                info['error'] = str(e)
        return info