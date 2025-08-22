"""
Configuration backup and restore functionality.
"""
import json
import shutil
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid
from recon.core.bypass.config.config_models import ConfigurationBackup, ConfigurationVersion

class BackupManager:
    """Manages configuration backups and restore operations."""

    def __init__(self, backup_dir: str='config_backups'):
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(exist_ok=True)
        self.metadata_file = self.backup_dir / 'backup_metadata.json'
        self._load_metadata()

    def _load_metadata(self) -> None:
        """Load backup metadata from file."""
        self.backups = {}
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for backup_data in data.get('backups', []):
                    backup = ConfigurationBackup.from_dict(backup_data)
                    self.backups[backup.id] = backup
            except Exception as e:
                print(f'Warning: Could not load backup metadata: {e}')

    def _save_metadata(self) -> None:
        """Save backup metadata to file."""
        try:
            data = {'backups': [backup.to_dict() for backup in self.backups.values()], 'last_updated': datetime.now().isoformat()}
            with open(self.metadata_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f'Warning: Could not save backup metadata: {e}')

    def create_backup(self, config_path: str, description: str='', version: Optional[ConfigurationVersion]=None) -> str:
        """
        Create backup of configuration file.

        Args:
            config_path: Path to configuration file to backup
            description: Optional description for the backup
            version: Configuration version (auto-detected if not provided)

        Returns:
            Backup ID
        """
        config_path = Path(config_path)
        if not config_path.exists():
            raise FileNotFoundError(f'Configuration file not found: {config_path}')
        backup_id = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        backup_filename = f'{backup_id}_{config_path.name}'
        backup_path = self.backup_dir / backup_filename
        if version is None:
            version = self._detect_version(config_path)
        shutil.copy2(config_path, backup_path)
        backup = ConfigurationBackup(id=backup_id, original_path=str(config_path.absolute()), backup_path=str(backup_path.absolute()), version=version, created_at=datetime.now(), description=description)
        self.backups[backup_id] = backup
        self._save_metadata()
        return backup_id

    def _detect_version(self, config_path: Path) -> ConfigurationVersion:
        """Detect configuration version from file content."""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if 'version' in data:
                return ConfigurationVersion(data['version'])
            if 'pools' in data:
                return ConfigurationVersion.POOL_V1
            if 'strategy' in data and 'result_status' in data:
                return ConfigurationVersion.LEGACY_V1
            return ConfigurationVersion.LEGACY_V1
        except Exception:
            return ConfigurationVersion.LEGACY_V1

    def restore_backup(self, backup_id: str, target_path: Optional[str]=None) -> str:
        """
        Restore configuration from backup.

        Args:
            backup_id: ID of backup to restore
            target_path: Target path for restored file (uses original path if not provided)

        Returns:
            Path where file was restored
        """
        if backup_id not in self.backups:
            raise ValueError(f'Backup not found: {backup_id}')
        backup = self.backups[backup_id]
        backup_path = Path(backup.backup_path)
        if not backup_path.exists():
            raise FileNotFoundError(f'Backup file not found: {backup_path}')
        if target_path is None:
            target_path = backup.original_path
        target_path = Path(target_path)
        if target_path.exists():
            current_backup_id = self.create_backup(str(target_path), f'Auto-backup before restore of {backup_id}')
            print(f'Created backup of current file: {current_backup_id}')
        target_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(backup_path, target_path)
        return str(target_path.absolute())

    def list_backups(self, config_path: Optional[str]=None) -> List[ConfigurationBackup]:
        """
        List available backups.

        Args:
            config_path: Filter backups for specific configuration file

        Returns:
            List of backup metadata
        """
        backups = list(self.backups.values())
        if config_path:
            config_path = str(Path(config_path).absolute())
            backups = [b for b in backups if b.original_path == config_path]
        backups.sort(key=lambda b: b.created_at, reverse=True)
        return backups

    def delete_backup(self, backup_id: str) -> None:
        """
        Delete backup.

        Args:
            backup_id: ID of backup to delete
        """
        if backup_id not in self.backups:
            raise ValueError(f'Backup not found: {backup_id}')
        backup = self.backups[backup_id]
        backup_path = Path(backup.backup_path)
        if backup_path.exists():
            backup_path.unlink()
        del self.backups[backup_id]
        self._save_metadata()

    def cleanup_old_backups(self, keep_count: int=10, keep_days: int=30) -> int:
        """
        Clean up old backups.

        Args:
            keep_count: Number of recent backups to keep per configuration
            keep_days: Number of days to keep backups

        Returns:
            Number of backups deleted
        """
        deleted_count = 0
        cutoff_date = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        cutoff_date = cutoff_date.replace(day=cutoff_date.day - keep_days)
        by_path = {}
        for backup in self.backups.values():
            path = backup.original_path
            if path not in by_path:
                by_path[path] = []
            by_path[path].append(backup)
        for path, backups in by_path.items():
            backups.sort(key=lambda b: b.created_at, reverse=True)
            to_keep = backups[:keep_count]
            to_check = backups[keep_count:]
            for backup in to_check:
                if backup.created_at < cutoff_date:
                    try:
                        self.delete_backup(backup.id)
                        deleted_count += 1
                    except Exception as e:
                        print(f'Warning: Could not delete backup {backup.id}: {e}')
        return deleted_count

    def get_backup_info(self, backup_id: str) -> Dict[str, Any]:
        """
        Get detailed backup information.

        Args:
            backup_id: Backup ID

        Returns:
            Backup information dictionary
        """
        if backup_id not in self.backups:
            raise ValueError(f'Backup not found: {backup_id}')
        backup = self.backups[backup_id]
        backup_path = Path(backup.backup_path)
        info = backup.to_dict()
        info.update({'file_exists': backup_path.exists(), 'file_size': backup_path.stat().st_size if backup_path.exists() else 0, 'age_days': (datetime.now() - backup.created_at).days})
        return info

    def verify_backups(self) -> Dict[str, Any]:
        """
        Verify integrity of all backups.

        Returns:
            Verification report
        """
        report = {'total_backups': len(self.backups), 'valid_backups': 0, 'missing_files': [], 'corrupted_files': [], 'orphaned_files': []}
        for backup_id, backup in self.backups.items():
            backup_path = Path(backup.backup_path)
            if not backup_path.exists():
                report['missing_files'].append(backup_id)
                continue
            try:
                with open(backup_path, 'r', encoding='utf-8') as f:
                    json.load(f)
                report['valid_backups'] += 1
            except Exception:
                report['corrupted_files'].append(backup_id)
        if self.backup_dir.exists():
            known_files = {Path(b.backup_path).name for b in self.backups.values()}
            known_files.add(self.metadata_file.name)
            for file_path in self.backup_dir.iterdir():
                if file_path.is_file() and file_path.name not in known_files:
                    report['orphaned_files'].append(str(file_path))
        return report

    def export_backup(self, backup_id: str, export_path: str) -> None:
        """
        Export backup to external location.

        Args:
            backup_id: Backup ID to export
            export_path: Path where to export the backup
        """
        if backup_id not in self.backups:
            raise ValueError(f'Backup not found: {backup_id}')
        backup = self.backups[backup_id]
        backup_path = Path(backup.backup_path)
        export_path = Path(export_path)
        if not backup_path.exists():
            raise FileNotFoundError(f'Backup file not found: {backup_path}')
        export_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(backup_path, export_path)
        metadata_export = export_path.with_suffix('.metadata.json')
        with open(metadata_export, 'w', encoding='utf-8') as f:
            json.dump(backup.to_dict(), f, indent=2, ensure_ascii=False)