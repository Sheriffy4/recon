# recon/core/bypass/filtering/migration.py

import json
import logging
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

from .config import FilterConfig, FilterMode

LOG = logging.getLogger("FilteringMigration")


class MigrationStatus(Enum):
    """Migration status enumeration."""

    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass
class MigrationResult:
    """Result of a migration operation."""

    status: MigrationStatus
    message: str
    backup_path: Optional[str] = None
    migrated_configs: List[str] = None
    errors: List[str] = None

    def __post_init__(self):
        if self.migrated_configs is None:
            self.migrated_configs = []
        if self.errors is None:
            self.errors = []


class ConfigurationMigrator:
    """
    Utility for migrating IP-based configurations to domain-based runtime filtering.

    Handles conversion of existing configurations that use IP addresses to
    new configurations that use domain names for runtime packet filtering.
    """

    def __init__(self, backup_dir: str = "config_backups"):
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(exist_ok=True)

    def migrate_config_file(self, config_path: str) -> MigrationResult:
        """
        Migrate a single configuration file from IP-based to domain-based format.

        Args:
            config_path: Path to the configuration file to migrate

        Returns:
            MigrationResult with migration status and details
        """
        config_file = Path(config_path)

        if not config_file.exists():
            return MigrationResult(
                status=MigrationStatus.FAILED,
                message=f"Configuration file not found: {config_path}",
                errors=[f"File does not exist: {config_path}"],
            )

        try:
            # Create backup
            backup_path = self._create_backup(config_file)

            # Load and analyze current config
            with open(config_file, "r", encoding="utf-8") as f:
                config_data = json.load(f)

            # Detect configuration type and migrate
            migration_result = self._migrate_config_data(config_data, config_file.name)

            if migration_result.status == MigrationStatus.COMPLETED:
                # Write migrated configuration
                with open(config_file, "w", encoding="utf-8") as f:
                    json.dump(migration_result.migrated_data, f, indent=2, ensure_ascii=False)

                migration_result.backup_path = str(backup_path)
                migration_result.migrated_configs = [str(config_file)]
                migration_result.message = f"Successfully migrated {config_file.name}"

                LOG.info(f"Migrated configuration: {config_path}")

            return migration_result

        except Exception as e:
            LOG.error(f"Failed to migrate {config_path}: {e}")
            return MigrationResult(
                status=MigrationStatus.FAILED,
                message=f"Migration failed: {str(e)}",
                errors=[str(e)],
            )

    def migrate_directory(self, config_dir: str, pattern: str = "*.json") -> MigrationResult:
        """
        Migrate all configuration files in a directory.

        Args:
            config_dir: Directory containing configuration files
            pattern: File pattern to match (default: *.json)

        Returns:
            MigrationResult with overall migration status
        """
        config_path = Path(config_dir)

        if not config_path.exists():
            return MigrationResult(
                status=MigrationStatus.FAILED,
                message=f"Configuration directory not found: {config_dir}",
                errors=[f"Directory does not exist: {config_dir}"],
            )

        config_files = list(config_path.glob(pattern))

        if not config_files:
            return MigrationResult(
                status=MigrationStatus.COMPLETED,
                message=f"No configuration files found matching pattern: {pattern}",
            )

        overall_result = MigrationResult(
            status=MigrationStatus.IN_PROGRESS, message="Migrating directory configurations"
        )

        for config_file in config_files:
            file_result = self.migrate_config_file(str(config_file))

            if file_result.status == MigrationStatus.COMPLETED:
                overall_result.migrated_configs.extend(file_result.migrated_configs)
            else:
                overall_result.errors.extend(file_result.errors)

        # Determine overall status
        if overall_result.errors:
            overall_result.status = MigrationStatus.FAILED
            overall_result.message = f"Migration completed with {len(overall_result.errors)} errors"
        else:
            overall_result.status = MigrationStatus.COMPLETED
            overall_result.message = (
                f"Successfully migrated {len(overall_result.migrated_configs)} files"
            )

        return overall_result

    def validate_migration(self, config_path: str) -> Tuple[bool, List[str]]:
        """
        Validate that a migrated configuration is correct.

        Args:
            config_path: Path to the migrated configuration file

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        config_file = Path(config_path)
        errors = []

        if not config_file.exists():
            errors.append(f"Configuration file not found: {config_path}")
            return False, errors

        try:
            with open(config_file, "r", encoding="utf-8") as f:
                config_data = json.load(f)

            # Validate structure based on configuration type
            if self._is_filter_config(config_data):
                errors.extend(self._validate_filter_config(config_data))
            elif self._is_subdomain_config(config_data):
                errors.extend(self._validate_subdomain_config(config_data))
            elif self._is_engine_config(config_data):
                errors.extend(self._validate_engine_config(config_data))
            else:
                errors.append("Unknown configuration format")

            return len(errors) == 0, errors

        except Exception as e:
            errors.append(f"Failed to validate configuration: {str(e)}")
            return False, errors

    def rollback_migration(self, backup_path: str, target_path: str) -> MigrationResult:
        """
        Rollback a migration by restoring from backup.

        Args:
            backup_path: Path to the backup file
            target_path: Path where to restore the backup

        Returns:
            MigrationResult with rollback status
        """
        backup_file = Path(backup_path)
        target_file = Path(target_path)

        if not backup_file.exists():
            return MigrationResult(
                status=MigrationStatus.FAILED,
                message=f"Backup file not found: {backup_path}",
                errors=[f"Backup does not exist: {backup_path}"],
            )

        try:
            shutil.copy2(backup_file, target_file)

            LOG.info(f"Rolled back configuration: {target_path}")

            return MigrationResult(
                status=MigrationStatus.ROLLED_BACK,
                message=f"Successfully rolled back {target_file.name}",
                migrated_configs=[str(target_file)],
            )

        except Exception as e:
            LOG.error(f"Failed to rollback {target_path}: {e}")
            return MigrationResult(
                status=MigrationStatus.FAILED, message=f"Rollback failed: {str(e)}", errors=[str(e)]
            )

    def _create_backup(self, config_file: Path) -> Path:
        """Create a backup of the configuration file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"{config_file.stem}_{timestamp}{config_file.suffix}"
        backup_path = self.backup_dir / backup_name

        shutil.copy2(config_file, backup_path)
        LOG.info(f"Created backup: {backup_path}")

        return backup_path

    def _migrate_config_data(self, config_data: Dict[str, Any], filename: str) -> MigrationResult:
        """
        Migrate configuration data based on its type.

        Args:
            config_data: Configuration data to migrate
            filename: Name of the configuration file

        Returns:
            MigrationResult with migrated data
        """
        result = MigrationResult(
            status=MigrationStatus.IN_PROGRESS, message="Analyzing configuration format"
        )

        try:
            if self._is_filter_config(config_data):
                result.migrated_data = self._migrate_filter_config(config_data)
            elif self._is_subdomain_config(config_data):
                result.migrated_data = self._migrate_subdomain_config(config_data)
            elif self._is_engine_config(config_data):
                result.migrated_data = self._migrate_engine_config(config_data)
            else:
                # Unknown format - add runtime filtering section
                result.migrated_data = self._add_runtime_filtering_section(config_data)

            result.status = MigrationStatus.COMPLETED
            result.message = f"Successfully migrated {filename}"

        except Exception as e:
            result.status = MigrationStatus.FAILED
            result.message = f"Failed to migrate {filename}: {str(e)}"
            result.errors = [str(e)]

        return result

    def _is_filter_config(self, config_data: Dict[str, Any]) -> bool:
        """Check if configuration is a filter configuration."""
        return any(key in config_data for key in ["target_ips", "target_domains", "filter_mode"])

    def _is_subdomain_config(self, config_data: Dict[str, Any]) -> bool:
        """Check if configuration is a subdomain configuration."""
        return "subdomain_strategies" in config_data

    def _is_engine_config(self, config_data: Dict[str, Any]) -> bool:
        """Check if configuration is an engine configuration."""
        return any(key in config_data for key in ["profiles", "dns", "timeouts"])

    def _migrate_filter_config(self, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Migrate filter configuration from IP-based to domain-based.

        Converts target_ips to target_domains and adds runtime filtering settings.
        """
        migrated = config_data.copy()

        # Convert IP addresses to domains if possible
        if "target_ips" in config_data:
            target_ips = config_data["target_ips"]

            # For migration, we'll convert known IP patterns to domain patterns
            # In practice, users would need to provide domain mappings
            migrated["target_domains"] = self._convert_ips_to_domains(target_ips)

            # Keep original IPs as backup reference
            migrated["legacy_target_ips"] = target_ips

            # Remove old IP-based configuration
            del migrated["target_ips"]

        # Add runtime filtering configuration
        migrated["runtime_filtering"] = {
            "enabled": True,
            "mode": config_data.get("filter_mode", "blacklist"),
            "cache_size": 1000,
            "cache_ttl": 300,
            "enable_wildcards": True,
            "enable_subdomains": True,
        }

        # Add migration metadata
        migrated["_migration"] = {
            "migrated_at": datetime.now().isoformat(),
            "migrated_from": "ip_based_filtering",
            "migration_version": "1.0",
        }

        return migrated

    def _migrate_subdomain_config(self, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Migrate subdomain configuration to support runtime filtering.

        Adds runtime filtering metadata to subdomain strategies.
        """
        migrated = config_data.copy()

        # Add runtime filtering support to each subdomain strategy
        if "subdomain_strategies" in migrated:
            for domain, strategy_data in migrated["subdomain_strategies"].items():
                # Add runtime filtering metadata
                strategy_data["runtime_filtering"] = {
                    "domain_pattern": domain,
                    "enable_wildcards": True,
                    "custom_sni": strategy_data.get("strategy", {})
                    .get("parameters", {})
                    .get("fake_sni", False),
                }

        # Add global runtime filtering configuration
        migrated["runtime_filtering"] = {
            "enabled": True,
            "mode": "blacklist",  # Subdomain configs typically use blacklist mode
            "cache_size": 1000,
            "cache_ttl": 300,
        }

        # Add migration metadata
        migrated["_migration"] = {
            "migrated_at": datetime.now().isoformat(),
            "migrated_from": "subdomain_config",
            "migration_version": "1.0",
        }

        return migrated

    def _migrate_engine_config(self, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Migrate engine configuration to support runtime filtering.

        Adds runtime filtering settings to engine configuration.
        """
        migrated = config_data.copy()

        # Add runtime filtering configuration section
        migrated["runtime_filtering"] = {
            "enabled": True,
            "mode": "none",  # Engine configs typically don't filter by default
            "performance": {
                "cache_size": 1000,
                "cache_ttl": 300,
                "max_packet_rate": 1000,
                "memory_limit_mb": 100,
            },
            "extraction": {
                "enable_sni_extraction": True,
                "enable_host_extraction": True,
                "enable_wildcards": True,
                "enable_subdomains": True,
            },
        }

        # Add migration metadata
        migrated["_migration"] = {
            "migrated_at": datetime.now().isoformat(),
            "migrated_from": "engine_config",
            "migration_version": "1.0",
        }

        return migrated

    def _add_runtime_filtering_section(self, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Add runtime filtering section to unknown configuration format.
        """
        migrated = config_data.copy()

        # Add basic runtime filtering configuration
        migrated["runtime_filtering"] = {
            "enabled": False,  # Disabled by default for unknown formats
            "mode": "none",
            "cache_size": 1000,
            "cache_ttl": 300,
        }

        # Add migration metadata
        migrated["_migration"] = {
            "migrated_at": datetime.now().isoformat(),
            "migrated_from": "unknown_format",
            "migration_version": "1.0",
            "note": "Runtime filtering added to unknown configuration format",
        }

        return migrated

    def _convert_ips_to_domains(self, target_ips: List[str]) -> List[str]:
        """
        Convert IP addresses to domain patterns where possible.

        This is a best-effort conversion. In practice, users would need to
        provide IP-to-domain mappings for accurate migration.
        """
        domains = []

        # Common IP ranges to domain mappings
        ip_to_domain_mappings = {
            # Google/YouTube IP ranges
            "142.250.": "*.google.com",
            "172.217.": "*.google.com",
            "216.58.": "*.google.com",
            # Facebook/Instagram IP ranges
            "31.13.": "*.facebook.com",
            "157.240.": "*.facebook.com",
            # Twitter IP ranges
            "104.244.": "*.twitter.com",
            "199.16.": "*.twitter.com",
            # Cloudflare IP ranges
            "104.16.": "*.cloudflare.com",
            "172.64.": "*.cloudflare.com",
        }

        for ip in target_ips:
            # Try to map IP to known domain patterns
            mapped = False
            for ip_prefix, domain_pattern in ip_to_domain_mappings.items():
                if ip.startswith(ip_prefix):
                    if domain_pattern not in domains:
                        domains.append(domain_pattern)
                    mapped = True
                    break

            # If no mapping found, create a generic pattern
            if not mapped:
                # For unmapped IPs, suggest manual review
                domains.append(f"# MANUAL_REVIEW_NEEDED: {ip}")

        return domains

    def _validate_filter_config(self, config_data: Dict[str, Any]) -> List[str]:
        """Validate migrated filter configuration."""
        errors = []

        if "runtime_filtering" not in config_data:
            errors.append("Missing runtime_filtering section")
        else:
            rf_config = config_data["runtime_filtering"]

            if "enabled" not in rf_config:
                errors.append("Missing runtime_filtering.enabled")

            if "mode" not in rf_config:
                errors.append("Missing runtime_filtering.mode")
            elif rf_config["mode"] not in ["none", "blacklist", "whitelist"]:
                errors.append(f"Invalid runtime_filtering.mode: {rf_config['mode']}")

        if "target_domains" in config_data:
            domains = config_data["target_domains"]
            if not isinstance(domains, list):
                errors.append("target_domains must be a list")

        return errors

    def _validate_subdomain_config(self, config_data: Dict[str, Any]) -> List[str]:
        """Validate migrated subdomain configuration."""
        errors = []

        if "subdomain_strategies" not in config_data:
            errors.append("Missing subdomain_strategies section")

        if "runtime_filtering" not in config_data:
            errors.append("Missing runtime_filtering section")

        return errors

    def _validate_engine_config(self, config_data: Dict[str, Any]) -> List[str]:
        """Validate migrated engine configuration."""
        errors = []

        if "runtime_filtering" not in config_data:
            errors.append("Missing runtime_filtering section")
        else:
            rf_config = config_data["runtime_filtering"]

            if "performance" not in rf_config:
                errors.append("Missing runtime_filtering.performance section")

            if "extraction" not in rf_config:
                errors.append("Missing runtime_filtering.extraction section")

        return errors


class BackwardCompatibilityLayer:
    """
    Provides backward compatibility for existing IP-based configurations.

    This layer allows existing code to continue working while gradually
    migrating to the new runtime filtering system.
    """

    def __init__(self):
        self.legacy_mode = False

    def enable_legacy_mode(self) -> None:
        """Enable legacy IP-based filtering mode."""
        self.legacy_mode = True
        LOG.info("Legacy compatibility mode enabled")

    def disable_legacy_mode(self) -> None:
        """Disable legacy IP-based filtering mode."""
        self.legacy_mode = False
        LOG.info("Legacy compatibility mode disabled")

    def is_legacy_config(self, config_data: Dict[str, Any]) -> bool:
        """Check if configuration uses legacy IP-based format."""
        return "target_ips" in config_data and "runtime_filtering" not in config_data

    def convert_legacy_call(self, target_ips: Set[str], target_ports: Set[int]) -> Dict[str, Any]:
        """
        Convert legacy function call parameters to new format.

        Args:
            target_ips: Legacy IP addresses
            target_ports: Target ports

        Returns:
            Dictionary with converted parameters for new system
        """
        # In legacy mode, we still use IP-based filtering
        if self.legacy_mode:
            return {
                "use_legacy_filtering": True,
                "target_ips": target_ips,
                "target_ports": target_ports,
            }

        # Convert to runtime filtering parameters
        return {
            "use_legacy_filtering": False,
            "target_ports": target_ports,
            "filter_mode": "none",  # No domain filtering for converted calls
            "domains": set(),  # Empty domain set
        }
