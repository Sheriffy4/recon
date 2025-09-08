"""
Tests for configuration migration and management functionality.
"""

import json
import tempfile
import pytest
from pathlib import Path
from core.bypass.config.config_models import (
    PoolConfiguration,
    BypassStrategy,
    StrategyPool,
    ConfigurationVersion,
)
from core.bypass.config.config_migrator import ConfigurationMigrator
from core.bypass.config.config_validator import ConfigurationValidator
from core.bypass.config.config_manager import ConfigurationManager
from core.bypass.config.backup_manager import BackupManager


class TestConfigurationMigrator:
    """Test configuration migration functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.migrator = ConfigurationMigrator()
        self.temp_dir = tempfile.mkdtemp()

    def test_migrate_legacy_to_pool_success(self):
        """Test successful migration from legacy to pool format."""
        legacy_config = {
            "strategy": "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-pos=4",
            "result_status": "PARTIAL_SUCCESS",
            "successful_sites": 3,
            "total_sites": 5,
            "success_rate": 0.6,
            "avg_latency_ms": 250.5,
            "fingerprint_used": True,
            "dpi_type": "roskomnadzor",
            "dpi_confidence": 0.8,
        }
        legacy_path = Path(self.temp_dir) / "legacy.json"
        with open(legacy_path, "w") as f:
            json.dump(legacy_config, f)
        target_path = Path(self.temp_dir) / "pool_config.json"
        result = self.migrator.migrate_legacy_to_pool(
            str(legacy_path), str(target_path)
        )
        assert result.success
        assert result.source_version == ConfigurationVersion.LEGACY_V1
        assert result.target_version == ConfigurationVersion.POOL_V1
        assert result.migrated_pools > 0
        assert len(result.errors) == 0
        assert target_path.exists()
        with open(target_path, "r") as f:
            pool_data = json.load(f)
        assert "pools" in pool_data
        assert "version" in pool_data
        assert pool_data["version"] == ConfigurationVersion.POOL_V1.value

    def test_parse_zapret_strategy(self):
        """Test parsing of zapret strategy strings."""
        strategy_str = "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-pos=4 --dpi-desync-fooling=badsum"
        strategy = self.migrator._parse_zapret_strategy(strategy_str)
        assert isinstance(strategy, BypassStrategy)
        assert (
            "tcp_multisplit" in strategy.attacks
            or "tcp_fragmentation" in strategy.attacks
        )
        assert "tcp_bad_checksum" in strategy.attacks
        assert strategy.parameters.get("split_count") == 5
        assert strategy.parameters.get("split_pos") == 4

    def test_migrate_goodbyedpi_config(self):
        """Test migration of goodbyedpi configuration."""
        goodbyedpi_params = ["-p", "-r", "-s", "-f"]
        config = self.migrator.migrate_goodbyedpi_config(goodbyedpi_params)
        assert isinstance(config, PoolConfiguration)
        assert len(config.pools) == 1
        assert config.pools[0].strategy.compatibility_mode == "goodbyedpi"
        assert len(config.pools[0].strategy.attacks) > 0

    def test_migrate_zapret_config(self):
        """Test migration of zapret configuration string."""
        zapret_config = "--dpi-desync=fake --dpi-desync-fooling=md5sig"
        config = self.migrator.migrate_zapret_config(zapret_config)
        assert isinstance(config, PoolConfiguration)
        assert len(config.pools) == 1
        assert "tcp_fake_packet" in config.pools[0].strategy.attacks
        assert "tcp_md5_signature" in config.pools[0].strategy.attacks

    def test_validation_after_migration(self):
        """Test that migrated configurations are valid."""
        legacy_config = {
            "strategy": "--dpi-desync=multisplit --dpi-desync-split-count=3",
            "result_status": "SUCCESS",
            "success_rate": 0.9,
        }
        legacy_path = Path(self.temp_dir) / "legacy.json"
        with open(legacy_path, "w") as f:
            json.dump(legacy_config, f)
        target_path = Path(self.temp_dir) / "migrated.json"
        result = self.migrator.migrate_legacy_to_pool(
            str(legacy_path), str(target_path)
        )
        assert result.success
        validation_issues = self.migrator.validate_migration(
            str(legacy_path), str(target_path)
        )
        assert len(validation_issues) == 0


class TestConfigurationValidator:
    """Test configuration validation functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.validator = ConfigurationValidator()

    def test_validate_valid_configuration(self):
        """Test validation of valid configuration."""
        strategy = BypassStrategy(
            id="test_strategy",
            name="Test Strategy",
            attacks=["tcp_fragmentation", "http_host_case"],
            parameters={"split_pos": 2},
            target_ports=[443],
        )
        pool = StrategyPool(
            id="test_pool",
            name="Test Pool",
            description="Test pool",
            strategy=strategy,
            domains=["example.com"],
            priority=1,
        )
        config = PoolConfiguration(
            version=ConfigurationVersion.POOL_V1, pools=[pool], default_pool="test_pool"
        )
        errors = self.validator.validate_configuration(config)
        error_count = len([e for e in errors if e.level == "error"])
        assert error_count == 0

    def test_validate_invalid_attacks(self):
        """Test validation catches invalid attacks."""
        strategy = BypassStrategy(
            id="test_strategy",
            name="Test Strategy",
            attacks=["invalid_attack", "another_invalid"],
            target_ports=[443],
        )
        pool = StrategyPool(
            id="test_pool",
            name="Test Pool",
            description="Test pool",
            strategy=strategy,
            domains=["example.com"],
        )
        config = PoolConfiguration(version=ConfigurationVersion.POOL_V1, pools=[pool])
        errors = self.validator.validate_configuration(config)
        warning_count = len(
            [
                e
                for e in errors
                if e.level == "warning" and "Unknown attack" in e.message
            ]
        )
        assert warning_count >= 2

    def test_validate_duplicate_pool_ids(self):
        """Test validation catches duplicate pool IDs."""
        strategy = BypassStrategy(
            id="test_strategy",
            name="Test Strategy",
            attacks=["tcp_fragmentation"],
            target_ports=[443],
        )
        pool1 = StrategyPool(
            id="duplicate_id",
            name="Pool 1",
            description="First pool",
            strategy=strategy,
            domains=["example.com"],
        )
        pool2 = StrategyPool(
            id="duplicate_id",
            name="Pool 2",
            description="Second pool",
            strategy=strategy,
            domains=["test.com"],
        )
        config = PoolConfiguration(
            version=ConfigurationVersion.POOL_V1, pools=[pool1, pool2]
        )
        errors = self.validator.validate_configuration(config)
        error_count = len(
            [
                e
                for e in errors
                if e.level == "error" and "Duplicate pool ID" in e.message
            ]
        )
        assert error_count >= 1

    def test_validate_invalid_default_pool(self):
        """Test validation catches invalid default pool reference."""
        strategy = BypassStrategy(
            id="test_strategy",
            name="Test Strategy",
            attacks=["tcp_fragmentation"],
            target_ports=[443],
        )
        pool = StrategyPool(
            id="existing_pool",
            name="Existing Pool",
            description="Pool that exists",
            strategy=strategy,
            domains=["example.com"],
        )
        config = PoolConfiguration(
            version=ConfigurationVersion.POOL_V1,
            pools=[pool],
            default_pool="nonexistent_pool",
        )
        errors = self.validator.validate_configuration(config)
        error_count = len(
            [e for e in errors if e.level == "error" and "Default pool" in e.message]
        )
        assert error_count >= 1

    def test_validate_invalid_ports(self):
        """Test validation catches invalid port numbers."""
        strategy = BypassStrategy(
            id="test_strategy",
            name="Test Strategy",
            attacks=["tcp_fragmentation"],
            target_ports=[0, 70000, -1],
        )
        pool = StrategyPool(
            id="test_pool",
            name="Test Pool",
            description="Test pool",
            strategy=strategy,
            domains=["example.com"],
        )
        config = PoolConfiguration(version=ConfigurationVersion.POOL_V1, pools=[pool])
        errors = self.validator.validate_configuration(config)
        error_count = len(
            [e for e in errors if e.level == "error" and "Invalid port" in e.message]
        )
        assert error_count >= 3


class TestBackupManager:
    """Test backup management functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.backup_manager = BackupManager(str(Path(self.temp_dir) / "backups"))

    def test_create_backup(self):
        """Test creating configuration backup."""
        config_data = {"test": "data", "version": "pool_v1"}
        config_path = Path(self.temp_dir) / "test_config.json"
        with open(config_path, "w") as f:
            json.dump(config_data, f)
        backup_id = self.backup_manager.create_backup(str(config_path), "Test backup")
        assert backup_id is not None
        assert backup_id in self.backup_manager.backups
        backup = self.backup_manager.backups[backup_id]
        assert backup.description == "Test backup"
        assert Path(backup.backup_path).exists()

    def test_restore_backup(self):
        """Test restoring configuration from backup."""
        original_data = {"original": "data"}
        original_path = Path(self.temp_dir) / "original.json"
        with open(original_path, "w") as f:
            json.dump(original_data, f)
        backup_id = self.backup_manager.create_backup(str(original_path))
        modified_data = {"modified": "data"}
        with open(original_path, "w") as f:
            json.dump(modified_data, f)
        restored_path = self.backup_manager.restore_backup(backup_id)
        with open(restored_path, "r") as f:
            restored_data = json.load(f)
        assert restored_data == original_data

    def test_list_backups(self):
        """Test listing backups."""
        config_path = Path(self.temp_dir) / "config.json"
        with open(config_path, "w") as f:
            json.dump({"test": "data"}, f)
        backup_id1 = self.backup_manager.create_backup(str(config_path), "Backup 1")
        backup_id2 = self.backup_manager.create_backup(str(config_path), "Backup 2")
        all_backups = self.backup_manager.list_backups()
        assert len(all_backups) >= 2
        file_backups = self.backup_manager.list_backups(str(config_path))
        assert len(file_backups) >= 2

    def test_delete_backup(self):
        """Test deleting backup."""
        config_path = Path(self.temp_dir) / "config.json"
        with open(config_path, "w") as f:
            json.dump({"test": "data"}, f)
        backup_id = self.backup_manager.create_backup(str(config_path))
        backup_path = self.backup_manager.backups[backup_id].backup_path
        assert Path(backup_path).exists()
        assert backup_id in self.backup_manager.backups
        self.backup_manager.delete_backup(backup_id)
        assert not Path(backup_path).exists()
        assert backup_id not in self.backup_manager.backups


class TestConfigurationManager:
    """Test main configuration manager functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_manager = ConfigurationManager(
            config_dir=str(Path(self.temp_dir) / "config"),
            backup_dir=str(Path(self.temp_dir) / "backups"),
        )

    def test_create_default_configuration(self):
        """Test creating default configuration."""
        config = self.config_manager._create_default_configuration()
        assert isinstance(config, PoolConfiguration)
        assert config.version == ConfigurationVersion.POOL_V1
        assert len(config.pools) >= 1
        assert config.default_pool is not None
        assert config.fallback_strategy is not None

    def test_save_and_load_configuration(self):
        """Test saving and loading configuration."""
        config = self.config_manager._create_default_configuration()
        config_path = Path(self.temp_dir) / "test_config.json"
        self.config_manager.save_configuration(config, str(config_path))
        assert config_path.exists()
        loaded_config = self.config_manager.load_configuration(str(config_path))
        assert loaded_config.version == config.version
        assert len(loaded_config.pools) == len(config.pools)
        assert loaded_config.default_pool == config.default_pool

    def test_migrate_legacy_configuration(self):
        """Test migrating legacy configuration through manager."""
        legacy_config = {
            "strategy": "--dpi-desync=multisplit --dpi-desync-split-count=3",
            "result_status": "SUCCESS",
            "success_rate": 0.8,
        }
        legacy_path = Path(self.temp_dir) / "legacy.json"
        with open(legacy_path, "w") as f:
            json.dump(legacy_config, f)
        target_path = Path(self.temp_dir) / "migrated.json"
        result = self.config_manager.migrate_legacy_configuration(
            str(legacy_path), str(target_path)
        )
        assert result.success
        assert target_path.exists()
        assert result.backup_path is not None

    def test_add_and_remove_pool(self):
        """Test adding and removing pools from configuration."""
        config = self.config_manager._create_default_configuration()
        strategy = BypassStrategy(
            id="new_strategy",
            name="New Strategy",
            attacks=["tcp_fragmentation"],
            target_ports=[443],
        )
        new_pool = self.config_manager.create_pool(
            "new_pool", "New Pool", strategy, "Test pool for adding/removing"
        )
        initial_count = len(config.pools)
        self.config_manager.add_pool_to_configuration(config, new_pool)
        assert len(config.pools) == initial_count + 1
        assert self.config_manager.get_pool_by_id(config, "new_pool") is not None
        self.config_manager.remove_pool_from_configuration(config, "new_pool")
        assert len(config.pools) == initial_count
        assert self.config_manager.get_pool_by_id(config, "new_pool") is None

    def test_validation_integration(self):
        """Test validation integration with configuration manager."""
        invalid_config = {
            "version": "pool_v1",
            "pools": [
                {
                    "id": "",
                    "name": "Invalid Pool",
                    "strategy": {
                        "id": "invalid_strategy",
                        "name": "Invalid Strategy",
                        "attacks": ["nonexistent_attack"],
                        "target_ports": [70000],
                    },
                }
            ],
        }
        config_path = Path(self.temp_dir) / "invalid.json"
        with open(config_path, "w") as f:
            json.dump(invalid_config, f)
        errors = self.config_manager.validate_configuration_file(str(config_path))
        error_count = len([e for e in errors if e.level == "error"])
        assert error_count > 0
        report = self.config_manager.get_validation_report(str(config_path))
        assert not report["summary"]["is_valid"]
        assert len(report["errors"]) > 0


def test_integration_workflow():
    """Test complete integration workflow."""
    with tempfile.TemporaryDirectory() as temp_dir:
        manager = ConfigurationManager(
            config_dir=str(Path(temp_dir) / "config"),
            backup_dir=str(Path(temp_dir) / "backups"),
        )
        legacy_config = {
            "strategy": "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-fooling=badsum",
            "result_status": "PARTIAL_SUCCESS",
            "successful_sites": 3,
            "total_sites": 5,
            "success_rate": 0.6,
        }
        legacy_path = Path(temp_dir) / "best_strategy.json"
        with open(legacy_path, "w") as f:
            json.dump(legacy_config, f)
        result = manager.migrate_legacy_configuration(str(legacy_path))
        assert result.success
        config = manager.load_configuration()
        assert isinstance(config, PoolConfiguration)
        errors = manager.validate_configuration_file(str(manager.default_config_path))
        error_count = len([e for e in errors if e.level == "error"])
        assert error_count == 0
        new_strategy = BypassStrategy(
            id="custom_strategy",
            name="Custom Strategy",
            attacks=["http_host_case", "tls_sni_modification"],
            target_ports=[443],
        )
        new_pool = manager.create_pool(
            "custom_pool",
            "Custom Pool",
            new_strategy,
            "Custom pool for specific domains",
            ["custom.example.com"],
        )
        manager.add_pool_to_configuration(config, new_pool)
        manager.save_configuration(config)
        final_config = manager.load_configuration()
        assert len(final_config.pools) >= 2
        assert manager.get_pool_by_id(final_config, "custom_pool") is not None


if __name__ == "__main__":
    pytest.main([__file__])
