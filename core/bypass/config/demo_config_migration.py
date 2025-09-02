"""
Demonstration of configuration migration and management functionality.
"""

import json
import tempfile
from pathlib import Path
from core.bypass.config.config_models import BypassStrategy
from core.bypass.config.config_manager import ConfigurationManager


def demo_legacy_migration():
    """Demonstrate migration from legacy best_strategy.json format."""
    print("=== Configuration Migration Demo ===\n")
    with tempfile.TemporaryDirectory() as temp_dir:
        manager = ConfigurationManager(
            config_dir=str(Path(temp_dir) / "config"),
            backup_dir=str(Path(temp_dir) / "backups"),
        )
        print("1. Creating sample legacy configuration...")
        legacy_config = {
            "strategy": "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=20 --dpi-desync-fooling=badsum --dpi-desync-split-pos=4",
            "result_status": "PARTIAL_SUCCESS",
            "successful_sites": 1,
            "total_sites": 4,
            "success_rate": 0.25,
            "avg_latency_ms": 465.984582901001,
            "fingerprint_used": True,
            "dpi_type": "unknown",
            "dpi_confidence": 0.0,
        }
        legacy_path = Path(temp_dir) / "best_strategy.json"
        with open(legacy_path, "w", encoding="utf-8") as f:
            json.dump(legacy_config, f, indent=2)
        print(f"   Created legacy config at: {legacy_path}")
        print(f"   Legacy strategy: {legacy_config['strategy']}")
        print(f"   Success rate: {legacy_config['success_rate']:.2%}")
        print("\n2. Migrating to new pool-based format...")
        migration_result = manager.migrate_legacy_configuration(str(legacy_path))
        if migration_result.success:
            print("   ✓ Migration successful!")
            print(f"   Migrated {migration_result.migrated_pools} pools")
            print(f"   Migrated {migration_result.migrated_domains} domain assignments")
            if migration_result.backup_path:
                print(f"   Created backup: {migration_result.backup_path}")
        else:
            print("   ✗ Migration failed!")
            for error in migration_result.errors:
                print(f"     Error: {error}")
            return
        print("\n3. Loading and examining migrated configuration...")
        config = manager.load_configuration()
        print(f"   Configuration version: {config.version.value}")
        print(f"   Number of pools: {len(config.pools)}")
        print(f"   Default pool: {config.default_pool}")
        for i, pool in enumerate(config.pools):
            print(f"\n   Pool {i + 1}: {pool.name} (ID: {pool.id})")
            print(f"     Description: {pool.description}")
            print(f"     Domains: {pool.domains}")
            print(f"     Strategy attacks: {pool.strategy.attacks}")
            print(f"     Strategy parameters: {pool.strategy.parameters}")
            if pool.subdomains:
                print(f"     Subdomain strategies: {len(pool.subdomains)}")
            if pool.ports:
                print(f"     Port-specific strategies: {len(pool.ports)}")
        print("\n4. Demonstrating configuration management...")
        custom_strategy = BypassStrategy(
            id="demo_custom_strategy",
            name="Demo Custom Strategy",
            attacks=["http_host_case", "tls_sni_modification", "tcp_fragmentation"],
            parameters={
                "host_case_mix": True,
                "sni_case_randomization": True,
                "split_count": 3,
            },
            target_ports=[80, 443],
        )
        custom_pool = manager.create_pool(
            "demo_custom_pool",
            "Demo Custom Pool",
            custom_strategy,
            "Custom pool created for demonstration",
            ["demo.example.com", "test.example.com"],
        )
        manager.add_pool_to_configuration(config, custom_pool)
        print(f"   ✓ Added custom pool: {custom_pool.name}")
        manager.save_configuration(config)
        print("   ✓ Saved updated configuration")
        print("\n5. Validating configuration...")
        validation_report = manager.get_validation_report(
            str(manager.default_config_path)
        )
        print(f"   Total issues: {validation_report['summary']['total_issues']}")
        print(f"   Errors: {validation_report['summary']['errors']}")
        print(f"   Warnings: {validation_report['summary']['warnings']}")
        print(f"   Valid: {validation_report['summary']['is_valid']}")
        if validation_report["errors"]:
            print("   Validation errors:")
            for error in validation_report["errors"]:
                print(f"     - {error}")
        if validation_report["warnings"]:
            print("   Validation warnings:")
            for warning in validation_report["warnings"][:3]:
                print(f"     - {warning}")
            if len(validation_report["warnings"]) > 3:
                print(f"     ... and {len(validation_report['warnings']) - 3} more")
        print("\n6. Backup management demonstration...")
        backups = manager.backup_manager.list_backups()
        print(f"   Available backups: {len(backups)}")
        for backup in backups[:3]:
            print(f"     - {backup.id}: {backup.description}")
            print(f"       Created: {backup.created_at.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"       Version: {backup.version.value}")
        print("\n7. Configuration export/import demonstration...")
        export_path = Path(temp_dir) / "exported_config.json"
        manager.export_configuration(config, str(export_path))
        print(f"   ✓ Exported configuration to: {export_path}")
        imported_config = manager.import_configuration(str(export_path))
        print(f"   ✓ Imported configuration with {len(imported_config.pools)} pools")
        print("\n8. Configuration information...")
        config_info = manager.get_configuration_info()
        print(f"   Path: {config_info['path']}")
        print(f"   Size: {config_info['size']} bytes")
        print(f"   Version: {config_info['version']}")
        print(f"   Pools: {config_info['pools']}")
        print(f"   Total domains: {config_info['domains']}")
        print("\n=== Demo Complete ===")
        print("\nThe configuration migration system provides:")
        print("• Automatic migration from legacy best_strategy.json format")
        print("• Pool-based configuration management")
        print("• Comprehensive validation and error checking")
        print("• Automatic backup and restore functionality")
        print("• Support for subdomain and port-specific strategies")
        print("• Integration with external tool formats (zapret, goodbyedpi)")


def demo_external_tool_migration():
    """Demonstrate migration from external tool configurations."""
    print("\n=== External Tool Migration Demo ===\n")
    with tempfile.TemporaryDirectory() as temp_dir:
        manager = ConfigurationManager(
            config_dir=str(Path(temp_dir) / "config"),
            backup_dir=str(Path(temp_dir) / "backups"),
        )
        print("1. Migrating zapret configuration...")
        zapret_config = (
            "--dpi-desync=fake --dpi-desync-fooling=md5sig --dpi-desync-ttl=8"
        )
        migrated_config = manager.migrator.migrate_zapret_config(zapret_config)
        print(f"   Original zapret: {zapret_config}")
        print(f"   Migrated to {len(migrated_config.pools)} pool(s)")
        print(f"   Strategy attacks: {migrated_config.pools[0].strategy.attacks}")
        print("\n2. Migrating goodbyedpi configuration...")
        goodbyedpi_params = ["-p", "-r", "-s", "-f", "-k"]
        goodbyedpi_config = manager.migrator.migrate_goodbyedpi_config(
            goodbyedpi_params
        )
        print(f"   Original goodbyedpi: {' '.join(goodbyedpi_params)}")
        print(f"   Migrated to {len(goodbyedpi_config.pools)} pool(s)")
        print(f"   Strategy attacks: {goodbyedpi_config.pools[0].strategy.attacks}")
        print("\n3. Combining multiple configurations...")
        combined_config = manager._create_default_configuration()
        zapret_pool = migrated_config.pools[0]
        zapret_pool.id = "zapret_pool"
        zapret_pool.name = "Zapret Pool"
        manager.add_pool_to_configuration(combined_config, zapret_pool)
        goodbyedpi_pool = goodbyedpi_config.pools[0]
        goodbyedpi_pool.id = "goodbyedpi_pool"
        goodbyedpi_pool.name = "GoodbyeDPI Pool"
        manager.add_pool_to_configuration(combined_config, goodbyedpi_pool)
        print(f"   Combined configuration has {len(combined_config.pools)} pools:")
        for pool in combined_config.pools:
            print(f"     - {pool.name} ({pool.strategy.compatibility_mode})")
        manager.save_configuration(combined_config)
        print("   ✓ Saved combined configuration")


if __name__ == "__main__":
    demo_legacy_migration()
    demo_external_tool_migration()
