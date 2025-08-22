"""
Simple test script for configuration migration functionality.
"""
import json
import tempfile
from pathlib import Path
from recon.core.bypass.config.config_models import ConfigurationVersion, BypassStrategy
from recon.core.bypass.config.config_manager import ConfigurationManager

def test_basic_functionality():
    """Test basic configuration migration functionality."""
    print('Testing configuration migration functionality...')
    with tempfile.TemporaryDirectory() as temp_dir:
        manager = ConfigurationManager(config_dir=str(Path(temp_dir) / 'config'), backup_dir=str(Path(temp_dir) / 'backups'))
        print('1. Testing default configuration creation...')
        config = manager._create_default_configuration()
        assert config.version == ConfigurationVersion.POOL_V1
        assert len(config.pools) >= 1
        assert config.default_pool is not None
        print('   ✓ Default configuration created successfully')
        print('2. Testing save/load configuration...')
        manager.save_configuration(config)
        loaded_config = manager.load_configuration()
        assert loaded_config.version == config.version
        assert len(loaded_config.pools) == len(config.pools)
        print('   ✓ Configuration saved and loaded successfully')
        print('3. Testing legacy migration...')
        legacy_config = {'strategy': '--dpi-desync=multisplit --dpi-desync-split-count=3', 'result_status': 'SUCCESS', 'success_rate': 0.8}
        legacy_path = Path(temp_dir) / 'legacy.json'
        with open(legacy_path, 'w') as f:
            json.dump(legacy_config, f)
        migration_result = manager.migrate_legacy_configuration(str(legacy_path))
        assert migration_result.success
        assert migration_result.migrated_pools > 0
        print('   ✓ Legacy migration completed successfully')
        print('4. Testing configuration validation...')
        errors = manager.validate_configuration_file(str(manager.default_config_path))
        error_count = len([e for e in errors if e.level == 'error'])
        assert error_count == 0
        print('   ✓ Configuration validation passed')
        print('5. Testing pool management...')
        strategy = BypassStrategy(id='test_strategy', name='Test Strategy', attacks=['tcp_fragmentation'], target_ports=[443])
        new_pool = manager.create_pool('test_pool', 'Test Pool', strategy, 'Test pool for verification')
        initial_count = len(config.pools)
        manager.add_pool_to_configuration(config, new_pool)
        assert len(config.pools) == initial_count + 1
        manager.remove_pool_from_configuration(config, 'test_pool')
        assert len(config.pools) == initial_count
        print('   ✓ Pool management working correctly')
        print('6. Testing backup functionality...')
        backup_id = manager.backup_manager.create_backup(str(manager.default_config_path), 'Test backup')
        assert backup_id is not None
        backups = manager.backup_manager.list_backups()
        assert len(backups) > 0
        print('   ✓ Backup functionality working correctly')
        print('\nAll tests passed! ✓')

def test_zapret_migration():
    """Test zapret configuration migration."""
    print('\nTesting zapret configuration migration...')
    manager = ConfigurationManager()
    test_configs = ['--dpi-desync=multisplit --dpi-desync-split-count=5', '--dpi-desync=fake --dpi-desync-fooling=badsum', '--dpi-desync=multidisorder --dpi-desync-split-seqovl=10']
    for i, zapret_config in enumerate(test_configs, 1):
        print(f'  Test {i}: {zapret_config}')
        migrated = manager.migrator.migrate_zapret_config(zapret_config)
        assert isinstance(migrated.pools[0].strategy, BypassStrategy)
        assert len(migrated.pools[0].strategy.attacks) > 0
        print(f'    ✓ Migrated to attacks: {migrated.pools[0].strategy.attacks}')
    print('Zapret migration tests passed! ✓')

def test_validation_scenarios():
    """Test various validation scenarios."""
    print('\nTesting validation scenarios...')
    manager = ConfigurationManager()
    valid_config = manager._create_default_configuration()
    errors = manager.validator.validate_configuration(valid_config)
    error_count = len([e for e in errors if e.level == 'error'])
    assert error_count == 0
    print('  ✓ Valid configuration passes validation')
    invalid_strategy = BypassStrategy(id='invalid_strategy', name='Invalid Strategy', attacks=['nonexistent_attack'], target_ports=[443])
    errors = manager.validator._validate_strategy(invalid_strategy, 'test')
    warning_count = len([e for e in errors if e.level == 'warning' and 'Unknown attack' in e.message])
    assert warning_count > 0
    print('  ✓ Invalid attacks detected correctly')
    invalid_port_strategy = BypassStrategy(id='invalid_port_strategy', name='Invalid Port Strategy', attacks=['tcp_fragmentation'], target_ports=[0, 70000])
    errors = manager.validator._validate_strategy(invalid_port_strategy, 'test')
    error_count = len([e for e in errors if e.level == 'error' and 'Invalid port' in e.message])
    assert error_count > 0
    print('  ✓ Invalid ports detected correctly')
    print('Validation tests passed! ✓')
if __name__ == '__main__':
    test_basic_functionality()
    test_zapret_migration()
    test_validation_scenarios()
    print('\n🎉 All configuration migration tests completed successfully!')