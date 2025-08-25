"""
Engine Configuration Manager for centralized configuration management.
"""
from typing import Dict, Any, List, Optional, Union
import os
import json
import logging
import platform
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
from core.bypass.engines.base import EngineType, EngineConfig
LOG = logging.getLogger('EngineConfigManager')

class ConfigSource(Enum):
    """Configuration source types."""
    DEFAULT = 'default'
    FILE = 'file'
    ENVIRONMENT = 'environment'
    OVERRIDE = 'override'

@dataclass
class EngineConfigProfile:
    """Configuration profile for an engine type."""
    engine_type: EngineType
    priority: int = 50
    enabled: bool = True
    default_config: Dict[str, Any] = field(default_factory=dict)
    required_permissions: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    fallback_engines: List[EngineType] = field(default_factory=list)
    platform_specific: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    description: str = ''

@dataclass
class ConfigurationState:
    """Current configuration state."""
    loaded_from: List[ConfigSource] = field(default_factory=list)
    config_files: List[str] = field(default_factory=list)
    last_updated: Optional[str] = None
    validation_errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

class EngineConfigManager:
    """
    Manager for engine configuration and defaults.

    This manager provides:
    - Centralized configuration loading from files and environment
    - Configuration validation and default value handling
    - Engine priority and fallback management
    - Platform-specific configuration support
    - Configuration hot-reloading and updates
    """

    def __init__(self, config_dir: Optional[str]=None):
        self.logger = LOG
        self.config_dir = Path(config_dir) if config_dir else Path.cwd() / 'config'
        self._profiles: Dict[EngineType, EngineConfigProfile] = {}
        self._global_config: Dict[str, Any] = {}
        self._state = ConfigurationState()
        self._config_overrides: Dict[str, Any] = {}
        self._config_files = ['engine_config.json', 'engine_config.yaml', '.engine_config.json', 'engines.json']
        self._env_prefix = 'ENGINE_'
        self._load_default_configuration()
        self._load_configuration()

    def get_default_engine_type(self) -> EngineType:
        """
        Get the default engine type based on configuration and platform.

        Returns:
            Default engine type
        """
        if 'default_engine' in self._global_config:
            default_name = self._global_config['default_engine']
            for engine_type in EngineType:
                if engine_type.value == default_name:
                    return engine_type
        available_profiles = [profile for profile in self._profiles.values() if profile.enabled]
        if not available_profiles:
            return self._get_platform_default()
        available_profiles.sort(key=lambda p: p.priority, reverse=True)
        return available_profiles[0].engine_type

    def get_engine_config(self, engine_type: Union[str, EngineType]) -> Dict[str, Any]:
        """
        Get configuration for a specific engine type.

        Args:
            engine_type: Engine type to get configuration for

        Returns:
            Configuration dictionary
        """
        if isinstance(engine_type, str):
            for et in EngineType:
                if et.value == engine_type.lower():
                    engine_type = et
                    break
            else:
                self.logger.warning(f'Unknown engine type: {engine_type}')
                return {}
        profile = self._profiles.get(engine_type)
        if not profile:
            self.logger.warning(f'No configuration profile for engine: {engine_type.value}')
            return {}
        config = profile.default_config.copy()
        current_platform = platform.system()
        if current_platform in profile.platform_specific:
            platform_config = profile.platform_specific[current_platform]
            config.update(platform_config)
        engine_key = f'{engine_type.value}_config'
        if engine_key in self._global_config:
            config.update(self._global_config[engine_key])
        override_key = f'{engine_type.value}'
        if override_key in self._config_overrides:
            config.update(self._config_overrides[override_key])
        return config

    def get_engine_config_object(self, engine_type: Union[str, EngineType]) -> EngineConfig:
        """
        Get EngineConfig object for a specific engine type.

        Args:
            engine_type: Engine type to get configuration for

        Returns:
            EngineConfig object
        """
        config_dict = self.get_engine_config(engine_type)
        return EngineConfig(debug=config_dict.get('debug', False), timeout=config_dict.get('timeout', 30.0), base_path=config_dict.get('base_path'), tool_name=config_dict.get('tool_name'), packet_buffer_size=config_dict.get('packet_buffer_size', 65535), max_concurrent_connections=config_dict.get('max_concurrent_connections', 1000), log_packets=config_dict.get('log_packets', False))

    def validate_config(self, config: Dict[str, Any], engine_type: Optional[EngineType]=None) -> bool:
        """
        Validate configuration dictionary.

        Args:
            config: Configuration to validate
            engine_type: Optional engine type for specific validation

        Returns:
            True if configuration is valid
        """
        try:
            if not isinstance(config, dict):
                self.logger.error('Configuration must be a dictionary')
                return False
            if 'timeout' in config:
                timeout = config['timeout']
                if not isinstance(timeout, (int, float)) or timeout <= 0:
                    self.logger.error('Timeout must be a positive number')
                    return False
            if 'debug' in config:
                if not isinstance(config['debug'], bool):
                    self.logger.error('Debug must be a boolean')
                    return False
            if 'packet_buffer_size' in config:
                buffer_size = config['packet_buffer_size']
                if not isinstance(buffer_size, int) or buffer_size <= 0:
                    self.logger.error('Packet buffer size must be a positive integer')
                    return False
            if 'max_concurrent_connections' in config:
                max_conn = config['max_concurrent_connections']
                if not isinstance(max_conn, int) or max_conn <= 0:
                    self.logger.error('Max concurrent connections must be a positive integer')
                    return False
            if engine_type:
                profile = self._profiles.get(engine_type)
                if profile:
                    pass
            return True
        except Exception as e:
            self.logger.error(f'Configuration validation error: {e}')
            return False

    def get_fallback_order(self, preferred_engine: Optional[EngineType]=None) -> List[EngineType]:
        """
        Get fallback order for engine types.

        Args:
            preferred_engine: Optional preferred engine to start with

        Returns:
            List of engine types in fallback order
        """
        fallback_order = []
        if preferred_engine and preferred_engine in self._profiles:
            profile = self._profiles[preferred_engine]
            if profile.enabled:
                fallback_order.append(preferred_engine)
                fallback_order.extend([et for et in profile.fallback_engines if et in self._profiles and self._profiles[et].enabled])
        remaining_engines = [profile.engine_type for profile in self._profiles.values() if profile.enabled and profile.engine_type not in fallback_order]
        remaining_engines.sort(key=lambda et: self._profiles[et].priority, reverse=True)
        fallback_order.extend(remaining_engines)
        return fallback_order

    def get_engine_priority(self, engine_type: EngineType) -> int:
        """
        Get priority for an engine type.

        Args:
            engine_type: Engine type

        Returns:
            Priority value (higher = more preferred)
        """
        profile = self._profiles.get(engine_type)
        return profile.priority if profile else 0

    def set_engine_priority(self, engine_type: EngineType, priority: int):
        """
        Set priority for an engine type.

        Args:
            engine_type: Engine type
            priority: Priority value
        """
        if engine_type in self._profiles:
            self._profiles[engine_type].priority = priority
            self.logger.info(f'Set priority for {engine_type.value}: {priority}')
        else:
            self.logger.warning(f'Cannot set priority for unknown engine: {engine_type.value}')

    def enable_engine(self, engine_type: EngineType, enabled: bool=True):
        """
        Enable or disable an engine type.

        Args:
            engine_type: Engine type
            enabled: Whether to enable the engine
        """
        if engine_type in self._profiles:
            self._profiles[engine_type].enabled = enabled
            status = 'enabled' if enabled else 'disabled'
            self.logger.info(f'Engine {engine_type.value} {status}')
        else:
            self.logger.warning(f'Cannot modify unknown engine: {engine_type.value}')

    def set_config_override(self, engine_type: EngineType, config: Dict[str, Any]):
        """
        Set configuration override for an engine type.

        Args:
            engine_type: Engine type
            config: Configuration overrides
        """
        if self.validate_config(config, engine_type):
            self._config_overrides[engine_type.value] = config
            self.logger.info(f'Set configuration override for {engine_type.value}')
        else:
            self.logger.error(f'Invalid configuration override for {engine_type.value}')

    def clear_config_override(self, engine_type: EngineType):
        """
        Clear configuration override for an engine type.

        Args:
            engine_type: Engine type
        """
        if engine_type.value in self._config_overrides:
            del self._config_overrides[engine_type.value]
            self.logger.info(f'Cleared configuration override for {engine_type.value}')

    def reload_configuration(self):
        """Reload configuration from files and environment."""
        self.logger.info('Reloading configuration...')
        self._state = ConfigurationState()
        self._config_overrides.clear()
        self._load_default_configuration()
        self._load_configuration()
        self.logger.info('Configuration reloaded successfully')

    def get_configuration_state(self) -> Dict[str, Any]:
        """
        Get current configuration state information.

        Returns:
            Configuration state information
        """
        return {'loaded_from': [source.value for source in self._state.loaded_from], 'config_files': self._state.config_files, 'last_updated': self._state.last_updated, 'validation_errors': self._state.validation_errors, 'warnings': self._state.warnings, 'profiles': {et.value: {'priority': profile.priority, 'enabled': profile.enabled, 'description': profile.description, 'dependencies': profile.dependencies, 'fallback_engines': [fe.value for fe in profile.fallback_engines]} for et, profile in self._profiles.items()}, 'global_config': self._global_config, 'overrides': self._config_overrides}

    def export_configuration(self, file_path: str):
        """
        Export current configuration to a file.

        Args:
            file_path: Path to export configuration to
        """
        try:
            config_data = {'global': self._global_config, 'profiles': {et.value: {'priority': profile.priority, 'enabled': profile.enabled, 'default_config': profile.default_config, 'required_permissions': profile.required_permissions, 'dependencies': profile.dependencies, 'fallback_engines': [fe.value for fe in profile.fallback_engines], 'platform_specific': profile.platform_specific, 'description': profile.description} for et, profile in self._profiles.items()}}
            with open(file_path, 'w') as f:
                json.dump(config_data, f, indent=2)
            self.logger.info(f'Configuration exported to: {file_path}')
        except Exception as e:
            self.logger.error(f'Failed to export configuration: {e}')

    def _load_default_configuration(self):
        """Load default configuration profiles."""
        self._profiles[EngineType.NATIVE_PYDIVERT] = EngineConfigProfile(engine_type=EngineType.NATIVE_PYDIVERT, priority=100, enabled=True, default_config={'debug': False, 'timeout': 30.0, 'packet_buffer_size': 65535, 'max_concurrent_connections': 1000, 'log_packets': False}, required_permissions=['administrator'], dependencies=['pydivert'], fallback_engines=[EngineType.EXTERNAL_TOOL], platform_specific={'Windows': {'packet_buffer_size': 65535}}, description='High-performance Windows packet interception using PyDivert')
        self._profiles[EngineType.EXTERNAL_TOOL] = EngineConfigProfile(engine_type=EngineType.EXTERNAL_TOOL, priority=50, enabled=True, default_config={'debug': False, 'timeout': 30.0, 'tool_name': 'zapret', 'base_path': None}, required_permissions=[], dependencies=[], fallback_engines=[], platform_specific={'Windows': {'tool_name': 'zapret'}, 'Linux': {'tool_name': 'zapret'}}, description='Cross-platform engine using external DPI bypass tools')
        self._profiles[EngineType.NATIVE_NETFILTER] = EngineConfigProfile(engine_type=EngineType.NATIVE_NETFILTER, priority=80, enabled=False, default_config={'debug': False, 'timeout': 30.0, 'packet_buffer_size': 65535, 'max_concurrent_connections': 1000, 'log_packets': False}, required_permissions=['root'], dependencies=['netfilterqueue'], fallback_engines=[EngineType.EXTERNAL_TOOL], platform_specific={'Linux': {'packet_buffer_size': 65535}}, description='Linux netfilter-based packet interception (not implemented)')
        self._global_config = {'default_engine': None, 'enable_fallback': True, 'validate_dependencies': True, 'log_level': 'INFO'}
        self._state.loaded_from.append(ConfigSource.DEFAULT)

    def _load_configuration(self):
        """Load configuration from files and environment."""
        self._load_from_files()
        self._load_from_environment()

    def _load_from_files(self):
        """Load configuration from files."""
        for config_file in self._config_files:
            config_path = self.config_dir / config_file
            if config_path.exists():
                try:
                    self._load_config_file(config_path)
                    self._state.config_files.append(str(config_path))
                    self._state.loaded_from.append(ConfigSource.FILE)
                except Exception as e:
                    error_msg = f'Failed to load config file {config_path}: {e}'
                    self.logger.error(error_msg)
                    self._state.validation_errors.append(error_msg)

    def _load_config_file(self, config_path: Path):
        """Load a specific configuration file."""
        with open(config_path, 'r') as f:
            if config_path.suffix.lower() == '.json':
                config_data = json.load(f)
            else:
                config_data = json.load(f)
        if 'global' in config_data:
            self._global_config.update(config_data['global'])
        if 'profiles' in config_data:
            for engine_name, profile_data in config_data['profiles'].items():
                engine_type = None
                for et in EngineType:
                    if et.value == engine_name:
                        engine_type = et
                        break
                if engine_type and engine_type in self._profiles:
                    profile = self._profiles[engine_type]
                    if 'priority' in profile_data:
                        profile.priority = profile_data['priority']
                    if 'enabled' in profile_data:
                        profile.enabled = profile_data['enabled']
                    if 'default_config' in profile_data:
                        profile.default_config.update(profile_data['default_config'])
                    if 'required_permissions' in profile_data:
                        profile.required_permissions = profile_data['required_permissions']
                    if 'dependencies' in profile_data:
                        profile.dependencies = profile_data['dependencies']
                    if 'platform_specific' in profile_data:
                        profile.platform_specific.update(profile_data['platform_specific'])
                    if 'description' in profile_data:
                        profile.description = profile_data['description']
                    if 'fallback_engines' in profile_data:
                        fallback_engines = []
                        for fallback_name in profile_data['fallback_engines']:
                            for et in EngineType:
                                if et.value == fallback_name:
                                    fallback_engines.append(et)
                                    break
                        profile.fallback_engines = fallback_engines
        self.logger.info(f'Loaded configuration from: {config_path}')

    def _load_from_environment(self):
        """Load configuration from environment variables."""
        env_vars_found = False
        for key, value in os.environ.items():
            if key.startswith(self._env_prefix):
                env_key = key[len(self._env_prefix):].lower()
                try:
                    if value.startswith('{') or value.startswith('['):
                        parsed_value = json.loads(value)
                    elif value.lower() in ['true', 'false']:
                        parsed_value = value.lower() == 'true'
                    elif value.isdigit():
                        parsed_value = int(value)
                    elif '.' in value and value.replace('.', '').isdigit():
                        parsed_value = float(value)
                    else:
                        parsed_value = value
                    self._global_config[env_key] = parsed_value
                    env_vars_found = True
                except json.JSONDecodeError:
                    self._global_config[env_key] = value
                    env_vars_found = True
        if env_vars_found:
            self._state.loaded_from.append(ConfigSource.ENVIRONMENT)
            self.logger.info('Loaded configuration from environment variables')

    def _get_platform_default(self) -> EngineType:
        """Get platform-specific default engine type."""
        current_platform = platform.system()
        if current_platform == 'Windows':
            return EngineType.NATIVE_PYDIVERT
        elif current_platform == 'Linux':
            return EngineType.EXTERNAL_TOOL
        else:
            return EngineType.EXTERNAL_TOOL
_config_manager = EngineConfigManager()

def get_engine_config_manager() -> EngineConfigManager:
    """Get the global engine configuration manager instance."""
    return _config_manager

def get_default_engine_type() -> EngineType:
    """Convenience function to get default engine type."""
    return _config_manager.get_default_engine_type()

def get_engine_config(engine_type: Union[str, EngineType]) -> Dict[str, Any]:
    """Convenience function to get engine configuration."""
    return _config_manager.get_engine_config(engine_type)

def get_fallback_order(preferred_engine: Optional[EngineType]=None) -> List[EngineType]:
    """Convenience function to get fallback order."""
    return _config_manager.get_fallback_order(preferred_engine)