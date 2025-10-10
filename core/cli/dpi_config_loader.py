"""
DPI Configuration Loader

This module provides functionality to load DPI strategy configurations
from JSON files and apply them to CLI arguments.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Union

from ..bypass.strategies.config_models import DPIConfig
from ..bypass.strategies.exceptions import ConfigurationError

logger = logging.getLogger(__name__)


class DPIConfigLoader:
    """
    Loader for DPI strategy configurations from files.
    
    Supports loading configurations from JSON files and applying
    domain-specific settings.
    """
    
    def __init__(self):
        """Initialize the DPI configuration loader."""
        self.default_config_paths = [
            'config/dpi_strategy_config.json',
            'dpi_config.json',
            '.dpi_config.json'
        ]
    
    def load_config_file(self, config_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Load DPI configuration from a JSON file.
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            Dictionary with configuration data
            
        Raises:
            ConfigurationError: If file cannot be loaded or parsed
        """
        try:
            config_path = Path(config_path)
            
            if not config_path.exists():
                raise ConfigurationError('config_file', str(config_path), "Configuration file not found")
            
            with open(config_path, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            
            logger.info(f"Loaded DPI configuration from {config_path}")
            return config_data
            
        except json.JSONDecodeError as e:
            raise ConfigurationError('config_file', str(config_path), f"Invalid JSON: {e}")
        except Exception as e:
            raise ConfigurationError('config_file', str(config_path), f"Failed to load config: {e}")
    
    def find_default_config(self) -> Optional[Path]:
        """
        Find the first available default configuration file.
        
        Returns:
            Path to configuration file or None if not found
        """
        for config_path in self.default_config_paths:
            path = Path(config_path)
            if path.exists():
                logger.debug(f"Found default DPI config: {path}")
                return path
        
        logger.debug("No default DPI configuration file found")
        return None
    
    def load_default_config(self) -> Optional[Dict[str, Any]]:
        """
        Load default DPI configuration if available.
        
        Returns:
            Configuration dictionary or None if no default config found
        """
        config_path = self.find_default_config()
        if config_path:
            try:
                return self.load_config_file(config_path)
            except ConfigurationError as e:
                logger.warning(f"Failed to load default config: {e}")
        
        return None
    
    def create_dpi_config_from_file(self, config_path: Union[str, Path], 
                                   domain: Optional[str] = None) -> DPIConfig:
        """
        Create DPI configuration from file with optional domain-specific settings.
        
        Args:
            config_path: Path to configuration file
            domain: Domain name for domain-specific configuration
            
        Returns:
            DPI configuration object
        """
        config_data = self.load_config_file(config_path)
        return self.create_dpi_config_from_data(config_data, domain)
    
    def create_dpi_config_from_data(self, config_data: Dict[str, Any], 
                                   domain: Optional[str] = None) -> DPIConfig:
        """
        Create DPI configuration from configuration data.
        
        Args:
            config_data: Configuration dictionary
            domain: Domain name for domain-specific configuration
            
        Returns:
            DPI configuration object
        """
        try:
            # Start with base configuration
            base_config = config_data.get('dpi_strategy', {})
            
            # Apply domain-specific configuration if available
            if domain and 'domain_specific' in config_data:
                domain_configs = config_data['domain_specific']
                
                # Look for exact domain match first
                if domain in domain_configs:
                    domain_config = domain_configs[domain]
                    base_config.update(domain_config)
                    logger.info(f"Applied domain-specific config for {domain}")
                else:
                    # Look for wildcard matches
                    for pattern, domain_config in domain_configs.items():
                        if self._matches_wildcard_pattern(domain, pattern):
                            base_config.update(domain_config)
                            logger.info(f"Applied wildcard config {pattern} for {domain}")
                            break
            
            # Create DPI configuration
            config = DPIConfig(
                enabled=base_config.get('enabled', True),
                desync_mode=base_config.get('desync_mode', 'split'),
                split_positions=base_config.get('split_positions', []),
                fooling_methods=base_config.get('fooling_methods', []),
                ttl=base_config.get('ttl'),
                repeats=base_config.get('repeats', 1),
                split_count=base_config.get('split_count'),
                split_seqovl=base_config.get('split_seqovl')
            )
            
            logger.debug(f"Created DPI config from file: {config.to_dict()}")
            return config
            
        except Exception as e:
            logger.error(f"Failed to create DPI config from data: {e}")
            raise ConfigurationError('config_creation', str(config_data), f"Config creation failed: {e}")
    
    def _matches_wildcard_pattern(self, domain: str, pattern: str) -> bool:
        """
        Check if domain matches a wildcard pattern.
        
        Args:
            domain: Domain name to check
            pattern: Wildcard pattern (e.g., "*.example.com")
            
        Returns:
            True if domain matches pattern
        """
        if '*' not in pattern:
            return domain == pattern
        
        # Simple wildcard matching
        if pattern.startswith('*.'):
            suffix = pattern[2:]
            return domain.endswith(suffix) and domain != suffix
        elif pattern.endswith('.*'):
            prefix = pattern[:-2]
            return domain.startswith(prefix) and domain != prefix
        else:
            # More complex patterns would need proper regex
            return False
    
    def get_preset_config(self, config_data: Dict[str, Any], preset_name: str) -> DPIConfig:
        """
        Get a preset configuration by name.
        
        Args:
            config_data: Configuration dictionary
            preset_name: Name of preset to load
            
        Returns:
            DPI configuration object
            
        Raises:
            ConfigurationError: If preset not found
        """
        if 'presets' not in config_data:
            raise ConfigurationError('preset', preset_name, "No presets defined in configuration")
        
        presets = config_data['presets']
        if preset_name not in presets:
            available = list(presets.keys())
            raise ConfigurationError('preset', preset_name, f"Preset not found. Available: {available}")
        
        preset_data = presets[preset_name]
        
        config = DPIConfig(
            enabled=preset_data.get('enabled', True),
            desync_mode=preset_data.get('desync_mode', 'split'),
            split_positions=preset_data.get('split_positions', []),
            fooling_methods=preset_data.get('fooling_methods', []),
            ttl=preset_data.get('ttl'),
            repeats=preset_data.get('repeats', 1),
            split_count=preset_data.get('split_count'),
            split_seqovl=preset_data.get('split_seqovl')
        )
        
        logger.info(f"Loaded preset configuration: {preset_name}")
        return config
    
    def list_available_presets(self, config_data: Dict[str, Any]) -> list:
        """
        List available preset names.
        
        Args:
            config_data: Configuration dictionary
            
        Returns:
            List of preset names
        """
        return list(config_data.get('presets', {}).keys())
    
    def validate_config_file(self, config_path: Union[str, Path]) -> bool:
        """
        Validate a DPI configuration file.
        
        Args:
            config_path: Path to configuration file
            
        Returns:
            True if configuration is valid
        """
        try:
            config_data = self.load_config_file(config_path)
            
            # Basic structure validation
            if 'dpi_strategy' not in config_data:
                logger.error("Configuration missing 'dpi_strategy' section")
                return False
            
            # Validate against schema if available
            validation_rules = config_data.get('validation', {})
            if validation_rules:
                return self._validate_against_rules(config_data, validation_rules)
            
            logger.info(f"Configuration file {config_path} is valid")
            return True
            
        except Exception as e:
            logger.error(f"Configuration validation failed: {e}")
            return False
    
    def _validate_against_rules(self, config_data: Dict[str, Any], 
                               validation_rules: Dict[str, Any]) -> bool:
        """
        Validate configuration against validation rules.
        
        Args:
            config_data: Configuration data
            validation_rules: Validation rules
            
        Returns:
            True if validation passes
        """
        try:
            # Validate desync modes
            supported_modes = validation_rules.get('supported_desync_modes', [])
            if supported_modes:
                dpi_config = config_data.get('dpi_strategy', {})
                mode = dpi_config.get('desync_mode')
                if mode and mode not in supported_modes:
                    logger.error(f"Unsupported desync mode: {mode}")
                    return False
            
            # Validate fooling methods
            supported_fooling = validation_rules.get('supported_fooling_methods', [])
            if supported_fooling:
                dpi_config = config_data.get('dpi_strategy', {})
                methods = dpi_config.get('fooling_methods', [])
                for method in methods:
                    if method not in supported_fooling:
                        logger.error(f"Unsupported fooling method: {method}")
                        return False
            
            # Validate numeric limits
            max_ttl = validation_rules.get('max_ttl', 255)
            max_repeats = validation_rules.get('max_repeats', 10)
            
            dpi_config = config_data.get('dpi_strategy', {})
            if dpi_config.get('ttl', 0) > max_ttl:
                logger.error(f"TTL exceeds maximum: {max_ttl}")
                return False
            
            if dpi_config.get('repeats', 1) > max_repeats:
                logger.error(f"Repeats exceeds maximum: {max_repeats}")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Validation rule checking failed: {e}")
            return False


def create_dpi_config_loader() -> DPIConfigLoader:
    """
    Create a DPI configuration loader instance.
    
    Returns:
        Configured DPI configuration loader
    """
    return DPIConfigLoader()


def load_dpi_config_for_domain(domain: str, config_path: Optional[str] = None) -> Optional[DPIConfig]:
    """
    Load DPI configuration for a specific domain.
    
    Args:
        domain: Domain name
        config_path: Optional path to configuration file
        
    Returns:
        DPI configuration or None if not available
    """
    try:
        loader = create_dpi_config_loader()
        
        if config_path:
            return loader.create_dpi_config_from_file(config_path, domain)
        else:
            # Try to load default configuration
            config_data = loader.load_default_config()
            if config_data:
                return loader.create_dpi_config_from_data(config_data, domain)
        
        return None
        
    except Exception as e:
        logger.error(f"Failed to load DPI config for domain {domain}: {e}")
        return None