"""
Enhanced Strategy Configuration Manager

This module provides an enhanced configuration system for DPI bypass strategies
with support for wildcard patterns, priorities, and backward compatibility.
"""

import json
import os
import re
from datetime import datetime
from typing import Dict, List, Optional, Union, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


@dataclass
class StrategyMetadata:
    """Metadata for a strategy configuration."""
    priority: int = 1
    description: str = ""
    success_rate: float = 0.0
    avg_latency_ms: float = 0.0
    last_tested: Optional[str] = None
    test_count: int = 0
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


@dataclass
class StrategyRule:
    """A strategy rule with pattern, strategy, and metadata."""
    pattern: str
    strategy: str
    metadata: StrategyMetadata
    is_wildcard: bool = False
    
    def __post_init__(self):
        """Determine if pattern is wildcard after initialization."""
        self.is_wildcard = self._is_wildcard_pattern(self.pattern)
    
    @staticmethod
    def _is_wildcard_pattern(pattern: str) -> bool:
        """Check if pattern contains wildcard characters."""
        return '*' in pattern or '?' in pattern


@dataclass
class StrategyConfiguration:
    """Complete strategy configuration with version and rules."""
    version: str = "3.0"
    strategy_priority: List[str] = None
    domain_strategies: Dict[str, StrategyRule] = None
    ip_strategies: Dict[str, StrategyRule] = None
    global_strategy: Optional[StrategyRule] = None
    last_updated: Optional[str] = None
    
    def __post_init__(self):
        """Initialize default values after creation."""
        if self.strategy_priority is None:
            self.strategy_priority = ["domain", "ip", "global"]
        if self.domain_strategies is None:
            self.domain_strategies = {}
        if self.ip_strategies is None:
            self.ip_strategies = {}
        if self.last_updated is None:
            self.last_updated = datetime.now().isoformat()


class ConfigurationError(Exception):
    """Exception raised for configuration-related errors."""
    pass


class StrategyConfigManager:
    """
    Enhanced strategy configuration manager with wildcard support,
    priorities, and backward compatibility.
    """
    
    SUPPORTED_VERSIONS = ["2.0", "3.0"]
    DEFAULT_CONFIG_FILE = "domain_strategies.json"
    BACKUP_SUFFIX = ".backup"
    
    def __init__(self, config_dir: str = "recon"):
        """
        Initialize the configuration manager.
        
        Args:
            config_dir: Directory containing configuration files
        """
        self.config_dir = Path(config_dir)
        self.config_file = self.config_dir / self.DEFAULT_CONFIG_FILE
        self._config: Optional[StrategyConfiguration] = None
        
    def load_configuration(self, config_file: Optional[str] = None) -> StrategyConfiguration:
        """
        Load strategy configuration from file with backward compatibility.
        
        Args:
            config_file: Optional path to configuration file
            
        Returns:
            StrategyConfiguration object
            
        Raises:
            ConfigurationError: If configuration is invalid or cannot be loaded
        """
        if config_file:
            config_path = Path(config_file)
        else:
            config_path = self.config_file
            
        if not config_path.exists():
            logger.warning(f"Configuration file {config_path} not found, creating default")
            return self._create_default_configuration()
            
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                raw_config = json.load(f)
                
            # Detect configuration version and convert if needed
            version = raw_config.get('version', '2.0')
            
            if version == '2.0':
                logger.info("Converting legacy v2.0 configuration to v3.0 format")
                config = self._convert_legacy_config(raw_config)
            elif version == '3.0':
                config = self._parse_v3_config(raw_config)
            else:
                raise ConfigurationError(f"Unsupported configuration version: {version}")
                
            self._validate_configuration(config)
            self._config = config
            
            logger.info(f"Loaded configuration v{config.version} with {len(config.domain_strategies)} domain rules")
            return config
            
        except json.JSONDecodeError as e:
            raise ConfigurationError(f"Invalid JSON in configuration file: {e}")
        except Exception as e:
            raise ConfigurationError(f"Failed to load configuration: {e}")
    
    def save_configuration(self, config: StrategyConfiguration, 
                          config_file: Optional[str] = None,
                          create_backup: bool = True) -> None:
        """
        Save strategy configuration to file.
        
        Args:
            config: Configuration to save
            config_file: Optional path to save configuration
            create_backup: Whether to create backup of existing file
            
        Raises:
            ConfigurationError: If configuration cannot be saved
        """
        if config_file:
            config_path = Path(config_file)
        else:
            config_path = self.config_file
            
        # Create backup if requested and file exists
        if create_backup and config_path.exists():
            backup_path = config_path.with_suffix(config_path.suffix + self.BACKUP_SUFFIX)
            try:
                backup_path.write_bytes(config_path.read_bytes())
                logger.info(f"Created backup: {backup_path}")
            except Exception as e:
                logger.warning(f"Failed to create backup: {e}")
        
        # Ensure directory exists
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Update timestamp
        config.last_updated = datetime.now().isoformat()
        
        try:
            # Convert to JSON-serializable format
            config_dict = self._config_to_dict(config)
            
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config_dict, f, indent=2, ensure_ascii=False)
                
            logger.info(f"Saved configuration to {config_path}")
            
        except Exception as e:
            raise ConfigurationError(f"Failed to save configuration: {e}")
    
    def add_domain_strategy(self, pattern: str, strategy: str, 
                           metadata: Optional[StrategyMetadata] = None) -> None:
        """
        Add or update a domain strategy rule.
        
        Args:
            pattern: Domain pattern (can include wildcards)
            strategy: Strategy string
            metadata: Optional metadata for the strategy
        """
        if self._config is None:
            self._config = self.load_configuration()
            
        if metadata is None:
            metadata = StrategyMetadata(
                created_at=datetime.now().isoformat()
            )
        else:
            metadata.updated_at = datetime.now().isoformat()
            
        rule = StrategyRule(
            pattern=pattern,
            strategy=strategy,
            metadata=metadata
        )
        
        self._config.domain_strategies[pattern] = rule
        logger.info(f"Added domain strategy for pattern '{pattern}': {strategy}")
    
    def remove_domain_strategy(self, pattern: str) -> bool:
        """
        Remove a domain strategy rule.
        
        Args:
            pattern: Domain pattern to remove
            
        Returns:
            True if rule was removed, False if not found
        """
        if self._config is None:
            self._config = self.load_configuration()
            
        if pattern in self._config.domain_strategies:
            del self._config.domain_strategies[pattern]
            logger.info(f"Removed domain strategy for pattern '{pattern}'")
            return True
        return False
    
    def get_domain_strategies(self) -> Dict[str, StrategyRule]:
        """Get all domain strategy rules."""
        if self._config is None:
            self._config = self.load_configuration()
        return self._config.domain_strategies.copy()
    
    def get_wildcard_patterns(self) -> List[str]:
        """Get all wildcard domain patterns."""
        if self._config is None:
            self._config = self.load_configuration()
            
        return [pattern for pattern, rule in self._config.domain_strategies.items() 
                if rule.is_wildcard]
    
    def validate_strategy_syntax(self, strategy: str) -> bool:
        """
        Validate strategy syntax.
        
        Args:
            strategy: Strategy string to validate
            
        Returns:
            True if syntax is valid
        """
        # Basic validation - check for common strategy patterns
        valid_patterns = [
            r'--dpi-desync=\w+',
            r'--dpi-desync-split-pos=\d+',
            r'--dpi-desync-fooling=[\w,]+',
            r'--dpi-desync-ttl=\d+',
            r'--dpi-desync-repeats=\d+',
            r'multisplit\(',
            r'seqovl\(',
            r'fakedisorder\(',
            r'badsum_race\('
        ]
        
        # Check if strategy contains at least one valid pattern
        for pattern in valid_patterns:
            if re.search(pattern, strategy):
                return True
                
        logger.warning(f"Strategy syntax validation failed: {strategy}")
        return False
    
    def _create_default_configuration(self) -> StrategyConfiguration:
        """Create a default configuration."""
        default_metadata = StrategyMetadata(
            priority=1,
            description="Default fallback strategy",
            created_at=datetime.now().isoformat()
        )
        
        global_strategy = StrategyRule(
            pattern="*",
            strategy="--dpi-desync=badsum_race --dpi-desync-ttl=4 --dpi-desync-split-pos=3",
            metadata=default_metadata
        )
        
        config = StrategyConfiguration(
            global_strategy=global_strategy
        )
        
        return config
    
    def _convert_legacy_config(self, raw_config: Dict[str, Any]) -> StrategyConfiguration:
        """
        Convert legacy v2.0 configuration to v3.0 format.
        
        Args:
            raw_config: Raw configuration dictionary
            
        Returns:
            StrategyConfiguration object
        """
        config = StrategyConfiguration(version="3.0")
        
        domain_strategies = raw_config.get('domain_strategies', {})
        
        for domain, domain_data in domain_strategies.items():
            if domain == 'default':
                # Convert default strategy to global strategy
                metadata = StrategyMetadata(
                    priority=0,  # Lowest priority for global
                    description="Converted from legacy default strategy",
                    success_rate=domain_data.get('success_rate', 0.0),
                    avg_latency_ms=domain_data.get('avg_latency_ms', 0.0),
                    last_tested=domain_data.get('last_tested'),
                    test_count=domain_data.get('test_count', 0)
                )
                
                config.global_strategy = StrategyRule(
                    pattern="*",
                    strategy=domain_data.get('strategy', ''),
                    metadata=metadata
                )
            else:
                # Convert domain strategy
                metadata = StrategyMetadata(
                    priority=1,  # Default priority for domain strategies
                    description=f"Converted from legacy configuration for {domain}",
                    success_rate=domain_data.get('success_rate', 0.0),
                    avg_latency_ms=domain_data.get('avg_latency_ms', 0.0),
                    last_tested=domain_data.get('last_tested'),
                    test_count=domain_data.get('test_count', 0)
                )
                
                rule = StrategyRule(
                    pattern=domain,
                    strategy=domain_data.get('strategy', ''),
                    metadata=metadata
                )
                
                config.domain_strategies[domain] = rule
        
        # Preserve original timestamps
        config.last_updated = raw_config.get('last_updated', datetime.now().isoformat())
        
        return config
    
    def _parse_v3_config(self, raw_config: Dict[str, Any]) -> StrategyConfiguration:
        """
        Parse v3.0 configuration format.
        
        Args:
            raw_config: Raw configuration dictionary
            
        Returns:
            StrategyConfiguration object
        """
        config = StrategyConfiguration(
            version=raw_config.get('version', '3.0'),
            strategy_priority=raw_config.get('strategy_priority', ["domain", "ip", "global"]),
            last_updated=raw_config.get('last_updated')
        )
        
        # Parse domain strategies
        domain_strategies = raw_config.get('domain_strategies', {})
        for pattern, strategy_data in domain_strategies.items():
            if isinstance(strategy_data, str):
                # Simple string format
                metadata = StrategyMetadata()
                rule = StrategyRule(pattern=pattern, strategy=strategy_data, metadata=metadata)
            else:
                # Full format with metadata
                metadata_data = strategy_data.get('metadata', {})
                metadata = StrategyMetadata(**metadata_data)
                
                rule = StrategyRule(
                    pattern=pattern,
                    strategy=strategy_data.get('strategy', ''),
                    metadata=metadata
                )
            
            config.domain_strategies[pattern] = rule
        
        # Parse IP strategies
        ip_strategies = raw_config.get('ip_strategies', {})
        for ip_pattern, strategy_data in ip_strategies.items():
            if isinstance(strategy_data, str):
                metadata = StrategyMetadata()
                rule = StrategyRule(pattern=ip_pattern, strategy=strategy_data, metadata=metadata)
            else:
                metadata_data = strategy_data.get('metadata', {})
                metadata = StrategyMetadata(**metadata_data)
                
                rule = StrategyRule(
                    pattern=ip_pattern,
                    strategy=strategy_data.get('strategy', ''),
                    metadata=metadata
                )
            
            config.ip_strategies[ip_pattern] = rule
        
        # Parse global strategy
        global_strategy_data = raw_config.get('global_strategy')
        if global_strategy_data:
            if isinstance(global_strategy_data, str):
                metadata = StrategyMetadata(priority=0)
                config.global_strategy = StrategyRule(
                    pattern="*", 
                    strategy=global_strategy_data, 
                    metadata=metadata
                )
            else:
                metadata_data = global_strategy_data.get('metadata', {})
                metadata = StrategyMetadata(**metadata_data)
                
                config.global_strategy = StrategyRule(
                    pattern="*",
                    strategy=global_strategy_data.get('strategy', ''),
                    metadata=metadata
                )
        
        return config
    
    def _validate_configuration(self, config: StrategyConfiguration) -> None:
        """
        Validate configuration for correctness.
        
        Args:
            config: Configuration to validate
            
        Raises:
            ConfigurationError: If configuration is invalid
        """
        if config.version not in self.SUPPORTED_VERSIONS:
            raise ConfigurationError(f"Unsupported version: {config.version}")
        
        # Validate strategy priority
        valid_priorities = {"domain", "ip", "global"}
        if not set(config.strategy_priority).issubset(valid_priorities):
            raise ConfigurationError(f"Invalid strategy priority: {config.strategy_priority}")
        
        # Validate domain strategies
        for pattern, rule in config.domain_strategies.items():
            if not rule.strategy.strip():
                raise ConfigurationError(f"Empty strategy for domain pattern: {pattern}")
            
            if not self.validate_strategy_syntax(rule.strategy):
                logger.warning(f"Potentially invalid strategy syntax for {pattern}: {rule.strategy}")
        
        # Validate IP strategies
        for ip_pattern, rule in config.ip_strategies.items():
            if not rule.strategy.strip():
                raise ConfigurationError(f"Empty strategy for IP pattern: {ip_pattern}")
        
        # Validate global strategy
        if config.global_strategy and not config.global_strategy.strategy.strip():
            raise ConfigurationError("Empty global strategy")
    
    def _config_to_dict(self, config: StrategyConfiguration) -> Dict[str, Any]:
        """
        Convert StrategyConfiguration to dictionary for JSON serialization.
        
        Args:
            config: Configuration to convert
            
        Returns:
            Dictionary representation
        """
        result = {
            "version": config.version,
            "strategy_priority": config.strategy_priority,
            "last_updated": config.last_updated,
            "domain_strategies": {},
            "ip_strategies": {}
        }
        
        # Convert domain strategies
        for pattern, rule in config.domain_strategies.items():
            result["domain_strategies"][pattern] = {
                "strategy": rule.strategy,
                "metadata": asdict(rule.metadata),
                "is_wildcard": rule.is_wildcard
            }
        
        # Convert IP strategies
        for pattern, rule in config.ip_strategies.items():
            result["ip_strategies"][pattern] = {
                "strategy": rule.strategy,
                "metadata": asdict(rule.metadata),
                "is_wildcard": rule.is_wildcard
            }
        
        # Convert global strategy
        if config.global_strategy:
            result["global_strategy"] = {
                "strategy": config.global_strategy.strategy,
                "metadata": asdict(config.global_strategy.metadata)
            }
        
        return result