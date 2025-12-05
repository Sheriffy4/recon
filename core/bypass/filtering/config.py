"""
Filter configuration system for runtime packet filtering.

This module provides configuration management, validation, and loading
for the runtime packet filtering system.
"""

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Set, List, Dict, Any, Optional, Union


logger = logging.getLogger(__name__)


class FilterMode(Enum):
    """Filtering mode enumeration."""
    NONE = "none"          # Apply to all traffic
    BLACKLIST = "blacklist"  # Apply only to domains in list
    WHITELIST = "whitelist"  # Apply only to domains in list


@dataclass
class FilterConfig:
    """
    Configuration for runtime packet filtering.
    
    This dataclass holds all configuration parameters for the filtering
    system including mode, domain lists, and performance settings.
    """
    
    # Core filtering settings
    mode: FilterMode = FilterMode.NONE
    domains: Set[str] = field(default_factory=set)
    
    # Pattern matching settings
    enable_wildcards: bool = True
    enable_subdomains: bool = True
    case_sensitive: bool = False
    
    # Performance settings
    cache_size: int = 1000
    cache_ttl: int = 300  # seconds
    cleanup_interval: int = 60  # seconds
    
    # Domain list file paths
    domain_files: List[str] = field(default_factory=list)
    
    # Validation settings
    validate_domains: bool = True
    skip_invalid_domains: bool = True
    
    def __post_init__(self):
        """Post-initialization validation and normalization."""
        # Normalize domains to lowercase if not case sensitive
        if not self.case_sensitive:
            self.domains = {domain.lower().strip() for domain in self.domains}
        else:
            self.domains = {domain.strip() for domain in self.domains}
        
        # Validate configuration
        if self.validate_domains:
            self._validate_configuration()
    
    def _validate_configuration(self) -> None:
        """
        Validate configuration parameters.
        
        Raises:
            ValueError: If configuration is invalid
            
        Requirements: 5.1, 5.2, 5.3
        """
        # Validate cache settings
        if self.cache_size < 0:
            raise ValueError("cache_size must be non-negative")
        
        if self.cache_ttl < 0:
            raise ValueError("cache_ttl must be non-negative")
        
        if self.cleanup_interval < 0:
            raise ValueError("cleanup_interval must be non-negative")
        
        # Validate domains if enabled
        if self.validate_domains:
            invalid_domains = []
            for domain in self.domains:
                if not self._is_valid_domain_pattern(domain):
                    invalid_domains.append(domain)
            
            if invalid_domains:
                if self.skip_invalid_domains:
                    # Remove invalid domains and log warning
                    for domain in invalid_domains:
                        self.domains.discard(domain)
                    logger.warning(f"Skipped {len(invalid_domains)} invalid domains: {invalid_domains[:5]}")
                else:
                    raise ValueError(f"Invalid domains found: {invalid_domains[:5]}")
    
    def _is_valid_domain_pattern(self, domain: str) -> bool:
        """
        Validate domain pattern.
        
        Args:
            domain: Domain or pattern to validate
            
        Returns:
            True if domain pattern is valid
        """
        if not domain or len(domain) > 253:
            return False
        
        # Allow wildcards if enabled
        if self.enable_wildcards and ('*' in domain or '?' in domain):
            # Basic wildcard validation
            if domain.count('*') > 5 or domain.count('?') > 10:
                return False  # Too many wildcards
        
        # Check for valid characters
        allowed_chars = set(
            'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-'
        )
        if self.enable_wildcards:
            allowed_chars.update('*?')
        
        if not all(c in allowed_chars for c in domain):
            return False
        
        # Basic structure validation
        if domain.startswith('.') or domain.endswith('.') or '..' in domain:
            return False
        
        return True
    
    def add_domain(self, domain: str) -> bool:
        """
        Add a domain to the configuration.
        
        Args:
            domain: Domain or pattern to add
            
        Returns:
            True if domain was added, False if invalid
            
        Requirements: 5.1, 5.2, 5.3
        """
        # Normalize domain
        normalized_domain = domain.lower().strip() if not self.case_sensitive else domain.strip()
        
        # Validate if enabled
        if self.validate_domains and not self._is_valid_domain_pattern(normalized_domain):
            if not self.skip_invalid_domains:
                raise ValueError(f"Invalid domain pattern: {domain}")
            logger.warning(f"Skipping invalid domain: {domain}")
            return False
        
        self.domains.add(normalized_domain)
        return True
    
    def remove_domain(self, domain: str) -> bool:
        """
        Remove a domain from the configuration.
        
        Args:
            domain: Domain or pattern to remove
            
        Returns:
            True if domain was removed, False if not found
        """
        normalized_domain = domain.lower().strip() if not self.case_sensitive else domain.strip()
        
        if normalized_domain in self.domains:
            self.domains.remove(normalized_domain)
            return True
        
        return False
    
    def load_domains_from_file(self, file_path: Union[str, Path]) -> int:
        """
        Load domains from a file.
        
        Args:
            file_path: Path to file containing domains (one per line)
            
        Returns:
            Number of domains loaded
            
        Requirements: 5.1, 5.2, 5.3
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"Domain file not found: {file_path}")
        
        loaded_count = 0
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue
                    
                    try:
                        if self.add_domain(line):
                            loaded_count += 1
                    except ValueError as e:
                        logger.warning(f"Invalid domain at {file_path}:{line_num}: {line} - {e}")
            
            logger.info(f"Loaded {loaded_count} domains from {file_path}")
            return loaded_count
            
        except Exception as e:
            logger.error(f"Error loading domains from {file_path}: {e}")
            raise
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert configuration to dictionary.
        
        Returns:
            Dictionary representation of configuration
        """
        return {
            'mode': self.mode.value,
            'domains': list(self.domains),
            'enable_wildcards': self.enable_wildcards,
            'enable_subdomains': self.enable_subdomains,
            'case_sensitive': self.case_sensitive,
            'cache_size': self.cache_size,
            'cache_ttl': self.cache_ttl,
            'cleanup_interval': self.cleanup_interval,
            'domain_files': self.domain_files,
            'validate_domains': self.validate_domains,
            'skip_invalid_domains': self.skip_invalid_domains
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FilterConfig':
        """
        Create configuration from dictionary.
        
        Args:
            data: Dictionary with configuration data
            
        Returns:
            FilterConfig instance
        """
        # Convert mode string to enum
        if 'mode' in data and isinstance(data['mode'], str):
            data['mode'] = FilterMode(data['mode'])
        
        # Convert domains list to set
        if 'domains' in data and isinstance(data['domains'], list):
            data['domains'] = set(data['domains'])
        
        return cls(**data)


class FilterConfigManager:
    """
    Manager for filter configuration with loading and validation.
    
    This class provides centralized configuration management with
    support for loading from files, validation, and runtime updates.
    """
    
    def __init__(self, config: Optional[FilterConfig] = None):
        """
        Initialize Filter Configuration Manager.
        
        Args:
            config: Initial configuration (defaults to empty config)
        """
        self.config = config or FilterConfig()
        self._config_file_path: Optional[Path] = None
    
    def load_from_file(self, file_path: Union[str, Path]) -> None:
        """
        Load configuration from JSON file.
        
        Args:
            file_path: Path to configuration file
            
        Raises:
            FileNotFoundError: If configuration file not found
            ValueError: If configuration is invalid
            
        Requirements: 5.1, 5.2, 5.3
        """
        file_path = Path(file_path)
        self._config_file_path = file_path
        
        if not file_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            self.config = FilterConfig.from_dict(data)
            
            # Load domains from referenced files
            for domain_file in self.config.domain_files:
                domain_file_path = file_path.parent / domain_file
                try:
                    self.config.load_domains_from_file(domain_file_path)
                except Exception as e:
                    logger.error(f"Failed to load domain file {domain_file}: {e}")
                    if not self.config.skip_invalid_domains:
                        raise
            
            logger.info(f"Configuration loaded from {file_path}")
            
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in configuration file: {e}")
        except Exception as e:
            logger.error(f"Error loading configuration from {file_path}: {e}")
            raise
    
    def save_to_file(self, file_path: Optional[Union[str, Path]] = None) -> None:
        """
        Save configuration to JSON file.
        
        Args:
            file_path: Path to save configuration (uses loaded path if None)
            
        Requirements: 5.1, 5.2, 5.3
        """
        if file_path is None:
            if self._config_file_path is None:
                raise ValueError("No file path specified and no previous file loaded")
            file_path = self._config_file_path
        else:
            file_path = Path(file_path)
        
        try:
            # Create directory if it doesn't exist
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(self.config.to_dict(), f, indent=2, sort_keys=True)
            
            logger.info(f"Configuration saved to {file_path}")
            
        except Exception as e:
            logger.error(f"Error saving configuration to {file_path}: {e}")
            raise
    
    def update_config(self, **kwargs) -> None:
        """
        Update configuration parameters.
        
        Args:
            **kwargs: Configuration parameters to update
            
        Requirements: 5.1, 5.2, 5.3
        """
        # Create new config with updated parameters
        config_dict = self.config.to_dict()
        config_dict.update(kwargs)
        
        # Validate new configuration
        new_config = FilterConfig.from_dict(config_dict)
        
        self.config = new_config
        logger.info(f"Configuration updated: {kwargs}")
    
    def reload_from_file(self) -> None:
        """
        Reload configuration from the previously loaded file.
        
        Raises:
            ValueError: If no file was previously loaded
        """
        if self._config_file_path is None:
            raise ValueError("No configuration file was previously loaded")
        
        self.load_from_file(self._config_file_path)
    
    def get_config(self) -> FilterConfig:
        """
        Get current configuration.
        
        Returns:
            Current FilterConfig instance
        """
        return self.config
    
    def validate_config(self) -> List[str]:
        """
        Validate current configuration.
        
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        try:
            # Create a copy and validate it
            test_config = FilterConfig.from_dict(self.config.to_dict())
        except Exception as e:
            errors.append(f"Configuration validation failed: {e}")
        
        return errors


def create_default_config() -> FilterConfig:
    """
    Create a default filter configuration.
    
    Returns:
        Default FilterConfig instance
        
    Requirements: 5.1, 5.2, 5.3
    """
    return FilterConfig(
        mode=FilterMode.NONE,
        domains=set(),
        enable_wildcards=True,
        enable_subdomains=True,
        case_sensitive=False,
        cache_size=1000,
        cache_ttl=300,
        cleanup_interval=60,
        validate_domains=True,
        skip_invalid_domains=True
    )


def load_config_from_dict(data: Dict[str, Any]) -> FilterConfig:
    """
    Load configuration from dictionary with error handling.
    
    Args:
        data: Configuration dictionary
        
    Returns:
        FilterConfig instance
        
    Raises:
        ValueError: If configuration is invalid
    """
    try:
        return FilterConfig.from_dict(data)
    except Exception as e:
        logger.error(f"Error loading configuration from dictionary: {e}")
        raise ValueError(f"Invalid configuration: {e}")


def load_config_from_file(file_path: Union[str, Path]) -> FilterConfig:
    """
    Load configuration from file with error handling.
    
    Args:
        file_path: Path to configuration file
        
    Returns:
        FilterConfig instance
        
    Raises:
        FileNotFoundError: If file not found
        ValueError: If configuration is invalid
    """
    manager = FilterConfigManager()
    manager.load_from_file(file_path)
    return manager.get_config()