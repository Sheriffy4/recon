"""
Domain Filter Configuration Management

This module provides configuration management for domain filtering rules,
supporting persistence, validation, and runtime updates.

Requirements: 1.1, 1.2, 1.4 from auto-strategy-discovery spec
"""

import json
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from pathlib import Path
import time

from core.domain_filter import FilterMode, FilterRule

LOG = logging.getLogger(__name__)


@dataclass
class DomainFilterConfig:
    """Configuration for domain filtering system"""

    # Default filtering settings
    default_mode: FilterMode = FilterMode.NORMAL
    enable_subdomain_matching: bool = True
    enable_statistics: bool = True

    # Performance settings
    max_rules: int = 100
    stats_retention_hours: int = 24
    cache_size: int = 1000

    # Logging settings
    log_filtered_packets: bool = False
    log_level: str = "INFO"

    # Discovery mode settings
    discovery_timeout_minutes: int = 60
    auto_cleanup_rules: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary for serialization."""
        result = asdict(self)
        # Convert enum to string
        result["default_mode"] = self.default_mode.value
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DomainFilterConfig":
        """Create config from dictionary."""
        # Convert string back to enum
        if "default_mode" in data:
            data["default_mode"] = FilterMode(data["default_mode"])

        return cls(**data)


class DomainFilterConfigManager:
    """
    Configuration manager for domain filtering system.

    Handles loading, saving, and validation of domain filter configurations
    and rules. Supports both file-based persistence and runtime updates.
    """

    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize configuration manager.

        Args:
            config_file: Path to configuration file (optional)
        """
        self.config_file = Path(config_file) if config_file else Path("config/domain_filter.json")
        self.config = DomainFilterConfig()
        self._rules_cache: Dict[str, FilterRule] = {}

        # Ensure config directory exists
        self.config_file.parent.mkdir(parents=True, exist_ok=True)

        # Load existing configuration
        self.load_config()

        LOG.info(f"DomainFilterConfigManager initialized with config file: {self.config_file}")

    def load_config(self) -> None:
        """
        Load configuration from file.

        Creates default configuration if file doesn't exist.
        """
        try:
            if self.config_file.exists():
                with open(self.config_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                # Load main config
                if "config" in data:
                    self.config = DomainFilterConfig.from_dict(data["config"])

                # Load rules
                if "rules" in data:
                    self._load_rules_from_data(data["rules"])

                LOG.info(f"Loaded domain filter configuration from {self.config_file}")
            else:
                # Create default configuration
                self.save_config()
                LOG.info(f"Created default domain filter configuration at {self.config_file}")

        except Exception as e:
            LOG.error(f"Error loading domain filter configuration: {e}")
            # Use default configuration on error
            self.config = DomainFilterConfig()

    def save_config(self) -> None:
        """Save current configuration to file."""
        try:
            data = {
                "config": self.config.to_dict(),
                "rules": self._serialize_rules(),
                "metadata": {"saved_at": time.time(), "version": "1.0"},
            }

            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            LOG.info(f"Saved domain filter configuration to {self.config_file}")

        except Exception as e:
            LOG.error(f"Error saving domain filter configuration: {e}")

    def _load_rules_from_data(self, rules_data: List[Dict[str, Any]]) -> None:
        """Load rules from serialized data."""
        self._rules_cache.clear()

        for rule_data in rules_data:
            try:
                # Convert mode string back to enum
                if "mode" in rule_data:
                    rule_data["mode"] = FilterMode(rule_data["mode"])

                rule = FilterRule(**rule_data)
                self._rules_cache[rule.target_domain] = rule

            except Exception as e:
                LOG.warning(f"Error loading rule {rule_data}: {e}")

        LOG.info(f"Loaded {len(self._rules_cache)} domain filter rules")

    def _serialize_rules(self) -> List[Dict[str, Any]]:
        """Serialize rules for saving."""
        rules_data = []

        for rule in self._rules_cache.values():
            rule_dict = asdict(rule)
            # Convert enum to string
            rule_dict["mode"] = rule.mode.value
            rules_data.append(rule_dict)

        return rules_data

    def add_rule(self, target_domain: str, mode: FilterMode = FilterMode.DISCOVERY) -> FilterRule:
        """
        Add a new domain filtering rule.

        Args:
            target_domain: Domain to create rule for
            mode: Filtering mode for the rule

        Returns:
            Created FilterRule object

        Raises:
            ValueError: If domain is invalid or too many rules exist
        """
        # Validate domain
        if not self._is_valid_domain(target_domain):
            raise ValueError(f"Invalid domain: {target_domain}")

        # Check rule limit
        if len(self._rules_cache) >= self.config.max_rules:
            raise ValueError(f"Maximum number of rules ({self.config.max_rules}) exceeded")

        # Normalize domain
        domain = self._normalize_domain(target_domain)

        # Create rule
        rule = FilterRule(target_domain=domain, mode=mode)
        self._rules_cache[domain] = rule

        LOG.info(f"Added domain filter rule: {domain} -> {mode.value}")
        return rule

    def remove_rule(self, target_domain: str) -> bool:
        """
        Remove a domain filtering rule.

        Args:
            target_domain: Domain to remove rule for

        Returns:
            True if rule was removed, False if not found
        """
        domain = self._normalize_domain(target_domain)

        if domain in self._rules_cache:
            del self._rules_cache[domain]
            LOG.info(f"Removed domain filter rule: {domain}")
            return True

        return False

    def get_rule(self, target_domain: str) -> Optional[FilterRule]:
        """
        Get a domain filtering rule.

        Args:
            target_domain: Domain to get rule for

        Returns:
            FilterRule object or None if not found
        """
        domain = self._normalize_domain(target_domain)
        return self._rules_cache.get(domain)

    def get_all_rules(self) -> Dict[str, FilterRule]:
        """Get all domain filtering rules."""
        return self._rules_cache.copy()

    def clear_rules(self) -> None:
        """Clear all domain filtering rules."""
        self._rules_cache.clear()
        LOG.info("Cleared all domain filter rules")

    def update_config(self, **kwargs) -> None:
        """
        Update configuration parameters.

        Args:
            **kwargs: Configuration parameters to update
        """
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
                LOG.info(f"Updated config parameter: {key} = {value}")
            else:
                LOG.warning(f"Unknown config parameter: {key}")

    def validate_config(self) -> List[str]:
        """
        Validate current configuration.

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        # Validate numeric ranges
        if self.config.max_rules <= 0:
            errors.append("max_rules must be positive")

        if self.config.stats_retention_hours <= 0:
            errors.append("stats_retention_hours must be positive")

        if self.config.cache_size <= 0:
            errors.append("cache_size must be positive")

        if self.config.discovery_timeout_minutes <= 0:
            errors.append("discovery_timeout_minutes must be positive")

        # Validate log level
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.config.log_level not in valid_levels:
            errors.append(f"log_level must be one of: {valid_levels}")

        return errors

    def cleanup_expired_rules(self) -> int:
        """
        Clean up expired rules based on configuration.

        Returns:
            Number of rules removed
        """
        if not self.config.auto_cleanup_rules:
            return 0

        current_time = time.time()
        timeout_seconds = self.config.discovery_timeout_minutes * 60
        removed_count = 0

        # Find expired rules
        expired_domains = []
        for domain, rule in self._rules_cache.items():
            if rule.mode == FilterMode.DISCOVERY:
                age_seconds = current_time - rule.created_at
                if age_seconds > timeout_seconds:
                    expired_domains.append(domain)

        # Remove expired rules
        for domain in expired_domains:
            del self._rules_cache[domain]
            removed_count += 1
            LOG.info(f"Removed expired discovery rule: {domain}")

        if removed_count > 0:
            LOG.info(f"Cleaned up {removed_count} expired domain filter rules")

        return removed_count

    def _is_valid_domain(self, domain: str) -> bool:
        """
        Validate domain name format.

        Args:
            domain: Domain to validate

        Returns:
            True if domain is valid
        """
        if not domain or not isinstance(domain, str):
            return False

        # Basic length check
        if len(domain) > 253:
            return False

        # Must contain at least one dot
        if "." not in domain:
            return False

        # Basic character validation
        allowed_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")
        if not all(c in allowed_chars for c in domain):
            return False

        # Must not start or end with dot or hyphen
        if domain.startswith(".") or domain.endswith("."):
            return False
        if domain.startswith("-") or domain.endswith("-"):
            return False

        return True

    def _normalize_domain(self, domain: str) -> str:
        """
        Normalize domain name for consistent storage.

        Args:
            domain: Domain to normalize

        Returns:
            Normalized domain name
        """
        if not domain:
            return domain

        return domain.strip().lower().rstrip(".")

    def export_config(self, export_file: str) -> None:
        """
        Export configuration to a different file.

        Args:
            export_file: Path to export file
        """
        try:
            export_path = Path(export_file)
            export_path.parent.mkdir(parents=True, exist_ok=True)

            data = {
                "config": self.config.to_dict(),
                "rules": self._serialize_rules(),
                "metadata": {
                    "exported_at": time.time(),
                    "exported_from": str(self.config_file),
                    "version": "1.0",
                },
            }

            with open(export_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            LOG.info(f"Exported domain filter configuration to {export_path}")

        except Exception as e:
            LOG.error(f"Error exporting configuration: {e}")
            raise

    def import_config(self, import_file: str, merge: bool = False) -> None:
        """
        Import configuration from a file.

        Args:
            import_file: Path to import file
            merge: If True, merge with existing config; if False, replace
        """
        try:
            import_path = Path(import_file)
            if not import_path.exists():
                raise FileNotFoundError(f"Import file not found: {import_path}")

            with open(import_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if not merge:
                # Replace existing configuration
                self._rules_cache.clear()

            # Import config
            if "config" in data:
                imported_config = DomainFilterConfig.from_dict(data["config"])
                if merge:
                    # Merge selected fields (you can customize this)
                    self.config.max_rules = imported_config.max_rules
                    self.config.enable_subdomain_matching = (
                        imported_config.enable_subdomain_matching
                    )
                else:
                    self.config = imported_config

            # Import rules
            if "rules" in data:
                self._load_rules_from_data(data["rules"])

            LOG.info(f"Imported domain filter configuration from {import_path} (merge={merge})")

        except Exception as e:
            LOG.error(f"Error importing configuration: {e}")
            raise
