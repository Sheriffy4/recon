"""
Discovery Configuration and Validation System

This module implements configuration classes and validation for discovery parameters,
providing comprehensive validation for target domains and discovery settings with
proper error handling for invalid configurations.

Requirements: All requirements from auto-strategy-discovery spec
"""

import logging
import re
import socket
import ipaddress
from typing import Dict, List, Optional, Any, Union, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import json
from pathlib import Path

LOG = logging.getLogger(__name__)


class ValidationError(Exception):
    """Exception raised for configuration validation errors"""

    pass


class ConfigurationError(Exception):
    """Exception raised for configuration loading/parsing errors"""

    pass


class DiscoveryMode(Enum):
    """Discovery operation modes"""

    ADAPTIVE = "adaptive"  # Adaptive strategy discovery
    COMPREHENSIVE = "comprehensive"  # Comprehensive testing of all strategies
    TARGETED = "targeted"  # Targeted testing of specific attack types
    QUICK = "quick"  # Quick discovery with limited strategies


class LogLevel(Enum):
    """Logging levels for discovery operations"""

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass
class DomainValidationConfig:
    """Configuration for domain validation rules"""

    allow_wildcards: bool = True
    allow_subdomains: bool = True
    allow_ip_addresses: bool = False
    max_domain_length: int = 253
    min_domain_length: int = 1
    blocked_domains: Set[str] = field(default_factory=set)
    allowed_tlds: Optional[Set[str]] = None  # None means all TLDs allowed

    def __post_init__(self):
        """Validate configuration after initialization"""
        if self.max_domain_length <= 0:
            raise ValidationError("max_domain_length must be positive")
        if self.min_domain_length <= 0:
            raise ValidationError("min_domain_length must be positive")
        if self.min_domain_length > self.max_domain_length:
            raise ValidationError("min_domain_length cannot exceed max_domain_length")


@dataclass
class StrategyConfig:
    """Configuration for strategy generation and testing"""

    max_strategies: int = 50
    max_duration_seconds: int = 3600
    strategy_timeout_seconds: int = 30
    prefer_untested: bool = True
    exclude_attack_types: List[str] = field(default_factory=list)
    include_attack_types: Optional[List[str]] = None  # None means all types
    max_complexity_score: float = 1.0
    min_complexity_score: float = 0.0

    def __post_init__(self):
        """Validate strategy configuration"""
        # CRITICAL FIX: Handle None values before validation
        if self.max_strategies is None:
            self.max_strategies = 50  # Default value
        if self.max_duration_seconds is None:
            self.max_duration_seconds = 3600  # Default value
        if self.strategy_timeout_seconds is None:
            self.strategy_timeout_seconds = 30  # Default value

        if self.max_strategies <= 0:
            raise ValidationError("max_strategies must be positive")
        if self.max_duration_seconds <= 0:
            raise ValidationError("max_duration_seconds must be positive")
        if self.strategy_timeout_seconds <= 0:
            raise ValidationError("strategy_timeout_seconds must be positive")
        if self.strategy_timeout_seconds >= self.max_duration_seconds:
            raise ValidationError("strategy_timeout_seconds must be less than max_duration_seconds")
        if not 0.0 <= self.min_complexity_score <= self.max_complexity_score <= 1.0:
            raise ValidationError("complexity scores must be between 0.0 and 1.0, with min <= max")


@dataclass
class PCAPConfig:
    """Configuration for PCAP capture during discovery"""

    enabled: bool = True
    max_packets: Optional[int] = 1000
    max_seconds: Optional[int] = 60
    capture_filter: Optional[str] = None
    output_directory: Optional[str] = None
    compress_files: bool = True
    auto_cleanup: bool = True
    cleanup_after_hours: Optional[int] = 24

    def __post_init__(self):
        """Validate PCAP configuration"""
        if self.max_packets is not None and self.max_packets <= 0:
            raise ValidationError("max_packets must be positive")
        if self.max_seconds is not None and self.max_seconds <= 0:
            raise ValidationError("max_seconds must be positive")
        if self.cleanup_after_hours is not None and self.cleanup_after_hours <= 0:
            raise ValidationError("cleanup_after_hours must be positive")

        # Set default value if None
        if self.cleanup_after_hours is None:
            self.cleanup_after_hours = 24


@dataclass
class ResultsConfig:
    """Configuration for results collection and reporting"""

    collect_pcap_analysis: bool = True
    collect_validation_results: bool = True
    collect_performance_metrics: bool = True
    max_result_history: int = 1000
    export_format: str = "json"  # json, csv, xml
    auto_export: bool = False
    export_directory: Optional[str] = None

    def __post_init__(self):
        """Validate results configuration"""
        if self.max_result_history <= 0:
            raise ValidationError("max_result_history must be positive")
        if self.export_format not in ["json", "csv", "xml"]:
            raise ValidationError("export_format must be one of: json, csv, xml")


@dataclass
class IntegrationConfig:
    """Configuration for system integration settings"""

    override_domain_rules: bool = True
    restore_rules_on_completion: bool = True
    backup_existing_config: bool = True
    max_concurrent_sessions: int = 1
    enable_monitoring: bool = True
    monitoring_interval_seconds: int = 30

    def __post_init__(self):
        """Validate integration configuration"""
        if self.max_concurrent_sessions <= 0:
            raise ValidationError("max_concurrent_sessions must be positive")
        if self.monitoring_interval_seconds <= 0:
            raise ValidationError("monitoring_interval_seconds must be positive")


@dataclass
class DiscoveryConfig:
    """
    Comprehensive configuration for discovery sessions.

    This class provides complete configuration management for auto strategy discovery,
    including validation, serialization, and error handling.
    """

    # Core settings
    target_domain: str
    mode: DiscoveryMode = DiscoveryMode.ADAPTIVE

    # Component configurations
    domain_validation: DomainValidationConfig = field(default_factory=DomainValidationConfig)
    strategy: StrategyConfig = field(default_factory=StrategyConfig)
    pcap: PCAPConfig = field(default_factory=PCAPConfig)
    results: ResultsConfig = field(default_factory=ResultsConfig)
    integration: IntegrationConfig = field(default_factory=IntegrationConfig)

    # Logging and debugging
    log_level: LogLevel = LogLevel.INFO
    debug_mode: bool = False
    verbose_logging: bool = False

    # Session metadata
    session_name: Optional[str] = None
    description: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    created_at: Optional[datetime] = None

    def __post_init__(self):
        """Validate configuration after initialization"""
        if self.created_at is None:
            self.created_at = datetime.now()

        # Validate target domain
        self.validate_target_domain()

        # Validate component configurations are already validated in their __post_init__

        # Cross-component validation
        self._validate_cross_component_settings()

    def validate_target_domain(self) -> None:
        """
        Validate the target domain according to domain validation rules.

        Raises:
            ValidationError: If domain validation fails
        """
        if not self.target_domain:
            raise ValidationError("Target domain cannot be empty")

        domain = self.target_domain.strip().lower()

        # Length validation
        if len(domain) < self.domain_validation.min_domain_length:
            raise ValidationError(
                f"Domain too short (min: {self.domain_validation.min_domain_length})"
            )

        if len(domain) > self.domain_validation.max_domain_length:
            raise ValidationError(
                f"Domain too long (max: {self.domain_validation.max_domain_length})"
            )

        # Check blocked domains
        if domain in self.domain_validation.blocked_domains:
            raise ValidationError(f"Domain '{domain}' is blocked")

        # IP address validation
        if self._is_ip_address(domain):
            if not self.domain_validation.allow_ip_addresses:
                raise ValidationError("IP addresses are not allowed as target domains")
            return  # IP addresses don't need further domain validation

        # Wildcard validation
        if "*" in domain:
            if not self.domain_validation.allow_wildcards:
                raise ValidationError("Wildcard domains are not allowed")
            self._validate_wildcard_domain(domain)
        else:
            self._validate_regular_domain(domain)

        # TLD validation
        if self.domain_validation.allowed_tlds is not None:
            tld = domain.split(".")[-1] if "." in domain else domain
            if tld not in self.domain_validation.allowed_tlds:
                raise ValidationError(f"TLD '{tld}' is not allowed")

    def _is_ip_address(self, domain: str) -> bool:
        """Check if domain is an IP address"""
        try:
            ipaddress.ip_address(domain)
            return True
        except ValueError:
            return False

    def _validate_wildcard_domain(self, domain: str) -> None:
        """Validate wildcard domain format"""
        # Basic wildcard validation - only allow * at the beginning
        if not domain.startswith("*."):
            raise ValidationError(
                "Wildcards are only allowed at the beginning (e.g., '*.example.com')"
            )

        # Validate the non-wildcard part
        base_domain = domain[2:]  # Remove '*.'
        if not base_domain:
            raise ValidationError("Wildcard domain must have a base domain")

        self._validate_regular_domain(base_domain)

    def _validate_regular_domain(self, domain: str) -> None:
        """Validate regular domain format"""
        # RFC 1123 compliant domain validation
        domain_pattern = re.compile(
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
        )

        if not domain_pattern.match(domain):
            raise ValidationError(f"Invalid domain format: '{domain}'")

        # Additional checks
        if domain.startswith("-") or domain.endswith("-"):
            raise ValidationError("Domain cannot start or end with hyphen")

        if ".." in domain:
            raise ValidationError("Domain cannot contain consecutive dots")

        # Check subdomain restrictions
        if not self.domain_validation.allow_subdomains and domain.count(".") > 0:
            # This is a subdomain (has dots), but subdomains are not allowed
            raise ValidationError("Subdomains are not allowed")

    def _validate_cross_component_settings(self) -> None:
        """Validate settings across different components"""
        # Ensure PCAP timeout doesn't exceed strategy timeout
        if (
            self.pcap.enabled
            and self.pcap.max_seconds is not None
            and self.pcap.max_seconds > self.strategy.strategy_timeout_seconds
        ):
            LOG.warning(
                f"PCAP timeout ({self.pcap.max_seconds}s) exceeds strategy timeout "
                f"({self.strategy.strategy_timeout_seconds}s)"
            )

        # Validate export directory if auto-export is enabled
        if self.results.auto_export and not self.results.export_directory:
            raise ValidationError("export_directory must be specified when auto_export is enabled")

        # Validate PCAP output directory if specified
        if self.pcap.output_directory:
            try:
                Path(self.pcap.output_directory).mkdir(parents=True, exist_ok=True)
            except Exception as e:
                raise ValidationError(f"Cannot create PCAP output directory: {e}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary for serialization"""

        def convert_value(value):
            if isinstance(value, Enum):
                return value.value
            elif isinstance(value, datetime):
                return value.isoformat()
            elif isinstance(value, set):
                return list(value)
            elif hasattr(value, "__dict__"):
                return {k: convert_value(v) for k, v in value.__dict__.items()}
            else:
                return value

        return {k: convert_value(v) for k, v in self.__dict__.items()}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DiscoveryConfig":
        """Create configuration from dictionary"""
        try:
            # Convert enum values back to enums
            if "mode" in data and isinstance(data["mode"], str):
                data["mode"] = DiscoveryMode(data["mode"])

            if "log_level" in data and isinstance(data["log_level"], str):
                data["log_level"] = LogLevel(data["log_level"])

            # Convert datetime strings back to datetime objects
            if "created_at" in data and isinstance(data["created_at"], str):
                data["created_at"] = datetime.fromisoformat(data["created_at"])

            # Convert nested configurations
            nested_configs = {
                "domain_validation": DomainValidationConfig,
                "strategy": StrategyConfig,
                "pcap": PCAPConfig,
                "results": ResultsConfig,
                "integration": IntegrationConfig,
            }

            for key, config_class in nested_configs.items():
                if key in data and isinstance(data[key], dict):
                    # Convert sets back from lists
                    if key == "domain_validation" and "blocked_domains" in data[key]:
                        data[key]["blocked_domains"] = set(data[key]["blocked_domains"])
                    if (
                        key == "domain_validation"
                        and "allowed_tlds" in data[key]
                        and data[key]["allowed_tlds"] is not None
                    ):
                        data[key]["allowed_tlds"] = set(data[key]["allowed_tlds"])

                    data[key] = config_class(**data[key])

            return cls(**data)

        except Exception as e:
            raise ConfigurationError(f"Failed to create configuration from dictionary: {e}")

    def to_json(self, indent: int = 2) -> str:
        """Convert configuration to JSON string"""
        try:
            return json.dumps(self.to_dict(), indent=indent, default=str)
        except Exception as e:
            raise ConfigurationError(f"Failed to serialize configuration to JSON: {e}")

    @classmethod
    def from_json(cls, json_str: str) -> "DiscoveryConfig":
        """Create configuration from JSON string"""
        try:
            data = json.loads(json_str)
            return cls.from_dict(data)
        except json.JSONDecodeError as e:
            raise ConfigurationError(f"Invalid JSON format: {e}")
        except Exception as e:
            raise ConfigurationError(f"Failed to parse configuration from JSON: {e}")

    def save_to_file(self, file_path: Union[str, Path]) -> None:
        """Save configuration to file"""
        try:
            path = Path(file_path)
            path.parent.mkdir(parents=True, exist_ok=True)

            with open(path, "w") as f:
                f.write(self.to_json())

            LOG.info(f"Configuration saved to {path}")

        except Exception as e:
            raise ConfigurationError(f"Failed to save configuration to file: {e}")

    @classmethod
    def load_from_file(cls, file_path: Union[str, Path]) -> "DiscoveryConfig":
        """Load configuration from file"""
        try:
            path = Path(file_path)

            if not path.exists():
                raise ConfigurationError(f"Configuration file not found: {path}")

            with open(path, "r") as f:
                json_str = f.read()

            config = cls.from_json(json_str)
            LOG.info(f"Configuration loaded from {path}")
            return config

        except Exception as e:
            raise ConfigurationError(f"Failed to load configuration from file: {e}")

    def validate_full_configuration(self) -> List[str]:
        """
        Perform comprehensive validation of the entire configuration.

        Returns:
            List of validation warnings (empty if no warnings)

        Raises:
            ValidationError: If critical validation errors are found
        """
        warnings = []

        try:
            # Re-validate target domain
            self.validate_target_domain()

            # Validate component configurations
            self._validate_cross_component_settings()

            # Performance warnings
            if self.strategy.max_strategies > 100:
                warnings.append(
                    f"Large number of strategies ({self.strategy.max_strategies}) may take significant time"
                )

            if self.strategy.max_duration_seconds > 7200:  # 2 hours
                warnings.append(
                    f"Long duration ({self.strategy.max_duration_seconds}s) may consume significant resources"
                )

            if self.pcap.enabled and self.pcap.max_packets and self.pcap.max_packets > 10000:
                warnings.append(
                    f"Large PCAP capture ({self.pcap.max_packets} packets) may use significant disk space"
                )

            # Integration warnings
            if not self.integration.backup_existing_config:
                warnings.append(
                    "Existing configuration backup is disabled - changes may be irreversible"
                )

            if self.integration.max_concurrent_sessions > 3:
                warnings.append(
                    f"High concurrent sessions ({self.integration.max_concurrent_sessions}) may impact performance"
                )

            # Results warnings
            if self.results.max_result_history > 5000:
                warnings.append(
                    f"Large result history ({self.results.max_result_history}) may use significant memory"
                )

            LOG.info(f"Configuration validation completed with {len(warnings)} warnings")
            return warnings

        except Exception as e:
            raise ValidationError(f"Configuration validation failed: {e}")

    def get_effective_settings_summary(self) -> Dict[str, Any]:
        """Get a summary of effective configuration settings"""
        return {
            "target_domain": self.target_domain,
            "mode": self.mode.value,
            "max_strategies": self.strategy.max_strategies,
            "max_duration_minutes": self.strategy.max_duration_seconds // 60,
            "pcap_enabled": self.pcap.enabled,
            "override_domain_rules": self.integration.override_domain_rules,
            "debug_mode": self.debug_mode,
            "log_level": self.log_level.value,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def clone(self, **overrides) -> "DiscoveryConfig":
        """Create a copy of the configuration with optional overrides"""
        # Convert to dict, apply overrides, then create new instance
        config_dict = self.to_dict()
        config_dict.update(overrides)
        return self.from_dict(config_dict)


class DiscoveryConfigValidator:
    """
    Standalone validator for discovery configurations.

    Provides additional validation methods and utilities for configuration management.
    """

    @staticmethod
    def validate_domain_accessibility(domain: str, timeout: int = 5) -> bool:
        """
        Test if a domain is accessible via DNS resolution.

        Args:
            domain: Domain to test
            timeout: DNS resolution timeout in seconds

        Returns:
            True if domain is accessible, False otherwise
        """
        try:
            # Remove wildcard prefix if present
            test_domain = domain.replace("*.", "") if domain.startswith("*.") else domain

            # Try DNS resolution
            socket.setdefaulttimeout(timeout)
            socket.gethostbyname(test_domain)
            return True

        except (socket.gaierror, socket.timeout):
            return False
        except Exception as e:
            LOG.warning(f"Unexpected error testing domain accessibility: {e}")
            return False

    @staticmethod
    def validate_attack_types(attack_types: List[str]) -> List[str]:
        """
        Validate attack type names against known types.

        Args:
            attack_types: List of attack type names to validate

        Returns:
            List of invalid attack type names
        """
        # Import here to avoid circular imports
        from core.strategy_diversifier import AttackType

        valid_types = {at.value for at in AttackType}
        invalid_types = [at for at in attack_types if at not in valid_types]

        return invalid_types

    @staticmethod
    def suggest_configuration_improvements(config: DiscoveryConfig) -> List[str]:
        """
        Suggest improvements for a configuration.

        Args:
            config: Configuration to analyze

        Returns:
            List of improvement suggestions
        """
        suggestions = []

        # Strategy suggestions
        if config.strategy.max_strategies < 10:
            suggestions.append(
                "Consider increasing max_strategies for more comprehensive discovery"
            )

        if config.strategy.strategy_timeout_seconds < 15:
            suggestions.append(
                "Consider increasing strategy_timeout_seconds for more reliable testing"
            )

        # PCAP suggestions
        if not config.pcap.enabled:
            suggestions.append("Consider enabling PCAP capture for better analysis capabilities")

        if config.pcap.enabled and not config.pcap.auto_cleanup:
            suggestions.append("Consider enabling PCAP auto_cleanup to manage disk space")

        # Results suggestions
        if not config.results.collect_performance_metrics:
            suggestions.append(
                "Consider enabling performance metrics collection for optimization insights"
            )

        # Integration suggestions
        if not config.integration.enable_monitoring:
            suggestions.append("Consider enabling monitoring for better session visibility")

        return suggestions

    @staticmethod
    def create_quick_config(target_domain: str) -> DiscoveryConfig:
        """
        Create a quick discovery configuration with sensible defaults.

        Args:
            target_domain: Target domain for discovery

        Returns:
            DiscoveryConfig configured for quick discovery
        """
        return DiscoveryConfig(
            target_domain=target_domain,
            mode=DiscoveryMode.QUICK,
            strategy=StrategyConfig(
                max_strategies=10,
                max_duration_seconds=300,  # 5 minutes
                strategy_timeout_seconds=15,
            ),
            pcap=PCAPConfig(enabled=True, max_packets=500, max_seconds=30),
            results=ResultsConfig(
                collect_pcap_analysis=False, collect_performance_metrics=False  # Skip for speed
            ),
        )

    @staticmethod
    def create_comprehensive_config(target_domain: str) -> DiscoveryConfig:
        """
        Create a comprehensive discovery configuration.

        Args:
            target_domain: Target domain for discovery

        Returns:
            DiscoveryConfig configured for comprehensive discovery
        """
        return DiscoveryConfig(
            target_domain=target_domain,
            mode=DiscoveryMode.COMPREHENSIVE,
            strategy=StrategyConfig(
                max_strategies=100,
                max_duration_seconds=7200,  # 2 hours
                strategy_timeout_seconds=60,
            ),
            pcap=PCAPConfig(enabled=True, max_packets=2000, max_seconds=120),
            results=ResultsConfig(
                collect_pcap_analysis=True,
                collect_validation_results=True,
                collect_performance_metrics=True,
            ),
            debug_mode=True,
            verbose_logging=True,
        )


# Example usage and testing
if __name__ == "__main__":
    # Test configuration creation and validation
    print("Testing DiscoveryConfig...")

    try:
        # Create basic configuration
        config = DiscoveryConfig(target_domain="example.com")
        print(f"✅ Created basic config for {config.target_domain}")

        # Test validation
        warnings = config.validate_full_configuration()
        print(f"✅ Validation completed with {len(warnings)} warnings")

        # Test serialization
        json_str = config.to_json()
        print(f"✅ Serialized to JSON ({len(json_str)} chars)")

        # Test deserialization
        config2 = DiscoveryConfig.from_json(json_str)
        print(f"✅ Deserialized from JSON: {config2.target_domain}")

        # Test invalid domain
        try:
            invalid_config = DiscoveryConfig(target_domain="")
            print("❌ Should have failed for empty domain")
        except ValidationError as e:
            print(f"✅ Correctly rejected empty domain: {e}")

        # Test validator utilities
        validator = DiscoveryConfigValidator()
        suggestions = validator.suggest_configuration_improvements(config)
        print(f"✅ Generated {len(suggestions)} improvement suggestions")

        # Test quick config
        quick_config = validator.create_quick_config("test.com")
        print(f"✅ Created quick config: {quick_config.mode.value} mode")

        print("All tests passed!")

    except Exception as e:
        print(f"❌ Test failed: {e}")
        raise
