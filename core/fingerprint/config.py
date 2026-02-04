#!/usr/bin/env python3
"""
Configuration and Customization System for Advanced DPI Fingerprinting - Task 16 Implementation
Provides configuration file support, runtime configuration, feature flags, and performance tuning.
"""

import json
import yaml
import os
import logging
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass, field, asdict
from enum import Enum

logger = logging.getLogger(__name__)


class ConfigurationError(Exception):
    """Base exception for configuration system"""

    pass


class ConfigValidationError(ConfigurationError):
    """Configuration validation errors"""

    pass


class ConfigLoadError(ConfigurationError):
    """Configuration loading errors"""

    pass


class AnalyzerType(Enum):
    """Available analyzer types"""

    TCP = "tcp"
    HTTP = "http"
    DNS = "dns"
    ML_CLASSIFIER = "ml_classifier"
    METRICS_COLLECTOR = "metrics_collector"
    CACHE = "cache"
    MONITOR = "monitor"


class LogLevel(Enum):
    """Logging levels"""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


@dataclass
class NetworkConfig:
    """Network-related configuration"""

    timeout: float = 5.0
    max_retries: int = 3
    retry_delay: float = 1.0
    concurrent_limit: int = 10
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    dns_servers: List[str] = field(default_factory=lambda: ["8.8.8.8", "1.1.1.1"])
    bind_address: Optional[str] = None
    proxy_url: Optional[str] = None


@dataclass
class CacheConfig:
    """Cache system configuration"""

    enabled: bool = True
    cache_dir: str = "cache"
    max_size: int = 1000
    ttl_seconds: int = 3600
    cleanup_interval: int = 300
    compression: bool = True
    backup_enabled: bool = True
    backup_interval: int = 86400


@dataclass
class MLConfig:
    """Machine Learning configuration"""

    enabled: bool = True
    model_path: str = "models/dpi_classifier.joblib"
    training_data_path: str = "data/training_data.json"
    confidence_threshold: float = 0.7
    retrain_threshold: float = 0.6
    max_training_samples: int = 10000
    feature_selection: bool = True
    cross_validation_folds: int = 5
    random_state: int = 42


@dataclass
class MonitoringConfig:
    """Real-time monitoring configuration"""

    enabled: bool = True
    check_interval: int = 300
    adaptive_frequency: bool = True
    min_interval: int = 60
    max_interval: int = 3600
    alert_threshold: float = 0.8
    max_alerts_per_hour: int = 10
    background_monitoring: bool = True


@dataclass
class AnalyzerConfig:
    """Individual analyzer configuration"""

    enabled: bool = True
    timeout: float = 10.0
    max_samples: int = 10
    confidence_weight: float = 1.0
    priority: int = 1
    custom_params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PerformanceConfig:
    """Performance tuning configuration"""

    max_concurrent_fingerprints: int = 5
    fingerprint_timeout: float = 30.0
    batch_size: int = 10
    memory_limit_mb: int = 512
    cpu_limit_percent: int = 80
    enable_profiling: bool = False
    profile_output_dir: str = "profiles"

    # New parallel processing settings
    max_parallel_targets: int = 15  # сколько доменов одновременно
    semaphore_limit: int = 10  # ограничение на одномоментные задачи

    # Configurable timeouts (подхватываются методами)
    connect_timeout: float = 1.5  # TCP connect
    tls_timeout: float = 2.0  # TLS handshake
    udp_timeout: float = 0.3  # UDP/QUIC
    dns_timeout: float = 1.0  # DNS resolution

    # Analysis level control
    analysis_level: str = "balanced"  # 'fast' | 'balanced' | 'full'

    # Feature toggles for performance
    enable_scapy_probes: bool = False  # Heavy scapy operations
    sni_probe_mode: str = "basic"  # 'off' | 'basic' | 'detailed'
    enable_behavioral_probes: bool = True  # Advanced behavioral analysis
    enable_extended_metrics: bool = True  # Extended metrics collection

    # Fail-fast settings
    enable_fail_fast: bool = True  # Skip heavy probes on obvious blocks
    early_exit_on_timeout: bool = True  # Exit early on connection timeouts
    skip_heavy_on_block: bool = True  # Skip heavy analysis if blocked

    # Performance monitoring
    collect_timing_metrics: bool = True  # Collect detailed timing info
    log_slow_operations: bool = True  # Log operations taking > threshold
    slow_operation_threshold: float = 2.0  # Seconds

    # New parallel processing settings
    max_parallel_targets: int = 15  # сколько доменов одновременно
    semaphore_limit: int = 10  # ограничение на одномоментные задачи

    # Configurable timeouts (подхватываются методами)
    connect_timeout: float = 1.5  # TCP connect
    tls_timeout: float = 2.0  # TLS handshake
    udp_timeout: float = 0.3  # UDP/QUIC
    dns_timeout: float = 1.0  # DNS resolution

    # Analysis level control
    analysis_level: str = "balanced"  # 'fast' | 'balanced' | 'full'

    # Feature toggles for performance
    enable_scapy_probes: bool = False  # Heavy scapy operations
    sni_probe_mode: str = "basic"  # 'off' | 'basic' | 'detailed'
    enable_behavioral_probes: bool = True  # Advanced behavioral analysis
    enable_extended_metrics: bool = True  # Extended metrics collection

    # Fail-fast settings
    enable_fail_fast: bool = True  # Skip heavy probes on obvious blocks
    early_exit_on_timeout: bool = True  # Exit early on connection timeouts
    skip_heavy_on_block: bool = True  # Skip heavy analysis if blocked

    # Performance monitoring
    collect_timing_metrics: bool = True  # Collect detailed timing info
    log_slow_operations: bool = True  # Log operations taking > threshold
    slow_operation_threshold: float = 2.0  # Seconds


@dataclass
class LoggingConfig:
    """Logging configuration"""

    level: LogLevel = LogLevel.INFO
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file_path: Optional[str] = None
    max_file_size: int = 10485760  # 10MB
    backup_count: int = 5
    console_output: bool = True
    structured_logging: bool = False


@dataclass
class AdvancedFingerprintingConfig:
    """Main configuration class for advanced DPI fingerprinting"""

    # Core settings
    enabled: bool = True
    debug_mode: bool = False
    config_version: str = "1.0"

    # Component configurations
    network: NetworkConfig = field(default_factory=NetworkConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    ml: MLConfig = field(default_factory=MLConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)

    # Analyzer configurations
    analyzers: Dict[str, AnalyzerConfig] = field(
        default_factory=lambda: {
            "tcp": AnalyzerConfig(enabled=True, timeout=5.0, max_samples=10),
            "http": AnalyzerConfig(enabled=True, timeout=10.0, max_samples=5),
            "dns": AnalyzerConfig(enabled=True, timeout=5.0, max_samples=3),
            "ml_classifier": AnalyzerConfig(enabled=True, timeout=2.0, max_samples=1),
            "metrics_collector": AnalyzerConfig(enabled=True, timeout=15.0, max_samples=20),
            "monitor": AnalyzerConfig(enabled=True, timeout=30.0, max_samples=1),
        }
    )

    # Feature flags
    feature_flags: Dict[str, bool] = field(
        default_factory=lambda: {
            "advanced_tcp_analysis": True,
            "deep_packet_inspection": True,
            "ml_classification": True,
            "real_time_monitoring": True,
            "cache_compression": True,
            "background_learning": True,
            "performance_profiling": False,
            "experimental_features": False,
        }
    )

    # Custom settings
    custom_settings: Dict[str, Any] = field(default_factory=dict)

    def validate(self) -> List[str]:
        """Validate configuration and return list of errors."""
        errors = []

        # Validate network settings
        if self.network.timeout <= 0:
            errors.append("Network timeout must be positive")
        if self.network.max_retries < 0:
            errors.append("Max retries cannot be negative")
        if self.network.concurrent_limit <= 0:
            errors.append("Concurrent limit must be positive")

        # Validate cache settings
        if self.cache.max_size <= 0:
            errors.append("Cache max size must be positive")
        if self.cache.ttl_seconds <= 0:
            errors.append("Cache TTL must be positive")

        # Validate ML settings
        if self.ml.confidence_threshold < 0 or self.ml.confidence_threshold > 1:
            errors.append("ML confidence threshold must be between 0 and 1")
        if self.ml.retrain_threshold < 0 or self.ml.retrain_threshold > 1:
            errors.append("ML retrain threshold must be between 0 and 1")

        # Validate monitoring settings
        if self.monitoring.check_interval <= 0:
            errors.append("Monitoring check interval must be positive")
        if self.monitoring.min_interval >= self.monitoring.max_interval:
            errors.append("Monitoring min interval must be less than max interval")

        # Validate performance settings
        if self.performance.max_concurrent_fingerprints <= 0:
            errors.append("Max concurrent fingerprints must be positive")
        if self.performance.fingerprint_timeout <= 0:
            errors.append("Fingerprint timeout must be positive")
        if self.performance.memory_limit_mb <= 0:
            errors.append("Memory limit must be positive")

        # Validate analyzer configurations
        for name, analyzer_config in self.analyzers.items():
            if analyzer_config.timeout <= 0:
                errors.append(f"Analyzer {name} timeout must be positive")
            if analyzer_config.max_samples <= 0:
                errors.append(f"Analyzer {name} max samples must be positive")
            if analyzer_config.confidence_weight < 0:
                errors.append(f"Analyzer {name} confidence weight cannot be negative")

        return errors

    def is_analyzer_enabled(self, analyzer_type: Union[str, AnalyzerType]) -> bool:
        """Check if specific analyzer is enabled."""
        if isinstance(analyzer_type, AnalyzerType):
            analyzer_type = analyzer_type.value

        return (
            self.enabled
            and analyzer_type in self.analyzers
            and self.analyzers[analyzer_type].enabled
        )

    def is_feature_enabled(self, feature_name: str) -> bool:
        """Check if specific feature is enabled."""
        return self.enabled and self.feature_flags.get(feature_name, False)

    def get_analyzer_config(
        self, analyzer_type: Union[str, AnalyzerType]
    ) -> Optional[AnalyzerConfig]:
        """Get configuration for specific analyzer."""
        if isinstance(analyzer_type, AnalyzerType):
            analyzer_type = analyzer_type.value

        return self.analyzers.get(analyzer_type)

    def update_analyzer_config(self, analyzer_type: Union[str, AnalyzerType], **kwargs):
        """Update analyzer configuration."""
        if isinstance(analyzer_type, AnalyzerType):
            analyzer_type = analyzer_type.value

        if analyzer_type not in self.analyzers:
            self.analyzers[analyzer_type] = AnalyzerConfig()

        for key, value in kwargs.items():
            if hasattr(self.analyzers[analyzer_type], key):
                setattr(self.analyzers[analyzer_type], key, value)

    def enable_analyzer(self, analyzer_type: Union[str, AnalyzerType]):
        """Enable specific analyzer."""
        self.update_analyzer_config(analyzer_type, enabled=True)

    def disable_analyzer(self, analyzer_type: Union[str, AnalyzerType]):
        """Disable specific analyzer."""
        self.update_analyzer_config(analyzer_type, enabled=False)

    def enable_feature(self, feature_name: str):
        """Enable specific feature."""
        self.feature_flags[feature_name] = True

    def disable_feature(self, feature_name: str):
        """Disable specific feature."""
        self.feature_flags[feature_name] = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AdvancedFingerprintingConfig":
        """Create configuration from dictionary."""
        # Handle nested dataclasses
        if "network" in data and isinstance(data["network"], dict):
            data["network"] = NetworkConfig(**data["network"])

        if "cache" in data and isinstance(data["cache"], dict):
            data["cache"] = CacheConfig(**data["cache"])

        if "ml" in data and isinstance(data["ml"], dict):
            data["ml"] = MLConfig(**data["ml"])

        if "monitoring" in data and isinstance(data["monitoring"], dict):
            data["monitoring"] = MonitoringConfig(**data["monitoring"])

        if "performance" in data and isinstance(data["performance"], dict):
            data["performance"] = PerformanceConfig(**data["performance"])

        if "logging" in data and isinstance(data["logging"], dict):
            # Handle LogLevel enum
            if "level" in data["logging"] and isinstance(data["logging"]["level"], str):
                data["logging"]["level"] = LogLevel(data["logging"]["level"])
            data["logging"] = LoggingConfig(**data["logging"])

        # Handle analyzer configurations
        if "analyzers" in data and isinstance(data["analyzers"], dict):
            analyzers = {}
            for name, config in data["analyzers"].items():
                if isinstance(config, dict):
                    analyzers[name] = AnalyzerConfig(**config)
                else:
                    analyzers[name] = config
            data["analyzers"] = analyzers

        return cls(**data)


class ConfigurationManager:
    """Manages configuration loading, saving, and runtime updates."""

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration manager.

        Args:
            config_path: Path to configuration file
        """
        self.config_path = config_path or self._find_config_file()
        self.config = AdvancedFingerprintingConfig()
        self._watchers = []
        self._last_modified = 0

        # Load configuration if file exists
        if self.config_path and os.path.exists(self.config_path):
            try:
                self.load_config()
            except Exception as e:
                logger.warning(f"Failed to load config from {self.config_path}: {e}")

    def _find_config_file(self) -> Optional[str]:
        """Find configuration file in common locations."""
        search_paths = [
            "fingerprint_config.yaml",
            "fingerprint_config.yml",
            "fingerprint_config.json",
            "config/fingerprint.yaml",
            "config/fingerprint.yml",
            "config/fingerprint.json",
            os.path.expanduser("~/.fingerprint_config.yaml"),
            "/etc/fingerprint/config.yaml",
        ]

        for path in search_paths:
            if os.path.exists(path):
                return path

        return None

    def load_config(self, config_path: Optional[str] = None) -> AdvancedFingerprintingConfig:
        """
        Load configuration from file.

        Args:
            config_path: Path to configuration file

        Returns:
            Loaded configuration

        Raises:
            ConfigLoadError: If configuration cannot be loaded
        """
        if config_path:
            self.config_path = config_path

        if not self.config_path or not os.path.exists(self.config_path):
            raise ConfigLoadError(f"Configuration file not found: {self.config_path}")

        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                if self.config_path.endswith((".yaml", ".yml")):
                    data = yaml.safe_load(f)
                elif self.config_path.endswith(".json"):
                    data = json.load(f)
                else:
                    raise ConfigLoadError(f"Unsupported configuration format: {self.config_path}")

            self.config = AdvancedFingerprintingConfig.from_dict(data)
            self._last_modified = os.path.getmtime(self.config_path)

            # Validate configuration
            errors = self.config.validate()
            if errors:
                raise ConfigValidationError(f"Configuration validation failed: {errors}")

            logger.info(f"Configuration loaded from {self.config_path}")
            return self.config

        except Exception as e:
            if isinstance(e, (ConfigLoadError, ConfigValidationError)):
                raise
            raise ConfigLoadError(f"Failed to load configuration: {e}")

    def save_config(self, config_path: Optional[str] = None) -> None:
        """
        Save configuration to file.

        Args:
            config_path: Path to save configuration file

        Raises:
            ConfigLoadError: If configuration cannot be saved
        """
        if config_path:
            self.config_path = config_path

        if not self.config_path:
            raise ConfigLoadError("No configuration path specified")

        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)

            data = self.config.to_dict()

            with open(self.config_path, "w", encoding="utf-8") as f:
                if self.config_path.endswith((".yaml", ".yml")):
                    yaml.dump(data, f, default_flow_style=False, indent=2)
                elif self.config_path.endswith(".json"):
                    json.dump(data, f, indent=2, default=str)
                else:
                    raise ConfigLoadError(f"Unsupported configuration format: {self.config_path}")

            self._last_modified = os.path.getmtime(self.config_path)
            logger.info(f"Configuration saved to {self.config_path}")

        except Exception as e:
            raise ConfigLoadError(f"Failed to save configuration: {e}")

    def reload_if_changed(self) -> bool:
        """
        Reload configuration if file has been modified.

        Returns:
            True if configuration was reloaded
        """
        if not self.config_path or not os.path.exists(self.config_path):
            return False

        try:
            current_modified = os.path.getmtime(self.config_path)
            if current_modified > self._last_modified:
                self.load_config()
                return True
        except Exception as e:
            logger.warning(f"Failed to check config file modification: {e}")

        return False

    def create_default_config(self, config_path: str) -> None:
        """
        Create default configuration file.

        Args:
            config_path: Path to create configuration file
        """
        self.config = AdvancedFingerprintingConfig()
        self.config_path = config_path
        self.save_config()

    def update_config(self, **kwargs) -> None:
        """
        Update configuration with new values.

        Args:
            **kwargs: Configuration values to update
        """
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)

        # Validate updated configuration
        errors = self.config.validate()
        if errors:
            raise ConfigValidationError(f"Configuration validation failed: {errors}")

    def get_config(self) -> AdvancedFingerprintingConfig:
        """Get current configuration."""
        return self.config

    def reset_to_defaults(self) -> None:
        """Reset configuration to defaults."""
        self.config = AdvancedFingerprintingConfig()


# Global configuration manager instance
_config_manager = None


def get_config_manager(config_path: Optional[str] = None) -> ConfigurationManager:
    """Get global configuration manager instance."""
    global _config_manager

    if _config_manager is None:
        _config_manager = ConfigurationManager(config_path)

    return _config_manager


def get_config() -> AdvancedFingerprintingConfig:
    """Get current configuration."""
    return get_config_manager().get_config()


def load_config(config_path: str) -> AdvancedFingerprintingConfig:
    """Load configuration from file."""
    return get_config_manager().load_config(config_path)


def save_config(config_path: Optional[str] = None) -> None:
    """Save current configuration to file."""
    get_config_manager().save_config(config_path)


def create_default_config(config_path: str) -> None:
    """Create default configuration file."""
    get_config_manager().create_default_config(config_path)


if __name__ == "__main__":
    # CLI interface for configuration management
    import argparse

    parser = argparse.ArgumentParser(
        description="Advanced DPI Fingerprinting Configuration Manager"
    )
    parser.add_argument("--create-default", help="Create default configuration file")
    parser.add_argument("--validate", help="Validate configuration file")
    parser.add_argument("--show", help="Show configuration from file")
    parser.add_argument("--format", choices=["yaml", "json"], default="yaml", help="Output format")

    args = parser.parse_args()

    if args.create_default:
        create_default_config(args.create_default)
        print(f"Default configuration created: {args.create_default}")

    elif args.validate:
        try:
            config = load_config(args.validate)
            errors = config.validate()
            if errors:
                print("❌ Configuration validation failed:")
                for error in errors:
                    print(f"   - {error}")
            else:
                print("✅ Configuration is valid")
        except Exception as e:
            print(f"❌ Failed to validate configuration: {e}")

    elif args.show:
        try:
            config = load_config(args.show)
            data = config.to_dict()

            if args.format == "yaml":
                print(yaml.dump(data, default_flow_style=False, indent=2))
            else:
                print(json.dumps(data, indent=2, default=str))
        except Exception as e:
            print(f"❌ Failed to show configuration: {e}")

    else:
        parser.print_help()
