#!/usr/bin/env python3
"""
Performance Configuration Management
Centralized configuration system for performance optimization settings.
"""

import json
import yaml
import logging
from typing import Dict, Any, Optional, List
from pathlib import Path
from dataclasses import dataclass, asdict, field
import os


@dataclass
class MonitoringConfig:
    """Configuration for performance monitoring."""

    enabled: bool = True
    interval_seconds: float = 30.0
    max_history_entries: int = 1000
    alert_thresholds: Dict[str, float] = field(
        default_factory=lambda: {
            "bypass_success_rate_critical": 0.1,
            "bypass_success_rate_warning": 0.3,
            "fingerprint_time_warning": 60.0,
            "memory_usage_warning": 1000.0,
            "cpu_usage_warning": 80.0,
        }
    )
    export_metrics: bool = True
    export_interval_minutes: int = 60
    export_path: str = "recon/logs/metrics"


@dataclass
class CachingConfig:
    """Configuration for caching system."""

    enabled: bool = True
    max_memory_mb: int = 100
    max_entries: int = 10000
    default_ttl_seconds: float = 3600
    persistent_cache: bool = True
    cache_directory: str = "recon/cache"
    fingerprint_cache: Dict[str, Any] = field(
        default_factory=lambda: {
            "max_memory_mb": 50,
            "default_ttl_seconds": 7200,
            "confidence_ttl_multiplier": {
                "high": 2.0,  # > 0.8 confidence
                "medium": 1.0,  # > 0.5 confidence
                "low": 0.5,  # <= 0.5 confidence
            },
        }
    )
    strategy_cache: Dict[str, Any] = field(
        default_factory=lambda: {
            "max_memory_mb": 30,
            "default_ttl_seconds": 1800,
            "success_ttl_multiplier": {
                "high": 2.0,  # > 0.8 success rate
                "medium": 1.0,  # > 0.3 success rate
                "low": 0.33,  # <= 0.3 success rate
            },
        }
    )


@dataclass
class AsyncConfig:
    """Configuration for async operations optimization."""

    enabled: bool = True
    max_concurrent_operations: int = 10
    operation_timeout_seconds: float = 30.0
    use_thread_pool: bool = True
    thread_pool_size: int = 4
    connection_pool_size: int = 20
    connection_timeout_seconds: float = 10.0
    read_timeout_seconds: float = 30.0


@dataclass
class FingerprintingConfig:
    """Configuration for fingerprinting optimization."""

    enabled: bool = True
    timeout_seconds: float = 30.0
    max_concurrent_fingerprints: int = 5
    cache_results: bool = True
    skip_on_cache_hit: bool = True
    analysis_levels: Dict[str, bool] = field(
        default_factory=lambda: {
            "basic": True,
            "advanced": True,
            "deep": False,  # Disabled by default for performance
            "behavioral": True,
            "timing": False,  # Disabled by default for performance
        }
    )
    component_timeouts: Dict[str, float] = field(
        default_factory=lambda: {
            "tcp_analyzer": 10.0,
            "http_analyzer": 15.0,
            "dns_analyzer": 10.0,
            "tls_analyzer": 20.0,
            "behavioral_analyzer": 30.0,
        }
    )


@dataclass
class BypassEngineConfig:
    """Configuration for bypass engine optimization."""

    enabled: bool = True
    max_concurrent_bypasses: int = 15
    strategy_timeout_seconds: float = 60.0
    packet_injection_timeout_seconds: float = 5.0
    tcp_retransmission_mitigation: bool = True
    packet_validation: bool = True
    telemetry_enabled: bool = True
    performance_mode: str = "balanced"  # "fast", "balanced", "thorough"


@dataclass
class PerformanceConfig:
    """Main performance configuration."""

    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    caching: CachingConfig = field(default_factory=CachingConfig)
    async_ops: AsyncConfig = field(default_factory=AsyncConfig)
    fingerprinting: FingerprintingConfig = field(default_factory=FingerprintingConfig)
    bypass_engine: BypassEngineConfig = field(default_factory=BypassEngineConfig)

    # Global settings
    debug_mode: bool = False
    log_level: str = "INFO"
    profile_performance: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PerformanceConfig":
        """Create from dictionary."""
        return cls(
            monitoring=MonitoringConfig(**data.get("monitoring", {})),
            caching=CachingConfig(**data.get("caching", {})),
            async_ops=AsyncConfig(**data.get("async_ops", {})),
            fingerprinting=FingerprintingConfig(**data.get("fingerprinting", {})),
            bypass_engine=BypassEngineConfig(**data.get("bypass_engine", {})),
            debug_mode=data.get("debug_mode", False),
            log_level=data.get("log_level", "INFO"),
            profile_performance=data.get("profile_performance", False),
        )


class PerformanceConfigManager:
    """Manages performance configuration with hot reloading."""

    def __init__(self, config_path: Optional[str] = None):
        self.logger = logging.getLogger(__name__)

        # Default config paths
        if config_path is None:
            config_paths = [
                "recon/config/performance.yaml",
                "recon/config/performance.json",
                "performance.yaml",
                "performance.json",
            ]

            for path in config_paths:
                if Path(path).exists():
                    config_path = path
                    break

        self.config_path = config_path
        self.config = PerformanceConfig()
        self.callbacks: List[callable] = []

        # Load configuration
        if self.config_path and Path(self.config_path).exists():
            self.load_config()
        else:
            self.logger.info("No configuration file found, using defaults")
            self.save_config()  # Save default config

    def load_config(self) -> bool:
        """Load configuration from file."""
        if not self.config_path or not Path(self.config_path).exists():
            return False

        try:
            with open(self.config_path, "r") as f:
                if self.config_path.endswith(".yaml") or self.config_path.endswith(
                    ".yml"
                ):
                    data = yaml.safe_load(f)
                else:
                    data = json.load(f)

            self.config = PerformanceConfig.from_dict(data)
            self.logger.info(f"Configuration loaded from {self.config_path}")

            # Notify callbacks
            for callback in self.callbacks:
                try:
                    callback(self.config)
                except Exception as e:
                    self.logger.error(f"Error in config callback: {e}")

            return True

        except Exception as e:
            self.logger.error(f"Error loading configuration: {e}")
            return False

    def save_config(self) -> bool:
        """Save current configuration to file."""
        if not self.config_path:
            self.config_path = "recon/config/performance.yaml"

        try:
            # Ensure directory exists
            Path(self.config_path).parent.mkdir(parents=True, exist_ok=True)

            with open(self.config_path, "w") as f:
                if self.config_path.endswith(".yaml") or self.config_path.endswith(
                    ".yml"
                ):
                    yaml.dump(
                        self.config.to_dict(), f, default_flow_style=False, indent=2
                    )
                else:
                    json.dump(self.config.to_dict(), f, indent=2)

            self.logger.info(f"Configuration saved to {self.config_path}")
            return True

        except Exception as e:
            self.logger.error(f"Error saving configuration: {e}")
            return False

    def update_config(self, updates: Dict[str, Any]) -> bool:
        """Update configuration with new values."""
        try:
            # Deep merge updates into current config
            current_dict = self.config.to_dict()
            self._deep_merge(current_dict, updates)

            # Create new config from merged data
            self.config = PerformanceConfig.from_dict(current_dict)

            # Save updated config
            self.save_config()

            # Notify callbacks
            for callback in self.callbacks:
                try:
                    callback(self.config)
                except Exception as e:
                    self.logger.error(f"Error in config callback: {e}")

            return True

        except Exception as e:
            self.logger.error(f"Error updating configuration: {e}")
            return False

    def _deep_merge(self, base: Dict[str, Any], updates: Dict[str, Any]):
        """Deep merge updates into base dictionary."""
        for key, value in updates.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value

    def add_change_callback(self, callback: callable):
        """Add callback to be called when configuration changes."""
        self.callbacks.append(callback)

    def remove_change_callback(self, callback: callable):
        """Remove configuration change callback."""
        if callback in self.callbacks:
            self.callbacks.remove(callback)

    def get_config(self) -> PerformanceConfig:
        """Get current configuration."""
        return self.config

    def reload_config(self) -> bool:
        """Reload configuration from file."""
        return self.load_config()

    def reset_to_defaults(self) -> bool:
        """Reset configuration to defaults."""
        self.config = PerformanceConfig()
        return self.save_config()


# Environment-based configuration overrides
def apply_environment_overrides(config: PerformanceConfig) -> PerformanceConfig:
    """Apply environment variable overrides to configuration."""

    # Monitoring overrides
    if os.getenv("RECON_MONITORING_ENABLED"):
        config.monitoring.enabled = (
            os.getenv("RECON_MONITORING_ENABLED").lower() == "true"
        )

    if os.getenv("RECON_MONITORING_INTERVAL"):
        config.monitoring.interval_seconds = float(
            os.getenv("RECON_MONITORING_INTERVAL")
        )

    # Caching overrides
    if os.getenv("RECON_CACHE_ENABLED"):
        config.caching.enabled = os.getenv("RECON_CACHE_ENABLED").lower() == "true"

    if os.getenv("RECON_CACHE_MEMORY_MB"):
        config.caching.max_memory_mb = int(os.getenv("RECON_CACHE_MEMORY_MB"))

    # Async overrides
    if os.getenv("RECON_MAX_CONCURRENT"):
        config.async_ops.max_concurrent_operations = int(
            os.getenv("RECON_MAX_CONCURRENT")
        )

    if os.getenv("RECON_OPERATION_TIMEOUT"):
        config.async_ops.operation_timeout_seconds = float(
            os.getenv("RECON_OPERATION_TIMEOUT")
        )

    # Fingerprinting overrides
    if os.getenv("RECON_FINGERPRINT_TIMEOUT"):
        config.fingerprinting.timeout_seconds = float(
            os.getenv("RECON_FINGERPRINT_TIMEOUT")
        )

    if os.getenv("RECON_FINGERPRINT_DEEP_ANALYSIS"):
        config.fingerprinting.analysis_levels["deep"] = (
            os.getenv("RECON_FINGERPRINT_DEEP_ANALYSIS").lower() == "true"
        )

    # Bypass engine overrides
    if os.getenv("RECON_BYPASS_TIMEOUT"):
        config.bypass_engine.strategy_timeout_seconds = float(
            os.getenv("RECON_BYPASS_TIMEOUT")
        )

    if os.getenv("RECON_PERFORMANCE_MODE"):
        mode = os.getenv("RECON_PERFORMANCE_MODE").lower()
        if mode in ["fast", "balanced", "thorough"]:
            config.bypass_engine.performance_mode = mode

    # Global overrides
    if os.getenv("RECON_DEBUG"):
        config.debug_mode = os.getenv("RECON_DEBUG").lower() == "true"

    if os.getenv("RECON_LOG_LEVEL"):
        config.log_level = os.getenv("RECON_LOG_LEVEL").upper()

    return config


# Performance mode presets
PERFORMANCE_PRESETS = {
    "fast": {
        "fingerprinting": {
            "timeout_seconds": 15.0,
            "max_concurrent_fingerprints": 10,
            "analysis_levels": {
                "basic": True,
                "advanced": False,
                "deep": False,
                "behavioral": False,
                "timing": False,
            },
        },
        "bypass_engine": {
            "max_concurrent_bypasses": 20,
            "strategy_timeout_seconds": 30.0,
            "packet_validation": False,
        },
        "caching": {"max_memory_mb": 200, "default_ttl_seconds": 7200},
    },
    "balanced": {
        "fingerprinting": {
            "timeout_seconds": 30.0,
            "max_concurrent_fingerprints": 5,
            "analysis_levels": {
                "basic": True,
                "advanced": True,
                "deep": False,
                "behavioral": True,
                "timing": False,
            },
        },
        "bypass_engine": {
            "max_concurrent_bypasses": 15,
            "strategy_timeout_seconds": 60.0,
            "packet_validation": True,
        },
    },
    "thorough": {
        "fingerprinting": {
            "timeout_seconds": 60.0,
            "max_concurrent_fingerprints": 3,
            "analysis_levels": {
                "basic": True,
                "advanced": True,
                "deep": True,
                "behavioral": True,
                "timing": True,
            },
        },
        "bypass_engine": {
            "max_concurrent_bypasses": 10,
            "strategy_timeout_seconds": 120.0,
            "packet_validation": True,
        },
        "caching": {"max_memory_mb": 50, "default_ttl_seconds": 1800},
    },
}


def apply_performance_preset(
    config: PerformanceConfig, preset_name: str
) -> PerformanceConfig:
    """Apply a performance preset to configuration."""
    if preset_name not in PERFORMANCE_PRESETS:
        raise ValueError(
            f"Unknown preset: {preset_name}. Available: {list(PERFORMANCE_PRESETS.keys())}"
        )

    preset = PERFORMANCE_PRESETS[preset_name]
    config_dict = config.to_dict()

    # Deep merge preset into config
    def deep_merge(base, updates):
        for key, value in updates.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                deep_merge(base[key], value)
            else:
                base[key] = value

    deep_merge(config_dict, preset)
    return PerformanceConfig.from_dict(config_dict)


# Global configuration manager instance
_global_config_manager: Optional[PerformanceConfigManager] = None


def get_global_config_manager() -> PerformanceConfigManager:
    """Get or create global configuration manager."""
    global _global_config_manager
    if _global_config_manager is None:
        _global_config_manager = PerformanceConfigManager()
    return _global_config_manager


def get_performance_config() -> PerformanceConfig:
    """Get current performance configuration."""
    return get_global_config_manager().get_config()
