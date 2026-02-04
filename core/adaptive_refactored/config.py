"""
Configuration models for the refactored Adaptive Engine components.

These configuration classes provide type-safe, validated configuration
for all system components.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union
from pathlib import Path


@dataclass
class StrategyConfig:
    """Configuration for strategy generation and management."""

    max_trials: int = 15
    generation_timeout: float = 30.0
    enable_failure_analysis: bool = True
    enable_fingerprinting: bool = True
    enable_parallel_generation: bool = False
    max_parallel_workers: int = 3
    strategy_diversity_threshold: float = 0.7
    confidence_threshold: float = 0.6
    enable_learning: bool = True
    learning_rate: float = 0.1
    max_strategies_per_domain: int = 10
    strategy_ttl_hours: int = 24
    enable_strategy_validation: bool = True

    def validate(self) -> List[str]:
        """Validate strategy configuration."""
        errors = []

        if self.max_trials <= 0:
            errors.append("max_trials must be positive")

        if self.generation_timeout <= 0:
            errors.append("generation_timeout must be positive")

        if not 0 <= self.strategy_diversity_threshold <= 1:
            errors.append("strategy_diversity_threshold must be between 0 and 1")

        if not 0 <= self.confidence_threshold <= 1:
            errors.append("confidence_threshold must be between 0 and 1")

        if self.max_parallel_workers <= 0:
            errors.append("max_parallel_workers must be positive")

        return errors


@dataclass
class TestingConfig:
    """Configuration for strategy testing operations."""

    strategy_timeout: float = 30.0
    connection_timeout: float = 5.0
    enable_parallel_testing: bool = False
    max_parallel_workers: int = 5
    verify_with_pcap: bool = False
    pcap_capture_duration: float = 10.0
    enable_test_validation: bool = True
    retry_failed_tests: bool = True
    max_test_retries: int = 3
    test_retry_delay: float = 1.0
    enable_detailed_logging: bool = False
    test_result_ttl_hours: int = 6
    enable_test_artifacts: bool = True

    def validate(self) -> List[str]:
        """Validate testing configuration."""
        errors = []

        if self.strategy_timeout <= 0:
            errors.append("strategy_timeout must be positive")

        if self.connection_timeout <= 0:
            errors.append("connection_timeout must be positive")

        if self.max_parallel_workers <= 0:
            errors.append("max_parallel_workers must be positive")

        if self.pcap_capture_duration <= 0:
            errors.append("pcap_capture_duration must be positive")

        if self.max_test_retries < 0:
            errors.append("max_test_retries must be non-negative")

        if self.test_retry_delay < 0:
            errors.append("test_retry_delay must be non-negative")

        return errors


@dataclass
class CacheConfig:
    """Configuration for caching operations."""

    enable_caching: bool = True
    cache_ttl_hours: int = 24
    fingerprint_cache_size: int = 1000
    strategy_cache_size: int = 500
    domain_cache_size: int = 2000
    metrics_cache_size: int = 100
    enable_cache_persistence: bool = True
    cache_persistence_path: Optional[str] = None
    cache_cleanup_interval_minutes: int = 60
    enable_cache_compression: bool = False
    max_memory_usage_mb: int = 512

    def validate(self) -> List[str]:
        """Validate cache configuration."""
        errors = []

        if self.cache_ttl_hours <= 0:
            errors.append("cache_ttl_hours must be positive")

        if self.fingerprint_cache_size <= 0:
            errors.append("fingerprint_cache_size must be positive")

        if self.strategy_cache_size <= 0:
            errors.append("strategy_cache_size must be positive")

        if self.domain_cache_size <= 0:
            errors.append("domain_cache_size must be positive")

        if self.cache_cleanup_interval_minutes <= 0:
            errors.append("cache_cleanup_interval_minutes must be positive")

        if self.max_memory_usage_mb <= 0:
            errors.append("max_memory_usage_mb must be positive")

        return errors


@dataclass
class AnalyticsConfig:
    """Configuration for analytics and metrics collection."""

    enable_metrics: bool = True
    enable_profiling: bool = False
    export_diagnostics_on_shutdown: bool = False
    metrics_export_format: str = "json"  # json, csv, prometheus
    metrics_export_path: Optional[str] = None
    enable_real_time_monitoring: bool = False
    monitoring_update_interval_seconds: int = 30
    enable_performance_alerts: bool = False
    performance_alert_thresholds: Dict[str, float] = field(
        default_factory=lambda: {
            "cpu_usage_percent": 80.0,
            "memory_usage_mb": 1024.0,
            "average_test_time": 60.0,
            "cache_hit_rate": 0.5,
        }
    )

    def validate(self) -> List[str]:
        """Validate analytics configuration."""
        errors = []

        valid_formats = ["json", "csv", "prometheus"]
        if self.metrics_export_format not in valid_formats:
            errors.append(f"metrics_export_format must be one of {valid_formats}")

        if self.monitoring_update_interval_seconds <= 0:
            errors.append("monitoring_update_interval_seconds must be positive")

        return errors


@dataclass
class NetworkingConfig:
    """Configuration for networking operations."""

    enable_ipv6: bool = True
    prefer_ipv4: bool = False
    dns_timeout: float = 5.0
    connection_pool_size: int = 10
    max_connections_per_host: int = 5
    enable_connection_reuse: bool = True
    tcp_keepalive: bool = True
    tcp_keepalive_idle: int = 60
    tcp_keepalive_interval: int = 30
    tcp_keepalive_probes: int = 3
    enable_ssl_verification: bool = True
    ssl_context_options: Dict[str, Any] = field(default_factory=dict)
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    def validate(self) -> List[str]:
        """Validate networking configuration."""
        errors = []

        if self.dns_timeout <= 0:
            errors.append("dns_timeout must be positive")

        if self.connection_pool_size <= 0:
            errors.append("connection_pool_size must be positive")

        if self.max_connections_per_host <= 0:
            errors.append("max_connections_per_host must be positive")

        if self.tcp_keepalive_idle <= 0:
            errors.append("tcp_keepalive_idle must be positive")

        if self.tcp_keepalive_interval <= 0:
            errors.append("tcp_keepalive_interval must be positive")

        if self.tcp_keepalive_probes <= 0:
            errors.append("tcp_keepalive_probes must be positive")

        return errors


@dataclass
class ErrorHandlingConfig:
    """Configuration for error handling and resilience."""

    enable_circuit_breaker: bool = True
    circuit_breaker_failure_threshold: int = 5
    circuit_breaker_recovery_timeout: float = 60.0
    circuit_breaker_half_open_max_calls: int = 3
    enable_retry_mechanism: bool = True
    max_retries: int = 3
    retry_base_delay: float = 1.0
    retry_max_delay: float = 60.0
    retry_exponential_base: float = 2.0
    enable_failure_isolation: bool = True
    enable_graceful_degradation: bool = True
    enable_structured_logging: bool = True
    log_level: str = "INFO"
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    def validate(self) -> List[str]:
        """Validate error handling configuration."""
        errors = []

        if self.circuit_breaker_failure_threshold <= 0:
            errors.append("circuit_breaker_failure_threshold must be positive")

        if self.circuit_breaker_recovery_timeout <= 0:
            errors.append("circuit_breaker_recovery_timeout must be positive")

        if self.max_retries < 0:
            errors.append("max_retries must be non-negative")

        if self.retry_base_delay <= 0:
            errors.append("retry_base_delay must be positive")

        if self.retry_max_delay <= self.retry_base_delay:
            errors.append("retry_max_delay must be greater than retry_base_delay")

        if self.retry_exponential_base <= 1:
            errors.append("retry_exponential_base must be greater than 1")

        return errors


@dataclass
class AdaptiveEngineConfig:
    """Main configuration for the Adaptive Engine."""

    strategy: StrategyConfig = field(default_factory=StrategyConfig)
    testing: TestingConfig = field(default_factory=TestingConfig)
    caching: CacheConfig = field(default_factory=CacheConfig)
    analytics: AnalyticsConfig = field(default_factory=AnalyticsConfig)
    networking: NetworkingConfig = field(default_factory=NetworkingConfig)
    error_handling: ErrorHandlingConfig = field(default_factory=ErrorHandlingConfig)

    # Global settings
    enable_debug_mode: bool = False
    log_level: str = "INFO"
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    enable_structured_logging: bool = True
    config_file_path: Optional[str] = None

    def validate(self) -> List[str]:
        """Validate entire configuration."""
        errors = []

        # Validate all sub-configurations
        errors.extend([f"strategy.{e}" for e in self.strategy.validate()])
        errors.extend([f"testing.{e}" for e in self.testing.validate()])
        errors.extend([f"caching.{e}" for e in self.caching.validate()])
        errors.extend([f"analytics.{e}" for e in self.analytics.validate()])
        errors.extend([f"networking.{e}" for e in self.networking.validate()])
        errors.extend([f"error_handling.{e}" for e in self.error_handling.validate()])

        # Validate global settings
        valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.log_level not in valid_log_levels:
            errors.append(f"log_level must be one of {valid_log_levels}")

        return errors

    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> "AdaptiveEngineConfig":
        """Create configuration from dictionary."""
        return cls(
            strategy=StrategyConfig(**config_dict.get("strategy", {})),
            testing=TestingConfig(**config_dict.get("testing", {})),
            caching=CacheConfig(**config_dict.get("caching", {})),
            analytics=AnalyticsConfig(**config_dict.get("analytics", {})),
            networking=NetworkingConfig(**config_dict.get("networking", {})),
            error_handling=ErrorHandlingConfig(**config_dict.get("error_handling", {})),
            enable_debug_mode=config_dict.get("enable_debug_mode", False),
            log_level=config_dict.get("log_level", "INFO"),
            log_format=config_dict.get(
                "log_format", "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            ),
            enable_structured_logging=config_dict.get("enable_structured_logging", True),
            config_file_path=config_dict.get("config_file_path"),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            "strategy": self.strategy.__dict__,
            "testing": self.testing.__dict__,
            "caching": self.caching.__dict__,
            "analytics": self.analytics.__dict__,
            "networking": self.networking.__dict__,
            "error_handling": self.error_handling.__dict__,
            "enable_debug_mode": self.enable_debug_mode,
            "log_level": self.log_level,
            "log_format": self.log_format,
            "enable_structured_logging": self.enable_structured_logging,
            "config_file_path": self.config_file_path,
        }
