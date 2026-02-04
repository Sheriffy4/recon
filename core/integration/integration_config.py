# recon/core/integration/integration_config.py
"""
Configuration for Integration Layer

Defines configuration options for the integration between unified attack system
and existing components.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional
import logging

LOG = logging.getLogger("IntegrationConfig")


@dataclass
class IntegrationConfig:
    """Configuration for integration layer."""

    # Compatibility settings
    enable_legacy_compatibility: bool = True
    enable_automatic_fallback: bool = True

    # Attack selection strategy
    attack_selection_strategy: str = "optimal"  # optimal, random, round_robin, adaptive

    # Execution settings
    parallel_execution_limit: int = 5
    max_attack_chain_length: int = 10
    attack_timeout_seconds: float = 30.0

    # Performance settings
    performance_monitoring: bool = True
    cache_attack_results: bool = True
    cache_ttl_seconds: int = 300
    max_cache_size: int = 1000

    # Logging and debugging
    debug_mode: bool = False
    log_attack_execution: bool = True
    log_strategy_mapping: bool = True
    log_performance_metrics: bool = False

    # Error handling
    retry_failed_attacks: bool = True
    max_retry_attempts: int = 3
    retry_delay_seconds: float = 1.0

    # Resource limits
    max_memory_usage_mb: int = 512
    max_cpu_usage_percent: float = 80.0

    # Network validation settings
    enable_network_validation: bool = True
    network_test_timeout: float = 5.0
    skip_network_test_for_errors: bool = True
    strict_network_validation: bool = False  # If False, network failures don't fail the attack

    @classmethod
    def load_from_dict(cls, config_dict: Dict) -> "IntegrationConfig":
        """Load configuration from dictionary."""
        try:
            return cls(**{k: v for k, v in config_dict.items() if hasattr(cls, k)})
        except Exception as e:
            LOG.warning(f"Failed to load integration config: {e}")
            return cls()  # Return default config

    def to_dict(self) -> Dict:
        """Convert configuration to dictionary."""
        return {
            field.name: getattr(self, field.name) for field in self.__dataclass_fields__.values()
        }

    def validate(self) -> List[str]:
        """Validate configuration and return list of issues."""
        issues = []

        if self.parallel_execution_limit < 1:
            issues.append("parallel_execution_limit must be >= 1")

        if self.max_attack_chain_length < 1:
            issues.append("max_attack_chain_length must be >= 1")

        if self.attack_timeout_seconds <= 0:
            issues.append("attack_timeout_seconds must be > 0")

        if self.cache_ttl_seconds < 0:
            issues.append("cache_ttl_seconds must be >= 0")

        if self.max_cache_size < 0:
            issues.append("max_cache_size must be >= 0")

        if self.max_retry_attempts < 0:
            issues.append("max_retry_attempts must be >= 0")

        if self.retry_delay_seconds < 0:
            issues.append("retry_delay_seconds must be >= 0")

        if self.max_memory_usage_mb <= 0:
            issues.append("max_memory_usage_mb must be > 0")

        if not 0 < self.max_cpu_usage_percent <= 100:
            issues.append("max_cpu_usage_percent must be between 0 and 100")

        valid_strategies = ["optimal", "random", "round_robin", "adaptive"]
        if self.attack_selection_strategy not in valid_strategies:
            issues.append(f"attack_selection_strategy must be one of: {valid_strategies}")

        return issues


@dataclass
class AttackMapping:
    """Mapping between legacy strategy and new attacks."""

    legacy_strategy: str
    attack_names: List[str]
    parameter_mapping: Dict[str, str]
    confidence: float
    fallback_attacks: List[str]
    description: Optional[str] = None

    def __post_init__(self):
        """Validate mapping after initialization."""
        if not 0 <= self.confidence <= 1:
            raise ValueError("confidence must be between 0 and 1")

        if not self.attack_names:
            raise ValueError("attack_names cannot be empty")


@dataclass
class PerformanceMetrics:
    """Performance metrics for attack execution."""

    attack_name: str
    execution_time_ms: float
    success_rate: float
    bytes_processed: int
    packets_sent: int
    effectiveness_score: float
    resource_usage: Dict[str, float]
    timestamp: float

    def __post_init__(self):
        """Validate metrics after initialization."""
        if not 0 <= self.success_rate <= 1:
            raise ValueError("success_rate must be between 0 and 1")

        if not 0 <= self.effectiveness_score <= 1:
            raise ValueError("effectiveness_score must be between 0 and 1")

        if self.execution_time_ms < 0:
            raise ValueError("execution_time_ms must be >= 0")

        if self.bytes_processed < 0:
            raise ValueError("bytes_processed must be >= 0")

        if self.packets_sent < 0:
            raise ValueError("packets_sent must be >= 0")


# Integration-specific exceptions
class IntegrationError(Exception):
    """Base exception for integration errors."""

    pass


class StrategyMappingError(IntegrationError):
    """Error in mapping legacy strategy to attacks."""

    pass


class AttackExecutionError(IntegrationError):
    """Error in executing attacks through adapter."""

    pass


class CompatibilityError(IntegrationError):
    """Error in maintaining backward compatibility."""

    pass


class PerformanceError(IntegrationError):
    """Error related to performance constraints."""

    pass


class ConfigurationError(IntegrationError):
    """Error in integration configuration."""

    pass
