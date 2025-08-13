# recon/core/di/config.py
"""
Dependency Injection Configuration

Provides configuration classes for different DI modes and service configurations.
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from enum import Enum

LOG = logging.getLogger("DIConfig")


class DIMode(Enum):
    """DI container operation modes."""

    PRODUCTION = "production"
    DEVELOPMENT = "development"
    TESTING = "testing"
    CUSTOM = "custom"


@dataclass
class ServiceConfig:
    """Configuration for a single service."""

    implementation_class: str
    lifetime: str = "singleton"  # singleton, transient, scoped
    parameters: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    debug: bool = False


@dataclass
class DIConfiguration:
    """Complete DI container configuration."""

    mode: DIMode = DIMode.PRODUCTION
    debug_enabled: bool = False

    # Core service configurations
    fingerprint_engine: ServiceConfig = field(
        default_factory=lambda: ServiceConfig(
            "UltimateAdvancedFingerprintEngine",
            parameters={"debug": False, "ml_enabled": True},
        )
    )

    prober: ServiceConfig = field(
        default_factory=lambda: ServiceConfig(
            "UltimateDPIProber", parameters={"debug": False}
        )
    )

    classifier: ServiceConfig = field(
        default_factory=lambda: ServiceConfig(
            "UltimateDPIClassifier", parameters={"ml_enabled": True}
        )
    )

    attack_adapter: ServiceConfig = field(
        default_factory=lambda: ServiceConfig(
            "AttackAdapter", parameters={"debug_mode": False}
        )
    )

    effectiveness_tester: ServiceConfig = field(
        default_factory=lambda: ServiceConfig(
            "RealEffectivenessTester", parameters={"timeout": 10.0, "max_retries": 2}
        )
    )

    learning_memory: ServiceConfig = field(
        default_factory=lambda: ServiceConfig(
            "LearningMemory", parameters={"storage_path": "learning_memory.db"}
        )
    )

    strategy_generator: ServiceConfig = field(
        default_factory=lambda: ServiceConfig(
            "AdvancedStrategyGenerator", parameters={}
        )
    )

    strategy_saver: ServiceConfig = field(
        default_factory=lambda: ServiceConfig(
            "StrategySaver", parameters={"storage_path": "best_strategy.json"}
        )
    )

    closed_loop_manager: ServiceConfig = field(
        default_factory=lambda: ServiceConfig(
            "ClosedLoopManager",
            parameters={"max_iterations": 5, "convergence_threshold": 0.9},
        )
    )

    failure_analyzer: ServiceConfig = field(
        default_factory=lambda: ServiceConfig("FailureAnalyzer", parameters={})
    )

    # Additional service configurations
    http_client_pool: ServiceConfig = field(
        default_factory=lambda: ServiceConfig(
            "OptimizedHTTPClientPool",
            parameters={"request_timeout": 10.0, "max_connections": 100},
        )
    )

    parameter_optimizer: ServiceConfig = field(
        default_factory=lambda: ServiceConfig(
            "DynamicParameterOptimizer",
            parameters={"optimization_strategy": "grid_search"},
        )
    )

    # Custom service overrides
    custom_services: Dict[str, ServiceConfig] = field(default_factory=dict)

    def get_service_config(self, service_name: str) -> Optional[ServiceConfig]:
        """Get configuration for a specific service."""
        # Check custom services first
        if service_name in self.custom_services:
            return self.custom_services[service_name]

        # Check standard services
        if hasattr(self, service_name):
            return getattr(self, service_name)

        return None

    def set_service_config(self, service_name: str, config: ServiceConfig) -> None:
        """Set configuration for a specific service."""
        if hasattr(self, service_name):
            setattr(self, service_name, config)
        else:
            self.custom_services[service_name] = config

    def enable_debug_mode(self) -> None:
        """Enable debug mode for all services."""
        self.debug_enabled = True

        # Update all service configs to enable debug
        for attr_name in dir(self):
            attr = getattr(self, attr_name)
            if isinstance(attr, ServiceConfig):
                attr.debug = True
                if "debug" in attr.parameters:
                    attr.parameters["debug"] = True
                if "debug_mode" in attr.parameters:
                    attr.parameters["debug_mode"] = True

    def disable_ml_features(self) -> None:
        """Disable ML features for all services."""
        self.fingerprint_engine.parameters["ml_enabled"] = False
        self.classifier.parameters["ml_enabled"] = False

    def set_timeouts(self, timeout_seconds: float) -> None:
        """Set timeout for all services that support it."""
        self.effectiveness_tester.parameters["timeout"] = timeout_seconds
        self.http_client_pool.parameters["request_timeout"] = timeout_seconds

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        result = {
            "mode": self.mode.value,
            "debug_enabled": self.debug_enabled,
            "services": {},
        }

        # Add standard services
        for attr_name in dir(self):
            if attr_name.startswith("_") or attr_name in [
                "mode",
                "debug_enabled",
                "custom_services",
            ]:
                continue

            attr = getattr(self, attr_name)
            if isinstance(attr, ServiceConfig):
                result["services"][attr_name] = {
                    "implementation_class": attr.implementation_class,
                    "lifetime": attr.lifetime,
                    "parameters": attr.parameters,
                    "enabled": attr.enabled,
                    "debug": attr.debug,
                }

        # Add custom services
        for service_name, config in self.custom_services.items():
            result["services"][service_name] = {
                "implementation_class": config.implementation_class,
                "lifetime": config.lifetime,
                "parameters": config.parameters,
                "enabled": config.enabled,
                "debug": config.debug,
            }

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DIConfiguration":
        """Create configuration from dictionary."""
        config = cls()

        if "mode" in data:
            config.mode = DIMode(data["mode"])

        if "debug_enabled" in data:
            config.debug_enabled = data["debug_enabled"]

        if "services" in data:
            for service_name, service_data in data["services"].items():
                service_config = ServiceConfig(
                    implementation_class=service_data["implementation_class"],
                    lifetime=service_data.get("lifetime", "singleton"),
                    parameters=service_data.get("parameters", {}),
                    enabled=service_data.get("enabled", True),
                    debug=service_data.get("debug", False),
                )
                config.set_service_config(service_name, service_config)

        return config


class DIConfigurationBuilder:
    """Builder for creating DI configurations."""

    def __init__(self):
        self._config = DIConfiguration()

    def set_mode(self, mode: DIMode) -> "DIConfigurationBuilder":
        """Set the DI mode."""
        self._config.mode = mode
        return self

    def enable_debug(self) -> "DIConfigurationBuilder":
        """Enable debug mode."""
        self._config.enable_debug_mode()
        return self

    def disable_ml(self) -> "DIConfigurationBuilder":
        """Disable ML features."""
        self._config.disable_ml_features()
        return self

    def set_timeouts(self, timeout: float) -> "DIConfigurationBuilder":
        """Set timeouts for all services."""
        self._config.set_timeouts(timeout)
        return self

    def configure_service(
        self,
        service_name: str,
        implementation_class: str,
        lifetime: str = "singleton",
        parameters: Optional[Dict[str, Any]] = None,
        enabled: bool = True,
        debug: bool = False,
    ) -> "DIConfigurationBuilder":
        """Configure a specific service."""
        service_config = ServiceConfig(
            implementation_class=implementation_class,
            lifetime=lifetime,
            parameters=parameters or {},
            enabled=enabled,
            debug=debug,
        )
        self._config.set_service_config(service_name, service_config)
        return self

    def build(self) -> DIConfiguration:
        """Build the final configuration."""
        return self._config


# Predefined configurations
def get_production_config() -> DIConfiguration:
    """Get production DI configuration."""
    return DIConfiguration(mode=DIMode.PRODUCTION)


def get_development_config() -> DIConfiguration:
    """Get development DI configuration."""
    config = DIConfiguration(mode=DIMode.DEVELOPMENT)
    config.enable_debug_mode()
    return config


def get_testing_config() -> DIConfiguration:
    """Get testing DI configuration."""
    config = DIConfiguration(mode=DIMode.TESTING)
    config.set_timeouts(5.0)  # Shorter timeouts for tests
    return config


def get_minimal_config() -> DIConfiguration:
    """Get minimal DI configuration (no ML, fast timeouts)."""
    config = DIConfiguration(mode=DIMode.CUSTOM)
    config.disable_ml_features()
    config.set_timeouts(5.0)
    return config
