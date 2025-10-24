# recon/core/di/typed_config.py
"""
Typed Configuration System for Dependency Injection

Provides strongly typed configuration classes using dataclasses and Pydantic
for better type safety and validation.
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, Union
from enum import Enum
from pathlib import Path

try:
    from pydantic import BaseModel, Field, field_validator

    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False
    # Fallback to dataclasses only
    BaseModel = object
    Field = lambda default=None, **kwargs: default

LOG = logging.getLogger("TypedConfig")


class ServiceLifetime(Enum):
    SINGLETON = "singleton"
    TRANSIENT = "transient"
    SCOPED = "scoped"


class DIMode(Enum):
    PRODUCTION = "production"
    DEVELOPMENT = "development"
    TESTING = "testing"
    CUSTOM = "custom"


if PYDANTIC_AVAILABLE:

    class ServiceConfiguration(BaseModel):
        """Pydantic-based service configuration."""

        implementation_class: str
        lifetime: ServiceLifetime = ServiceLifetime.SINGLETON
        parameters: Dict[str, Any] = Field(default_factory=dict)
        enabled: bool = True
        debug: bool = False

        # --- НАЧАЛО ИЗМЕНЕНИЯ 2: Обновляем синтаксис валидатора ---
        @field_validator("lifetime", mode="before")
        @classmethod
        def validate_lifetime(cls, v):
            if isinstance(v, ServiceLifetime):
                return v.value
            elif isinstance(v, str):
                return v
            return v

        # --- КОНЕЦ ИЗМЕНЕНИЯ 2 ---

        class Config:
            use_enum_values = True

    class FingerprintEngineConfig(BaseModel):
        debug: bool = False
        ml_enabled: bool = True
        timeout_seconds: float = 30.0
        max_probes: int = 10
        enable_advanced_classification: bool = True

    class ProberConfig(BaseModel):
        debug: bool = False
        timeout_seconds: float = 10.0
        max_retries: int = 3
        probe_interval_ms: int = 100

    class ClassifierConfig(BaseModel):
        ml_enabled: bool = True
        confidence_threshold: float = 0.7
        use_ensemble: bool = True
        model_path: Optional[str] = None

    class AttackAdapterConfig(BaseModel):
        debug_mode: bool = False
        parallel_execution_limit: int = 10
        attack_timeout_seconds: float = 30.0
        cache_attack_results: bool = True
        cache_ttl_seconds: int = 300
        max_cache_size: int = 1000
        enable_network_validation: bool = True

    class EffectivenessTesterConfig(BaseModel):
        timeout: float = 10.0
        max_retries: int = 2
        request_delay_ms: int = 100
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        engine_override: Optional[str] = None

    class MonitoringConfig(BaseModel):
        monitor_interval_seconds: int = 60
        alert_success_rate_threshold: float = 0.6
        use_https: bool = True

    class HealthThresholdsConfig(BaseModel):
        failing_success_rate: float = 0.4
        degrading_success_rate: float = 0.7
        degrading_latency_ms: float = 1500.0

    class LearningMemoryConfig(BaseModel):
        storage_path: str = "learning_memory.db"
        max_history_entries: int = 10000
        cleanup_interval_hours: int = 24
        enable_compression: bool = True

    class StrategyGeneratorConfig(BaseModel):
        max_strategies: int = 50
        enable_ml_prediction: bool = True
        diversity_factor: float = 0.3

    class StrategySaverConfig(BaseModel):
        storage_path: str = "best_strategy.json"
        max_strategies_to_save: int = 20
        backup_enabled: bool = True
        validation_enabled: bool = True

    class ClosedLoopManagerConfig(BaseModel):
        max_iterations: int = 5
        convergence_threshold: float = 0.9
        strategies_per_iteration: int = 10
        enable_adaptive_threshold: bool = True

    class HTTPClientPoolConfig(BaseModel):
        request_timeout: float = 10.0
        max_connections: int = 100
        max_connections_per_host: int = 10
        keepalive_timeout: int = 30

    class ParameterOptimizerConfig(BaseModel):
        optimization_strategy: str = "random_search"
        max_iterations: int = 15
        timeout: float = 120.0
        convergence_threshold: float = 0.85
        population_size: int = 20

    class TypedDIConfiguration(BaseModel):
        """Complete typed DI configuration using Pydantic."""

        # --- НАЧАЛО ИЗМЕНЕНИЯ: Используем str вместо DIMode ---
        mode: str = DIMode.PRODUCTION.value
        # --- КОНЕЦ ИЗМЕНЕНИЯ ---
        debug_enabled: bool = False

        # Service configurations
        fingerprint_engine: FingerprintEngineConfig = Field(
            default_factory=FingerprintEngineConfig
        )
        prober: ProberConfig = Field(default_factory=ProberConfig)
        classifier: ClassifierConfig = Field(default_factory=ClassifierConfig)
        attack_adapter: AttackAdapterConfig = Field(default_factory=AttackAdapterConfig)
        effectiveness_tester: EffectivenessTesterConfig = Field(
            default_factory=EffectivenessTesterConfig
        )
        learning_memory: LearningMemoryConfig = Field(
            default_factory=LearningMemoryConfig
        )
        strategy_generator: StrategyGeneratorConfig = Field(
            default_factory=StrategyGeneratorConfig
        )
        strategy_saver: StrategySaverConfig = Field(default_factory=StrategySaverConfig)
        closed_loop_manager: ClosedLoopManagerConfig = Field(
            default_factory=ClosedLoopManagerConfig
        )
        http_client_pool: HTTPClientPoolConfig = Field(
            default_factory=HTTPClientPoolConfig
        )
        parameter_optimizer: ParameterOptimizerConfig = Field(
            default_factory=ParameterOptimizerConfig
        )

        # Monitoring and Health
        monitoring: MonitoringConfig = Field(default_factory=MonitoringConfig)
        health_thresholds: HealthThresholdsConfig = Field(
            default_factory=HealthThresholdsConfig
        )

        # Custom service configurations
        custom_services: Dict[str, ServiceConfiguration] = Field(default_factory=dict)

        class Config:
            use_enum_values = True
            validate_assignment = True

        # --- НАЧАЛО ИЗМЕНЕНИЯ: Валидатор теперь проверяет строку ---
        @field_validator("mode")
        @classmethod
        def validate_mode(cls, v):
            if v not in [e.value for e in DIMode]:
                raise ValueError(f"Invalid mode: {v}")
            return v

        def enable_debug_mode(self) -> None:
            self.debug_enabled = True
            self.fingerprint_engine.debug = True
            self.prober.debug = True
            self.attack_adapter.debug_mode = True

        def disable_ml_features(self) -> None:
            self.fingerprint_engine.ml_enabled = False
            self.classifier.ml_enabled = False
            self.strategy_generator.enable_ml_prediction = False

        def set_timeouts(self, timeout_seconds: float) -> None:
            self.effectiveness_tester.timeout = timeout_seconds
            self.http_client_pool.request_timeout = timeout_seconds
            self.attack_adapter.attack_timeout_seconds = timeout_seconds
            self.fingerprint_engine.timeout_seconds = timeout_seconds
            self.prober.timeout_seconds = min(timeout_seconds, 10.0)

        def apply_cli_args(self, args) -> None:
            if hasattr(args, "debug") and args.debug:
                self.enable_debug_mode()
            if hasattr(args, "timeout"):
                self.set_timeouts(args.timeout)
            if hasattr(args, "no_ml") and args.no_ml:
                self.disable_ml_features()
            if hasattr(args, "optimize_parameters") and args.optimize_parameters:
                self.parameter_optimizer.optimization_strategy = getattr(
                    args, "optimization_strategy", "random_search"
                )
                self.parameter_optimizer.max_iterations = getattr(
                    args, "optimization_iterations", 15
                )
                self.parameter_optimizer.timeout = getattr(
                    args, "optimization_timeout", 120.0
                )
            if hasattr(args, "closed_loop") and args.closed_loop:
                self.closed_loop_manager.max_iterations = getattr(
                    args, "max_iterations", 5
                )
                self.closed_loop_manager.convergence_threshold = getattr(
                    args, "convergence_threshold", 0.9
                )
            # Обработка выбора движка из CLI + раннее предупреждение для неподходящей ОС
            eng = getattr(args, "engine", None) if hasattr(args, "engine") else None
            if eng is None or str(eng).lower() == "auto":
                setattr(self.effectiveness_tester, "engine_override", None)
            else:
                override = str(eng).lower()
                setattr(self.effectiveness_tester, "engine_override", override)
                try:
                    import platform

                    if override == "native" and platform.system().lower() != "windows":
                        LOG.warning(
                            "Selected --engine=native on non-Windows platform; this engine may be unavailable. Auto-detection is recommended."
                        )
                except Exception:
                    pass

else:
    # Fallback to dataclasses when Pydantic is not available
    @dataclass
    class ServiceConfiguration:
        implementation_class: str
        lifetime: ServiceLifetime = ServiceLifetime.SINGLETON
        parameters: Dict[str, Any] = field(default_factory=dict)
        enabled: bool = True
        debug: bool = False

    @dataclass
    class FingerprintEngineConfig:
        debug: bool = False
        ml_enabled: bool = True
        timeout_seconds: float = 30.0
        max_probes: int = 10
        enable_advanced_classification: bool = True

    @dataclass
    class ProberConfig:
        debug: bool = False
        timeout_seconds: float = 10.0
        max_retries: int = 3
        probe_interval_ms: int = 100

    @dataclass
    class ClassifierConfig:
        ml_enabled: bool = True
        confidence_threshold: float = 0.7
        use_ensemble: bool = True
        model_path: Optional[str] = None

    @dataclass
    class AttackAdapterConfig:
        debug_mode: bool = False
        parallel_execution_limit: int = 10
        attack_timeout_seconds: float = 30.0
        cache_attack_results: bool = True
        cache_ttl_seconds: int = 300
        max_cache_size: int = 1000
        enable_network_validation: bool = True

    @dataclass
    class EffectivenessTesterConfig:
        timeout: float = 10.0
        max_retries: int = 2
        request_delay_ms: int = 100
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    @dataclass
    class MonitoringConfig:
        monitor_interval_seconds: int = 60
        alert_success_rate_threshold: float = 0.6
        use_https: bool = True

    @dataclass
    class HealthThresholdsConfig:
        failing_success_rate: float = 0.4
        degrading_success_rate: float = 0.7
        degrading_latency_ms: float = 1500.0

    @dataclass
    class LearningMemoryConfig:
        storage_path: str = "learning_memory.db"
        max_history_entries: int = 10000
        cleanup_interval_hours: int = 24
        enable_compression: bool = True

    @dataclass
    class StrategyGeneratorConfig:
        max_strategies: int = 50
        enable_ml_prediction: bool = True
        diversity_factor: float = 0.3

    @dataclass
    class StrategySaverConfig:
        storage_path: str = "best_strategy.json"
        max_strategies_to_save: int = 20
        backup_enabled: bool = True
        validation_enabled: bool = True

    @dataclass
    class ClosedLoopManagerConfig:
        max_iterations: int = 5
        convergence_threshold: float = 0.9
        strategies_per_iteration: int = 10
        enable_adaptive_threshold: bool = True

    @dataclass
    class HTTPClientPoolConfig:
        request_timeout: float = 10.0
        max_connections: int = 100
        max_connections_per_host: int = 10
        keepalive_timeout: int = 30

    @dataclass
    class ParameterOptimizerConfig:
        optimization_strategy: str = "random_search"
        max_iterations: int = 15
        timeout: float = 120.0
        convergence_threshold: float = 0.85
        population_size: int = 20

    @dataclass
    class TypedDIConfiguration:
        """Complete typed DI configuration using dataclasses."""

        mode: DIMode = DIMode.PRODUCTION
        debug_enabled: bool = False

        # Service configurations
        fingerprint_engine: FingerprintEngineConfig = field(
            default_factory=FingerprintEngineConfig
        )
        prober: ProberConfig = field(default_factory=ProberConfig)
        classifier: ClassifierConfig = field(default_factory=ClassifierConfig)
        attack_adapter: AttackAdapterConfig = field(default_factory=AttackAdapterConfig)
        effectiveness_tester: EffectivenessTesterConfig = field(
            default_factory=EffectivenessTesterConfig
        )
        learning_memory: LearningMemoryConfig = field(
            default_factory=LearningMemoryConfig
        )
        strategy_generator: StrategyGeneratorConfig = field(
            default_factory=StrategyGeneratorConfig
        )
        strategy_saver: StrategySaverConfig = field(default_factory=StrategySaverConfig)
        closed_loop_manager: ClosedLoopManagerConfig = field(
            default_factory=ClosedLoopManagerConfig
        )
        http_client_pool: HTTPClientPoolConfig = field(
            default_factory=HTTPClientPoolConfig
        )
        parameter_optimizer: ParameterOptimizerConfig = field(
            default_factory=ParameterOptimizerConfig
        )

        # Monitoring and Health
        monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
        health_thresholds: HealthThresholdsConfig = field(
            default_factory=HealthThresholdsConfig
        )

        # Custom service configurations
        custom_services: Dict[str, ServiceConfiguration] = field(default_factory=dict)

        def enable_debug_mode(self) -> None:
            """Enable debug mode for all services."""
            self.debug_enabled = True
            self.fingerprint_engine.debug = True
            self.prober.debug = True
            self.attack_adapter.debug_mode = True

        def disable_ml_features(self) -> None:
            """Disable ML features for all services."""
            self.fingerprint_engine.ml_enabled = False
            self.classifier.ml_enabled = False
            self.strategy_generator.enable_ml_prediction = False

        def set_timeouts(self, timeout_seconds: float) -> None:
            """Set timeout for all services that support it."""
            self.effectiveness_tester.timeout = timeout_seconds
            self.http_client_pool.request_timeout = timeout_seconds
            self.attack_adapter.attack_timeout_seconds = timeout_seconds
            self.fingerprint_engine.timeout_seconds = timeout_seconds
            self.prober.timeout_seconds = min(timeout_seconds, 10.0)

        def apply_cli_args(self, args) -> None:
            """Apply CLI arguments to configuration."""
            if hasattr(args, "debug") and args.debug:
                self.enable_debug_mode()

            if hasattr(args, "timeout"):
                self.set_timeouts(args.timeout)

            if hasattr(args, "no_ml") and args.no_ml:
                self.disable_ml_features()

            if hasattr(args, "optimize_parameters") and args.optimize_parameters:
                self.parameter_optimizer.optimization_strategy = getattr(
                    args, "optimization_strategy", "random_search"
                )
                self.parameter_optimizer.max_iterations = getattr(
                    args, "optimization_iterations", 15
                )
                self.parameter_optimizer.timeout = getattr(
                    args, "optimization_timeout", 120.0
                )

            if hasattr(args, "closed_loop") and args.closed_loop:
                self.closed_loop_manager.max_iterations = getattr(
                    args, "max_iterations", 5
                )
                self.closed_loop_manager.convergence_threshold = getattr(
                    args, "convergence_threshold", 0.9
                )


def create_production_config() -> TypedDIConfiguration:
    """Create production configuration."""
    return TypedDIConfiguration(mode=DIMode.PRODUCTION)


def create_development_config() -> TypedDIConfiguration:
    """Create development configuration."""
    config = TypedDIConfiguration(mode=DIMode.DEVELOPMENT)
    config.enable_debug_mode()
    return config


def create_testing_config() -> TypedDIConfiguration:
    """Create testing configuration."""
    config = TypedDIConfiguration(mode=DIMode.TESTING)
    config.set_timeouts(5.0)  # Shorter timeouts for tests
    return config


def create_config_from_file(file_path: Union[str, Path]) -> TypedDIConfiguration:
    """Create configuration from JSON/YAML file."""
    import json

    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {file_path}")

    with open(file_path, "r") as f:
        if file_path.suffix.lower() == ".json":
            data = json.load(f)
        else:
            # Try YAML if available
            try:
                import yaml

                data = yaml.safe_load(f)
            except ImportError:
                raise ImportError("YAML support requires PyYAML package")

    if PYDANTIC_AVAILABLE:
        return TypedDIConfiguration(**data)
    else:
        # Manual conversion for dataclasses
        config = TypedDIConfiguration()
        # This would need more sophisticated conversion logic
        # for dataclass-based configuration
        return config


def save_config_to_file(
    config: TypedDIConfiguration, file_path: Union[str, Path]
) -> None:
    """Save configuration to JSON file."""
    import json

    file_path = Path(file_path)

    if PYDANTIC_AVAILABLE:
        data = config.dict()
    else:
        # Convert dataclass to dict
        import dataclasses

        data = dataclasses.asdict(config)

    with open(file_path, "w") as f:
        json.dump(data, f, indent=2, default=str)

    LOG.info(f"Configuration saved to {file_path}")


class ConfigurationBuilder:
    """Builder for creating typed DI configurations."""

    def __init__(self):
        self._config = TypedDIConfiguration()

    def set_mode(self, mode: DIMode) -> "ConfigurationBuilder":
        """Set the DI mode."""
        # --- НАЧАЛО ИЗМЕНЕНИЯ ---
        self._config.mode = mode.value  # Передаем строковое значение
        # --- КОНЕЦ ИЗМЕНЕНИЯ ---
        return self

    def enable_debug(self) -> "ConfigurationBuilder":
        """Enable debug mode."""
        self._config.enable_debug_mode()
        return self

    def disable_ml(self) -> "ConfigurationBuilder":
        """Disable ML features."""
        self._config.disable_ml_features()
        return self

    def set_timeouts(self, timeout: float) -> "ConfigurationBuilder":
        """Set timeouts for all services."""
        self._config.set_timeouts(timeout)
        return self

    def configure_fingerprint_engine(self, **kwargs) -> "ConfigurationBuilder":
        """Configure fingerprint engine."""
        for key, value in kwargs.items():
            if hasattr(self._config.fingerprint_engine, key):
                setattr(self._config.fingerprint_engine, key, value)
        return self

    def configure_attack_adapter(self, **kwargs) -> "ConfigurationBuilder":
        """Configure attack adapter."""
        for key, value in kwargs.items():
            if hasattr(self._config.attack_adapter, key):
                setattr(self._config.attack_adapter, key, value)
        return self

    def apply_cli_args(self, args) -> "ConfigurationBuilder":
        """Apply CLI arguments."""
        self._config.apply_cli_args(args)
        return self

    def build(self) -> TypedDIConfiguration:
        """Build the final configuration."""
        return self._config
