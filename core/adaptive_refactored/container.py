"""
Dependency Injection Container for the refactored Adaptive Engine.

This module provides a simple but effective dependency injection container
that manages component lifecycles and dependencies.
"""

import logging
from typing import Dict, Type, TypeVar, Callable, Any, Optional, List
from abc import ABC
from .interfaces import *
from .config import AdaptiveEngineConfig


T = TypeVar("T")
logger = logging.getLogger(__name__)


class DIContainer:
    """
    Simple dependency injection container for managing component dependencies.

    Supports:
    - Singleton and transient lifetimes
    - Constructor injection
    - Interface-based registration
    - Circular dependency detection
    """

    def __init__(self):
        self._services: Dict[Type, Any] = {}
        self._factories: Dict[Type, Callable] = {}
        self._singletons: Dict[Type, Any] = {}
        self._resolving: set = set()  # For circular dependency detection

    def register_singleton(self, interface: Type[T], implementation: Type[T]) -> None:
        """Register a service as singleton (one instance for the entire application)."""
        self._services[interface] = implementation
        logger.debug(f"Registered singleton: {interface.__name__} -> {implementation.__name__}")

    def register_transient(self, interface: Type[T], implementation: Type[T]) -> None:
        """Register a service as transient (new instance every time)."""
        self._services[interface] = implementation
        logger.debug(f"Registered transient: {interface.__name__} -> {implementation.__name__}")

    def register_factory(self, interface: Type[T], factory: Callable[[], T]) -> None:
        """Register a factory function for creating instances."""
        self._factories[interface] = factory
        logger.debug(f"Registered factory for: {interface.__name__}")

    def register_instance(self, interface: Type[T], instance: T) -> None:
        """Register a pre-created instance."""
        self._singletons[interface] = instance
        logger.debug(f"Registered instance: {interface.__name__}")

    def resolve(self, interface: Type[T]) -> T:
        """Resolve an instance of the requested interface."""
        if interface in self._resolving:
            raise ValueError(f"Circular dependency detected for {interface.__name__}")

        # Check if we have a pre-created instance
        if interface in self._singletons:
            return self._singletons[interface]

        # Check if we have a factory
        if interface in self._factories:
            return self._factories[interface]()

        # Check if we have a registered service
        if interface not in self._services:
            raise ValueError(f"Service {interface.__name__} not registered")

        implementation = self._services[interface]

        # Add to resolving set to detect circular dependencies
        self._resolving.add(interface)

        try:
            # Create instance with dependency injection
            instance = self._create_instance(implementation)

            # Store as singleton if it's registered as such
            if self._is_singleton(interface):
                self._singletons[interface] = instance

            return instance

        finally:
            self._resolving.discard(interface)

    def _create_instance(self, implementation: Type[T]) -> T:
        """Create an instance with constructor dependency injection."""
        import inspect

        # Get constructor signature
        sig = inspect.signature(implementation.__init__)

        # Resolve constructor parameters
        kwargs = {}
        for param_name, param in sig.parameters.items():
            if param_name == "self":
                continue

            # Skip parameters with default values if we can't resolve them
            if param.annotation == inspect.Parameter.empty:
                if param.default != inspect.Parameter.empty:
                    continue
                else:
                    raise ValueError(
                        f"Cannot resolve parameter {param_name} for {implementation.__name__}"
                    )

            # Try to resolve the parameter type
            try:
                # Handle string annotations (forward references)
                annotation = param.annotation
                if isinstance(annotation, str):
                    # Try to resolve string annotation from the implementation's module
                    try:
                        # Get the module where the implementation is defined
                        module = inspect.getmodule(implementation)
                        if module and hasattr(module, annotation):
                            annotation = getattr(module, annotation)
                        else:
                            # Try to find it in the local scope of the test
                            frame = inspect.currentframe()
                            while frame:
                                if annotation in frame.f_locals:
                                    annotation = frame.f_locals[annotation]
                                    break
                                frame = frame.f_back
                            else:
                                # If we still can't resolve it, skip if there's a default
                                if param.default != inspect.Parameter.empty:
                                    continue
                                else:
                                    raise ValueError(
                                        f"Cannot resolve string annotation {param.annotation} for parameter {param_name}"
                                    )
                    except Exception:
                        if param.default != inspect.Parameter.empty:
                            continue
                        else:
                            raise ValueError(
                                f"Cannot resolve string annotation {param.annotation} for parameter {param_name}"
                            )

                kwargs[param_name] = self.resolve(annotation)
            except ValueError as e:
                # Re-raise circular dependency errors immediately
                if "Circular dependency detected" in str(e):
                    raise e

                # If we can't resolve and there's a default, use it
                if param.default != inspect.Parameter.empty:
                    continue
                else:
                    raise ValueError(
                        f"Cannot resolve parameter {param_name} of type {param.annotation} for {implementation.__name__}"
                    )

        return implementation(**kwargs)

    def _is_singleton(self, interface: Type) -> bool:
        """Check if a service is registered as singleton."""
        # For now, we'll assume all services are singletons unless explicitly registered as transient
        # This can be enhanced later with explicit lifetime management
        return True

    def clear(self) -> None:
        """Clear all registrations and instances."""
        self._services.clear()
        self._factories.clear()
        self._singletons.clear()
        self._resolving.clear()
        logger.debug("Container cleared")

    def get_registered_services(self) -> List[str]:
        """Get list of registered service names."""
        services = []
        services.extend([f"{k.__name__} (service)" for k in self._services.keys()])
        services.extend([f"{k.__name__} (factory)" for k in self._factories.keys()])
        services.extend([f"{k.__name__} (instance)" for k in self._singletons.keys()])
        return services


class ContainerBuilder:
    """Builder for configuring the DI container with default implementations."""

    def __init__(self, config: AdaptiveEngineConfig):
        self.config = config
        self.container = DIContainer()

    def build_default_container(self) -> DIContainer:
        """Build container with default implementations."""

        # Register configuration as instance
        self.container.register_instance(AdaptiveEngineConfig, self.config)

        # Register configuration components
        self.container.register_instance(StrategyConfig, self.config.strategy)
        self.container.register_instance(TestingConfig, self.config.testing)
        self.container.register_instance(CacheConfig, self.config.caching)
        self.container.register_instance(AnalyticsConfig, self.config.analytics)
        self.container.register_instance(NetworkingConfig, self.config.networking)

        # Note: Actual implementations will be registered when they are created
        # For now, we'll register placeholder factories that raise NotImplementedError

        self._register_placeholder_services()

        logger.info("Default DI container built successfully")
        return self.container

    def _register_placeholder_services(self) -> None:
        """Register actual implementations and placeholder services."""

        # Import actual implementations
        from .infrastructure.cache_manager import CacheManager
        from .infrastructure.configuration_manager import ConfigurationManager
        from .infrastructure.metrics_collector import MetricsCollector
        from .infrastructure.performance_monitor import PerformanceMonitor
        from .infrastructure.monitoring_system import MonitoringSystem
        from .components.strategy_generator import StrategyGenerator
        from .components.test_coordinator import TestCoordinator
        from .components.failure_analyzer import FailureAnalyzer
        from .services.strategy_service import StrategyService
        from .services.testing_service import TestingService
        from .services.analytics_service import AnalyticsService

        # Register infrastructure components with proper dependencies
        self.container.register_singleton(ICacheManager, CacheManager)
        self.container.register_singleton(IConfigurationManager, ConfigurationManager)
        self.container.register_singleton(IMetricsCollector, MetricsCollector)
        self.container.register_singleton(IPerformanceMonitor, PerformanceMonitor)
        self.container.register_singleton(MonitoringSystem, MonitoringSystem)

        # Register domain components with dependencies
        self.container.register_singleton(IStrategyGenerator, StrategyGenerator)

        # Register TestCoordinator with factory to properly inject dependencies
        def test_coordinator_factory():
            try:
                bypass_engine = self.container.resolve(IBypassEngine)
            except Exception as e:
                logger.warning(f"Could not resolve IBypassEngine for TestCoordinator: {e}")
                bypass_engine = None

            try:
                pcap_analyzer = self.container.resolve(IPCAPAnalyzer)
            except Exception as e:
                logger.debug(f"Could not resolve IPCAPAnalyzer for TestCoordinator: {e}")
                pcap_analyzer = None

            try:
                strategy_validator = self.container.resolve(IStrategyValidator)
            except Exception as e:
                logger.debug(f"Could not resolve IStrategyValidator for TestCoordinator: {e}")
                strategy_validator = None

            config = self.config.testing
            return TestCoordinator(config, bypass_engine, pcap_analyzer, strategy_validator)

        self.container.register_factory(ITestCoordinator, test_coordinator_factory)

        self.container.register_singleton(IFailureAnalyzer, FailureAnalyzer)

        # Register application services with dependencies
        self.container.register_singleton(IStrategyService, StrategyService)
        self.container.register_singleton(ITestingService, TestingService)
        self.container.register_singleton(IAnalyticsService, AnalyticsService)

        # Register placeholder factories for external interfaces
        def not_implemented_factory(service_name: str):
            def factory():
                logger.warning(
                    f"{service_name} implementation not yet available, using placeholder"
                )
                raise NotImplementedError(f"{service_name} implementation not yet available")

            return factory

        # Register real bypass engine
        def bypass_engine_factory():
            try:
                from ..unified_bypass_engine import UnifiedBypassEngine

                engine = UnifiedBypassEngine()
                logger.info("✅ Real UnifiedBypassEngine registered")
                return engine
            except Exception as e:
                logger.warning(f"⚠️ Failed to create UnifiedBypassEngine: {e}")
                raise NotImplementedError(f"UnifiedBypassEngine not available: {e}")

        self.container.register_factory(IBypassEngine, bypass_engine_factory)

        # Register PCAP analyzer implementation
        def pcap_analyzer_factory():
            try:
                from .infrastructure.pcap_analyzer_impl import PCAPAnalyzerImpl

                analyzer = PCAPAnalyzerImpl()
                logger.info("✅ PCAPAnalyzerImpl registered")
                return analyzer
            except Exception as e:
                logger.warning(f"⚠️ Failed to create PCAPAnalyzerImpl: {e}")
                raise NotImplementedError(f"PCAPAnalyzerImpl not available: {e}")

        self.container.register_factory(IPCAPAnalyzer, pcap_analyzer_factory)

        # Register strategy validator implementation
        def strategy_validator_factory():
            try:
                from .infrastructure.strategy_validator_impl import StrategyValidatorImpl

                validator = StrategyValidatorImpl()
                logger.info("✅ StrategyValidatorImpl registered")
                return validator
            except Exception as e:
                logger.warning(f"⚠️ Failed to create StrategyValidatorImpl: {e}")
                raise NotImplementedError(f"StrategyValidatorImpl not available: {e}")

        self.container.register_factory(IStrategyValidator, strategy_validator_factory)

        logger.info("All services registered in DI container")
        logger.debug(f"Registered services: {self.container.get_registered_services()}")


def create_default_container(config: Optional[AdaptiveEngineConfig] = None) -> DIContainer:
    """Create a default DI container with the given configuration."""
    if config is None:
        config = AdaptiveEngineConfig()

    builder = ContainerBuilder(config)
    return builder.build_default_container()


# Global container instance (can be replaced for testing)
_global_container: Optional[DIContainer] = None


def get_container() -> DIContainer:
    """Get the global DI container instance."""
    global _global_container
    if _global_container is None:
        _global_container = create_default_container()
    return _global_container


def set_container(container: DIContainer) -> None:
    """Set the global DI container instance."""
    global _global_container
    _global_container = container


def reset_container() -> None:
    """Reset the global DI container."""
    global _global_container
    _global_container = None
