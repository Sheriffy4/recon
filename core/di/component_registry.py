#!/usr/bin/env python3
"""
Component Registry for DI Container.

This module provides comprehensive registration of all system components
in the dependency injection container, including interfaces and implementations.
"""

import logging
from typing import Type, TypeVar, Optional, Dict, Any

from .container import DIContainer, ServiceLifetime

# Import will be done dynamically to avoid circular dependencies
from ..bypass.engines.packet_processing_engine import PacketProcessingEngine

LOG = logging.getLogger("ComponentRegistry")

T = TypeVar("T")


class ISegmentPerformanceOptimizer:
    """Interface for segment performance optimization."""

    def optimize_segments(self, segments: list, context: Any) -> list:
        """Optimize segments for better performance."""
        raise NotImplementedError

    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get current performance metrics."""
        raise NotImplementedError


class IDPIEffectivenessValidator:
    """Interface for DPI effectiveness validation."""

    def validate_attack_effectiveness(
        self, attack_result: Any, baseline: Any
    ) -> Dict[str, Any]:
        """Validate attack effectiveness against baseline."""
        raise NotImplementedError

    def get_validation_report(self) -> Dict[str, Any]:
        """Get comprehensive validation report."""
        raise NotImplementedError


class IProperTestingMethodology:
    """Interface for proper testing methodology."""

    def test_with_baseline(self, domain: str, port: int) -> Any:
        """Test domain with baseline methodology."""
        raise NotImplementedError

    def compare_results(self, baseline: Any, bypass: Any) -> Dict[str, Any]:
        """Compare baseline and bypass results."""
        raise NotImplementedError


class IAttackAdapter:
    """Interface for attack adaptation."""

    def execute_attack_by_name(
        self, attack_name: str, context: Any, params: Dict[str, Any]
    ) -> Any:
        """Execute attack by name with given context and parameters."""
        raise NotImplementedError

    def get_available_attacks(self) -> list:
        """Get list of available attacks."""
        raise NotImplementedError


class IResultProcessor:
    """Interface for result processing."""

    def process_attack_result(self, result: Any) -> Dict[str, Any]:
        """Process attack result into standardized format."""
        raise NotImplementedError

    def aggregate_results(self, results: list) -> Dict[str, Any]:
        """Aggregate multiple results."""
        raise NotImplementedError


class IStrategyMapper:
    """Interface for strategy mapping."""

    def map_strategy_to_attacks(self, strategy: str) -> list:
        """Map strategy string to list of attacks."""
        raise NotImplementedError

    def get_strategy_parameters(self, strategy: str) -> Dict[str, Any]:
        """Get parameters for strategy."""
        raise NotImplementedError


class IEvolutionarySearcher:
    """Interface for evolutionary strategy search."""

    def search_optimal_strategies(self, domain: str, generations: int = 10) -> list:
        """Search for optimal strategies using evolutionary algorithm."""
        raise NotImplementedError

    def get_search_results(self) -> Dict[str, Any]:
        """Get results from evolutionary search."""
        raise NotImplementedError


class ComponentRegistry:
    """Registry for all system components with DI container integration."""

    def __init__(self, container: DIContainer):
        """
        Initialize component registry.

        Args:
            container: DI container to register components in
        """
        self.container = container
        self.logger = LOG
        self._registered_components: Dict[str, Type] = {}

    def register_all_components(self) -> None:
        """Register all system components in the DI container."""
        self.logger.info("🔧 Registering all system components in DI container...")

        try:
            # Register core performance components
            self._register_performance_components()

            # Register validation components
            self._register_validation_components()

            # Register testing components
            self._register_testing_components()

            # Register integration components
            self._register_integration_components()

            # Register engine components
            self._register_engine_components()

            # Register ML components
            self._register_ml_components()

            self.logger.info(
                f"✅ Successfully registered {len(self._registered_components)} components"
            )

        except Exception as e:
            self.logger.error(f"❌ Failed to register components: {e}")
            raise

    def _register_performance_components(self) -> None:
        """Register performance-related components."""
        self.logger.debug("Registering performance components...")

        try:
            from core.bypass.performance.segment_performance_optimizer_simple import (
                SegmentPerformanceOptimizer,
            )

            # Register SegmentPerformanceOptimizer as singleton
            self.container.register_singleton(
                ISegmentPerformanceOptimizer, SegmentPerformanceOptimizer
            )

            # Also register concrete type for backward compatibility
            self.container.register_singleton(
                SegmentPerformanceOptimizer, SegmentPerformanceOptimizer
            )

            self._registered_components["ISegmentPerformanceOptimizer"] = (
                ISegmentPerformanceOptimizer
            )
            self._registered_components["SegmentPerformanceOptimizer"] = (
                SegmentPerformanceOptimizer
            )

            self.logger.debug("✅ Performance components registered")

        except ImportError as e:
            self.logger.warning(f"⚠️ Could not register performance components: {e}")
            # Register interface with a mock implementation
            self.container.register_factory(
                ISegmentPerformanceOptimizer,
                lambda container: MockSegmentPerformanceOptimizer(),
                ServiceLifetime.SINGLETON,
            )
            self._registered_components["ISegmentPerformanceOptimizer"] = (
                ISegmentPerformanceOptimizer
            )

    def _register_validation_components(self) -> None:
        """Register validation-related components."""
        self.logger.debug("Registering validation components...")

        try:
            from core.bypass.validation.dpi_effectiveness_validator import (
                DPIEffectivenessValidator,
            )

            # Register DPIEffectivenessValidator as singleton
            self.container.register_singleton(
                IDPIEffectivenessValidator, DPIEffectivenessValidator
            )

            # Also register concrete type for backward compatibility
            self.container.register_singleton(
                DPIEffectivenessValidator, DPIEffectivenessValidator
            )

            self._registered_components["IDPIEffectivenessValidator"] = (
                IDPIEffectivenessValidator
            )
            self._registered_components["DPIEffectivenessValidator"] = (
                DPIEffectivenessValidator
            )

            self.logger.debug("✅ Validation components registered")

        except ImportError as e:
            self.logger.warning(f"⚠️ Could not register validation components: {e}")
            # Register interface with a mock implementation
            self.container.register_factory(
                IDPIEffectivenessValidator,
                lambda container: MockDPIEffectivenessValidator(),
                ServiceLifetime.SINGLETON,
            )
            self._registered_components["IDPIEffectivenessValidator"] = (
                IDPIEffectivenessValidator
            )

    def _register_testing_components(self) -> None:
        """Register testing methodology components."""
        self.logger.debug("Registering testing components...")

        try:
            from core.bypass.attacks.proper_testing_methodology import (
                ProperTestingMethodology,
            )

            # Register ProperTestingMethodology as singleton
            self.container.register_singleton(
                IProperTestingMethodology, ProperTestingMethodology
            )

            # Also register concrete type for backward compatibility
            self.container.register_singleton(
                ProperTestingMethodology, ProperTestingMethodology
            )

            self._registered_components["IProperTestingMethodology"] = (
                IProperTestingMethodology
            )
            self._registered_components["ProperTestingMethodology"] = (
                ProperTestingMethodology
            )

            self.logger.debug("✅ Testing components registered")

        except ImportError as e:
            self.logger.warning(f"⚠️ Could not register testing components: {e}")
            # Register interface with a mock implementation
            self.container.register_factory(
                IProperTestingMethodology,
                lambda container: MockProperTestingMethodology(),
                ServiceLifetime.SINGLETON,
            )
            self._registered_components["IProperTestingMethodology"] = (
                IProperTestingMethodology
            )

    def _register_integration_components(self) -> None:
        """Register integration-related components."""
        self.logger.debug("Registering integration components...")

        try:
            from core.integration.attack_adapter import AttackAdapter
            from core.integration.result_processor import ResultProcessor
            from core.integration.strategy_mapper import StrategyMapper

            # Register AttackAdapter as singleton
            self.container.register_singleton(IAttackAdapter, AttackAdapter)

            self.container.register_singleton(AttackAdapter, AttackAdapter)

            # Register ResultProcessor as transient (stateless)
            self.container.register_transient(IResultProcessor, ResultProcessor)

            self.container.register_transient(ResultProcessor, ResultProcessor)

            # Register StrategyMapper as singleton
            self.container.register_singleton(IStrategyMapper, StrategyMapper)

            self.container.register_singleton(StrategyMapper, StrategyMapper)

            self._registered_components["IAttackAdapter"] = IAttackAdapter
            self._registered_components["AttackAdapter"] = AttackAdapter
            self._registered_components["IResultProcessor"] = IResultProcessor
            self._registered_components["ResultProcessor"] = ResultProcessor
            self._registered_components["IStrategyMapper"] = IStrategyMapper
            self._registered_components["StrategyMapper"] = StrategyMapper

            self.logger.debug("✅ Integration components registered")

        except ImportError as e:
            self.logger.warning(f"⚠️ Could not register integration components: {e}")
            # Register interfaces with mock implementations
            self.container.register_factory(
                IAttackAdapter,
                lambda container: MockAttackAdapter(),
                ServiceLifetime.SINGLETON,
            )
            self.container.register_factory(
                IResultProcessor,
                lambda container: MockResultProcessor(),
                ServiceLifetime.TRANSIENT,
            )
            self.container.register_factory(
                IStrategyMapper,
                lambda container: MockStrategyMapper(),
                ServiceLifetime.SINGLETON,
            )

            self._registered_components["IAttackAdapter"] = IAttackAdapter
            self._registered_components["IResultProcessor"] = IResultProcessor
            self._registered_components["IStrategyMapper"] = IStrategyMapper

    def _register_engine_components(self) -> None:
        """Register engine-related components."""
        self.logger.debug("Registering engine components...")

        # Register PacketProcessingEngine with factory that uses DI for dependencies
        def create_packet_processing_engine(
            container: DIContainer,
        ) -> PacketProcessingEngine:
            """Factory function for PacketProcessingEngine with DI dependencies."""
            try:
                # Try to resolve dependencies from DI container
                performance_optimizer = container.resolve(ISegmentPerformanceOptimizer)
                effectiveness_validator = container.resolve(IDPIEffectivenessValidator)

                # Create engine with resolved dependencies
                engine = PacketProcessingEngine()

                # Inject dependencies if engine supports it
                if hasattr(engine, "set_performance_optimizer"):
                    engine.set_performance_optimizer(performance_optimizer)

                if hasattr(engine, "set_effectiveness_validator"):
                    engine.set_effectiveness_validator(effectiveness_validator)

                return engine

            except Exception as e:
                # Fallback to creating engine without DI dependencies
                LOG.warning(
                    f"Creating PacketProcessingEngine without DI dependencies: {e}"
                )
                return PacketProcessingEngine()

        self.container.register_factory(
            PacketProcessingEngine,
            create_packet_processing_engine,
            ServiceLifetime.SINGLETON,
        )

        self._registered_components["PacketProcessingEngine"] = PacketProcessingEngine

        self.logger.debug("✅ Engine components registered")

    def _register_ml_components(self) -> None:
        """Register ML-related components."""
        self.logger.debug("Registering ML components...")

        try:
            from ml.evolutionary_search import EvolutionarySearcher

            # Register EvolutionarySearcher as singleton
            self.container.register_singleton(
                IEvolutionarySearcher, EvolutionarySearcher
            )

            # Also register concrete type for backward compatibility
            self.container.register_singleton(
                EvolutionarySearcher, EvolutionarySearcher
            )

            self._registered_components["IEvolutionarySearcher"] = IEvolutionarySearcher
            self._registered_components["EvolutionarySearcher"] = EvolutionarySearcher

            self.logger.debug("✅ ML components registered")

        except ImportError as e:
            self.logger.warning(f"⚠️ Could not register ML components: {e}")
            # Register interface with a mock implementation
            self.container.register_factory(
                IEvolutionarySearcher,
                lambda container: MockEvolutionarySearcher(),
                ServiceLifetime.SINGLETON,
            )
            self._registered_components["IEvolutionarySearcher"] = IEvolutionarySearcher

    def register_custom_component(
        self,
        interface_type: Type[T],
        implementation_type: Type[T],
        lifetime: ServiceLifetime = ServiceLifetime.TRANSIENT,
        name: Optional[str] = None,
    ) -> None:
        """
        Register a custom component.

        Args:
            interface_type: Interface type
            implementation_type: Implementation type
            lifetime: Service lifetime
            name: Optional name for the component
        """
        component_name = name or interface_type.__name__

        if lifetime == ServiceLifetime.SINGLETON:
            self.container.register_singleton(interface_type, implementation_type)
        elif lifetime == ServiceLifetime.SCOPED:
            self.container.register_scoped(interface_type, implementation_type)
        else:
            self.container.register_transient(interface_type, implementation_type)

        self._registered_components[component_name] = interface_type
        self.logger.debug(f"✅ Custom component registered: {component_name}")

    def get_registered_components(self) -> Dict[str, Type]:
        """Get all registered components."""
        return self._registered_components.copy()

    def is_component_registered(self, component_type: Type) -> bool:
        """Check if a component type is registered."""
        return self.container.is_registered(component_type)

    def get_component_info(self, component_type: Type) -> Optional[Dict[str, Any]]:
        """Get information about a registered component."""
        return self.container.get_service_info(component_type)

    def validate_registrations(self) -> Dict[str, Any]:
        """Validate all component registrations."""
        validation_results = {
            "total_components": len(self._registered_components),
            "valid_components": 0,
            "invalid_components": 0,
            "validation_errors": [],
        }

        for name, component_type in self._registered_components.items():
            try:
                # Try to get service info to validate registration
                info = self.container.get_service_info(component_type)
                if info:
                    validation_results["valid_components"] += 1
                else:
                    validation_results["invalid_components"] += 1
                    validation_results["validation_errors"].append(
                        f"No service info for {name}"
                    )

            except Exception as e:
                validation_results["invalid_components"] += 1
                validation_results["validation_errors"].append(
                    f"Validation error for {name}: {e}"
                )

        return validation_results

    def create_health_report(self) -> Dict[str, Any]:
        """Create comprehensive health report for all registered components."""
        health_report = {
            "registry_status": "healthy",
            "total_components": len(self._registered_components),
            "container_health": self.container.probe_health(),
            "component_details": {},
            "validation_results": self.validate_registrations(),
        }

        # Add details for each component
        for name, component_type in self._registered_components.items():
            try:
                info = self.container.get_service_info(component_type)
                health_report["component_details"][name] = {
                    "registered": True,
                    "info": info,
                    "resolvable": self.container.is_registered(component_type),
                }
            except Exception as e:
                health_report["component_details"][name] = {
                    "registered": False,
                    "error": str(e),
                    "resolvable": False,
                }

        # Determine overall health
        if health_report["validation_results"]["invalid_components"] > 0:
            health_report["registry_status"] = "degraded"

        return health_report


def create_default_registry(
    container: Optional[DIContainer] = None,
) -> ComponentRegistry:
    """
    Create default component registry with all standard components.

    Args:
        container: Optional DI container to use (creates new one if None)

    Returns:
        Configured ComponentRegistry
    """
    if container is None:
        container = DIContainer()

    registry = ComponentRegistry(container)
    registry.register_all_components()

    return registry


def get_global_registry() -> ComponentRegistry:
    """Get or create global component registry instance."""
    if not hasattr(get_global_registry, "_instance"):
        get_global_registry._instance = create_default_registry()

    return get_global_registry._instance


# Export interfaces for use in other modules
__all__ = [
    "ComponentRegistry",
    "ISegmentPerformanceOptimizer",
    "IDPIEffectivenessValidator",
    "IProperTestingMethodology",
    "IAttackAdapter",
    "IResultProcessor",
    "IStrategyMapper",
    "IEvolutionarySearcher",
    "create_default_registry",
    "get_global_registry",
]


# Mock implementations for testing and fallback scenarios
class MockSegmentPerformanceOptimizer(ISegmentPerformanceOptimizer):
    """Mock implementation of ISegmentPerformanceOptimizer."""

    def optimize_segments(self, segments: list, context: Any) -> list:
        """Mock optimization - returns segments unchanged."""
        return segments

    def get_performance_metrics(self) -> Dict[str, Any]:
        """Mock metrics."""
        return {"mock": True, "optimizations_applied": 0}


class MockDPIEffectivenessValidator(IDPIEffectivenessValidator):
    """Mock implementation of IDPIEffectivenessValidator."""

    def validate_attack_effectiveness(
        self, attack_result: Any, baseline: Any
    ) -> Dict[str, Any]:
        """Mock validation."""
        return {"mock": True, "effectiveness_score": 0.5}

    def get_validation_report(self) -> Dict[str, Any]:
        """Mock validation report."""
        return {"mock": True, "total_validations": 0}


class MockProperTestingMethodology(IProperTestingMethodology):
    """Mock implementation of IProperTestingMethodology."""

    def test_with_baseline(self, domain: str, port: int) -> Any:
        """Mock baseline test."""
        return {"mock": True, "domain": domain, "port": port}

    def compare_results(self, baseline: Any, bypass: Any) -> Dict[str, Any]:
        """Mock comparison."""
        return {"mock": True, "comparison": "equal"}


class MockAttackAdapter(IAttackAdapter):
    """Mock implementation of IAttackAdapter."""

    def execute_attack_by_name(
        self, attack_name: str, context: Any, params: Dict[str, Any]
    ) -> Any:
        """Mock attack execution."""
        return {"mock": True, "attack_name": attack_name, "status": "success"}

    def get_available_attacks(self) -> list:
        """Mock available attacks."""
        return ["mock_attack_1", "mock_attack_2"]


class MockResultProcessor(IResultProcessor):
    """Mock implementation of IResultProcessor."""

    def process_attack_result(self, result: Any) -> Dict[str, Any]:
        """Mock result processing."""
        return {"mock": True, "processed": True}

    def aggregate_results(self, results: list) -> Dict[str, Any]:
        """Mock result aggregation."""
        return {"mock": True, "total_results": len(results)}


class MockStrategyMapper(IStrategyMapper):
    """Mock implementation of IStrategyMapper."""

    def map_strategy_to_attacks(self, strategy: str) -> list:
        """Mock strategy mapping."""
        return ["mock_attack_for_" + strategy]

    def get_strategy_parameters(self, strategy: str) -> Dict[str, Any]:
        """Mock strategy parameters."""
        return {"mock": True, "strategy": strategy}


class MockEvolutionarySearcher(IEvolutionarySearcher):
    """Mock implementation of IEvolutionarySearcher."""

    def search_optimal_strategies(self, domain: str, generations: int = 10) -> list:
        """Mock evolutionary search."""
        return ["mock_evolved_strategy_1", "mock_evolved_strategy_2"]

    def get_search_results(self) -> Dict[str, Any]:
        """Mock search results."""
        return {"mock": True, "generations": 10, "best_fitness": 0.85}
