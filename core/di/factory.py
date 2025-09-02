import logging
from typing import Dict, Any, Optional
from core.di.container import DIContainer, DIError
from core.di.typed_config import TypedDIConfiguration
from core.di.config import DIConfiguration, ServiceConfig
from core.interfaces import (
    IFingerprintEngine,
    IProber,
    IClassifier,
    IAttackAdapter,
    IEffectivenessTester,
    ILearningMemory,
    IStrategyGenerator,
    IStrategySaver,
    IClosedLoopManager,
    IEvolutionarySearcher,
)
from core.robust_packet_processor import RobustPacketProcessor
from core.integration.strategy_mapper import StrategyMapper
from core.integration.result_processor import ResultProcessor

try:
    from core.optimization.dynamic_parameter_optimizer import DynamicParameterOptimizer

    OPTIMIZER_AVAILABLE = True
except ImportError:
    OPTIMIZER_AVAILABLE = False
    DynamicParameterOptimizer = None
LOG = logging.getLogger("ServiceFactory")


class ServiceFactory:

    @staticmethod
    def create_container_from_typed_config(config: TypedDIConfiguration) -> DIContainer:
        container = DIContainer()
        try:
            from core.fingerprint.prober import UltimateDPIProber
            from core.fingerprint.classifier import UltimateDPIClassifier
            from core.fingerprint.advanced_fingerprint_engine import (
                UltimateAdvancedFingerprintEngine,
            )
            from core.integration.attack_adapter import AttackAdapter
            from core.bypass.attacks.real_effectiveness_tester import (
                RealEffectivenessTester,
            )
            from core.bypass.attacks.learning_memory import LearningMemory
            from ml.strategy_generator import AdvancedStrategyGenerator
            from core.integration.strategy_saver import StrategySaver
            from core.integration.closed_loop_manager import ClosedLoopManager
            from core.failure_analyzer import FailureAnalyzer
            from core.diagnostic_system import DiagnosticSystem
            from core.bypass.engines.packet_processing_engine import (
                PacketProcessingEngine,
            )
            from core.bypass.engines.base import EngineConfig
            from core.bypass.attacks.registry import AttackRegistry
            from core.domain_specific_strategies import DomainSpecificStrategies
            from ml.strategy_predictor import StrategyPredictor, SKLEARN_AVAILABLE
            from ml.evolutionary_search import EvolutionarySearcher

            container.register_singleton(AttackRegistry)

            def create_attack_adapter_factory(registry: AttackRegistry):
                from core.integration.integration_config import IntegrationConfig

                return AttackAdapter(
                    attack_registry=registry,
                    integration_config=IntegrationConfig(
                        debug_mode=config.attack_adapter.debug_mode
                    ),
                )

            container.register_singleton(
                IAttackAdapter, factory=create_attack_adapter_factory
            )

            def create_diagnostic_system_factory(attack_adapter: IAttackAdapter):
                return DiagnosticSystem(
                    attack_adapter=attack_adapter, debug=config.debug_enabled
                )

            container.register_singleton(
                DiagnosticSystem, factory=create_diagnostic_system_factory
            )

            def create_prober_factory():
                return UltimateDPIProber(debug=config.debug_enabled)

            container.register_singleton(IProber, factory=create_prober_factory)

            def create_classifier_factory():
                return UltimateDPIClassifier(
                    ml_enabled=config.classifier.ml_enabled, debug=config.debug_enabled
                )

            container.register_singleton(IClassifier, factory=create_classifier_factory)

            def create_effectiveness_tester_factory():
                return RealEffectivenessTester(
                    timeout=config.effectiveness_tester.timeout,
                    max_retries=config.effectiveness_tester.max_retries,
                )

            container.register_singleton(
                IEffectivenessTester, factory=create_effectiveness_tester_factory
            )

            def create_robust_packet_processor_factory():
                return RobustPacketProcessor(debug=config.debug_enabled)

            container.register_singleton(
                RobustPacketProcessor, factory=create_robust_packet_processor_factory
            )

            def create_strategy_mapper_factory():
                return StrategyMapper()

            container.register_singleton(
                StrategyMapper, factory=create_strategy_mapper_factory
            )
            container.register_singleton(ResultProcessor)

            def create_fingerprint_engine_factory(
                prober: IProber, classifier: IClassifier, attack_adapter: IAttackAdapter
            ):
                return UltimateAdvancedFingerprintEngine(
                    prober=prober,
                    classifier=classifier,
                    attack_adapter=attack_adapter,
                    debug=config.fingerprint_engine.debug,
                    ml_enabled=config.fingerprint_engine.ml_enabled,
                )

            container.register_singleton(
                IFingerprintEngine, factory=create_fingerprint_engine_factory
            )

            def create_effectiveness_tester_factory():
                return RealEffectivenessTester(
                    timeout=config.effectiveness_tester.timeout,
                    max_retries=config.effectiveness_tester.max_retries,
                )

            container.register_singleton(
                IEffectivenessTester, factory=create_effectiveness_tester_factory
            )

            def create_learning_memory_factory():
                return LearningMemory(
                    storage_path=config.learning_memory.storage_path,
                    max_history_entries=config.learning_memory.max_history_entries,
                )

            container.register_singleton(
                IAttackAdapter, factory=create_attack_adapter_factory
            )
            container.register_singleton(
                IEffectivenessTester, factory=create_effectiveness_tester_factory
            )
            container.register_singleton(
                ILearningMemory, factory=create_learning_memory_factory
            )

            def create_fingerprint_engine_factory(
                prober: IProber, classifier: IClassifier, attack_adapter: IAttackAdapter
            ):
                return UltimateAdvancedFingerprintEngine(
                    prober=prober,
                    classifier=classifier,
                    attack_adapter=attack_adapter,
                    debug=config.fingerprint_engine.debug,
                    ml_enabled=config.fingerprint_engine.ml_enabled,
                )

            container.register_singleton(
                IFingerprintEngine, factory=create_fingerprint_engine_factory
            )
            container.register_singleton(AttackRegistry)
            container.register_singleton(DomainSpecificStrategies)

            def create_strategy_predictor_factory():
                return StrategyPredictor(
                    model_path="data/strategy_predictor_model.joblib"
                )

            if config.strategy_generator.enable_ml_prediction and SKLEARN_AVAILABLE:
                container.register_singleton(
                    StrategyPredictor, factory=create_strategy_predictor_factory
                )
            else:
                container.register_singleton(StrategyPredictor, instance=None)

            def create_strategy_saver_factory():
                return StrategySaver(
                    strategy_file=config.strategy_saver.storage_path,
                    max_strategies_per_fingerprint=config.strategy_saver.max_strategies_to_save,
                )

            container.register_singleton(
                IStrategySaver, factory=create_strategy_saver_factory
            )
            if OPTIMIZER_AVAILABLE:

                def create_parameter_optimizer_factory(
                    effectiveness_tester: IEffectivenessTester,
                ):
                    return DynamicParameterOptimizer(
                        effectiveness_tester=effectiveness_tester
                    )

                container.register_singleton(
                    DynamicParameterOptimizer,
                    factory=create_parameter_optimizer_factory,
                )
            else:
                LOG.warning(
                    "DynamicParameterOptimizer not available. Registering as None."
                )
                container.register_singleton(DynamicParameterOptimizer, instance=None)

            def create_strategy_generator_factory(
                attack_registry: AttackRegistry,
                domain_strategies: DomainSpecificStrategies,
                strategy_predictor: Optional[StrategyPredictor],
                parameter_optimizer: Optional[DynamicParameterOptimizer],
            ):
                return AdvancedStrategyGenerator(
                    attack_registry=attack_registry,
                    domain_strategies=domain_strategies,
                    strategy_predictor=strategy_predictor,
                    parameter_optimizer=parameter_optimizer,
                    fingerprint_dict={},
                    history=[],
                    max_strategies=config.strategy_generator.max_strategies,
                    enable_ml_prediction=config.strategy_generator.enable_ml_prediction,
                )

            container.register_singleton(
                IStrategyGenerator, factory=create_strategy_generator_factory
            )

            def create_closed_loop_manager_factory(
                fingerprint_engine: IFingerprintEngine,
                strategy_generator: IStrategyGenerator,
                effectiveness_tester: IEffectivenessTester,
                learning_memory: ILearningMemory,
                attack_adapter: IAttackAdapter,
                strategy_saver: IStrategySaver,
            ):
                return ClosedLoopManager(
                    fingerprint_engine=fingerprint_engine,
                    strategy_generator=strategy_generator,
                    effectiveness_tester=effectiveness_tester,
                    learning_memory=learning_memory,
                    attack_adapter=attack_adapter,
                    strategy_saver=strategy_saver,
                )

            container.register_singleton(
                IClosedLoopManager, factory=create_closed_loop_manager_factory
            )
            container.register_singleton(FailureAnalyzer)

            def create_diagnostic_system_factory(attack_adapter: IAttackAdapter):
                return DiagnosticSystem(
                    attack_adapter=attack_adapter, debug=config.debug_enabled
                )

            container.register_singleton(
                DiagnosticSystem, factory=create_diagnostic_system_factory
            )

            def create_evolutionary_searcher_factory(
                attack_adapter: IAttackAdapter, strategy_generator: IStrategyGenerator
            ):
                return EvolutionarySearcher(
                    attack_adapter=attack_adapter, strategy_generator=strategy_generator
                )

            container.register_singleton(
                IEvolutionarySearcher, factory=create_evolutionary_searcher_factory
            )
            engine_config = EngineConfig(debug=config.debug_enabled)

            def create_packet_processing_engine_factory(
                attack_adapter: IAttackAdapter,
                fingerprint_engine: IFingerprintEngine,
                diagnostic_system: DiagnosticSystem,
                packet_processor: RobustPacketProcessor,
                strategy_mapper: StrategyMapper,
                result_processor: ResultProcessor,
            ):
                engine_config = EngineConfig(debug=config.debug_enabled)
                return PacketProcessingEngine(
                    attack_adapter=attack_adapter,
                    fingerprint_engine=fingerprint_engine,
                    diagnostic_system=diagnostic_system,
                    packet_processor=packet_processor,
                    strategy_mapper=strategy_mapper,
                    result_processor=result_processor,
                    config=engine_config,
                )

            container.register_singleton(
                PacketProcessingEngine, factory=create_packet_processing_engine_factory
            )
            LOG.info(
                f"Created DI container from typed configuration (mode: {config.mode})"
            )
            return container
        except Exception as e:
            LOG.error(
                f"Failed to create container from typed config: {e}", exc_info=True
            )
            raise DIError("Failed to build DI container from typed config.") from e

    @staticmethod
    def create_production_container() -> DIContainer:
        """
        Create DI container configured for production use.
        """
        from core.di.typed_config import create_production_config

        config = create_production_config()
        return ServiceFactory.create_container_from_typed_config(config)

    @staticmethod
    def create_development_container() -> DIContainer:
        """
        Create DI container configured for development use.
        """
        from core.di.typed_config import create_development_config

        config = create_development_config()
        return ServiceFactory.create_container_from_typed_config(config)

    @staticmethod
    def create_custom_container(config: Dict[str, Any]) -> DIContainer:
        """
        Create DI container with custom configuration.

        Args:
            config: Configuration dictionary specifying service implementations

        Returns:
            Configured DIContainer with custom services
        """
        container = DIContainer()
        LOG.info("Created custom DI container")
        return container

    @staticmethod
    def create_container_from_config(config: DIConfiguration) -> DIContainer:
        """
        Create DI container from configuration.
        Теперь эта функция будет работать, так как DIConfiguration известен.
        """
        container = DIContainer()
        service_interface_map = {
            "prober": IProber,
            "classifier": IClassifier,
            "fingerprint_engine": IFingerprintEngine,
            "attack_adapter": IAttackAdapter,
            "effectiveness_tester": IEffectivenessTester,
            "learning_memory": ILearningMemory,
            "strategy_generator": IStrategyGenerator,
            "strategy_saver": IStrategySaver,
            "closed_loop_manager": IClosedLoopManager,
        }
        for service_name, interface_type in service_interface_map.items():
            service_config = config.get_service_config(service_name)
            if service_config and service_config.enabled:
                ServiceFactory._register_service_from_config(
                    container, interface_type, service_config
                )
        for service_name, service_config in config.custom_services.items():
            if service_config.enabled:
                ServiceFactory._register_custom_service(
                    container, service_name, service_config
                )
        LOG.info(f"Created DI container from configuration (mode: {config.mode.value})")
        return container

    @staticmethod
    def _register_service_from_config(
        container: DIContainer, interface_type: type, service_config: ServiceConfig
    ) -> None:
        """Register a service in the container based on its configuration."""
        implementation_class = ServiceFactory._get_implementation_class(
            service_config.implementation_class
        )
        if implementation_class is None:
            LOG.warning(
                f"Could not find implementation class: {service_config.implementation_class}"
            )
            return

        def create_service(*args):
            return implementation_class(*args, **service_config.parameters)

        if service_config.lifetime == "singleton":
            container.register_singleton(interface_type, factory=create_service)
        elif service_config.lifetime == "transient":
            container.register_transient(interface_type, factory=create_service)
        elif service_config.lifetime == "scoped":
            container.register_scoped(interface_type, factory=create_service)
        else:
            LOG.warning(f"Unknown service lifetime: {service_config.lifetime}")
            container.register_singleton(interface_type, factory=create_service)

    @staticmethod
    def _register_custom_service(
        container: DIContainer, service_name: str, service_config: ServiceConfig
    ) -> None:
        """Register a custom service in the container."""
        LOG.info(f"Registering custom service: {service_name}")

    @staticmethod
    def _get_implementation_class(class_name: str) -> Optional[type]:
        """Get implementation class by name."""
        class_map = {
            "UltimateDPIProber": lambda: __import__(
                "core.fingerprint.prober", fromlist=["UltimateDPIProber"]
            ).UltimateDPIProber,
            "UltimateDPIClassifier": lambda: __import__(
                "core.fingerprint.classifier", fromlist=["UltimateDPIClassifier"]
            ).UltimateDPIClassifier,
            "UltimateAdvancedFingerprintEngine": lambda: __import__(
                "core.fingerprint.advanced_fingerprint_engine",
                fromlist=["UltimateAdvancedFingerprintEngine"],
            ).UltimateAdvancedFingerprintEngine,
            "AttackAdapter": lambda: __import__(
                "core.integration.attack_adapter", fromlist=["AttackAdapter"]
            ).AttackAdapter,
            "RealEffectivenessTester": lambda: __import__(
                "core.bypass.attacks.real_effectiveness_tester",
                fromlist=["RealEffectivenessTester"],
            ).RealEffectivenessTester,
            "LearningMemory": lambda: __import__(
                "core.bypass.attacks.learning_memory", fromlist=["LearningMemory"]
            ).LearningMemory,
            "AdvancedStrategyGenerator": lambda: __import__(
                "ml.strategy_generator", fromlist=["AdvancedStrategyGenerator"]
            ).AdvancedStrategyGenerator,
            "StrategySaver": lambda: __import__(
                "core.integration.strategy_saver", fromlist=["StrategySaver"]
            ).StrategySaver,
            "ClosedLoopManager": lambda: __import__(
                "core.integration.closed_loop_manager", fromlist=["ClosedLoopManager"]
            ).ClosedLoopManager,
            "FailureAnalyzer": lambda: __import__(
                "core.failure_analyzer", fromlist=["FailureAnalyzer"]
            ).FailureAnalyzer,
            "OptimizedHTTPClientPool": lambda: __import__(
                "core.optimization.http_client_pool",
                fromlist=["OptimizedHTTPClientPool"],
            ).OptimizedHTTPClientPool,
            "DynamicParameterOptimizer": lambda: __import__(
                "core.optimization.dynamic_parameter_optimizer",
                fromlist=["DynamicParameterOptimizer"],
            ).DynamicParameterOptimizer,
        }
        if class_name in class_map:
            try:
                return class_map[class_name]()
            except ImportError as e:
                LOG.warning(f"Could not import {class_name}: {e}")
                return None
        LOG.warning(f"Unknown implementation class: {class_name}")
        return None
