# recon/core/di/cli_integration.py
import logging
import asyncio
from typing import Dict, Any, Optional
from dataclasses import dataclass

from .cli_provider import CLIServiceProvider
from ..interfaces import (
    IFingerprintEngine,
    IProber,
    IClassifier,
    IAttackAdapter,
    IEffectivenessTester,
    ILearningMemory,
    IStrategyGenerator,
    IStrategySaver,
    IClosedLoopManager,
    IEvolutionarySearcher,  # Убедимся, что интерфейс импортирован
)
from ml.strategy_generator import AdvancedStrategyGenerator
from core.bypass.attacks.registry import AttackRegistry
from core.domain_specific_strategies import DomainSpecificStrategies
from ml.strategy_predictor import StrategyPredictor
from core.optimization.dynamic_parameter_optimizer import DynamicParameterOptimizer
from core.bypass.engines.packet_processing_engine import PacketProcessingEngine

LOG = logging.getLogger("CLIIntegration")


@dataclass
class CLIServices:
    """Container for all CLI services resolved from DI."""

    fingerprint_engine: IFingerprintEngine
    prober: IProber
    classifier: IClassifier
    attack_adapter: IAttackAdapter
    effectiveness_tester: IEffectivenessTester
    learning_memory: ILearningMemory
    strategy_generator: Optional[IStrategyGenerator]
    strategy_saver: IStrategySaver

    packet_processing_engine: PacketProcessingEngine

    evolutionary_searcher: Optional[IEvolutionarySearcher] = None
    closed_loop_manager: Optional[IClosedLoopManager] = None

    # Additional services
    result_processor: Optional[Any] = None
    diagnostic_system: Optional[Any] = None
    performance_optimizer: Optional[Any] = None


class CLIIntegration:
    """
    Main CLI integration class that manages DI services for CLI operations.
    """

    def __init__(self, args):
        self.args = args
        self.provider = CLIServiceProvider(args)
        self.services: Optional[CLIServices] = None
        self._logger = LOG

    async def initialize_services(self) -> CLIServices:
        """
        Initialize all services from DI container.
        """
        try:
            self._logger.info("Initializing CLI services from DI container")

            # Resolve core services
            fingerprint_engine = self.provider.get_fingerprint_engine()
            prober = self.provider.get_prober()
            classifier = self.provider.get_classifier()
            attack_adapter = self.provider.get_attack_adapter()
            effectiveness_tester = self.provider.get_effectiveness_tester()
            learning_memory = self.provider.get_learning_memory()
            strategy_saver = self.provider.get_strategy_saver()

            # +++ ДОБАВЬТЕ РЕЗОЛВИНГ ДВИЖКА +++
            packet_processing_engine = self.provider.get_packet_processing_engine()

            # Безопасное получение опциональных сервисов
            evolutionary_searcher = None
            if hasattr(self.args, "evolve") and self.args.evolve:
                try:
                    # >>> ИЗМЕНЕНИЕ: Резолвим сервис из DI <<<
                    evolutionary_searcher = self.provider.get_evolutionary_searcher()
                except Exception as e:
                    self._logger.warning(
                        f"Failed to resolve evolutionary searcher: {e}"
                    )

            closed_loop_manager = None
            if hasattr(self.args, "closed_loop") and self.args.closed_loop:
                try:
                    closed_loop_manager = self.provider.get_closed_loop_manager()
                except Exception as e:
                    self._logger.warning(f"Failed to resolve closed loop manager: {e}")

            # Create additional services that don't have interfaces yet
            result_processor = None
            diagnostic_system = None
            performance_optimizer = None

            try:
                from core.integration.result_processor import ResultProcessor

                result_processor = ResultProcessor()
            except Exception as e:
                self._logger.warning(f"Failed to create ResultProcessor: {e}")

            try:
                from core.diagnostic_system import DiagnosticSystem

                diagnostic_system = DiagnosticSystem(
                    attack_adapter=attack_adapter, debug=self.args.debug
                )
            except Exception as e:
                self._logger.warning(f"Failed to create DiagnosticSystem: {e}")

            try:
                from core.optimization.performance_optimizer import PerformanceOptimizer

                performance_optimizer = PerformanceOptimizer()
            except Exception as e:
                self._logger.warning(f"Failed to create PerformanceOptimizer: {e}")

            # Create services container
            self.services = CLIServices(
                fingerprint_engine=fingerprint_engine,
                prober=prober,
                classifier=classifier,
                attack_adapter=attack_adapter,
                effectiveness_tester=effectiveness_tester,
                learning_memory=learning_memory,
                strategy_generator=None,  # Генератор создается позже
                strategy_saver=strategy_saver,
                # +++ ПЕРЕДАЙТЕ ДВИЖОК В КОНТЕЙНЕР +++
                packet_processing_engine=packet_processing_engine,
                evolutionary_searcher=evolutionary_searcher,
                closed_loop_manager=closed_loop_manager,
                result_processor=result_processor,
                diagnostic_system=diagnostic_system,
                performance_optimizer=performance_optimizer,
            )

            self._logger.info("Successfully initialized all CLI services")
            return self.services

        except Exception as e:
            self._logger.error(f"Failed to initialize CLI services: {e}")
            raise RuntimeError(f"CLI service initialization failed: {e}")

    def create_domain_specific_services(
        self, domain: str, domain_ip: str, port: int
    ) -> Dict[str, Any]:
        """
        Create domain-specific service configurations.

        Args:
            domain: Target domain
            domain_ip: Resolved IP address
            port: Target port

        Returns:
            Dictionary of configured services for the domain
        """
        if not self.services:
            raise RuntimeError(
                "Services not initialized. Call initialize_services() first."
            )

        try:
            # Configure prober for domain
            from core.fingerprint.models import ProbeConfig

            probe_config = ProbeConfig(target_ip=domain_ip, port=port)

            # Update prober configuration
            if hasattr(self.services.prober, "config"):
                self.services.prober.config = probe_config

            # Create domain-specific context
            domain_services = {
                "domain": domain,
                "domain_ip": domain_ip,
                "port": port,
                "fingerprint_engine": self.services.fingerprint_engine,
                "prober": self.services.prober,
                "classifier": self.services.classifier,
                "attack_adapter": self.services.attack_adapter,
                "effectiveness_tester": self.services.effectiveness_tester,
                "learning_memory": self.services.learning_memory,
                "strategy_generator": self.services.strategy_generator,
                "strategy_saver": self.services.strategy_saver,
                "result_processor": self.services.result_processor,
            }

            # Add closed loop manager if available
            if self.services.closed_loop_manager:
                domain_services["closed_loop_manager"] = (
                    self.services.closed_loop_manager
                )

            self._logger.debug(f"Created domain-specific services for {domain}")
            return domain_services

        except Exception as e:
            self._logger.error(
                f"Failed to create domain-specific services for {domain}: {e}"
            )
            raise

    async def create_strategy_generator_for_fingerprint(
        self, fingerprint_dict: Dict[str, Any]
    ) -> IStrategyGenerator:
        """
        Create strategy generator configured for specific fingerprint.
        Теперь он сам получает зависимости из DI и создает экземпляр.
        """
        if not self.services:
            raise RuntimeError("Services not initialized")

        try:
            # Получаем зависимости из DI
            attack_registry = self.provider.container.resolve(AttackRegistry)
            domain_strategies = self.provider.container.resolve(
                DomainSpecificStrategies
            )
            strategy_predictor = self.provider.container.resolve(StrategyPredictor)
            parameter_optimizer = self.provider.container.resolve(
                DynamicParameterOptimizer
            )

            # Создаем экземпляр AdvancedStrategyGenerator
            strategy_generator = AdvancedStrategyGenerator(
                attack_registry=attack_registry,
                domain_strategies=domain_strategies,
                strategy_predictor=strategy_predictor,
                parameter_optimizer=parameter_optimizer,
                fingerprint_dict=fingerprint_dict,
                history=[],  # История должна передаваться из контекста
                max_strategies=self.args.count,
                enable_ml_prediction=(
                    not self.args.no_ml if hasattr(self.args, "no_ml") else True
                ),
            )

            return strategy_generator

        except Exception as e:
            self._logger.error(
                f"Failed to create strategy generator for fingerprint: {e}"
            )
            raise

    async def create_effectiveness_tester_for_optimization(
        self,
    ) -> IEffectivenessTester:
        """
        Create effectiveness tester specifically for parameter optimization.

        Returns:
            Effectiveness tester configured for optimization
        """
        try:
            from core.bypass.attacks.real_effectiveness_tester import (
                RealEffectivenessTester,
            )

            # Create with optimization-specific settings
            return RealEffectivenessTester(
                timeout=getattr(self.args, "optimization_timeout", 120.0)
                / 10,  # Shorter timeout for optimization
                max_retries=1,  # Fewer retries for optimization speed
            )

        except Exception as e:
            self._logger.error(
                f"Failed to create optimization effectiveness tester: {e}"
            )
            raise

    def get_container_info(self) -> Dict[str, Any]:
        """Get information about the DI container."""
        return self.provider.get_container_info()

    def cleanup(self) -> None:
        """Cleanup DI services and container."""
        try:
            # Cleanup effectiveness tester if it has async resources
            if self.services and self.services.effectiveness_tester:
                if hasattr(self.services.effectiveness_tester, "close"):
                    asyncio.create_task(self.services.effectiveness_tester.close())

            # Cleanup provider
            self.provider.cleanup()

            self._logger.info("CLI integration cleanup completed")

        except Exception as e:
            self._logger.warning(f"Error during CLI integration cleanup: {e}")


def create_cli_integration(args) -> CLIIntegration:
    """
    Factory function to create CLI integration.

    Args:
        args: Parsed command line arguments

    Returns:
        Configured CLIIntegration instance
    """
    return CLIIntegration(args)


# Utility functions for backward compatibility
def get_services_from_di(args) -> Optional[CLIServices]:
    """
    Get services from DI container (backward compatibility).

    Args:
        args: CLI arguments

    Returns:
        CLIServices or None if DI fails
    """
    try:
        integration = create_cli_integration(args)
        return asyncio.run(integration.initialize_services())
    except Exception as e:
        LOG.warning(f"Failed to get services from DI: {e}")
        return None


def create_fallback_services(args) -> Dict[str, Any]:
    """
    Create services manually as fallback when DI fails.

    Args:
        args: CLI arguments

    Returns:
        Dictionary of manually created services
    """
    LOG.warning("Creating fallback services (DI not available)")

    services = {}

    try:
        # Create core services manually
        from core.integration.attack_adapter import AttackAdapter
        from core.integration.integration_config import IntegrationConfig
        from core.integration.result_processor import ResultProcessor

        integration_config = IntegrationConfig(debug_mode=args.debug)
        services["attack_adapter"] = AttackAdapter(integration_config)
        services["result_processor"] = ResultProcessor()

        # Add other services as needed
        from core.diagnostic_system import DiagnosticSystem
        from core.optimization.performance_optimizer import PerformanceOptimizer

        services["diagnostic_system"] = DiagnosticSystem(
            attack_adapter=services["attack_adapter"], debug=args.debug
        )
        services["performance_optimizer"] = PerformanceOptimizer()

    except Exception as e:
        LOG.error(f"Failed to create fallback services: {e}")

    return services
