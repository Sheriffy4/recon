# recon/core/di/cli_provider.py
"""
CLI Service Provider for Dependency Injection

Provides DI container setup and service resolution for CLI operations.
"""

import logging
import argparse
from typing import Dict, Any, Optional

from .container import DIContainer
from .factory import ServiceFactory
from .config import (
    DIConfiguration,
    DIMode,
    get_production_config,
    get_development_config,
    get_testing_config,
)
from .typed_config import (
    TypedDIConfiguration,
    create_production_config,
    create_development_config,
    create_testing_config,
    ConfigurationBuilder,
    DIMode,  # <-- Добавляем импорт DIMode
)
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
    IEvolutionarySearcher, # Убедитесь, что этот импорт есть
)
from ..bypass.engines.packet_processing_engine import PacketProcessingEngine

LOG = logging.getLogger("CLIProvider")

class CLIServiceProvider:
    """
    Service provider for CLI operations using Dependency Injection.

    Manages DI container lifecycle and provides easy access to services
    for CLI commands.
    """

    def __init__(self, args: argparse.Namespace):
        """
        Initialize CLI service provider.

        Args:
            args: Parsed command line arguments
        """
        self.args = args
        self.container: Optional[DIContainer] = None
        self._config: Optional[DIConfiguration] = None
        self._typed_config: Optional[TypedDIConfiguration] = None
        self._logger = LOG

        # Initialize container based on CLI arguments
        self._initialize_container()

    def _initialize_container(self) -> None:
        """Initialize DI container based on CLI arguments."""
        try:
            builder = ConfigurationBuilder()

            # --- НАЧАЛО ИЗМЕНЕНИЯ ---
            if hasattr(self.args, "test_mode") and self.args.test_mode:
                builder.set_mode(DIMode.TESTING)
            elif self.args.debug:
                builder.set_mode(DIMode.DEVELOPMENT)
            else:
                builder.set_mode(DIMode.PRODUCTION)
            # --- КОНЕЦ ИЗМЕНЕНИЯ ---

            builder.apply_cli_args(self.args)
            self._typed_config = builder.build()
            self.container = ServiceFactory.create_container_from_typed_config(
                self._typed_config
            )

            # --- НАЧАЛО ИЗМЕНЕНИЯ ---
            self._logger.info(
                f"Initialized DI container for CLI (mode: {self._typed_config.mode})"
            )
        except Exception as e:
            self._logger.error(f"Failed to initialize DI container: {e}")
            self._initialize_fallback_container()

    def _initialize_fallback_container(self) -> None:
        """Initialize fallback container with basic services."""
        self._logger.warning("Using fallback DI container initialization")

        if self.args.debug:
            self.container = ServiceFactory.create_development_container()
        else:
            self.container = ServiceFactory.create_production_container()

    def get_fingerprint_engine(self) -> IFingerprintEngine:
        """Get fingerprint engine service."""
        return self._resolve_service(IFingerprintEngine)

    def get_prober(self) -> IProber:
        """Get prober service."""
        return self._resolve_service(IProber)

    def get_classifier(self) -> IClassifier:
        """Get classifier service."""
        return self._resolve_service(IClassifier)

    def get_attack_adapter(self) -> IAttackAdapter:
        """Get attack adapter service."""
        return self._resolve_service(IAttackAdapter)

    def get_effectiveness_tester(self) -> IEffectivenessTester:
        """Get effectiveness tester service."""
        return self._resolve_service(IEffectivenessTester)

    def get_packet_processing_engine(self) -> PacketProcessingEngine:
        """Get the main packet processing engine service."""
        # Мы резолвим конкретную реализацию, так как это production-движок
        return self._resolve_service(PacketProcessingEngine)

    def get_learning_memory(self) -> ILearningMemory:
        """Get learning memory service."""
        return self._resolve_service(ILearningMemory)



    def get_strategy_saver(self) -> IStrategySaver:
        """Get strategy saver service."""
        return self._resolve_service(IStrategySaver)

    def get_closed_loop_manager(self) -> IClosedLoopManager:
        """Get closed loop manager service."""
        return self._resolve_service(IClosedLoopManager)

    def get_evolutionary_searcher(self) -> IEvolutionarySearcher:
        """Get evolutionary searcher service."""
        return self._resolve_service(IEvolutionarySearcher)

    def _resolve_service(self, service_type: type):
        """Resolve service from container with error handling."""
        if not self.container:
            raise RuntimeError("DI container not initialized")

        try:
            return self.container.resolve(service_type)
        except Exception as e:
            self._logger.error(
                f"Failed to resolve service {service_type.__name__}: {e}"
            )
            raise RuntimeError(f"Service resolution failed: {service_type.__name__}")

    async def resolve_service_async(self, service_type: type):
        """Resolve service asynchronously from container."""
        if not self.container:
            raise RuntimeError("DI container not initialized")

        try:
            return await self.container.resolve_async(service_type)
        except Exception as e:
            self._logger.error(
                f"Failed to resolve service {service_type.__name__} async: {e}"
            )
            raise RuntimeError(
                f"Async service resolution failed: {service_type.__name__}"
            )

    def create_services_for_domain(
        self, domain: str, domain_ip: str, port: int
    ) -> Dict[str, Any]:
        """
        Create domain-specific services.

        Args:
            domain: Target domain
            domain_ip: Resolved IP address
            port: Target port

        Returns:
            Dictionary of configured services for the domain
        """
        try:
            # Create domain-specific probe config
            from ..fingerprint.models import ProbeConfig

            probe_config = ProbeConfig(target_ip=domain_ip, port=port)

            # Get services from container
            services = {
                "fingerprint_engine": self.get_fingerprint_engine(),
                "prober": self.get_prober(),
                "classifier": self.get_classifier(),
                "attack_adapter": self.get_attack_adapter(),
                "effectiveness_tester": self.get_effectiveness_tester(),
                "learning_memory": self.get_learning_memory(),
                "strategy_generator": self.get_strategy_generator(),
                "strategy_saver": self.get_strategy_saver(),
            }

            # Add closed loop manager if needed
            if hasattr(self.args, "closed_loop") and self.args.closed_loop:
                services["closed_loop_manager"] = self.get_closed_loop_manager()

            # Configure prober with domain-specific config
            if hasattr(services["prober"], "config"):
                services["prober"].config = probe_config

            self._logger.info(f"Created services for domain: {domain}")
            return services

        except Exception as e:
            self._logger.error(f"Failed to create services for domain {domain}: {e}")
            raise

    def cleanup(self) -> None:
        """Cleanup DI container and services."""
        if self.container:
            # Clear scoped instances
            self.container.clear_scoped()

            # Cleanup any services that need it
            try:
                # Get HTTP client pool and cleanup if available
                if self.container.is_registered(
                    type(None)
                ):  # Placeholder for HTTP pool interface
                    pass  # Would cleanup HTTP pool here
            except Exception as e:
                self._logger.warning(f"Error during service cleanup: {e}")

        self._logger.info("CLI service provider cleanup completed")

    def get_container_info(self) -> Dict[str, Any]:
        """Get information about the DI container."""
        if not self.container:
            return {"status": "not_initialized"}

        config_dict = None
        if self._typed_config:
            try:
                if hasattr(self._typed_config, "dict"):
                    config_dict = self._typed_config.dict()
                else:
                    import dataclasses

                    config_dict = dataclasses.asdict(self._typed_config)
            except Exception as e:
                self._logger.warning(f"Failed to serialize config: {e}")

        return {
            "status": "initialized",
            # --- НАЧАЛО ИЗМЕНЕНИЯ ---
            "mode": self._typed_config.mode if self._typed_config else "unknown",
            # --- КОНЕЦ ИЗМЕНЕНИЯ ---
            "registered_services": self.container.get_registered_services(),
            "debug_enabled": self.args.debug,
            "typed_config": config_dict,
            "legacy_config": self._config.to_dict() if self._config else None,
        }


def create_cli_provider(args: argparse.Namespace) -> CLIServiceProvider:
    """
    Factory function to create CLI service provider.

    Args:
        args: Parsed command line arguments

    Returns:
        Configured CLIServiceProvider instance
    """
    return CLIServiceProvider(args)
