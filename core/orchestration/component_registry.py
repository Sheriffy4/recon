"""
Component registry for managing specialized components.

This module provides a registry for managing and accessing all specialized
components used by the UnifiedBypassEngine orchestration layer.

Feature: unified-engine-refactoring
Requirements: 1.1, 1.4, 1.5
"""

import logging
from typing import Dict, Any, Optional, Type, TypeVar, Generic
from dataclasses import dataclass, field

from core.validation.result_validator import IResultValidator, ResultValidator
from core.strategy.circuit_breaker import ICircuitBreaker, CircuitBreaker
from core.net.connection_tester import IConnectionTester, ConnectionTester
from core.strategy.processor import IStrategyProcessor, StrategyProcessor
from core.session.engine_session_manager import EngineSessionManager
from core.telemetry import ITelemetryCollector, TelemetryCollector
from core.infrastructure import CacheManager, ConnectionPool, StructuredLogger, RetryConfig
from core.state_management import EngineStateMachine
from core.async_compat import AsyncSyncWrapper, EventLoopHandler


T = TypeVar("T")


@dataclass
class ComponentInfo:
    """Information about a registered component."""

    component_type: str
    instance: Any
    interface_type: Optional[Type] = None
    created_at: float = field(default_factory=lambda: __import__("time").time())
    metadata: Dict[str, Any] = field(default_factory=dict)


class ComponentRegistry:
    """
    Registry for managing specialized components.

    This class provides centralized management of all components used by
    the UnifiedBypassEngine orchestration layer, ensuring proper initialization,
    dependency injection, and lifecycle management.

    Requirements:
    - 1.1: Modular architecture with component separation
    - 1.4: Well-defined interfaces between components
    - 1.5: Single responsibility for each component
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize component registry.

        Args:
            logger: Optional logger instance
        """
        self.logger = logger or logging.getLogger(__name__)
        self._components: Dict[str, ComponentInfo] = {}
        self._initialized = False

        self.logger.debug("ComponentRegistry initialized")

    def register_component(
        self,
        name: str,
        instance: Any,
        interface_type: Optional[Type] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Register a component instance.

        Args:
            name: Component name/identifier
            instance: Component instance
            interface_type: Expected interface type for validation
            metadata: Additional metadata about the component

        Raises:
            ValueError: If component name already exists or interface validation fails
        """
        if name in self._components:
            raise ValueError(f"Component '{name}' is already registered")

        # Validate interface if specified
        if interface_type and not isinstance(instance, interface_type):
            raise ValueError(
                f"Component '{name}' does not implement interface {interface_type.__name__}"
            )

        component_info = ComponentInfo(
            component_type=type(instance).__name__,
            instance=instance,
            interface_type=interface_type,
            metadata=metadata or {},
        )

        self._components[name] = component_info
        self.logger.debug(f"Registered component: {name} ({component_info.component_type})")

    def get_component(self, name: str, expected_type: Optional[Type[T]] = None) -> T:
        """
        Get a registered component.

        Args:
            name: Component name
            expected_type: Expected component type for type checking

        Returns:
            Component instance

        Raises:
            KeyError: If component is not found
            TypeError: If component type doesn't match expected type
        """
        if name not in self._components:
            raise KeyError(f"Component '{name}' is not registered")

        component_info = self._components[name]
        instance = component_info.instance

        if expected_type and not isinstance(instance, expected_type):
            raise TypeError(f"Component '{name}' is not of expected type {expected_type.__name__}")

        return instance

    def has_component(self, name: str) -> bool:
        """
        Check if a component is registered.

        Args:
            name: Component name

        Returns:
            True if component is registered
        """
        return name in self._components

    def remove_component(self, name: str) -> bool:
        """
        Remove a registered component.

        Args:
            name: Component name

        Returns:
            True if component was removed, False if not found
        """
        if name in self._components:
            del self._components[name]
            self.logger.debug(f"Removed component: {name}")
            return True
        return False

    def list_components(self) -> Dict[str, str]:
        """
        List all registered components.

        Returns:
            Dictionary mapping component names to their types
        """
        return {name: info.component_type for name, info in self._components.items()}

    def initialize_default_components(self, debug: bool = False) -> None:
        """
        Initialize default components for the UnifiedBypassEngine.

        This method creates and registers all the standard components needed
        for the orchestration layer.

        Args:
            debug: Enable debug logging for components
        """
        if self._initialized:
            self.logger.warning("Default components already initialized")
            return

        try:
            # Core validation component
            if not self.has_component("result_validator"):
                result_validator = ResultValidator()
                self.register_component(
                    "result_validator",
                    result_validator,
                    IResultValidator,
                    {"description": "Centralized result validation"},
                )

            # Circuit breaker for strategy management
            if not self.has_component("circuit_breaker"):
                circuit_breaker = CircuitBreaker(logger=self.logger)
                self.register_component(
                    "circuit_breaker",
                    circuit_breaker,
                    ICircuitBreaker,
                    {"description": "Strategy failure management"},
                )

            # Connection testing component
            if not self.has_component("connection_tester"):
                connection_tester = ConnectionTester(logger=self.logger)
                self.register_component(
                    "connection_tester",
                    connection_tester,
                    IConnectionTester,
                    {"description": "Network connectivity testing"},
                )

            # Strategy processing component
            if not self.has_component("strategy_processor"):
                strategy_processor = StrategyProcessor(debug=debug)
                self.register_component(
                    "strategy_processor",
                    strategy_processor,
                    IStrategyProcessor,
                    {"description": "Strategy loading and processing"},
                )

            # Session management component
            if not self.has_component("session_manager"):
                session_manager = EngineSessionManager()
                self.register_component(
                    "session_manager",
                    session_manager,
                    EngineSessionManager,
                    {"description": "Engine lifecycle management"},
                )

            # Telemetry collection component
            if not self.has_component("telemetry_collector"):
                telemetry_collector = TelemetryCollector()
                self.register_component(
                    "telemetry_collector",
                    telemetry_collector,
                    ITelemetryCollector,
                    {"description": "Telemetry data collection"},
                )

            # Infrastructure components
            if not self.has_component("cache_manager"):
                cache_manager = CacheManager()
                self.register_component(
                    "cache_manager",
                    cache_manager,
                    CacheManager,
                    {"description": "Expensive operation caching"},
                )

            if not self.has_component("connection_pool"):
                connection_pool = ConnectionPool()
                self.register_component(
                    "connection_pool",
                    connection_pool,
                    ConnectionPool,
                    {"description": "Network connection reuse"},
                )

            if not self.has_component("structured_logger"):
                structured_logger = StructuredLogger(name="unified_engine")
                self.register_component(
                    "structured_logger",
                    structured_logger,
                    StructuredLogger,
                    {"description": "Machine-readable logging"},
                )

            # State management component
            if not self.has_component("state_machine"):
                state_machine = EngineStateMachine()
                self.register_component(
                    "state_machine",
                    state_machine,
                    EngineStateMachine,
                    {"description": "Engine state management"},
                )

            # Async/sync compatibility components
            if not self.has_component("async_wrapper"):
                async_wrapper = AsyncSyncWrapper()
                self.register_component(
                    "async_wrapper",
                    async_wrapper,
                    AsyncSyncWrapper,
                    {"description": "Async/sync compatibility"},
                )

            if not self.has_component("event_loop_handler"):
                event_loop_handler = EventLoopHandler()
                self.register_component(
                    "event_loop_handler",
                    event_loop_handler,
                    EventLoopHandler,
                    {"description": "Event loop management"},
                )

            self._initialized = True
            self.logger.info(f"Initialized {len(self._components)} default components")

        except Exception as e:
            self.logger.error(f"Failed to initialize default components: {e}")
            raise

    def get_component_status(self) -> Dict[str, Any]:
        """
        Get status information for all registered components.

        Returns:
            Dictionary with component status information
        """
        status = {
            "total_components": len(self._components),
            "initialized": self._initialized,
            "components": {},
        }

        for name, info in self._components.items():
            component_status = {
                "type": info.component_type,
                "interface": info.interface_type.__name__ if info.interface_type else None,
                "created_at": info.created_at,
                "metadata": info.metadata,
            }

            # Try to get component-specific status if available
            try:
                if hasattr(info.instance, "get_status"):
                    component_status["status"] = info.instance.get_status()
                elif hasattr(info.instance, "is_active"):
                    component_status["active"] = info.instance.is_active
            except Exception as e:
                component_status["status_error"] = str(e)

            status["components"][name] = component_status

        return status

    def cleanup_components(self) -> None:
        """
        Clean up all registered components.

        This method calls cleanup methods on components that support it.
        """
        import asyncio
        import inspect

        self.logger.info("Cleaning up registered components")

        for name, info in self._components.items():
            try:
                if hasattr(info.instance, "cleanup"):
                    cleanup_method = info.instance.cleanup
                    if inspect.iscoroutinefunction(cleanup_method):
                        # Handle async cleanup
                        try:
                            loop = asyncio.get_event_loop()
                            if loop.is_running():
                                # Create a task for async cleanup
                                task = loop.create_task(cleanup_method())
                                # Don't wait for it to avoid blocking
                                self.logger.debug(f"Scheduled async cleanup for component: {name}")
                            else:
                                loop.run_until_complete(cleanup_method())
                                self.logger.debug(f"Cleaned up async component: {name}")
                        except RuntimeError:
                            # No event loop available, skip async cleanup
                            self.logger.warning(
                                f"Cannot cleanup async component {name}: no event loop"
                            )
                    else:
                        cleanup_method()
                        self.logger.debug(f"Cleaned up component: {name}")
                elif hasattr(info.instance, "close"):
                    close_method = info.instance.close
                    if inspect.iscoroutinefunction(close_method):
                        # Handle async close
                        try:
                            loop = asyncio.get_event_loop()
                            if loop.is_running():
                                # Create a task for async close
                                task = loop.create_task(close_method())
                                # Don't wait for it to avoid blocking
                                self.logger.debug(f"Scheduled async close for component: {name}")
                            else:
                                loop.run_until_complete(close_method())
                                self.logger.debug(f"Closed async component: {name}")
                        except RuntimeError:
                            # No event loop available, skip async close
                            self.logger.warning(
                                f"Cannot close async component {name}: no event loop"
                            )
                    else:
                        close_method()
                        self.logger.debug(f"Closed component: {name}")
            except Exception as e:
                self.logger.error(f"Failed to cleanup component {name}: {e}")

        self.logger.info("Component cleanup completed")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        self.cleanup_components()
