"""
Engine orchestrator for coordinating component interactions.

This module provides the EngineOrchestrator class that coordinates interactions
between all specialized components in the UnifiedBypassEngine refactoring.

Feature: unified-engine-refactoring
Requirements: 1.1, 1.4, 1.5
"""

import asyncio
import logging
import time
from typing import Dict, Any, List, Optional, Set, Union, Tuple
from dataclasses import dataclass

from .component_registry import ComponentRegistry
from core.validation.result_validator import IResultValidator
from core.strategy.circuit_breaker import ICircuitBreaker
from core.net.connection_tester import IConnectionTester
from core.strategy.processor import IStrategyProcessor
from core.session.engine_session_manager import EngineSessionManager
from core.telemetry import ITelemetryCollector
from core.infrastructure import CacheManager, StructuredLogger
from core.state_management import EngineStateMachine
from core.async_compat import AsyncSyncWrapper
from core.unified_engine_models import (
    EngineState,
    ValidationResult,
    StrategyTestResult,
    TelemetrySnapshot,
)


@dataclass
class OrchestrationContext:
    """Context for orchestration operations."""

    operation_id: str
    strategy_data: Dict[str, Any]
    target_sites: List[str]
    target_ips: Dict[str, str]
    timeout: float = 15.0
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class EngineOrchestrator:
    """
    Orchestrator for coordinating component interactions.

    This class coordinates the interactions between all specialized components
    to provide unified bypass engine functionality. It implements the orchestration
    logic while delegating specific responsibilities to appropriate components.

    Requirements:
    - 1.1: Modular architecture with component separation
    - 1.4: Well-defined interfaces between components
    - 1.5: Single responsibility for orchestration logic
    """

    def __init__(
        self, component_registry: ComponentRegistry, logger: Optional[logging.Logger] = None
    ):
        """
        Initialize engine orchestrator.

        Args:
            component_registry: Registry containing all specialized components
            logger: Optional logger instance
        """
        self.registry = component_registry
        self.logger = logger or logging.getLogger(__name__)

        # Ensure default components are initialized
        if not self.registry._initialized:
            self.registry.initialize_default_components()

        # Get component references for performance
        self._result_validator = self.registry.get_component("result_validator", IResultValidator)
        self._circuit_breaker = self.registry.get_component("circuit_breaker", ICircuitBreaker)
        self._connection_tester = self.registry.get_component(
            "connection_tester", IConnectionTester
        )
        self._strategy_processor = self.registry.get_component(
            "strategy_processor", IStrategyProcessor
        )
        self._session_manager = self.registry.get_component("session_manager", EngineSessionManager)
        self._telemetry_collector = self.registry.get_component(
            "telemetry_collector", ITelemetryCollector
        )
        self._cache_manager = self.registry.get_component("cache_manager", CacheManager)
        self._structured_logger = self.registry.get_component("structured_logger", StructuredLogger)
        self._state_machine = self.registry.get_component("state_machine", EngineStateMachine)
        self._async_wrapper = self.registry.get_component("async_wrapper", AsyncSyncWrapper)

        self.logger.info("EngineOrchestrator initialized with all components")

    async def execute_strategy_test_async(
        self, context: OrchestrationContext
    ) -> StrategyTestResult:
        """
        Execute a complete strategy test using all components.

        This method orchestrates the complete strategy testing workflow:
        1. Process and validate strategy using StrategyProcessor
        2. Check circuit breaker status
        3. Test connectivity using ConnectionTester
        4. Collect telemetry using TelemetryCollector
        5. Validate results using ResultValidator
        6. Update circuit breaker with results

        Args:
            context: Orchestration context with test parameters

        Returns:
            StrategyTestResult with comprehensive test results
        """
        operation_start = time.time()

        with self._session_manager.operation_context(context.operation_id):
            try:
                self.logger.info(f"Starting strategy test: {context.operation_id}")

                # Step 1: Process strategy (Requirement 1.4 - component interface)
                self.logger.debug("Processing strategy configuration")
                processed_strategy = self._strategy_processor.load_strategy(context.strategy_data)

                # Validate strategy
                strategy_valid = self._strategy_processor.validate_strategy(processed_strategy)
                if not strategy_valid:
                    return StrategyTestResult(
                        strategy_id=context.operation_id,
                        success=False,
                        error="Strategy validation failed",
                        test_duration=time.time() - operation_start,
                    )

                # Step 2: Check circuit breaker (Requirement 1.4 - component interface)
                strategy_id = processed_strategy.get("type", "unknown")
                if not self._circuit_breaker.should_allow_test(strategy_id):
                    self.logger.warning(f"Strategy {strategy_id} blocked by circuit breaker")
                    return StrategyTestResult(
                        strategy_id=strategy_id,
                        success=False,
                        error="Strategy blocked by circuit breaker",
                        test_duration=time.time() - operation_start,
                    )

                # Step 3: Test connectivity (Requirement 1.4 - component interface)
                self.logger.debug("Testing connectivity")
                connectivity_results = await self._connection_tester.test_connectivity_async(
                    sites=context.target_sites,
                    target_ips=context.target_ips,
                    timeout=context.timeout,
                )

                # Analyze connectivity results
                successful_sites = [
                    site
                    for site, (status, _, _, _) in connectivity_results.items()
                    if status == "WORKING"
                ]

                http_success = len(successful_sites) > 0
                avg_latency = 0.0
                http_codes = []

                if successful_sites:
                    latencies = [
                        latency
                        for _, (status, _, latency, _) in connectivity_results.items()
                        if status == "WORKING"
                    ]
                    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0

                    http_codes = [
                        code
                        for _, (status, _, _, code) in connectivity_results.items()
                        if status == "WORKING" and code > 0
                    ]

                # Step 4: Collect telemetry (Requirement 1.4 - component interface)
                self.logger.debug("Collecting telemetry")
                telemetry_snapshot = self._telemetry_collector.get_snapshot()

                # Step 5: Validate results (Requirement 1.4 - component interface)
                self.logger.debug("Validating test results")
                primary_http_code = http_codes[0] if http_codes else 0
                validation_result = self._result_validator.validate(
                    http_success=http_success,
                    http_code=primary_http_code,
                    telemetry=telemetry_snapshot.to_dict(),
                    connection_verified=True,
                )

                # Create comprehensive test result
                test_result = StrategyTestResult(
                    strategy_id=strategy_id,
                    success=validation_result.success,
                    error=validation_result.error,
                    http_success=http_success,
                    http_codes=http_codes,
                    avg_latency=avg_latency,
                    successful_sites=len(successful_sites),
                    total_sites=len(context.target_sites),
                    test_duration=time.time() - operation_start,
                    telemetry=telemetry_snapshot,
                    validation_result=validation_result,
                    connectivity_details=connectivity_results,
                )

                # Step 6: Update circuit breaker (Requirement 1.4 - component interface)
                self.logger.debug("Updating circuit breaker")
                self._circuit_breaker.record_result(strategy_id, test_result)

                # Log structured result
                self._structured_logger.log_strategy_test(
                    strategy_id=strategy_id,
                    success=test_result.success,
                    duration=test_result.test_duration,
                    sites_tested=len(context.target_sites),
                    sites_successful=len(successful_sites),
                )

                self.logger.info(
                    f"Strategy test completed: {context.operation_id}, success: {test_result.success}"
                )
                return test_result

            except Exception as e:
                self.logger.error(
                    f"Strategy test failed: {context.operation_id}, error: {e}", exc_info=True
                )

                # Create failure result
                failure_result = StrategyTestResult(
                    strategy_id=context.operation_id,
                    success=False,
                    error=str(e),
                    test_duration=time.time() - operation_start,
                )

                # Update circuit breaker with failure
                try:
                    strategy_id = context.strategy_data.get("type", "unknown")
                    self._circuit_breaker.record_result(strategy_id, failure_result)
                except Exception:
                    pass  # Don't fail on circuit breaker update

                return failure_result

    def execute_strategy_test_sync(self, context: OrchestrationContext) -> StrategyTestResult:
        """
        Synchronous wrapper for strategy testing.

        Args:
            context: Orchestration context

        Returns:
            StrategyTestResult
        """
        return self._async_wrapper.run_sync(self.execute_strategy_test_async(context))

    async def execute_baseline_test_async(
        self, sites: List[str], target_ips: Dict[str, str], timeout: float = 15.0
    ) -> Dict[str, Tuple[str, str, float, int]]:
        """
        Execute baseline connectivity test without bypass strategies.

        Args:
            sites: List of sites to test
            target_ips: Mapping of hostnames to target IPs
            timeout: Connection timeout

        Returns:
            Dictionary with connectivity results
        """
        self.logger.info("Executing baseline connectivity test")

        # Use connection tester directly for baseline
        results = await self._connection_tester.test_connectivity_async(
            sites=sites, target_ips=target_ips, timeout=timeout
        )

        # Log baseline results
        working_sites = [site for site, (status, _, _, _) in results.items() if status == "WORKING"]
        self._structured_logger.log_baseline_test(
            sites_tested=len(sites),
            sites_working=len(working_sites),
            success_rate=len(working_sites) / len(sites) if sites else 0.0,
        )

        return results

    def execute_baseline_test_sync(
        self, sites: List[str], target_ips: Dict[str, str], timeout: float = 15.0
    ) -> Dict[str, Tuple[str, str, float, int]]:
        """
        Synchronous wrapper for baseline testing.

        Args:
            sites: List of sites to test
            target_ips: Mapping of hostnames to target IPs
            timeout: Connection timeout

        Returns:
            Dictionary with connectivity results
        """
        return self._async_wrapper.run_sync(
            self.execute_baseline_test_async(sites, target_ips, timeout)
        )

    def get_prioritized_strategies(self, strategy_ids: List[str]) -> List[str]:
        """
        Get strategies prioritized by circuit breaker.

        Args:
            strategy_ids: List of strategy identifiers

        Returns:
            List of strategies ordered by priority
        """
        return self._circuit_breaker.get_prioritized_strategies(strategy_ids)

    def reset_strategy_state(self, strategy_id: str) -> None:
        """
        Reset state for a specific strategy.

        Args:
            strategy_id: Strategy identifier to reset
        """
        self._circuit_breaker.reset_strategy(strategy_id)
        self.logger.info(f"Reset state for strategy: {strategy_id}")

    def get_engine_state(self) -> EngineState:
        """
        Get current engine state.

        Returns:
            Current engine state
        """
        return self._state_machine.current_state

    def transition_state(self, new_state: EngineState) -> bool:
        """
        Transition engine to new state.

        Args:
            new_state: Target state

        Returns:
            True if transition was successful
        """
        try:
            self._state_machine.transition_to(new_state)
            return True
        except Exception as e:
            self.logger.error(f"State transition failed: {e}")
            return False

    def get_telemetry_snapshot(self) -> Dict[str, Any]:
        """
        Get current telemetry snapshot.

        Returns:
            Dictionary with current metrics
        """
        # Use the underlying bypass engine for telemetry collection
        if hasattr(self, "_bypass_engine") and self._bypass_engine:
            return self._telemetry_collector.get_telemetry_snapshot(self._bypass_engine)
        else:
            # Return empty telemetry if no engine available
            return self._telemetry_collector._create_empty_metrics()

    def reset_telemetry(self) -> None:
        """Reset telemetry counters."""
        if hasattr(self, "_bypass_engine") and self._bypass_engine:
            self._telemetry_collector.reset_metrics(self._bypass_engine)
        self.logger.debug("Telemetry counters reset")

    def get_orchestrator_status(self) -> Dict[str, Any]:
        """
        Get comprehensive orchestrator status.

        Returns:
            Dictionary with orchestrator status information
        """
        return {
            "engine_state": self.get_engine_state().value,
            "session_status": self._session_manager.get_status(),
            "circuit_breaker_stats": self._circuit_breaker.get_statistics(),
            "telemetry": self.get_telemetry_snapshot(),
            "component_status": self.registry.get_component_status(),
            "cache_stats": (
                self._cache_manager.get_stats() if hasattr(self._cache_manager, "get_stats") else {}
            ),
            "timestamp": time.time(),
        }

    def cleanup(self) -> None:
        """
        Clean up orchestrator and all components.

        This method ensures proper cleanup of all managed resources.
        """
        self.logger.info("Cleaning up EngineOrchestrator")

        try:
            # Clean up session manager first
            self._session_manager.cleanup()

            # Clean up other components through registry
            self.registry.cleanup_components()

            self.logger.info("EngineOrchestrator cleanup completed")

        except Exception as e:
            self.logger.error(f"Error during orchestrator cleanup: {e}")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        self.cleanup()


def create_engine_orchestrator(debug: bool = False) -> EngineOrchestrator:
    """
    Factory function for creating EngineOrchestrator instances.

    Args:
        debug: Enable debug logging

    Returns:
        Configured EngineOrchestrator instance
    """
    # Create component registry and initialize default components
    registry = ComponentRegistry()
    registry.initialize_default_components(debug=debug)

    # Create orchestrator
    return EngineOrchestrator(registry)
