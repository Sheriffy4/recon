"""
Fallback and recovery mechanisms for the engine factory system.

This module provides comprehensive fallback logic, graceful degradation,
and mock engine creation for testing scenarios.
"""

from typing import Dict, Any, List, Optional, Callable
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod
from core.bypass.engines.base import BaseBypassEngine, EngineConfig, EngineType
from core.bypass.engines.error_handling import (
    BaseEngineError,
    EngineCreationError,
    EngineDependencyError,
    ErrorContext,
    ErrorSeverity,
    get_error_handler,
)
from core.bypass.engines.config_models import EngineCreationRequest

LOG = logging.getLogger("FallbackRecovery")


class FallbackStrategy(Enum):
    """Fallback strategies for engine creation."""

    PRIORITY_ORDER = "priority_order"
    DEPENDENCY_BASED = "dependency_based"
    PLATFORM_SPECIFIC = "platform_specific"
    LEAST_REQUIREMENTS = "least_requirements"
    MOCK_FALLBACK = "mock_fallback"


class RecoveryAction(Enum):
    """Recovery actions for failed engine creation."""

    RETRY = "retry"
    FALLBACK = "fallback"
    DEGRADE = "degrade"
    MOCK = "mock"
    FAIL = "fail"


@dataclass
class FallbackAttempt:
    """Information about a fallback attempt."""

    engine_type: EngineType
    attempt_number: int
    start_time: float
    end_time: Optional[float] = None
    success: bool = False
    error: Optional[BaseEngineError] = None
    recovery_action: Optional[RecoveryAction] = None

    @property
    def duration(self) -> Optional[float]:
        """Get the duration of the attempt."""
        if self.end_time and self.start_time:
            return self.end_time - self.start_time
        return None


@dataclass
class FallbackResult:
    """Result of fallback and recovery process."""

    success: bool
    engine: Optional[BaseBypassEngine] = None
    final_engine_type: Optional[EngineType] = None
    attempts: List[FallbackAttempt] = field(default_factory=list)
    total_duration: float = 0.0
    fallback_used: bool = False
    mock_used: bool = False
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def get_summary(self) -> str:
        """Get a summary of the fallback result."""
        if self.success:
            engine_info = f"{self.final_engine_type.value}" if self.final_engine_type else "Unknown"
            fallback_info = " (fallback)" if self.fallback_used else ""
            mock_info = " (mock)" if self.mock_used else ""
            return f"Success: {engine_info}{fallback_info}{mock_info} after {len(self.attempts)} attempts"
        else:
            return f"Failed after {len(self.attempts)} attempts in {self.total_duration:.2f}s"


class MockEngine(BaseBypassEngine):
    """Mock engine for testing and fallback scenarios."""

    def __init__(self, config: EngineConfig):
        super().__init__(config)
        self.mock_data = {}
        self.operation_count = 0
        self.logger.info("Mock engine initialized for testing/fallback")

    def start(self, target_ips, strategy_map) -> bool:
        """Mock start implementation."""
        self.operation_count += 1
        self.is_running = True
        self.logger.info(f"Mock engine started with {len(target_ips)} targets")
        return True

    def stop(self) -> bool:
        """Mock stop implementation."""
        self.operation_count += 1
        self.is_running = False
        self.logger.info("Mock engine stopped")
        return True

    def get_stats(self) -> Dict[str, Any]:
        """Mock stats implementation."""
        return {
            "mock_engine": True,
            "operation_count": self.operation_count,
            "is_running": self.is_running,
            "packets_processed": 0,
            "packets_modified": 0,
            "bytes_processed": 0,
            "errors": 0,
        }

    def is_healthy(self) -> bool:
        """Mock health check implementation."""
        return True

    def set_mock_data(self, key: str, value: Any):
        """Set mock data for testing."""
        self.mock_data[key] = value

    def get_mock_data(self, key: str) -> Any:
        """Get mock data for testing."""
        return self.mock_data.get(key)


class FallbackStrategy_Interface(ABC):
    """Interface for fallback strategies."""

    @abstractmethod
    def get_fallback_order(
        self,
        preferred_engine: Optional[EngineType],
        available_engines: List[EngineType],
        context: Optional[ErrorContext] = None,
    ) -> List[EngineType]:
        """Get the fallback order for engines."""
        pass

    @abstractmethod
    def should_attempt_fallback(self, error: BaseEngineError, attempt_count: int) -> bool:
        """Determine if fallback should be attempted."""
        pass


class PriorityOrderStrategy(FallbackStrategy_Interface):
    """Fallback strategy based on engine priority order."""

    def __init__(self, config_manager):
        self.config_manager = config_manager

    def get_fallback_order(
        self,
        preferred_engine: Optional[EngineType],
        available_engines: List[EngineType],
        context: Optional[ErrorContext] = None,
    ) -> List[EngineType]:
        """Get fallback order based on configured priorities."""
        return self.config_manager.get_fallback_order(preferred_engine)

    def should_attempt_fallback(self, error: BaseEngineError, attempt_count: int) -> bool:
        """Always attempt fallback for high/critical errors."""
        return error.severity in [ErrorSeverity.HIGH, ErrorSeverity.CRITICAL] and attempt_count < 3


class DependencyBasedStrategy(FallbackStrategy_Interface):
    """Fallback strategy based on dependency availability."""

    def __init__(self, detector):
        self.detector = detector

    def get_fallback_order(
        self,
        preferred_engine: Optional[EngineType],
        available_engines: List[EngineType],
        context: Optional[ErrorContext] = None,
    ) -> List[EngineType]:
        """Get fallback order based on dependency availability."""
        engines_with_deps = []
        engines_without_deps = []
        for engine_type in available_engines:
            if self.detector.check_engine_dependencies(engine_type):
                engines_with_deps.append(engine_type)
            else:
                engines_without_deps.append(engine_type)
        return engines_with_deps + engines_without_deps

    def should_attempt_fallback(self, error: BaseEngineError, attempt_count: int) -> bool:
        """Attempt fallback for dependency errors."""
        return isinstance(error, EngineDependencyError) and attempt_count < 5


class LeastRequirementsStrategy(FallbackStrategy_Interface):
    """Fallback strategy that prefers engines with fewer requirements."""

    def get_fallback_order(
        self,
        preferred_engine: Optional[EngineType],
        available_engines: List[EngineType],
        context: Optional[ErrorContext] = None,
    ) -> List[EngineType]:
        """Get fallback order based on engine requirements."""
        requirements_map = {
            EngineType.EXTERNAL_TOOL: 0,
            EngineType.NATIVE_PYDIVERT: 2,
            EngineType.NATIVE_NETFILTER: 2,
        }
        return sorted(available_engines, key=lambda e: requirements_map.get(e, 10))

    def should_attempt_fallback(self, error: BaseEngineError, attempt_count: int) -> bool:
        """Always attempt fallback with least requirements."""
        return attempt_count < 3


class FallbackRecoveryManager:
    """
    Manager for fallback and recovery mechanisms.

    This class provides comprehensive fallback logic, graceful degradation,
    and recovery mechanisms for engine creation failures.
    """

    def __init__(self, config_manager, detector, validator):
        self.logger = LOG
        self.config_manager = config_manager
        self.detector = detector
        self.validator = validator
        self.error_handler = get_error_handler()
        self.strategies = {
            FallbackStrategy.PRIORITY_ORDER: PriorityOrderStrategy(config_manager),
            FallbackStrategy.DEPENDENCY_BASED: DependencyBasedStrategy(detector),
            FallbackStrategy.LEAST_REQUIREMENTS: LeastRequirementsStrategy(),
        }
        self.max_fallback_attempts = 5
        self.fallback_timeout = 30.0
        self.enable_mock_fallback = True
        self.retry_delays = [0.1, 0.5, 1.0, 2.0, 5.0]

    def create_engine_with_fallback(
        self,
        request: EngineCreationRequest,
        engine_creator: Callable[[EngineType, EngineConfig], BaseBypassEngine],
        fallback_strategy: FallbackStrategy = FallbackStrategy.PRIORITY_ORDER,
    ) -> FallbackResult:
        """
        Create an engine with comprehensive fallback and recovery.

        Args:
            request: Engine creation request
            engine_creator: Function to create engines
            fallback_strategy: Strategy to use for fallback

        Returns:
            Fallback result with engine or error information
        """
        start_time = time.time()
        result = FallbackResult()
        strategy = self.strategies.get(fallback_strategy)
        if not strategy:
            strategy = self.strategies[FallbackStrategy.PRIORITY_ORDER]
        initial_engine_type = self._determine_initial_engine_type(request)
        available_engines = self.detector.detect_available_engines()
        fallback_order = strategy.get_fallback_order(
            initial_engine_type, available_engines, self._create_error_context(request)
        )
        if initial_engine_type and initial_engine_type not in fallback_order:
            fallback_order.insert(0, initial_engine_type)
        elif initial_engine_type and initial_engine_type in fallback_order:
            fallback_order.remove(initial_engine_type)
            fallback_order.insert(0, initial_engine_type)
        self.logger.info(
            f"Starting fallback process with order: {[e.value for e in fallback_order]}"
        )
        for attempt_num, engine_type in enumerate(fallback_order, 1):
            if attempt_num > self.max_fallback_attempts:
                break
            if time.time() - start_time > self.fallback_timeout:
                result.warnings.append("Fallback timeout reached")
                break
            attempt = self._attempt_engine_creation(
                engine_type, request, engine_creator, attempt_num
            )
            result.attempts.append(attempt)
            if attempt.success and attempt.engine:
                result.success = True
                result.engine = attempt.engine
                result.final_engine_type = engine_type
                result.fallback_used = attempt_num > 1
                break
            else:
                recovery_action = self._determine_recovery_action(
                    attempt.error, attempt_num, strategy
                )
                attempt.recovery_action = recovery_action
                if recovery_action == RecoveryAction.RETRY:
                    delay = self.retry_delays[min(attempt_num - 1, len(self.retry_delays) - 1)]
                    time.sleep(delay)
                    continue
                elif recovery_action == RecoveryAction.FAIL:
                    break
        if not result.success and self.enable_mock_fallback:
            mock_attempt = self._attempt_mock_engine_creation(request, len(result.attempts) + 1)
            result.attempts.append(mock_attempt)
            if mock_attempt.success:
                result.success = True
                result.engine = mock_attempt.engine
                result.final_engine_type = None
                result.mock_used = True
                result.warnings.append("Using mock engine as final fallback")
        result.total_duration = time.time() - start_time
        if not result.success:
            result.errors = [attempt.error.message for attempt in result.attempts if attempt.error]
        self.logger.info(f"Fallback process completed: {result.get_summary()}")
        return result

    def create_mock_engine(self, config: Optional[EngineConfig] = None) -> MockEngine:
        """
        Create a mock engine for testing scenarios.

        Args:
            config: Engine configuration

        Returns:
            Mock engine instance
        """
        if config is None:
            config = EngineConfig()
        return MockEngine(config)

    def configure_fallback_behavior(
        self,
        max_attempts: Optional[int] = None,
        timeout: Optional[float] = None,
        enable_mock: Optional[bool] = None,
        retry_delays: Optional[List[float]] = None,
    ):
        """
        Configure fallback behavior parameters.

        Args:
            max_attempts: Maximum number of fallback attempts
            timeout: Timeout for fallback process
            enable_mock: Whether to enable mock engine fallback
            retry_delays: Delays between retry attempts
        """
        if max_attempts is not None:
            self.max_fallback_attempts = max_attempts
        if timeout is not None:
            self.fallback_timeout = timeout
        if enable_mock is not None:
            self.enable_mock_fallback = enable_mock
        if retry_delays is not None:
            self.retry_delays = retry_delays
        self.logger.info(
            f"Fallback behavior configured: max_attempts={self.max_fallback_attempts}, timeout={self.fallback_timeout}, enable_mock={self.enable_mock_fallback}"
        )

    def get_fallback_statistics(self) -> Dict[str, Any]:
        """Get statistics about fallback usage."""
        return {
            "max_attempts": self.max_fallback_attempts,
            "timeout": self.fallback_timeout,
            "mock_enabled": self.enable_mock_fallback,
            "available_strategies": list(self.strategies.keys()),
            "retry_delays": self.retry_delays,
        }

    def test_fallback_chain(self, preferred_engine: Optional[EngineType] = None) -> Dict[str, Any]:
        """
        Test the fallback chain without actually creating engines.

        Args:
            preferred_engine: Preferred engine type to test

        Returns:
            Test results
        """
        available_engines = self.detector.detect_available_engines()
        results = {}
        for strategy_name, strategy in self.strategies.items():
            fallback_order = strategy.get_fallback_order(preferred_engine, available_engines)
            results[strategy_name.value] = {
                "fallback_order": [e.value for e in fallback_order],
                "available_engines": [e.value for e in available_engines],
                "total_options": len(fallback_order),
            }
        return results

    def _determine_initial_engine_type(
        self, request: EngineCreationRequest
    ) -> Optional[EngineType]:
        """Determine the initial engine type from request."""
        if request.engine_type:
            if isinstance(request.engine_type, str):
                for et in EngineType:
                    if et.value == request.engine_type.lower():
                        return et
            elif isinstance(request.engine_type, EngineType):
                return request.engine_type
        return self.config_manager.get_default_engine_type()

    def _create_error_context(self, request: EngineCreationRequest) -> ErrorContext:
        """Create error context from request."""
        from core.bypass.engines.error_handling import ErrorContext

        return ErrorContext(
            operation="fallback_engine_creation",
            user_action="create_engine_with_fallback",
            additional_info={
                "request_id": getattr(request, "request_id", None),
                "allow_fallback": request.allow_fallback,
                "validate_dependencies": request.validate_dependencies,
            },
        )

    def _attempt_engine_creation(
        self,
        engine_type: EngineType,
        request: EngineCreationRequest,
        engine_creator: Callable,
        attempt_num: int,
    ) -> FallbackAttempt:
        """Attempt to create an engine of the specified type."""
        attempt = FallbackAttempt(
            engine_type=engine_type, attempt_number=attempt_num, start_time=time.time()
        )
        try:
            self.logger.debug(
                f"Attempting to create {engine_type.value} engine (attempt {attempt_num})"
            )
            config = request.config
            if not config:
                config = self.config_manager.get_engine_config_object(engine_type)
            engine = engine_creator(engine_type, config)
            attempt.success = True
            attempt.engine = engine
            self.logger.info(
                f"Successfully created {engine_type.value} engine on attempt {attempt_num}"
            )
        except Exception as e:
            context = self._create_error_context(request)
            context.engine_type = engine_type
            from core.bypass.engines.error_handling import create_error_from_exception

            structured_error = create_error_from_exception(e, EngineCreationError, context)
            attempt.error = structured_error
            self.logger.warning(
                f"Failed to create {engine_type.value} engine: {structured_error.message}"
            )
        attempt.end_time = time.time()
        return attempt

    def _attempt_mock_engine_creation(
        self, request: EngineCreationRequest, attempt_num: int
    ) -> FallbackAttempt:
        """Attempt to create a mock engine."""
        attempt = FallbackAttempt(
            engine_type=None, attempt_number=attempt_num, start_time=time.time()
        )
        try:
            self.logger.info(f"Creating mock engine as final fallback (attempt {attempt_num})")
            config = request.config
            if not config:
                config = EngineConfig()
            mock_engine = self.create_mock_engine(config)
            attempt.success = True
            attempt.engine = mock_engine
        except Exception as e:
            context = self._create_error_context(request)
            from core.bypass.engines.error_handling import create_error_from_exception

            attempt.error = create_error_from_exception(e, EngineCreationError, context)
        attempt.end_time = time.time()
        return attempt

    def _determine_recovery_action(
        self,
        error: Optional[BaseEngineError],
        attempt_count: int,
        strategy: FallbackStrategy_Interface,
    ) -> RecoveryAction:
        """Determine the appropriate recovery action."""
        if not error:
            return RecoveryAction.FAIL
        if strategy.should_attempt_fallback(error, attempt_count):
            if attempt_count <= 2:
                return RecoveryAction.RETRY
            else:
                return RecoveryAction.FALLBACK
        if isinstance(error, EngineDependencyError):
            return RecoveryAction.FALLBACK
        elif error.severity == ErrorSeverity.CRITICAL:
            return RecoveryAction.FAIL
        elif attempt_count < 3:
            return RecoveryAction.RETRY
        else:
            return RecoveryAction.FALLBACK


_fallback_manager = None


def get_fallback_recovery_manager(config_manager=None, detector=None, validator=None):
    """Get the global fallback recovery manager instance."""
    global _fallback_manager
    if _fallback_manager is None and config_manager and detector and validator:
        _fallback_manager = FallbackRecoveryManager(config_manager, detector, validator)
    return _fallback_manager


def create_mock_engine(config: Optional[EngineConfig] = None) -> MockEngine:
    """Convenience function to create a mock engine."""
    if config is None:
        config = EngineConfig()
    return MockEngine(config)
