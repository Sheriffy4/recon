"""
Refactored UnifiedBypassEngine - Orchestration Layer.

This module provides the refactored UnifiedBypassEngine that acts as a thin
orchestration layer, integrating all specialized components while maintaining
backward compatibility with the existing API.

Feature: unified-engine-refactoring
Requirements: 1.1, 1.4, 1.5
"""

import asyncio
import logging
import threading
import time
from typing import Dict, Any, List, Optional, Set, Union, Tuple
from dataclasses import dataclass

from .engine_orchestrator import (
    EngineOrchestrator,
    OrchestrationContext,
    create_engine_orchestrator,
)
from .component_registry import ComponentRegistry
from core.unified_engine_models import EngineState, StrategyTestResult, TelemetrySnapshot
from core.bypass.engine.base_engine import WindowsBypassEngine, EngineConfig


@dataclass
class UnifiedEngineConfig:
    """Configuration for the unified bypass engine."""

    debug: bool = True
    force_override: bool = True
    enable_diagnostics: bool = True
    log_all_strategies: bool = True
    track_forced_override: bool = True


class UnifiedBypassEngine:
    """
    Refactored UnifiedBypassEngine - Orchestration Layer.

    This class provides a thin orchestration layer that integrates all specialized
    components while maintaining backward compatibility with the existing API.
    The monolithic functionality has been decomposed into specialized components
    that are coordinated through the EngineOrchestrator.

    Requirements:
    - 1.1: Modular architecture with component separation (< 500 lines per component)
    - 1.4: Well-defined interfaces between components
    - 1.5: Single responsibility for orchestration

    Key Changes from Original:
    - Decomposed into specialized components (ResultValidator, CircuitBreaker, etc.)
    - Uses EngineOrchestrator to coordinate component interactions
    - Maintains backward compatibility through API preservation
    - Each component has single responsibility and < 500 lines
    """

    def __init__(
        self,
        config: Optional[UnifiedEngineConfig] = None,
        enable_advanced_fingerprinting: bool = True,
        enable_modern_bypass: bool = True,
        verbosity: str = "normal",
        enable_enhanced_tracking: bool = False,
        enable_online_optimization: bool = False,
    ):
        """
        Initialize the refactored UnifiedBypassEngine.

        Args:
            config: Engine configuration
            enable_advanced_fingerprinting: Enable advanced fingerprinting (legacy)
            enable_modern_bypass: Enable modern bypass features (legacy)
            verbosity: Logging verbosity level
            enable_enhanced_tracking: Enable enhanced tracking (legacy)
            enable_online_optimization: Enable online optimization (legacy)
        """
        # Configuration
        self.config = config or UnifiedEngineConfig()
        self.logger = logging.getLogger(__name__)
        self.debug = self.config.debug

        if self.debug:
            self.logger.setLevel(logging.DEBUG)

        # Create orchestrator with all specialized components
        self.orchestrator = create_engine_orchestrator(debug=self.debug)

        # Legacy compatibility - maintain reference to underlying engine
        engine_config = EngineConfig(debug=self.config.debug)
        self._legacy_engine = WindowsBypassEngine(engine_config)

        # State tracking for backward compatibility
        self._running = False
        self._start_time: Optional[float] = None
        self._lock = threading.Lock()

        # Legacy compatibility counters
        self._forced_override_count = 0
        self._strategy_applications: Dict[str, List[Dict[str, Any]]] = {}

        self.logger.info(
            "🚀 UnifiedBypassEngine (Refactored) initialized with modular architecture"
        )
        self.logger.debug(
            f"Components initialized: {len(self.orchestrator.registry.list_components())}"
        )

    # ============================================================================
    # Core Strategy Testing Methods (Requirement 1.4 - Component Integration)
    # ============================================================================

    async def execute_strategy_real_world(
        self,
        strategy: Union[str, Dict[str, Any]],
        test_sites: List[str],
        target_ips: Set[str],
        dns_cache: Dict[str, str],
        target_port: int = 443,
        initial_ttl: Optional[int] = None,
        fingerprint: Optional[Any] = None,
        return_details: bool = False,
        prefer_retry_on_timeout: bool = False,
        warmup_ms: Optional[float] = None,
        enable_online_optimization: bool = False,
        engine_override: Optional[str] = None,
        strategy_id: Optional[str] = None,
    ) -> Any:
        """
        Execute strategy test using orchestrated components.

        This method replaces the monolithic implementation with orchestrated
        component interactions while maintaining API compatibility.
        """
        operation_id = strategy_id or f"strategy_test_{int(time.time() * 1000000)}"

        # Convert strategy to dictionary format if needed
        if isinstance(strategy, str):
            strategy_data = {"type": strategy, "params": {}}
        else:
            strategy_data = strategy

        # Create orchestration context
        context = OrchestrationContext(
            operation_id=operation_id,
            strategy_data=strategy_data,
            target_sites=test_sites,
            target_ips=dns_cache,
            timeout=15.0,
            metadata={
                "target_port": target_port,
                "initial_ttl": initial_ttl,
                "fingerprint": fingerprint,
                "return_details": return_details,
                "warmup_ms": warmup_ms,
            },
        )

        # Execute through orchestrator (Requirement 1.4 - component coordination)
        result = await self.orchestrator.execute_strategy_test_async(context)

        # Track for legacy compatibility
        with self._lock:
            self._forced_override_count += 1
            if operation_id not in self._strategy_applications:
                self._strategy_applications[operation_id] = []
            self._strategy_applications[operation_id].append(
                {
                    "strategy_type": strategy_data.get("type", "unknown"),
                    "timestamp": time.time(),
                    "success": result.success,
                }
            )

        # Return in expected format
        if return_details:
            return (
                "ALL_SITES_WORKING" if result.success else "FAILED",
                result.successful_sites,
                result.total_sites,
                result.avg_latency,
                result.connectivity_details,
                result.telemetry.to_dict() if result.telemetry else {},
            )
        else:
            return (
                "ALL_SITES_WORKING" if result.success else "FAILED",
                result.successful_sites,
                result.total_sites,
                result.avg_latency,
            )

    async def test_baseline_connectivity(
        self, test_sites: List[str], dns_cache: Dict[str, str]
    ) -> Dict[str, Tuple[str, str, float, int]]:
        """
        Test baseline connectivity using orchestrated components.

        Args:
            test_sites: List of sites to test
            dns_cache: DNS resolution cache

        Returns:
            Dictionary with connectivity results
        """
        self.logger.info("Testing baseline connectivity with orchestrated components")

        # Use orchestrator for baseline testing (Requirement 1.4)
        return await self.orchestrator.execute_baseline_test_async(
            sites=test_sites, target_ips=dns_cache
        )

    def test_strategy_like_testing_mode(
        self,
        target_ip: str,
        strategy_input: Union[str, Dict[str, Any]],
        domain: Optional[str] = None,
        timeout: float = 15.0,
    ) -> Dict[str, Any]:
        """
        Test strategy using orchestrated components (sync wrapper).

        Args:
            target_ip: Target IP address
            strategy_input: Strategy configuration
            domain: Optional domain name
            timeout: Test timeout

        Returns:
            Dictionary with test results
        """
        # Convert to async and run through orchestrator
        strategy_data = (
            strategy_input if isinstance(strategy_input, dict) else {"type": strategy_input}
        )

        context = OrchestrationContext(
            operation_id=f"testing_mode_{int(time.time() * 1000000)}",
            strategy_data=strategy_data,
            target_sites=[f"https://{domain}/"] if domain else [f"https://{target_ip}/"],
            target_ips={domain: target_ip} if domain else {"target": target_ip},
            timeout=timeout,
        )

        # Execute through orchestrator (sync wrapper)
        result = self.orchestrator.execute_strategy_test_sync(context)

        # Convert to expected format
        return {
            "success": result.success,
            "strategy_type": strategy_data.get("type", "unknown"),
            "target_ip": target_ip,
            "domain": domain,
            "test_duration_ms": result.test_duration * 1000,
            "error": result.error,
            "http_success": result.http_success,
            "avg_latency": result.avg_latency,
            "telemetry": result.telemetry.to_dict() if result.telemetry else {},
            "timestamp": time.time(),
        }

    # ============================================================================
    # Engine Lifecycle Management (Requirement 1.5 - Single Responsibility)
    # ============================================================================

    def start(
        self,
        target_ips: Set[str],
        strategy_map: Dict[str, Union[str, Dict]],
        reset_telemetry: bool = False,
        strategy_override: Optional[Dict[str, Any]] = None,
    ) -> threading.Thread:
        """
        Start the unified bypass engine.

        This method maintains API compatibility while using the orchestrated
        state management system.
        """
        with self._lock:
            self._running = True
            self._start_time = time.time()

        self.logger.info(
            f"🚀 Starting refactored UnifiedBypassEngine with {len(target_ips)} targets"
        )

        # Transition state through orchestrator
        self.orchestrator.transition_state(EngineState.STARTING)

        if reset_telemetry:
            self.orchestrator.reset_telemetry()

        # Start legacy engine for compatibility
        thread = self._legacy_engine.start(
            target_ips=target_ips,
            strategy_map=strategy_map,
            reset_telemetry=reset_telemetry,
            strategy_override=strategy_override,
        )

        # Transition to running state
        self.orchestrator.transition_state(EngineState.RUNNING)

        self.logger.info("✅ Refactored UnifiedBypassEngine started successfully")
        return thread

    def stop(self):
        """Stop the unified bypass engine."""
        with self._lock:
            self._running = False

        self.logger.info("🛑 Stopping refactored UnifiedBypassEngine")

        # Transition state through orchestrator
        self.orchestrator.transition_state(EngineState.STOPPING)

        # Stop legacy engine
        self._legacy_engine.stop()

        # Transition to stopped state
        self.orchestrator.transition_state(EngineState.STOPPED)

        self.logger.info("✅ Refactored UnifiedBypassEngine stopped")

    def is_running(self) -> bool:
        """Check if engine is running."""
        with self._lock:
            return self._running

    # ============================================================================
    # Telemetry and Monitoring (Requirement 1.4 - Component Interface)
    # ============================================================================

    def get_telemetry_snapshot(self) -> Dict[str, Any]:
        """
        Get telemetry snapshot through orchestrated components.

        Returns:
            Dictionary with telemetry data
        """
        # Get telemetry through orchestrator
        snapshot = self.orchestrator.get_telemetry_snapshot()

        # Add legacy compatibility metrics
        with self._lock:
            legacy_metrics = {
                "unified_engine": {
                    "forced_override_count": self._forced_override_count,
                    "strategy_applications": dict(self._strategy_applications),
                    "running": self._running,
                    "uptime_seconds": (time.time() - self._start_time) if self._start_time else 0,
                    "config": {
                        "force_override": self.config.force_override,
                        "enable_diagnostics": self.config.enable_diagnostics,
                        "debug": self.config.debug,
                    },
                }
            }

        # Merge with orchestrator telemetry (snapshot is already a dict)
        result = snapshot.copy()
        result.update(legacy_metrics)

        return result

    def get_diagnostics_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive diagnostics report.

        Returns:
            Dictionary with diagnostics information
        """
        return self.orchestrator.get_orchestrator_status()

    # ============================================================================
    # Strategy Management (Requirement 1.4 - Component Interface)
    # ============================================================================

    def apply_strategy(
        self,
        target_ip: str,
        strategy_input: Union[str, Dict[str, Any]],
        domain: Optional[str] = None,
    ) -> bool:
        """
        Apply strategy through orchestrated components.

        Args:
            target_ip: Target IP address
            strategy_input: Strategy configuration
            domain: Optional domain name

        Returns:
            True if strategy was applied successfully
        """
        try:
            # Process strategy through orchestrator
            strategy_data = (
                strategy_input if isinstance(strategy_input, dict) else {"type": strategy_input}
            )

            # Use strategy processor component
            strategy_processor = self.orchestrator.registry.get_component("strategy_processor")
            processed_strategy = strategy_processor.load_strategy(strategy_data)
            strategy_processor.validate_strategy(processed_strategy)

            # Track application for legacy compatibility
            with self._lock:
                self._forced_override_count += 1
                key = domain or target_ip
                if key not in self._strategy_applications:
                    self._strategy_applications[key] = []
                self._strategy_applications[key].append(
                    {
                        "strategy_type": processed_strategy.get("type", "unknown"),
                        "timestamp": time.time(),
                        "forced_override": True,
                        "target_ip": target_ip,
                        "domain": domain,
                    }
                )

            self.logger.info(
                f"🎯 Applied strategy through orchestrated components: {processed_strategy.get('type')}"
            )
            return True

        except Exception as e:
            self.logger.error(f"❌ Failed to apply strategy: {e}")
            return False

    def get_prioritized_strategies(self, strategy_ids: List[str]) -> List[str]:
        """
        Get prioritized strategies through circuit breaker component.

        Args:
            strategy_ids: List of strategy identifiers

        Returns:
            List of strategies ordered by priority
        """
        return self.orchestrator.get_prioritized_strategies(strategy_ids)

    # ============================================================================
    # Legacy Compatibility Methods
    # ============================================================================

    def set_strategy_override(self, strategy_input: Union[str, Dict[str, Any]]) -> None:
        """Set strategy override (legacy compatibility)."""
        self._legacy_engine.set_strategy_override(strategy_input)

    def clear_strategy_override(self) -> None:
        """Clear strategy override (legacy compatibility)."""
        self._legacy_engine.clear_strategy_override()

    def report_high_level_outcome(self, target_ip: str, success: bool):
        """Report high-level outcome (legacy compatibility)."""
        self._legacy_engine.report_high_level_outcome(target_ip, success)

    def get_forced_override_count(self) -> int:
        """Get forced override count (legacy compatibility)."""
        with self._lock:
            return self._forced_override_count

    def enable_debug_mode(self):
        """Enable debug mode."""
        self.config.debug = True
        self.logger.setLevel(logging.DEBUG)
        self.logger.info("🔍 Debug mode enabled for refactored engine")

    def disable_debug_mode(self):
        """Disable debug mode."""
        self.config.debug = False
        self.logger.setLevel(logging.INFO)
        self.logger.info("🔇 Debug mode disabled for refactored engine")

    # ============================================================================
    # Resource Management (Requirement 1.5 - Single Responsibility)
    # ============================================================================

    def cleanup(self):
        """
        Clean up all resources through orchestrated components.

        This method ensures proper cleanup of all managed resources
        through the component orchestration system.
        """
        self.logger.info("🧹 Cleaning up refactored UnifiedBypassEngine")

        try:
            # Stop if running
            if self.is_running():
                self.stop()

            # Clean up through orchestrator
            self.orchestrator.cleanup()

            # Clean up legacy engine
            if hasattr(self._legacy_engine, "cleanup"):
                self._legacy_engine.cleanup()

            self.logger.info("✅ Refactored UnifiedBypassEngine cleanup completed")

        except Exception as e:
            self.logger.error(f"❌ Error during cleanup: {e}")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        self.cleanup()

    def __del__(self):
        """Destructor with cleanup."""
        try:
            self.cleanup()
        except Exception:
            pass  # Avoid exceptions in destructor


# ============================================================================
# Factory Functions for Backward Compatibility
# ============================================================================


def create_unified_engine(debug: bool = True, force_override: bool = True) -> UnifiedBypassEngine:
    """
    Create a UnifiedBypassEngine with standard configuration.

    Args:
        debug: Enable debug logging
        force_override: Enable forced override

    Returns:
        Configured UnifiedBypassEngine instance
    """
    config = UnifiedEngineConfig(
        debug=debug,
        force_override=force_override,
        enable_diagnostics=True,
        log_all_strategies=debug,
        track_forced_override=True,
    )
    return UnifiedBypassEngine(config)


def create_service_mode_engine(debug: bool = False) -> UnifiedBypassEngine:
    """
    Create a UnifiedBypassEngine configured for service mode.

    Args:
        debug: Enable debug logging

    Returns:
        UnifiedBypassEngine configured for service mode
    """
    config = UnifiedEngineConfig(
        debug=debug,
        force_override=True,
        enable_diagnostics=False,
        log_all_strategies=False,
        track_forced_override=True,
    )
    return UnifiedBypassEngine(config)


def create_testing_mode_engine(debug: bool = True) -> UnifiedBypassEngine:
    """
    Create a UnifiedBypassEngine configured for testing mode.

    Args:
        debug: Enable debug logging

    Returns:
        UnifiedBypassEngine configured for testing mode
    """
    config = UnifiedEngineConfig(
        debug=debug,
        force_override=True,
        enable_diagnostics=True,
        log_all_strategies=True,
        track_forced_override=True,
    )
    return UnifiedBypassEngine(config)
