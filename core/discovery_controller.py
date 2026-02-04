"""
Discovery Controller - Main orchestrator for auto strategy discovery system

This module implements the DiscoveryController class as the main orchestrator
for discovery sessions, managing component coordination and discovery mode lifecycle.

Requirements: 4.4 from auto-strategy-discovery spec
"""

import logging
import time
import uuid
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from contextlib import contextmanager

from core.domain_filter import DomainFilter, FilterMode
from core.strategy_diversifier import StrategyDiversifier, StrategyVariation
from core.override_manager import OverrideManager
from core.results_collector import ResultsCollector, DiscoveryReport, ResultType
from core.auto_discovery_domain_integration import AutoDiscoveryDomainIntegration
from core.pcap.discovery_integration import PCAPCapturerFactory
from core.discovery_config import DiscoveryConfig, ValidationError, ConfigurationError
from core.discovery_logging import (
    DiscoveryLogger,
    DiscoveryMetricsCollector,
    get_discovery_logger,
    get_metrics_collector,
)
from core.discovery_debugging import DiscoveryDebugger, DebugLevel, get_discovery_debugger

LOG = logging.getLogger(__name__)


class DiscoveryStatus(Enum):
    """Discovery session status"""

    INACTIVE = "inactive"
    STARTING = "starting"
    ACTIVE = "active"
    PAUSING = "pausing"
    PAUSED = "paused"
    STOPPING = "stopping"
    COMPLETED = "completed"
    ERROR = "error"


# DiscoveryConfig is now imported from core.discovery_config


@dataclass
class DiscoverySession:
    """Represents an active discovery session"""

    session_id: str
    config: DiscoveryConfig
    status: DiscoveryStatus
    start_time: datetime
    end_time: Optional[datetime] = None

    # Component instances
    domain_filter: Optional[DomainFilter] = None
    strategy_diversifier: Optional[StrategyDiversifier] = None
    override_manager: Optional[OverrideManager] = None
    results_collector: Optional[ResultsCollector] = None

    # Session tracking
    strategies_tested: int = 0
    current_strategy: Optional[StrategyVariation] = None
    error_message: Optional[str] = None

    # Callbacks
    strategy_callback: Optional[Callable[[StrategyVariation], bool]] = None
    progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None

    @property
    def duration_seconds(self) -> float:
        """Calculate session duration in seconds"""
        end = self.end_time or datetime.now()
        return (end - self.start_time).total_seconds()

    @property
    def is_active(self) -> bool:
        """Check if session is currently active"""
        return self.status in [
            DiscoveryStatus.STARTING,
            DiscoveryStatus.ACTIVE,
            DiscoveryStatus.PAUSING,
        ]


class DiscoveryController:
    """
    Main orchestrator for auto strategy discovery sessions.

    The DiscoveryController coordinates all components of the discovery system:
    - Domain filtering to ensure only target domain traffic is processed
    - Strategy diversification to generate varied test strategies
    - Override management to disable conflicting domain rules
    - Results collection with domain-based filtering
    - Session lifecycle management

    Responsibilities:
    - Session management and component coordination
    - Discovery mode lifecycle management
    - Component integration and data flow orchestration
    - Error handling and recovery
    - Progress tracking and reporting

    Requirements: 4.4
    """

    def __init__(
        self,
        domain_rules_config: Optional[str] = None,
        max_concurrent_sessions: int = 1,
        discovery_logger: Optional[DiscoveryLogger] = None,
        metrics_collector: Optional[DiscoveryMetricsCollector] = None,
    ):
        """
        Initialize the DiscoveryController.

        Args:
            domain_rules_config: Path to domain rules configuration file
            max_concurrent_sessions: Maximum number of concurrent discovery sessions
            discovery_logger: Optional discovery logger instance
            metrics_collector: Optional metrics collector instance
        """
        self.max_concurrent_sessions = max_concurrent_sessions
        self.active_sessions: Dict[str, DiscoverySession] = {}

        # Initialize core components (shared across sessions)
        self.domain_integration = AutoDiscoveryDomainIntegration(domain_rules_config)

        # Initialize logging, monitoring, and debugging
        self.discovery_logger = discovery_logger or get_discovery_logger()
        self.metrics_collector = metrics_collector or get_metrics_collector()
        self.debugger = get_discovery_debugger()

        # Session management
        self._session_counter = 0
        self._global_callbacks: Dict[str, List[Callable]] = {
            "session_started": [],
            "session_completed": [],
            "session_error": [],
            "strategy_tested": [],
        }

        LOG.info(f"DiscoveryController initialized (max sessions: {max_concurrent_sessions})")

    def start_discovery(
        self,
        config: DiscoveryConfig,
        strategy_callback: Optional[Callable[[StrategyVariation], bool]] = None,
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> str:
        """
        Start a new discovery session.

        Args:
            config: Discovery configuration
            strategy_callback: Optional callback for strategy execution
            progress_callback: Optional callback for progress updates

        Returns:
            Session ID for the started discovery session

        Raises:
            RuntimeError: If maximum concurrent sessions exceeded or configuration invalid

        Requirements: 4.4
        """
        # Validate configuration
        self._validate_config(config)

        # Check session limits
        if len(self.active_sessions) >= self.max_concurrent_sessions:
            raise RuntimeError(
                f"Maximum concurrent sessions ({self.max_concurrent_sessions}) exceeded"
            )

        # Generate session ID
        self._session_counter += 1
        session_id = f"discovery_{int(time.time())}_{self._session_counter:03d}"

        LOG.info(f"Starting discovery session {session_id} for domain: {config.target_domain}")

        try:
            # Create session
            session = DiscoverySession(
                session_id=session_id,
                config=config,
                status=DiscoveryStatus.STARTING,
                start_time=datetime.now(),
                strategy_callback=strategy_callback,
                progress_callback=progress_callback,
            )

            # Initialize session components
            self._initialize_session_components(session)

            # Configure discovery mode
            self._configure_discovery_mode(session)

            # Register session
            self.active_sessions[session_id] = session
            session.status = DiscoveryStatus.ACTIVE

            # Start logging, metrics collection, and debugging
            self.discovery_logger.start_session_logging(session_id, config.target_domain)
            self.metrics_collector.start_session_metrics(session_id, config.target_domain)

            # Capture initial debug snapshot
            self.debugger.capture_debug_snapshot(
                session_id=session_id,
                target_domain=config.target_domain,
                session_status=session.status.value,
                session_duration_seconds=0.0,
                strategies_tested=0,
                debug_level=DebugLevel.BASIC,
            )

            # Notify callbacks
            self._notify_callbacks(
                "session_started",
                {"session_id": session_id, "target_domain": config.target_domain, "config": config},
            )

            LOG.info(f"✅ Discovery session {session_id} started successfully")
            return session_id

        except Exception as e:
            error_msg = f"Failed to start discovery session: {e}"
            LOG.error(error_msg)

            # Record error for debugging
            self.debugger.record_error(
                session_id,
                config.target_domain,
                "session_start_error",
                error_msg,
                "discovery_controller",
                e,
            )

            # Clean up partial session if it was created
            if session_id in self.active_sessions:
                self._cleanup_session(session_id, error_msg)

            raise RuntimeError(error_msg) from e

    def stop_discovery(self, session_id: str, reason: str = "Manual stop") -> DiscoveryReport:
        """
        Stop an active discovery session.

        Args:
            session_id: ID of session to stop
            reason: Reason for stopping the session

        Returns:
            Final discovery report

        Raises:
            ValueError: If session ID not found or session not active

        Requirements: 4.4
        """
        if session_id not in self.active_sessions:
            raise ValueError(f"Session {session_id} not found")

        session = self.active_sessions[session_id]

        if not session.is_active:
            LOG.warning(f"Session {session_id} is not active (status: {session.status.value})")

        LOG.info(f"Stopping discovery session {session_id}: {reason}")

        try:
            session.status = DiscoveryStatus.STOPPING
            session.end_time = datetime.now()

            # Generate final report
            report = self._generate_session_report(session)

            # End logging and metrics collection
            final_metrics = self.metrics_collector.end_session_metrics(session_id, True)
            self.discovery_logger.end_session_logging(session_id)

            # Clean up session
            self._cleanup_session(session_id, reason)

            # Update session status
            session.status = DiscoveryStatus.COMPLETED

            # Notify callbacks
            self._notify_callbacks(
                "session_completed",
                {
                    "session_id": session_id,
                    "report": report,
                    "reason": reason,
                    "final_metrics": final_metrics,
                },
            )

            LOG.info(f"✅ Discovery session {session_id} stopped successfully")
            return report

        except Exception as e:
            error_msg = f"Error stopping session {session_id}: {e}"
            LOG.error(error_msg)
            session.status = DiscoveryStatus.ERROR
            session.error_message = error_msg

            # Notify error callbacks
            self._notify_callbacks("session_error", {"session_id": session_id, "error": error_msg})

            raise RuntimeError(error_msg) from e

    def get_next_strategy(self, session_id: str) -> Optional[StrategyVariation]:
        """
        Get the next strategy to test for a discovery session.

        Args:
            session_id: ID of discovery session

        Returns:
            Next strategy variation to test, or None if no more strategies

        Raises:
            ValueError: If session ID not found or session not active
        """
        if session_id not in self.active_sessions:
            raise ValueError(f"Session {session_id} not found")

        session = self.active_sessions[session_id]

        if not session.is_active:
            raise ValueError(f"Session {session_id} is not active (status: {session.status.value})")

        # Check session limits
        if session.strategies_tested >= session.config.strategy.max_strategies:
            LOG.info(
                f"Session {session_id} reached max strategies limit ({session.config.strategy.max_strategies})"
            )
            return None

        if session.duration_seconds >= session.config.strategy.max_duration_seconds:
            LOG.info(
                f"Session {session_id} reached max duration limit ({session.config.strategy.max_duration_seconds}s)"
            )
            return None

        try:
            # Generate next strategy using diversifier
            from core.strategy_diversifier import AttackType

            exclude_types = [
                getattr(AttackType, at.upper(), None)
                for at in session.config.strategy.exclude_attack_types
            ]
            exclude_types = [at for at in exclude_types if at is not None]

            strategy = session.strategy_diversifier.generate_next_strategy(
                target_domain=session.config.target_domain,
                exclude_types=exclude_types,
                prefer_untested=session.config.strategy.prefer_untested,
            )

            if strategy:
                session.current_strategy = strategy
                LOG.info(f"Generated strategy for session {session_id}: {strategy.name}")

                # Log strategy generation
                self.discovery_logger.log_strategy_generated(
                    session_id,
                    session.config.target_domain,
                    strategy.name,
                    [at.value for at in strategy.attack_types],
                    strategy.parameters,
                )
                self.metrics_collector.record_strategy_generation(
                    session_id, [at.value for at in strategy.attack_types]
                )

                # Update progress
                self._update_session_progress(session)
            else:
                LOG.info(f"No more strategies available for session {session_id}")

            return strategy

        except Exception as e:
            error_msg = f"Error generating strategy for session {session_id}: {e}"
            LOG.error(error_msg)
            session.error_message = error_msg
            return None

    def mark_strategy_tested(
        self,
        session_id: str,
        strategy: StrategyVariation,
        success_rate: Optional[float] = None,
        test_results: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Mark a strategy as tested and collect results.

        Args:
            session_id: ID of discovery session
            strategy: Strategy that was tested
            success_rate: Optional success rate (0.0 to 1.0)
            test_results: Optional additional test results

        Raises:
            ValueError: If session ID not found
        """
        if session_id not in self.active_sessions:
            raise ValueError(f"Session {session_id} not found")

        session = self.active_sessions[session_id]

        try:
            # Mark strategy as tested in diversifier
            session.strategy_diversifier.mark_strategy_tested(strategy, success_rate)

            # Collect results if provided
            if test_results and session.results_collector:
                session.results_collector.collect_result(test_results, ResultType.STRATEGY_TEST)

            # Update session tracking
            session.strategies_tested += 1
            session.current_strategy = None

            # Log strategy testing and record metrics
            test_duration_ms = test_results.get("duration_ms", 0.0) if test_results else 0.0
            success = success_rate is not None and success_rate > 0.5

            self.discovery_logger.log_strategy_tested(
                session_id,
                session.config.target_domain,
                strategy.name,
                success,
                test_duration_ms,
                test_results,
            )
            self.metrics_collector.record_strategy_test(
                session_id,
                success,
                test_duration_ms,
                [at.value for at in strategy.attack_types],
                strategy.parameters,
            )

            # Notify callbacks
            self._notify_callbacks(
                "strategy_tested",
                {
                    "session_id": session_id,
                    "strategy": strategy,
                    "success_rate": success_rate,
                    "test_results": test_results,
                },
            )

            # Update progress
            self._update_session_progress(session)

            LOG.info(
                f"Marked strategy {strategy.name} as tested for session {session_id} "
                f"(success_rate: {success_rate})"
            )

        except Exception as e:
            error_msg = f"Error marking strategy tested for session {session_id}: {e}"
            LOG.error(error_msg)
            session.error_message = error_msg

    def get_session_status(self, session_id: str) -> Dict[str, Any]:
        """
        Get current status of a discovery session.

        Args:
            session_id: ID of discovery session

        Returns:
            Dictionary containing session status information

        Raises:
            ValueError: If session ID not found
        """
        if session_id not in self.active_sessions:
            raise ValueError(f"Session {session_id} not found")

        session = self.active_sessions[session_id]

        # Get component status
        diversity_metrics = None
        collection_stats = None
        override_status = None

        if session.strategy_diversifier:
            diversity_metrics = session.strategy_diversifier.get_diversity_metrics()

        if session.results_collector:
            collection_stats = session.results_collector.get_collection_stats()

        if session.override_manager:
            override_status = session.override_manager.get_discovery_status()

        return {
            "session_id": session_id,
            "status": session.status.value,
            "target_domain": session.config.target_domain,
            "start_time": session.start_time.isoformat(),
            "end_time": session.end_time.isoformat() if session.end_time else None,
            "duration_seconds": session.duration_seconds,
            "strategies_tested": session.strategies_tested,
            "max_strategies": session.config.strategy.max_strategies,
            "current_strategy": session.current_strategy.name if session.current_strategy else None,
            "error_message": session.error_message,
            "diversity_metrics": diversity_metrics,
            "collection_stats": collection_stats,
            "override_status": override_status,
        }

    def list_active_sessions(self) -> List[Dict[str, Any]]:
        """
        List all active discovery sessions.

        Returns:
            List of session status dictionaries
        """
        return [self.get_session_status(session_id) for session_id in self.active_sessions.keys()]

    def pause_discovery(self, session_id: str) -> None:
        """
        Pause an active discovery session.

        Args:
            session_id: ID of session to pause

        Raises:
            ValueError: If session ID not found or session not active
        """
        if session_id not in self.active_sessions:
            raise ValueError(f"Session {session_id} not found")

        session = self.active_sessions[session_id]

        if session.status != DiscoveryStatus.ACTIVE:
            raise ValueError(f"Session {session_id} is not active (status: {session.status.value})")

        session.status = DiscoveryStatus.PAUSED
        LOG.info(f"Paused discovery session {session_id}")

    def resume_discovery(self, session_id: str) -> None:
        """
        Resume a paused discovery session.

        Args:
            session_id: ID of session to resume

        Raises:
            ValueError: If session ID not found or session not paused
        """
        if session_id not in self.active_sessions:
            raise ValueError(f"Session {session_id} not found")

        session = self.active_sessions[session_id]

        if session.status != DiscoveryStatus.PAUSED:
            raise ValueError(f"Session {session_id} is not paused (status: {session.status.value})")

        session.status = DiscoveryStatus.ACTIVE
        LOG.info(f"Resumed discovery session {session_id}")

    @contextmanager
    def discovery_session_context(self, config: DiscoveryConfig):
        """
        Context manager for discovery sessions with automatic cleanup.

        Args:
            config: Discovery configuration

        Usage:
            with controller.discovery_session_context(config) as session_id:
                # Run discovery operations
                strategy = controller.get_next_strategy(session_id)
        """
        session_id = None
        try:
            session_id = self.start_discovery(config)
            yield session_id
        finally:
            if session_id and session_id in self.active_sessions:
                try:
                    self.stop_discovery(session_id, "Context manager cleanup")
                except Exception as e:
                    LOG.error(f"Error during context cleanup for session {session_id}: {e}")

    def add_callback(self, event_type: str, callback: Callable) -> None:
        """
        Add a callback for discovery events.

        Args:
            event_type: Type of event ('session_started', 'session_completed', 'session_error', 'strategy_tested')
            callback: Callback function to add
        """
        if event_type in self._global_callbacks:
            self._global_callbacks[event_type].append(callback)
            LOG.debug(f"Added callback for event type: {event_type}")
        else:
            raise ValueError(f"Unknown event type: {event_type}")

    def remove_callback(self, event_type: str, callback: Callable) -> None:
        """
        Remove a callback for discovery events.

        Args:
            event_type: Type of event
            callback: Callback function to remove
        """
        if event_type in self._global_callbacks:
            try:
                self._global_callbacks[event_type].remove(callback)
                LOG.debug(f"Removed callback for event type: {event_type}")
            except ValueError:
                LOG.warning(f"Callback not found for event type: {event_type}")
        else:
            raise ValueError(f"Unknown event type: {event_type}")

    def get_debug_info(
        self, session_id: str, debug_level: DebugLevel = DebugLevel.BASIC
    ) -> Dict[str, Any]:
        """
        Get debug information for a discovery session.

        Args:
            session_id: ID of discovery session
            debug_level: Level of detail to include

        Returns:
            Dictionary containing debug information

        Raises:
            ValueError: If session ID not found
        """
        if session_id not in self.active_sessions:
            raise ValueError(f"Session {session_id} not found")

        session = self.active_sessions[session_id]

        # Capture current debug snapshot
        components = {
            "domain_filter": session.domain_filter,
            "strategy_diversifier": session.strategy_diversifier,
            "results_collector": session.results_collector,
            "override_manager": session.override_manager,
        }

        snapshot = self.debugger.capture_debug_snapshot(
            session_id=session_id,
            target_domain=session.config.target_domain,
            session_status=session.status.value,
            session_duration_seconds=session.duration_seconds,
            strategies_tested=session.strategies_tested,
            current_strategy=session.current_strategy.name if session.current_strategy else None,
            debug_level=debug_level,
            components=components,
        )

        # Generate issue analysis
        issue_analysis = self.debugger.analyze_session_issues(session_id)

        return {
            "current_snapshot": snapshot.to_dict(),
            "issue_analysis": issue_analysis,
            "session_info": self.get_session_status(session_id),
        }

    def export_session_debug_data(self, session_id: str) -> str:
        """
        Export comprehensive debug data for a session.

        Args:
            session_id: ID of discovery session

        Returns:
            Path to exported debug file

        Raises:
            ValueError: If session ID not found
        """
        if session_id not in self.active_sessions:
            raise ValueError(f"Session {session_id} not found")

        return self.debugger.export_debug_data(session_id)

    def shutdown(self) -> List[DiscoveryReport]:
        """
        Shutdown the controller and stop all active sessions.

        Returns:
            List of final reports from stopped sessions
        """
        LOG.info("Shutting down DiscoveryController")

        reports = []
        session_ids = list(self.active_sessions.keys())

        for session_id in session_ids:
            try:
                report = self.stop_discovery(session_id, "Controller shutdown")
                reports.append(report)
            except Exception as e:
                LOG.error(f"Error stopping session {session_id} during shutdown: {e}")

        LOG.info(f"DiscoveryController shutdown complete ({len(reports)} sessions stopped)")
        return reports

    def _validate_config(self, config: DiscoveryConfig) -> None:
        """Validate discovery configuration"""
        try:
            # Use the comprehensive validation from the config system
            warnings = config.validate_full_configuration()

            # Log any warnings
            for warning in warnings:
                LOG.warning(f"Configuration warning: {warning}")

        except ValidationError as e:
            raise ValueError(f"Configuration validation failed: {e}") from e

    def _initialize_session_components(self, session: DiscoverySession) -> None:
        """Initialize components for a discovery session"""
        config = session.config

        # Initialize domain filter with session ID for logging integration
        session.domain_filter = DomainFilter(session_id=session.session_id)

        # Initialize strategy diversifier
        session.strategy_diversifier = StrategyDiversifier()

        # Initialize override manager if needed
        if config.integration.override_domain_rules:
            session.override_manager = OverrideManager()

        # Initialize results collector
        session.results_collector = ResultsCollector(session.domain_filter)

        LOG.debug(f"Initialized components for session {session.session_id}")

    def _configure_discovery_mode(self, session: DiscoverySession) -> None:
        """Configure discovery mode for a session"""
        config = session.config

        # Configure domain filtering
        session.domain_filter.configure_filter(config.target_domain, FilterMode.DISCOVERY)

        # Enable override mode if configured
        if session.override_manager and config.integration.override_domain_rules:
            session.override_manager.enable_discovery_mode(config.target_domain, session.session_id)

        # Start results collection session
        session.results_collector.start_collection_session(session.session_id, config.target_domain)

        LOG.debug(f"Configured discovery mode for session {session.session_id}")

    def _cleanup_session(self, session_id: str, reason: str) -> None:
        """Clean up a discovery session"""
        if session_id not in self.active_sessions:
            return

        session = self.active_sessions[session_id]

        try:
            # Disable override mode if active
            if session.override_manager and session.override_manager.is_override_active():
                session.override_manager.disable_discovery_mode()

            # End results collection
            if session.results_collector:
                session.results_collector.end_collection_session()

            # Clear domain filter
            if session.domain_filter:
                session.domain_filter.clear_rules()

            # Remove from active sessions
            del self.active_sessions[session_id]

            LOG.debug(f"Cleaned up session {session_id}: {reason}")

        except Exception as e:
            LOG.error(f"Error during session cleanup for {session_id}: {e}")

    def _generate_session_report(self, session: DiscoverySession) -> DiscoveryReport:
        """Generate final report for a discovery session"""
        if session.results_collector:
            return session.results_collector.generate_report()
        else:
            # Create minimal report if no results collector
            from core.results_collector import DiscoveryReport, AggregatedStats, CollectionStats

            return DiscoveryReport(
                session_id=session.session_id,
                target_domain=session.config.target_domain,
                start_time=session.start_time,
                end_time=session.end_time or datetime.now(),
                aggregated_stats=AggregatedStats(domain=session.config.target_domain),
                collection_stats=CollectionStats(),
            )

    def _update_session_progress(self, session: DiscoverySession) -> None:
        """Update session progress and notify callbacks"""
        if session.progress_callback:
            try:
                progress_data = {
                    "session_id": session.session_id,
                    "strategies_tested": session.strategies_tested,
                    "max_strategies": session.config.strategy.max_strategies,
                    "duration_seconds": session.duration_seconds,
                    "max_duration_seconds": session.config.strategy.max_duration_seconds,
                    "current_strategy": (
                        session.current_strategy.name if session.current_strategy else None
                    ),
                    "progress_percent": (
                        session.strategies_tested / session.config.strategy.max_strategies
                    )
                    * 100,
                }

                session.progress_callback(progress_data)

            except Exception as e:
                LOG.warning(f"Error in progress callback for session {session.session_id}: {e}")

    def _notify_callbacks(self, event_type: str, event_data: Dict[str, Any]) -> None:
        """Notify registered callbacks of an event"""
        callbacks = self._global_callbacks.get(event_type, [])

        for callback in callbacks:
            try:
                callback(event_data)
            except Exception as e:
                LOG.warning(f"Error in {event_type} callback: {e}")


# Global controller instance for easy access
_global_controller: Optional[DiscoveryController] = None


def get_controller() -> DiscoveryController:
    """Get or create global discovery controller instance."""
    global _global_controller
    if _global_controller is None:
        _global_controller = DiscoveryController()
    return _global_controller


def create_discovery_config(target_domain: str, **kwargs) -> DiscoveryConfig:
    """
    Convenience function to create discovery configuration.

    Args:
        target_domain: Target domain for discovery
        **kwargs: Additional configuration parameters

    Returns:
        DiscoveryConfig instance
    """
    # Extract strategy-related parameters and wrap them in StrategyConfig
    strategy_params = {}
    other_params = {}

    strategy_param_names = {
        "max_strategies",
        "max_duration_seconds",
        "strategy_timeout_seconds",
        "prefer_untested",
        "exclude_attack_types",
        "include_attack_types",
        "max_complexity_score",
        "min_complexity_score",
    }

    pcap_param_names = {
        "pcap_enabled",
        "max_packets",
        "max_seconds",
        "capture_filter",
        "output_directory",
        "compress_files",
        "auto_cleanup",
        "cleanup_after_hours",
    }

    results_param_names = {
        "collect_pcap_analysis",
        "collect_validation_results",
        "collect_performance_metrics",
        "max_result_history",
        "export_format",
        "auto_export",
        "export_directory",
    }

    integration_param_names = {
        "override_domain_rules",
        "restore_rules_on_completion",
        "backup_existing_config",
        "max_concurrent_sessions",
        "enable_monitoring",
        "monitoring_interval_seconds",
    }

    for key, value in kwargs.items():
        if key in strategy_param_names:
            strategy_params[key] = value
        elif key in pcap_param_names:
            # Handle pcap_enabled -> enabled mapping
            if key == "pcap_enabled":
                other_params.setdefault("pcap", {})["enabled"] = value
            else:
                other_params.setdefault("pcap", {})[key] = value
        elif key in results_param_names:
            other_params.setdefault("results", {})[key] = value
        elif key in integration_param_names:
            other_params.setdefault("integration", {})[key] = value
        else:
            other_params[key] = value

    # Create nested config objects
    if strategy_params:
        from core.discovery_config import StrategyConfig

        other_params["strategy"] = StrategyConfig(**strategy_params)

    if "pcap" in other_params:
        from core.discovery_config import PCAPConfig

        other_params["pcap"] = PCAPConfig(**other_params["pcap"])

    if "results" in other_params:
        from core.discovery_config import ResultsConfig

        other_params["results"] = ResultsConfig(**other_params["results"])

    if "integration" in other_params:
        from core.discovery_config import IntegrationConfig

        other_params["integration"] = IntegrationConfig(**other_params["integration"])

    return DiscoveryConfig(target_domain=target_domain, **other_params)


# Example usage and testing
if __name__ == "__main__":
    import asyncio

    # Create controller
    controller = DiscoveryController()

    # Create test configuration
    from core.discovery_config import StrategyConfig

    config = DiscoveryConfig(
        target_domain="example.com",
        strategy=StrategyConfig(max_strategies=10, max_duration_seconds=300),
    )

    # Test session management
    print("Testing discovery controller...")

    # Start session
    session_id = controller.start_discovery(config)
    print(f"Started session: {session_id}")

    # Get session status
    status = controller.get_session_status(session_id)
    print(f"Session status: {status['status']}")

    # Test strategy generation
    for i in range(3):
        strategy = controller.get_next_strategy(session_id)
        if strategy:
            print(f"Generated strategy {i+1}: {strategy.name}")

            # Simulate testing
            import random

            success_rate = random.uniform(0.0, 1.0)
            controller.mark_strategy_tested(session_id, strategy, success_rate)
            print(f"  Marked as tested (success: {success_rate:.2f})")
        else:
            print(f"No more strategies available")
            break

    # Stop session
    report = controller.stop_discovery(session_id)
    print(f"Session completed. Report generated for {report.target_domain}")
    print(f"  Duration: {report.duration_seconds:.1f}s")
    print(f"  Strategies tested: {report.aggregated_stats.total_tests}")

    print("Discovery controller test completed successfully!")
