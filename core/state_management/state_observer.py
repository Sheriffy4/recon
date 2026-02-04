"""
State observer interfaces and implementations for state management system.

This module provides observer pattern implementation for monitoring
state changes in the engine state machine.

Feature: unified-engine-refactoring
Requirements: 10.5
"""

import logging
import time
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

from .engine_state_machine import StateTransitionEvent


class IStateObserver(ABC):
    """
    Interface for state change observers.

    Requirement 10.5: Observable state change events for monitoring.
    """

    @abstractmethod
    def on_state_change(self, event: StateTransitionEvent) -> None:
        """
        Handle state change event.

        Args:
            event: State transition event
        """
        pass


@dataclass
class StateObserverMetrics:
    """Metrics for state observer."""

    events_processed: int = 0
    errors_count: int = 0
    last_event_time: Optional[float] = None
    processing_times: List[float] = field(default_factory=list)

    def add_processing_time(self, duration: float) -> None:
        """Add processing time measurement."""
        self.processing_times.append(duration)
        # Keep only last 100 measurements
        if len(self.processing_times) > 100:
            self.processing_times = self.processing_times[-100:]

    def get_average_processing_time(self) -> float:
        """Get average processing time."""
        if not self.processing_times:
            return 0.0
        return sum(self.processing_times) / len(self.processing_times)


class StateObserver(IStateObserver):
    """
    Base implementation of state observer with logging and metrics.

    Requirement 10.5: Observable state change events for monitoring.
    """

    def __init__(self, name: str, logger: Optional[logging.Logger] = None):
        """
        Initialize state observer.

        Args:
            name: Observer name for identification
            logger: Logger instance (creates default if None)
        """
        self.name = name
        self.logger = logger or logging.getLogger(f"{__name__}.{name}")
        self.metrics = StateObserverMetrics()
        self.enabled = True

    def on_state_change(self, event: StateTransitionEvent) -> None:
        """
        Handle state change event with metrics and error handling.

        Args:
            event: State transition event
        """
        if not self.enabled:
            return

        start_time = time.time()

        try:
            self._handle_state_change(event)
            self.metrics.events_processed += 1

        except Exception as e:
            self.metrics.errors_count += 1
            self.logger.error(f"Error in state observer {self.name}: {e}", exc_info=True)

        finally:
            processing_time = time.time() - start_time
            self.metrics.add_processing_time(processing_time)
            self.metrics.last_event_time = time.time()

    def _handle_state_change(self, event: StateTransitionEvent) -> None:
        """
        Override this method to implement specific state change handling.

        Args:
            event: State transition event
        """
        self.logger.info(f"State transition: {event.from_state.name} -> {event.to_state.name}")

        if not event.success:
            self.logger.warning(f"Failed state transition: {event.error}")

        if event.to_state.name == "ERROR":
            self.logger.error(f"Engine entered error state: {event.context}")

    def get_metrics(self) -> Dict[str, Any]:
        """
        Get observer metrics.

        Returns:
            Dictionary with metrics
        """
        return {
            "name": self.name,
            "enabled": self.enabled,
            "events_processed": self.metrics.events_processed,
            "errors_count": self.metrics.errors_count,
            "last_event_time": self.metrics.last_event_time,
            "average_processing_time": self.metrics.get_average_processing_time(),
            "error_rate": self.metrics.errors_count / max(self.metrics.events_processed, 1),
        }

    def enable(self) -> None:
        """Enable observer."""
        self.enabled = True
        self.logger.info(f"State observer {self.name} enabled")

    def disable(self) -> None:
        """Disable observer."""
        self.enabled = False
        self.logger.info(f"State observer {self.name} disabled")


class LoggingStateObserver(StateObserver):
    """
    State observer that logs all state transitions.

    Requirement 10.5: Observable state change events for monitoring.
    """

    def __init__(self, logger: Optional[logging.Logger] = None, log_level: int = logging.INFO):
        """
        Initialize logging observer.

        Args:
            logger: Logger instance
            log_level: Log level for state transitions
        """
        super().__init__("LoggingObserver", logger)
        self.log_level = log_level

    def _handle_state_change(self, event: StateTransitionEvent) -> None:
        """Log state change with appropriate level."""
        if event.success:
            self.logger.log(
                self.log_level,
                f"State transition: {event.from_state.name} -> {event.to_state.name} "
                f"(context: {event.context})",
            )
        else:
            self.logger.error(
                f"Failed state transition: {event.from_state.name} -> {event.to_state.name} "
                f"Error: {event.error} (context: {event.context})"
            )


class MetricsStateObserver(StateObserver):
    """
    State observer that collects detailed metrics about state transitions.

    Requirement 10.5: Observable state change events for monitoring.
    """

    def __init__(self):
        """Initialize metrics observer."""
        super().__init__("MetricsObserver")
        self.state_counts: Dict[str, int] = {}
        self.transition_counts: Dict[str, int] = {}
        self.error_transitions: List[StateTransitionEvent] = []
        self.transition_durations: Dict[str, List[float]] = {}
        self.last_state_times: Dict[str, float] = {}

    def _handle_state_change(self, event: StateTransitionEvent) -> None:
        """Collect metrics from state change."""
        # Count states
        to_state = event.to_state.name
        self.state_counts[to_state] = self.state_counts.get(to_state, 0) + 1

        # Count transitions
        transition_key = f"{event.from_state.name}->{event.to_state.name}"
        self.transition_counts[transition_key] = self.transition_counts.get(transition_key, 0) + 1

        # Track error transitions
        if not event.success or event.to_state.name == "ERROR":
            self.error_transitions.append(event)
            # Keep only last 100 error transitions
            if len(self.error_transitions) > 100:
                self.error_transitions = self.error_transitions[-100:]

        # Track state durations
        from_state = event.from_state.name
        if from_state in self.last_state_times:
            duration = event.timestamp - self.last_state_times[from_state]
            if from_state not in self.transition_durations:
                self.transition_durations[from_state] = []
            self.transition_durations[from_state].append(duration)
            # Keep only last 100 durations per state
            if len(self.transition_durations[from_state]) > 100:
                self.transition_durations[from_state] = self.transition_durations[from_state][-100:]

        self.last_state_times[to_state] = event.timestamp

    def get_detailed_metrics(self) -> Dict[str, Any]:
        """
        Get detailed metrics about state transitions.

        Returns:
            Dictionary with detailed metrics
        """
        base_metrics = self.get_metrics()

        # Calculate average durations
        avg_durations = {}
        for state, durations in self.transition_durations.items():
            if durations:
                avg_durations[state] = sum(durations) / len(durations)

        return {
            **base_metrics,
            "state_counts": self.state_counts.copy(),
            "transition_counts": self.transition_counts.copy(),
            "error_transition_count": len(self.error_transitions),
            "average_state_durations": avg_durations,
            "recent_errors": [e.to_dict() for e in self.error_transitions[-10:]],
        }


class CallbackStateObserver(StateObserver):
    """
    State observer that executes custom callbacks on state changes.

    Requirement 10.5: Observable state change events for monitoring.
    """

    def __init__(self, callback, name: str = "CallbackObserver"):
        """
        Initialize callback observer.

        Args:
            callback: Function to call on state changes
            name: Observer name
        """
        super().__init__(name)
        self.callback = callback

    def _handle_state_change(self, event: StateTransitionEvent) -> None:
        """Execute callback with state change event."""
        self.callback(event)
