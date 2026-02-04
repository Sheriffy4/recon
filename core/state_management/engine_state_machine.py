"""
Engine State Machine implementation for UnifiedBypassEngine refactoring.

This module provides a formal state machine with defined transitions,
thread-safe state management, and event emission for monitoring.

Feature: unified-engine-refactoring
Requirements: 10.1, 10.2, 10.3, 10.4, 10.5
"""

import threading
import time
from dataclasses import dataclass
from typing import Dict, Set, Optional, List, Callable, Any
from enum import Enum, auto

from core.unified_engine_models import EngineState, StateError


@dataclass
class StateTransitionEvent:
    """
    Event emitted when state transitions occur.

    Requirement 10.5: Observable state change events for monitoring.
    """

    from_state: EngineState
    to_state: EngineState
    timestamp: float
    context: Dict[str, Any]
    success: bool
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "from_state": self.from_state.name,
            "to_state": self.to_state.name,
            "timestamp": self.timestamp,
            "context": self.context,
            "success": self.success,
            "error": self.error,
        }


class EngineStateMachine:
    """
    Formal state machine for engine state management.

    Requirements:
    - 10.1: Formal state machine with defined transitions
    - 10.2: Reject invalid state transitions and maintain current state
    - 10.3: Transition to appropriate error states with recovery paths
    - 10.4: Thread-safe state management
    - 10.5: Observable state change events for monitoring
    """

    # Define valid state transitions (Requirement 10.1)
    VALID_TRANSITIONS: Dict[EngineState, Set[EngineState]] = {
        EngineState.IDLE: {EngineState.STARTING, EngineState.ERROR},
        EngineState.STARTING: {EngineState.RUNNING, EngineState.ERROR, EngineState.IDLE},
        EngineState.RUNNING: {EngineState.STOPPING, EngineState.ERROR},
        EngineState.STOPPING: {EngineState.IDLE, EngineState.ERROR},
        EngineState.ERROR: {EngineState.IDLE, EngineState.STARTING},  # Recovery paths
    }

    def __init__(self, initial_state: EngineState = EngineState.IDLE):
        """
        Initialize state machine.

        Args:
            initial_state: Initial state (default: IDLE)
        """
        # Thread-safe state management (Requirement 10.4)
        self._lock = threading.RLock()
        self._current_state = initial_state
        self._state_history: List[StateTransitionEvent] = []
        self._observers: List[Callable[[StateTransitionEvent], None]] = []

        # State transition tracking
        self._transition_count = 0
        self._last_transition_time = time.time()
        self._error_count = 0

        # Context for state transitions
        self._context: Dict[str, Any] = {}

    @property
    def current_state(self) -> EngineState:
        """
        Get current state (thread-safe).

        Requirement 10.4: Thread-safe state management.
        """
        with self._lock:
            return self._current_state

    @property
    def transition_count(self) -> int:
        """Get total number of transitions."""
        with self._lock:
            return self._transition_count

    @property
    def error_count(self) -> int:
        """Get total number of error transitions."""
        with self._lock:
            return self._error_count

    def can_transition_to(self, target_state: EngineState) -> bool:
        """
        Check if transition to target state is valid.

        Requirement 10.1: Formal state machine with defined transitions.

        Args:
            target_state: Target state to check

        Returns:
            True if transition is valid
        """
        with self._lock:
            return target_state in self.VALID_TRANSITIONS.get(self._current_state, set())

    def transition_to(
        self,
        target_state: EngineState,
        context: Optional[Dict[str, Any]] = None,
        force: bool = False,
    ) -> bool:
        """
        Attempt to transition to target state.

        Requirements:
        - 10.1: Formal state machine with defined transitions
        - 10.2: Reject invalid state transitions and maintain current state
        - 10.4: Thread-safe state management
        - 10.5: Observable state change events for monitoring

        Args:
            target_state: Target state
            context: Additional context for transition
            force: Force transition even if invalid (for error recovery)

        Returns:
            True if transition successful

        Raises:
            StateError: If transition is invalid and not forced
        """
        with self._lock:
            from_state = self._current_state
            timestamp = time.time()
            context = context or {}

            # Check if transition is valid (Requirement 10.2)
            if not force and not self.can_transition_to(target_state):
                error_msg = f"Invalid transition from {from_state.name} to {target_state.name}"

                # Create failed transition event
                event = StateTransitionEvent(
                    from_state=from_state,
                    to_state=target_state,
                    timestamp=timestamp,
                    context=context,
                    success=False,
                    error=error_msg,
                )

                # Notify observers of failed transition
                self._notify_observers(event)

                # Add to history
                self._state_history.append(event)

                # Reject invalid transition (Requirement 10.2)
                raise StateError(
                    error_msg,
                    context={"from_state": from_state.name, "to_state": target_state.name},
                )

            # Perform transition
            self._current_state = target_state
            self._transition_count += 1
            self._last_transition_time = timestamp

            # Track error transitions
            if target_state == EngineState.ERROR:
                self._error_count += 1

            # Update context
            self._context.update(context)

            # Create successful transition event (Requirement 10.5)
            event = StateTransitionEvent(
                from_state=from_state,
                to_state=target_state,
                timestamp=timestamp,
                context=context.copy(),
                success=True,
            )

            # Add to history
            self._state_history.append(event)

            # Notify observers (Requirement 10.5)
            self._notify_observers(event)

            return True

    def transition_to_error(
        self, error_message: str, context: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Transition to error state with error information.

        Requirement 10.3: Transition to appropriate error states with recovery paths.

        Args:
            error_message: Error description
            context: Additional error context

        Returns:
            True if transition successful
        """
        error_context = context or {}
        error_context["error_message"] = error_message
        error_context["error_timestamp"] = time.time()

        return self.transition_to(EngineState.ERROR, error_context, force=True)

    def recover_from_error(self, target_state: EngineState = EngineState.IDLE) -> bool:
        """
        Recover from error state.

        Requirement 10.3: Recovery paths from error states.

        Args:
            target_state: Target recovery state

        Returns:
            True if recovery successful

        Raises:
            StateError: If not in error state or invalid recovery target
        """
        with self._lock:
            if self._current_state != EngineState.ERROR:
                raise StateError(
                    "Can only recover from ERROR state", {"current_state": self._current_state.name}
                )

            # Check if recovery target is valid
            if target_state not in self.VALID_TRANSITIONS[EngineState.ERROR]:
                raise StateError(
                    f"Invalid recovery target: {target_state.name}",
                    {"valid_targets": [s.name for s in self.VALID_TRANSITIONS[EngineState.ERROR]]},
                )

            return self.transition_to(target_state, {"recovery": True})

    def add_observer(self, observer: Callable[[StateTransitionEvent], None]) -> None:
        """
        Add state change observer.

        Requirement 10.5: Observable state change events for monitoring.

        Args:
            observer: Callback function for state changes
        """
        with self._lock:
            if observer not in self._observers:
                self._observers.append(observer)

    def remove_observer(self, observer: Callable[[StateTransitionEvent], None]) -> None:
        """
        Remove state change observer.

        Args:
            observer: Observer to remove
        """
        with self._lock:
            if observer in self._observers:
                self._observers.remove(observer)

    def get_state_history(self, limit: Optional[int] = None) -> List[StateTransitionEvent]:
        """
        Get state transition history.

        Args:
            limit: Maximum number of events to return

        Returns:
            List of state transition events
        """
        with self._lock:
            history = self._state_history.copy()
            if limit:
                history = history[-limit:]
            return history

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get state machine statistics.

        Returns:
            Dictionary with statistics
        """
        with self._lock:
            return {
                "current_state": self._current_state.name,
                "transition_count": self._transition_count,
                "error_count": self._error_count,
                "last_transition_time": self._last_transition_time,
                "uptime_seconds": time.time()
                - (self._state_history[0].timestamp if self._state_history else time.time()),
                "history_length": len(self._state_history),
                "observer_count": len(self._observers),
                "context": self._context.copy(),
            }

    def reset(self, initial_state: EngineState = EngineState.IDLE) -> None:
        """
        Reset state machine to initial state.

        Args:
            initial_state: State to reset to
        """
        with self._lock:
            old_state = self._current_state
            self._current_state = initial_state
            self._transition_count = 0
            self._error_count = 0
            self._last_transition_time = time.time()
            self._context.clear()

            # Create reset event
            event = StateTransitionEvent(
                from_state=old_state,
                to_state=initial_state,
                timestamp=time.time(),
                context={"reset": True},
                success=True,
            )

            # Clear history and add reset event
            self._state_history.clear()
            self._state_history.append(event)

            # Notify observers
            self._notify_observers(event)

    def _notify_observers(self, event: StateTransitionEvent) -> None:
        """
        Notify all observers of state change.

        Requirement 10.5: Observable state change events for monitoring.

        Args:
            event: State transition event
        """
        # Create a copy of observers to avoid issues with concurrent modification
        observers = self._observers.copy()

        for observer in observers:
            try:
                # Support both callable observers and IStateObserver interface
                if hasattr(observer, "on_state_change"):
                    observer.on_state_change(event)
                elif callable(observer):
                    observer(event)
                else:
                    raise TypeError(
                        f"Observer {observer} is neither callable nor implements IStateObserver"
                    )
            except Exception as e:
                # Log observer errors but don't let them break state transitions
                import logging

                logging.getLogger(__name__).error(f"State observer error: {e}", exc_info=True)

    def __str__(self) -> str:
        """String representation of state machine."""
        return f"EngineStateMachine(state={self._current_state.name}, transitions={self._transition_count})"

    def __repr__(self) -> str:
        """Detailed representation of state machine."""
        return (
            f"EngineStateMachine(current_state={self._current_state.name}, "
            f"transition_count={self._transition_count}, "
            f"error_count={self._error_count}, "
            f"observers={len(self._observers)})"
        )
