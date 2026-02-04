"""
State management system for UnifiedBypassEngine refactoring.

This module provides thread-safe state management with formal state machine
transitions, event emission, and validation.

Feature: unified-engine-refactoring
Requirements: 10.1, 10.2, 10.3, 10.4, 10.5
"""

from .engine_state_machine import EngineStateMachine, StateTransitionEvent
from .state_observer import (
    StateObserver,
    IStateObserver,
    LoggingStateObserver,
    MetricsStateObserver,
    CallbackStateObserver,
)

__all__ = [
    "EngineStateMachine",
    "StateTransitionEvent",
    "StateObserver",
    "IStateObserver",
    "LoggingStateObserver",
    "MetricsStateObserver",
    "CallbackStateObserver",
]
