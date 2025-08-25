"""
Mode transition management with safe fallback mechanisms.
"""
import logging
import time
from typing import Dict, Any, Optional, Callable, List
from dataclasses import dataclass
from enum import Enum
try:
    from core.bypass.modes.exceptions import ModeTransitionError, ModeNotAvailableError
    from core.bypass.modes.capability_detector import CapabilityDetector
except ImportError:
    from exceptions import ModeTransitionError, ModeNotAvailableError
    from capability_detector import CapabilityDetector
LOG = logging.getLogger(__name__)

class TransitionState(Enum):
    """States during mode transition."""
    IDLE = 'idle'
    PREPARING = 'preparing'
    TRANSITIONING = 'transitioning'
    VALIDATING = 'validating'
    COMPLETED = 'completed'
    FAILED = 'failed'
    ROLLING_BACK = 'rolling_back'

@dataclass
class TransitionContext:
    """Context information for mode transitions."""
    from_mode: str
    to_mode: str
    reason: str
    timestamp: float
    metadata: Dict[str, Any]
    rollback_data: Optional[Dict[str, Any]] = None

class ModeTransitionManager:
    """
    Manages safe transitions between operation modes.

    This class handles the complex process of switching between native and
    emulated modes, including validation, rollback, and error recovery.
    """

    def __init__(self, capability_detector: CapabilityDetector):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.capability_detector = capability_detector
        self.current_state = TransitionState.IDLE
        self.transition_history: List[TransitionContext] = []
        self.rollback_handlers: Dict[str, Callable] = {}
        self.validation_handlers: Dict[str, Callable] = {}

    def register_rollback_handler(self, mode: str, handler: Callable) -> None:
        """
        Register a rollback handler for a specific mode.

        Args:
            mode: Mode name
            handler: Callable that handles rollback for this mode
        """
        self.rollback_handlers[mode] = handler
        self.logger.debug(f'Registered rollback handler for mode: {mode}')

    def register_validation_handler(self, mode: str, handler: Callable) -> None:
        """
        Register a validation handler for a specific mode.

        Args:
            mode: Mode name
            handler: Callable that validates this mode is working
        """
        self.validation_handlers[mode] = handler
        self.logger.debug(f'Registered validation handler for mode: {mode}')

    def transition_to_mode(self, target_mode: str, current_mode: str, reason: str='Manual transition', metadata: Optional[Dict[str, Any]]=None) -> bool:
        """
        Perform a safe transition to the target mode.

        Args:
            target_mode: Mode to transition to
            current_mode: Current mode
            reason: Reason for transition
            metadata: Additional metadata

        Returns:
            True if transition successful

        Raises:
            ModeTransitionError: If transition fails
        """
        if self.current_state != TransitionState.IDLE:
            raise ModeTransitionError(current_mode, target_mode, f'Cannot transition while in state: {self.current_state.value}')
        context = TransitionContext(from_mode=current_mode, to_mode=target_mode, reason=reason, timestamp=time.time(), metadata=metadata or {})
        self.logger.info(f'Starting transition from {current_mode} to {target_mode}: {reason}')
        try:
            self._change_state(TransitionState.PREPARING)
            self._prepare_transition(context)
            self._change_state(TransitionState.TRANSITIONING)
            self._execute_transition(context)
            self._change_state(TransitionState.VALIDATING)
            if not self._validate_transition(context):
                raise ModeTransitionError(current_mode, target_mode, 'Transition validation failed')
            self._change_state(TransitionState.COMPLETED)
            self.transition_history.append(context)
            self.logger.info(f'Successfully transitioned to {target_mode}')
            return True
        except Exception as e:
            self.logger.error(f'Transition failed: {e}')
            self._change_state(TransitionState.FAILED)
            try:
                self._rollback_transition(context)
            except Exception as rollback_error:
                self.logger.error(f'Rollback also failed: {rollback_error}')
                raise ModeTransitionError(current_mode, target_mode, f'Transition failed and rollback failed: {e}, {rollback_error}')
            raise ModeTransitionError(current_mode, target_mode, str(e))
        finally:
            self._change_state(TransitionState.IDLE)

    def auto_fallback(self, current_mode: str, error: Exception, metadata: Optional[Dict[str, Any]]=None) -> Optional[str]:
        """
        Automatically fallback to a working mode when current mode fails.

        Args:
            current_mode: Current failing mode
            error: Error that triggered fallback
            metadata: Additional metadata

        Returns:
            New mode name if fallback successful, None otherwise
        """
        self.logger.warning(f'Auto-fallback triggered from {current_mode}: {error}')
        fallback_mode = self._determine_fallback_mode(current_mode)
        if not fallback_mode:
            self.logger.error('No suitable fallback mode available')
            return None
        try:
            fallback_metadata = metadata or {}
            fallback_metadata.update({'auto_fallback': True, 'original_error': str(error), 'original_mode': current_mode})
            success = self.transition_to_mode(fallback_mode, current_mode, f'Auto-fallback due to error: {error}', fallback_metadata)
            if success:
                self.logger.info(f'Successfully fell back to {fallback_mode}')
                return fallback_mode
            else:
                self.logger.error(f'Fallback to {fallback_mode} failed')
                return None
        except Exception as fallback_error:
            self.logger.error(f'Auto-fallback failed: {fallback_error}')
            return None

    def get_transition_history(self) -> List[Dict[str, Any]]:
        """
        Get the history of mode transitions.

        Returns:
            List of transition records
        """
        return [{'from_mode': ctx.from_mode, 'to_mode': ctx.to_mode, 'reason': ctx.reason, 'timestamp': ctx.timestamp, 'metadata': ctx.metadata} for ctx in self.transition_history]

    def _change_state(self, new_state: TransitionState) -> None:
        """Change the current transition state."""
        old_state = self.current_state
        self.current_state = new_state
        self.logger.debug(f'Transition state: {old_state.value} -> {new_state.value}')

    def _prepare_transition(self, context: TransitionContext) -> None:
        """Prepare for mode transition."""
        capabilities = self.capability_detector.detect_all_capabilities()
        if context.to_mode == 'native':
            if not self.capability_detector.is_native_mode_available():
                raise ModeNotAvailableError('Native mode not available')
        elif context.to_mode == 'emulated':
            if not self.capability_detector.is_emulated_mode_available():
                raise ModeNotAvailableError('Emulated mode not available')
        context.rollback_data = {'previous_mode': context.from_mode, 'preparation_time': time.time()}
        self.logger.debug(f'Transition preparation complete for {context.to_mode}')

    def _execute_transition(self, context: TransitionContext) -> None:
        """Execute the actual mode transition."""
        self.logger.debug(f'Executing transition to {context.to_mode}')
        time.sleep(0.1)
        self.logger.debug('Transition execution complete')

    def _validate_transition(self, context: TransitionContext) -> bool:
        """Validate that the transition was successful."""
        validator = self.validation_handlers.get(context.to_mode)
        if validator:
            try:
                result = validator()
                self.logger.debug(f'Validation result for {context.to_mode}: {result}')
                return result
            except Exception as e:
                self.logger.error(f'Validation failed for {context.to_mode}: {e}')
                return False
        else:
            self.logger.debug(f'No validator for {context.to_mode}, assuming success')
            return True

    def _rollback_transition(self, context: TransitionContext) -> None:
        """Rollback a failed transition."""
        self._change_state(TransitionState.ROLLING_BACK)
        rollback_handler = self.rollback_handlers.get(context.from_mode)
        if rollback_handler:
            try:
                rollback_handler(context.rollback_data)
                self.logger.info(f'Successfully rolled back to {context.from_mode}')
            except Exception as e:
                self.logger.error(f'Rollback handler failed: {e}')
                raise
        else:
            self.logger.warning(f'No rollback handler for {context.from_mode}')

    def _determine_fallback_mode(self, current_mode: str) -> Optional[str]:
        """Determine the best fallback mode."""
        if current_mode == 'native':
            if self.capability_detector.is_emulated_mode_available():
                return 'emulated'
            else:
                return 'compatibility'
        elif current_mode == 'emulated':
            return 'compatibility'
        elif current_mode == 'hybrid':
            if self.capability_detector.is_native_mode_available():
                return 'native'
            elif self.capability_detector.is_emulated_mode_available():
                return 'emulated'
            else:
                return 'compatibility'
        return None