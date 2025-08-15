# recon/core/bypass/modes/exceptions.py
"""
Exceptions for mode management system.
"""

try:
    from ..exceptions import BypassError
except ImportError:
    # Fallback if parent exceptions not available
    class BypassError(Exception):
        """Base exception for bypass system."""
        pass


class ModeError(BypassError):
    """Base exception for mode-related errors."""
    pass


class ModeTransitionError(ModeError):
    """Raised when mode transition fails."""
    
    def __init__(self, from_mode: str, to_mode: str, reason: str):
        self.from_mode = from_mode
        self.to_mode = to_mode
        self.reason = reason
        super().__init__(f"Failed to transition from {from_mode} to {to_mode}: {reason}")


class CapabilityDetectionError(ModeError):
    """Raised when capability detection fails."""
    pass


class UnsupportedModeError(ModeError):
    """Raised when trying to use an unsupported mode."""
    pass


class ModeNotAvailableError(ModeError):
    """Raised when requested mode is not available."""
    pass