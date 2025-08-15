# recon/core/bypass/safety/exceptions.py

"""
Safety framework exceptions for the modernized bypass engine.
"""


class SafetyError(Exception):
    """Base exception for safety framework errors."""
    
    def __init__(self, message: str, attack_id: str = None, context: dict = None):
        super().__init__(message)
        self.attack_id = attack_id
        self.context = context or {}


class ResourceLimitExceededError(SafetyError):
    """Raised when attack execution exceeds resource limits."""
    
    def __init__(self, message: str, resource_type: str, limit_value: float, 
                 actual_value: float, attack_id: str = None):
        super().__init__(message, attack_id)
        self.resource_type = resource_type
        self.limit_value = limit_value
        self.actual_value = actual_value


class AttackTimeoutError(SafetyError):
    """Raised when attack execution times out."""
    
    def __init__(self, message: str, timeout_seconds: float, attack_id: str = None):
        super().__init__(message, attack_id)
        self.timeout_seconds = timeout_seconds


class SandboxViolationError(SafetyError):
    """Raised when attack violates sandbox constraints."""
    
    def __init__(self, message: str, violation_type: str, attack_id: str = None):
        super().__init__(message, attack_id)
        self.violation_type = violation_type


class EmergencyStopError(SafetyError):
    """Raised when emergency stop is triggered."""
    
    def __init__(self, message: str, stop_reason: str, attack_id: str = None):
        super().__init__(message, attack_id)
        self.stop_reason = stop_reason


class AttackValidationError(SafetyError):
    """Raised when attack fails safety validation."""
    
    def __init__(self, message: str, validation_failures: list, attack_id: str = None):
        super().__init__(message, attack_id)
        self.validation_failures = validation_failures