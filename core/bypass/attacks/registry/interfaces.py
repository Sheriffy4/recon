"""
Base interfaces and protocols for the refactored Attack Registry system.

This module defines the core interfaces that all registry components
must implement, ensuring consistent behavior and enabling dependency
injection for testing.
"""

from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional, Protocol
from .models import (
    AttackEntry,
    AttackMetadata,
    ValidationResult,
    RegistrationResult,
    RegistrationPriority,
    RegistryStats,
)


class IAliasManager(Protocol):
    """Interface for alias management components."""

    def register_alias(self, alias: str, canonical_name: str) -> bool:
        """Register an alias for an attack."""
        ...

    def resolve_name(self, name: str) -> str:
        """Resolve alias to canonical name."""
        ...

    def get_aliases(self, canonical_name: str) -> List[str]:
        """Get all aliases for an attack."""
        ...

    def is_alias(self, name: str) -> bool:
        """Check if name is an alias."""
        ...

    def get_all_names(self, canonical_name: str) -> List[str]:
        """Get all names (canonical + aliases)."""
        ...

    def validate_alias_conflicts(self) -> List[str]:
        """Check for alias conflicts."""
        ...


class IParameterValidator(Protocol):
    """Interface for parameter validation components."""

    def validate_parameters(
        self, attack_metadata: AttackMetadata, params: Dict[str, Any]
    ) -> ValidationResult:
        """Validate attack parameters."""
        ...

    def register_validation_rule(self, param_name: str, validator: Callable[[Any], bool]) -> None:
        """Register custom validation rule."""
        ...


class IPriorityManager(Protocol):
    """Interface for priority and conflict management."""

    def handle_registration_conflict(
        self,
        attack_type: str,
        existing_entry: AttackEntry,
        new_handler: Callable,
        new_metadata: AttackMetadata,
        new_priority: RegistrationPriority,
        source_module: str,
    ) -> RegistrationResult:
        """Handle registration conflicts."""
        ...

    def can_replace(
        self, existing_priority: RegistrationPriority, new_priority: RegistrationPriority
    ) -> bool:
        """Check if replacement is allowed."""
        ...

    def record_promotion(self, attack_type: str, promotion_info: Dict[str, Any]) -> None:
        """Record promotion event."""
        ...

    def get_promotion_history(self, attack_type: str) -> List[Dict[str, Any]]:
        """Get promotion history."""
        ...


class ILazyLoadingManager(Protocol):
    """Interface for lazy loading management."""

    def discover_modules(self) -> Dict[str, str]:
        """Discover available modules."""
        ...

    def load_module_on_demand(self, module_path: str) -> bool:
        """Load module on demand."""
        ...

    def ensure_attack_loaded(self, attack_type: str) -> bool:
        """Ensure attack is loaded."""
        ...

    def get_loading_stats(self) -> Dict[str, Any]:
        """Get loading statistics."""
        ...

    def preload_critical_attacks(self, attack_types: List[str]) -> None:
        """Preload critical attacks."""
        ...

    def clear_cache(self) -> None:
        """Clear module cache."""
        ...


class IHandlerFactory(Protocol):
    """Interface for attack handler creation."""

    def create_handler(self, attack_type: str, metadata: AttackMetadata) -> Callable:
        """Create handler for attack."""
        ...

    def register_handler_builder(self, attack_type: str, builder: Callable) -> None:
        """Register handler builder."""
        ...


class IAttackRegistry(Protocol):
    """Interface for the main attack registry."""

    def register_attack(
        self,
        attack_type: str,
        handler: Callable,
        metadata: AttackMetadata,
        priority: RegistrationPriority = RegistrationPriority.NORMAL,
    ) -> RegistrationResult:
        """Register an attack."""
        ...

    def get_attack_handler(self, attack_type: str) -> Optional[Callable]:
        """Get attack handler."""
        ...

    def get_attack_metadata(self, attack_type: str) -> Optional[AttackMetadata]:
        """Get attack metadata."""
        ...

    def validate_parameters(self, attack_type: str, params: Dict[str, Any]) -> ValidationResult:
        """Validate attack parameters."""
        ...

    def list_attacks(self, category: Optional[str] = None, enabled_only: bool = False) -> List[str]:
        """List available attacks."""
        ...

    def get_registry_stats(self) -> RegistryStats:
        """Get registry statistics."""
        ...


class BaseRegistryComponent(ABC):
    """
    Base class for registry components.

    Provides common functionality for all registry components:
    - Configuration management
    - Logging setup
    - Error handling
    - Status tracking
    """

    def __init__(self, config: Any, logger_name: str):
        """
        Initialize base component.

        Args:
            config: Component configuration
            logger_name: Logger name for this component
        """
        self.config = config
        self.logger = config.get_logger(logger_name)
        self._status = "initializing"
        self._errors: List[str] = []

    @property
    def status(self) -> str:
        """Get component status."""
        return self._status

    @property
    def errors(self) -> List[str]:
        """Get component errors."""
        return self._errors.copy()

    def _set_status(self, status: str) -> None:
        """Set component status."""
        self._status = status
        self.logger.debug(f"Component status changed to: {status}")

    def _add_error(self, error: str) -> None:
        """Add an error to the error list."""
        self._errors.append(error)
        self.logger.error(error)
        if self._status != "error":
            self._set_status("error")

    def _clear_errors(self) -> None:
        """Clear all errors."""
        self._errors.clear()

    @abstractmethod
    def initialize(self) -> bool:
        """
        Initialize the component.

        Returns:
            True if initialization successful
        """
        pass

    def is_ready(self) -> bool:
        """Check if component is ready for use."""
        return self._status == "ready"

    def has_errors(self) -> bool:
        """Check if component has errors."""
        return len(self._errors) > 0


class RegistryComponentError(Exception):
    """Base exception for registry component errors."""

    def __init__(self, component: str, message: str):
        self.component = component
        self.message = message
        super().__init__(f"{component}: {message}")


class ConfigurationError(RegistryComponentError):
    """Configuration-related errors."""

    pass


class ValidationError(RegistryComponentError):
    """Validation-related errors."""

    pass


class LoadingError(RegistryComponentError):
    """Module loading errors."""

    pass


class RegistrationError(RegistryComponentError):
    """Attack registration errors."""

    pass
