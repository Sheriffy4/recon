"""
Refactored Attack Registry Components.

This package contains the refactored components of the AttackRegistry:
- RegistryConfig: Centralized configuration management
- AttackAliasManager: Alias management and name resolution
- AttackParameterValidator: Parameter validation logic
- PriorityManager: Priority and conflict management
- LazyLoadingManager: Lazy loading of external modules
- AttackHandlerFactory: Handler creation factory
- AttackRegistry: Main registry class (refactored)
"""

from .config import RegistryConfig, DEFAULT_CONFIG
from .alias_manager import AttackAliasManager
from .parameter_validator import AttackParameterValidator
from .lazy_loading_manager import LazyLoadingManager
from .handler_factory import AttackHandlerFactory
from .priority_manager import PriorityManager
from .decorator import (
    register_attack,
    process_pending_registrations,
    get_pending_registrations,
    clear_pending_registrations,
)
from .models import (
    AttackEntry,
    AttackMetadata,
    ValidationResult,
    RegistrationResult,
    RegistrationPriority,
    AttackExecutionContext,
    ComponentStatus,
    RegistryStats,
    LoadingStats,
    ValidationConfig,
    LazyLoadingConfig,
)
from .interfaces import (
    IAliasManager,
    IParameterValidator,
    IPriorityManager,
    ILazyLoadingManager,
    IHandlerFactory,
    IAttackRegistry,
    BaseRegistryComponent,
    RegistryComponentError,
    ConfigurationError,
    ValidationError,
    LoadingError,
    RegistrationError,
)

__all__ = [
    # Configuration
    "RegistryConfig",
    "DEFAULT_CONFIG",
    # Components
    "AttackAliasManager",
    "AttackParameterValidator",
    "PriorityManager",
    "LazyLoadingManager",
    "AttackHandlerFactory",
    # Decorator
    "register_attack",
    "process_pending_registrations",
    "get_pending_registrations",
    "clear_pending_registrations",
    # Data Models
    "AttackEntry",
    "AttackMetadata",
    "ValidationResult",
    "RegistrationResult",
    "RegistrationPriority",
    "AttackExecutionContext",
    "ComponentStatus",
    "RegistryStats",
    "LoadingStats",
    "ValidationConfig",
    "LazyLoadingConfig",
    # Interfaces
    "IAliasManager",
    "IParameterValidator",
    "IPriorityManager",
    "ILazyLoadingManager",
    "IHandlerFactory",
    "IAttackRegistry",
    "BaseRegistryComponent",
    # Exceptions
    "RegistryComponentError",
    "ConfigurationError",
    "ValidationError",
    "LoadingError",
    "RegistrationError",
]
