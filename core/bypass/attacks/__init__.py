"""
Bypass Attacks Package - Unified Attack System

This package provides a centralized attack registry system with canonical implementations.

Architecture:
- Canonical implementations are in core/bypass/techniques/primitives.py
- All attacks are registered through the unified AttackRegistry
- External attacks are automatically discovered and registered
- Duplicate registrations are prevented through priority system

Canonical Attacks (from primitives.py):
- fakeddisorder: Fake packet + real parts in reverse order
- seqovl: Sequence overlap with fake packet
- multidisorder: Multiple split positions with disorder
- disorder/disorder2: Simple reordering without fake packet
- multisplit/split: Packet splitting at multiple/single positions
- fake: Race condition with fake packet

Usage:
    from core.bypass.attacks import get_attack_registry

    registry = get_attack_registry()
    handler = registry.get_attack_handler("fakeddisorder")
"""

import logging

LOG = logging.getLogger(__name__)

# Import core registry components
# The AttackRegistry automatically registers canonical implementations from primitives.py
# with CORE priority, ensuring they take precedence over any external implementations
from .attack_registry import (
    get_attack_registry,
    register_attack,
    AttackRegistry,
    AttackMetadata,
    ValidationResult,
    RegistrationPriority,
    AttackEntry,
    RegistrationResult,
    configure_lazy_loading,
    get_lazy_loading_config,
    clear_registry,
)

# Import registry components for advanced usage
from .registry import (
    RegistryConfig,
    DEFAULT_CONFIG,
    AttackAliasManager,
    AttackParameterValidator,
    LazyLoadingManager,
    AttackHandlerFactory,
    AttackExecutionContext,
    ComponentStatus,
    RegistryStats,
    LoadingStats,
    ValidationConfig,
    LazyLoadingConfig,
    # Interfaces
    IAliasManager,
    IParameterValidator,
    IPriorityManager,
    ILazyLoadingManager,
    IHandlerFactory,
    IAttackRegistry,
    BaseRegistryComponent,
    # Exceptions
    RegistryComponentError,
    ConfigurationError,
    ValidationError,
    LoadingError,
    RegistrationError,
)

from .module_loader import (
    load_optional_attack_modules as _load_optional_attack_modules,
    ensure_new_attacks_registered as _ensure_new_attacks_registered,
    verify_attack_loading as _verify_attack_loading,
)

# tcp_fragmentation.py has been removed - functionality migrated to primitives.py
# Unique features (window manipulation, TCP options modification) are now available
# as primitives.apply_window_manipulation() and primitives.apply_tcp_options_modification()

# Export main components for public API
__all__ = [
    # Core registry functions
    "get_attack_registry",
    "register_attack",
    "AttackRegistry",
    "configure_lazy_loading",
    "get_lazy_loading_config",
    "clear_registry",
    # Data models
    "AttackMetadata",
    "ValidationResult",
    "RegistrationPriority",
    "AttackEntry",
    "RegistrationResult",
    "AttackExecutionContext",
    "ComponentStatus",
    "RegistryStats",
    "LoadingStats",
    "ValidationConfig",
    "LazyLoadingConfig",
    # Registry components
    "RegistryConfig",
    "DEFAULT_CONFIG",
    "AttackAliasManager",
    "AttackParameterValidator",
    "LazyLoadingManager",
    "AttackHandlerFactory",
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

# Initialization Summary:
# - Canonical attacks from primitives.py are registered with CORE priority
# - External attack modules are loaded and registered with NORMAL priority
# - Duplicate registrations are automatically handled by priority system
# - All attacks are available through get_attack_registry()

LOG.info("Bypass attacks package initialized successfully")
LOG.info("Canonical implementations from primitives.py have CORE priority")
LOG.info("Use get_attack_registry() to access all registered attacks")

_load_optional_attack_modules()

_ensure_new_attacks_registered()
_verify_attack_loading()
