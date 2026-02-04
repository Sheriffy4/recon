"""
Enhanced data models for the refactored Attack Registry system.

This module provides improved data models that extend the original
metadata models with additional functionality needed for the
refactored architecture.
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
from datetime import datetime
from enum import Enum

# Import original models for compatibility
from ..metadata import (
    AttackMetadata,
    ValidationResult,
    RegistrationPriority,
    AttackExecutionContext,
    AttackCategories,
    AttackParameterTypes,
    SpecialParameterValues,
    FoolingMethods,
    create_attack_metadata,
)

# Re-export original models
__all__ = [
    "AttackMetadata",
    "ValidationResult",
    "RegistrationPriority",
    "AttackExecutionContext",
    "AttackCategories",
    "AttackParameterTypes",
    "SpecialParameterValues",
    "FoolingMethods",
    "create_attack_metadata",
    "AttackEntry",
    "RegistrationResult",
    "ComponentStatus",
    "RegistryStats",
    "LoadingStats",
    "ValidationConfig",
    "LazyLoadingConfig",
]


@dataclass
class AttackEntry:
    """
    Enhanced attack entry with additional tracking capabilities.

    This extends the original AttackEntry with better support for:
    - Component isolation
    - Performance tracking
    - Usage statistics
    - Detailed audit trails
    """

    attack_type: str
    """Canonical attack type identifier"""

    handler: Callable
    """Attack handler function"""

    metadata: AttackMetadata
    """Attack metadata"""

    priority: RegistrationPriority
    """Registration priority"""

    source_module: str
    """Source module path"""

    registration_time: datetime
    """Registration timestamp"""

    is_canonical: bool = True
    """Whether this is a canonical entry (not an alias)"""

    is_alias_of: Optional[str] = None
    """Reference to canonical attack if this is an alias"""

    promotion_history: List[Dict[str, Any]] = field(default_factory=list)
    """History of promotions and replacements"""

    performance_data: Dict[str, Any] = field(default_factory=dict)
    """Performance metrics and statistics"""

    usage_stats: Dict[str, int] = field(default_factory=dict)
    """Usage statistics (calls, successes, failures)"""

    last_accessed: Optional[datetime] = None
    """Last access timestamp"""

    component_info: Dict[str, Any] = field(default_factory=dict)
    """Information about which components created/modified this entry"""

    def update_access_time(self) -> None:
        """Update the last accessed timestamp."""
        self.last_accessed = datetime.now()

    def increment_usage(self, stat_name: str, count: int = 1) -> None:
        """
        Increment a usage statistic.

        Args:
            stat_name: Name of the statistic to increment
            count: Amount to increment by
        """
        self.usage_stats[stat_name] = self.usage_stats.get(stat_name, 0) + count

    def add_performance_data(self, key: str, value: Any) -> None:
        """
        Add performance data.

        Args:
            key: Performance metric key
            value: Performance metric value
        """
        self.performance_data[key] = value

    def record_promotion(self, promotion_info: Dict[str, Any]) -> None:
        """
        Record a promotion event.

        Args:
            promotion_info: Information about the promotion
        """
        promotion_record = {"timestamp": datetime.now(), **promotion_info}
        self.promotion_history.append(promotion_record)


@dataclass
class RegistrationResult:
    """
    Enhanced registration result with detailed component information.
    """

    success: bool
    """Whether registration was successful"""

    action: str
    """Action taken: 'registered', 'replaced', 'skipped', 'promoted'"""

    message: str
    """Detailed result message"""

    attack_type: Optional[str] = None
    """Attack type that was processed"""

    conflicts: List[str] = field(default_factory=list)
    """List of conflicts encountered"""

    previous_priority: Optional[RegistrationPriority] = None
    """Previous priority if replaced"""

    new_priority: Optional[RegistrationPriority] = None
    """New priority after operation"""

    component_actions: Dict[str, str] = field(default_factory=dict)
    """Actions taken by each component"""

    warnings: List[str] = field(default_factory=list)
    """Non-critical warnings"""

    processing_time: Optional[float] = None
    """Time taken to process registration"""

    def add_component_action(self, component: str, action: str) -> None:
        """
        Record an action taken by a component.

        Args:
            component: Component name
            action: Action description
        """
        self.component_actions[component] = action

    def add_warning(self, warning: str) -> None:
        """
        Add a warning message.

        Args:
            warning: Warning message
        """
        self.warnings.append(warning)


class ComponentStatus(Enum):
    """Status of registry components."""

    INITIALIZING = "initializing"
    READY = "ready"
    ERROR = "error"
    DISABLED = "disabled"


@dataclass
class RegistryStats:
    """
    Statistics about the registry state.
    """

    total_attacks: int = 0
    """Total number of registered attacks"""

    attacks_by_category: Dict[str, int] = field(default_factory=dict)
    """Attack count by category"""

    attacks_by_priority: Dict[str, int] = field(default_factory=dict)
    """Attack count by priority"""

    total_aliases: int = 0
    """Total number of aliases"""

    component_status: Dict[str, ComponentStatus] = field(default_factory=dict)
    """Status of each component"""

    initialization_time: Optional[float] = None
    """Time taken to initialize registry"""

    last_updated: datetime = field(default_factory=datetime.now)
    """Last update timestamp"""

    def update_component_status(self, component: str, status: ComponentStatus) -> None:
        """
        Update component status.

        Args:
            component: Component name
            status: New status
        """
        self.component_status[component] = status
        self.last_updated = datetime.now()


@dataclass
class LoadingStats:
    """
    Statistics about module loading operations.
    """

    total_modules_discovered: int = 0
    """Total modules discovered"""

    modules_loaded: int = 0
    """Modules successfully loaded"""

    modules_failed: int = 0
    """Modules that failed to load"""

    loading_times: Dict[str, float] = field(default_factory=dict)
    """Loading time per module"""

    cache_hits: int = 0
    """Cache hit count"""

    cache_misses: int = 0
    """Cache miss count"""

    last_discovery_time: Optional[datetime] = None
    """Last discovery operation timestamp"""

    def record_loading_time(self, module: str, time_taken: float) -> None:
        """
        Record loading time for a module.

        Args:
            module: Module name
            time_taken: Time taken to load
        """
        self.loading_times[module] = time_taken

    def increment_cache_hit(self) -> None:
        """Increment cache hit counter."""
        self.cache_hits += 1

    def increment_cache_miss(self) -> None:
        """Increment cache miss counter."""
        self.cache_misses += 1

    @property
    def cache_hit_rate(self) -> float:
        """Calculate cache hit rate."""
        total = self.cache_hits + self.cache_misses
        return self.cache_hits / total if total > 0 else 0.0


@dataclass
class ValidationConfig:
    """
    Configuration for parameter validation.
    """

    strict_mode: bool = False
    """Enable strict validation mode"""

    allow_unknown_params: bool = True
    """Allow parameters not in metadata"""

    validate_param_types: bool = True
    """Validate parameter types"""

    validate_param_ranges: bool = True
    """Validate parameter value ranges"""

    custom_validators: Dict[str, Callable] = field(default_factory=dict)
    """Custom validation functions"""

    def add_custom_validator(self, param_name: str, validator: Callable[[Any], bool]) -> None:
        """
        Add a custom validator for a parameter.

        Args:
            param_name: Parameter name
            validator: Validation function
        """
        self.custom_validators[param_name] = validator


@dataclass
class LazyLoadingConfig:
    """
    Configuration for lazy loading behavior.
    """

    enabled: bool = False
    """Enable lazy loading"""

    preload_critical: bool = True
    """Preload critical attacks"""

    cache_size: int = 50
    """Module cache size"""

    discovery_timeout: float = 5.0
    """Discovery operation timeout"""

    critical_attacks: List[str] = field(default_factory=list)
    """List of critical attacks to preload"""

    excluded_paths: List[str] = field(default_factory=list)
    """Paths to exclude from discovery"""

    def add_critical_attack(self, attack_type: str) -> None:
        """
        Add an attack to the critical list.

        Args:
            attack_type: Attack type to mark as critical
        """
        if attack_type not in self.critical_attacks:
            self.critical_attacks.append(attack_type)

    def is_critical(self, attack_type: str) -> bool:
        """
        Check if an attack is marked as critical.

        Args:
            attack_type: Attack type to check

        Returns:
            True if attack is critical
        """
        return attack_type in self.critical_attacks
