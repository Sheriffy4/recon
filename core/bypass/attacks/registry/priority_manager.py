"""
Priority management component for the Attack Registry system.

This module provides PriorityManager for handling attack registration
priorities, conflict resolution, and promotion history tracking.
"""

import logging
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from .models import (
    AttackEntry,
    AttackMetadata,
    RegistrationPriority,
    RegistrationResult,
    ValidationResult,
)
from .config import RegistryConfig


logger = logging.getLogger(__name__)


class PriorityManager:
    """
    Manages attack registration priorities and conflict resolution.

    This component handles:
    - Priority-based conflict resolution during registration
    - Promotion history tracking
    - Validation of promotion requests
    - Priority comparison logic

    The priority system follows this hierarchy:
    - CORE (highest): Built-in attacks that are fundamental
    - HIGH: Important external attacks
    - NORMAL: Standard attacks
    - LOW (lowest): Experimental or deprecated attacks
    """

    def __init__(self, config: Optional[RegistryConfig] = None):
        """
        Initialize the priority manager.

        Args:
            config: Registry configuration (uses default if None)
        """
        self.config = config or RegistryConfig()
        self.logger = self.config.get_logger(__name__)
        self._promotion_history: Dict[str, List[Dict[str, Any]]] = {}

    def handle_registration_conflict(
        self,
        attack_type: str,
        existing_entry: AttackEntry,
        new_handler: Callable,
        new_metadata: AttackMetadata,
        new_priority: RegistrationPriority,
        source_module: str,
    ) -> RegistrationResult:
        """
        Handle a registration conflict based on priority rules.

        Priority resolution logic:
        1. If new priority is higher - replace existing attack
        2. If priorities are equal - skip with warning
        3. If new priority is lower - skip with info message

        Args:
            attack_type: Type of attack being registered
            existing_entry: Current attack entry in registry
            new_handler: New attack handler function
            new_metadata: New attack metadata
            new_priority: Priority of new registration
            source_module: Module source of new attack

        Returns:
            RegistrationResult with conflict resolution outcome
        """
        # First, ensure we have the existing entry's history in our internal tracking
        if attack_type not in self._promotion_history and existing_entry.promotion_history:
            self._promotion_history[attack_type] = existing_entry.promotion_history.copy()

        existing_priority = existing_entry.priority

        if self.can_replace(existing_priority, new_priority):
            return self._handle_replacement(
                attack_type, existing_entry, new_handler, new_metadata, new_priority, source_module
            )
        elif new_priority.value == existing_priority.value:
            return self._handle_equal_priority(
                attack_type, existing_entry, new_priority, source_module
            )
        else:
            return self._handle_lower_priority(
                attack_type, existing_entry, new_priority, source_module
            )

    def can_replace(
        self, existing_priority: RegistrationPriority, new_priority: RegistrationPriority
    ) -> bool:
        """
        Check if an existing attack can be replaced based on priority.

        Args:
            existing_priority: Priority of existing attack
            new_priority: Priority of new attack

        Returns:
            True if replacement is allowed
        """
        return new_priority.value > existing_priority.value

    def record_promotion(self, attack_type: str, promotion_info: Dict[str, Any]) -> None:
        """
        Record a promotion event in the history.

        Args:
            attack_type: Attack type that was promoted
            promotion_info: Information about the promotion
        """
        if not self.config.enable_promotion_tracking:
            return

        if attack_type not in self._promotion_history:
            self._promotion_history[attack_type] = []

        # Add timestamp if not present
        if "timestamp" not in promotion_info:
            promotion_info["timestamp"] = datetime.now().isoformat()

        self._promotion_history[attack_type].append(promotion_info)

        # Limit history size
        max_history = self.config.max_promotion_history
        if len(self._promotion_history[attack_type]) > max_history:
            self._promotion_history[attack_type] = self._promotion_history[attack_type][
                -max_history:
            ]

        self.logger.debug(
            f"Recorded promotion for '{attack_type}': {promotion_info.get('action', 'unknown')}"
        )

    def get_promotion_history(self, attack_type: str) -> List[Dict[str, Any]]:
        """
        Get the promotion history for an attack.

        Args:
            attack_type: Attack type to get history for

        Returns:
            List of promotion records (empty if none)
        """
        import copy

        return copy.deepcopy(self._promotion_history.get(attack_type, []))

    def validate_promotion_request(
        self,
        attack_type: str,
        new_handler: Callable,
        existing_entry: AttackEntry,
        performance_data: Optional[Dict[str, Any]] = None,
    ) -> ValidationResult:
        """
        Validate a promotion request.

        Args:
            attack_type: Attack type to promote
            new_handler: Proposed new handler
            existing_entry: Current attack entry
            performance_data: Performance data supporting promotion

        Returns:
            ValidationResult with validation outcome
        """
        warnings = []

        # Check if handler is callable
        if not callable(new_handler):
            return ValidationResult(is_valid=False, error_message="New handler is not callable")

        # Warnings for CORE attacks
        if existing_entry.priority == RegistrationPriority.CORE:
            warnings.append("Promoting CORE attack requires careful consideration")

        # Check performance data
        if not performance_data:
            warnings.append("No performance data provided to justify promotion")
        elif isinstance(performance_data, dict):
            required_metrics = ["improvement_percent", "test_cases", "success_rate"]
            missing_metrics = [m for m in required_metrics if m not in performance_data]
            if missing_metrics:
                warnings.append(f"Missing recommended performance metrics: {missing_metrics}")

        # Check promotion frequency
        history = self.get_promotion_history(attack_type)
        if len(history) > 3:
            warnings.append("Attack has been promoted multiple times - consider stability")

        return ValidationResult(is_valid=True, warnings=warnings)

    def _handle_replacement(
        self,
        attack_type: str,
        existing_entry: AttackEntry,
        new_handler: Callable,
        new_metadata: AttackMetadata,
        new_priority: RegistrationPriority,
        source_module: str,
    ) -> RegistrationResult:
        """
        Handle replacement of existing attack with higher priority version.

        Args:
            attack_type: Attack type being replaced
            existing_entry: Current attack entry
            new_handler: New handler function
            new_metadata: New metadata
            new_priority: New priority
            source_module: Source module of new attack

        Returns:
            RegistrationResult for replacement
        """
        existing_priority = existing_entry.priority

        self.logger.info(
            f"Replacing attack '{attack_type}' (priority {existing_priority.name} -> {new_priority.name}) from {source_module}"
        )

        # Create promotion record
        promotion_info = {
            "timestamp": datetime.now().isoformat(),
            "action": "replaced_by_higher_priority",
            "old_priority": existing_priority.name,
            "new_priority": new_priority.name,
            "old_source": existing_entry.source_module,
            "new_source": source_module,
            "reason": f"Higher priority registration ({new_priority.name} > {existing_priority.name})",
        }

        # Record the promotion - this adds to the internal history
        self.record_promotion(attack_type, promotion_info)

        # Create new entry with updated promotion history
        # Get the current history (which now includes the new promotion)
        current_history = self.get_promotion_history(attack_type)

        new_entry = AttackEntry(
            attack_type=attack_type,
            handler=new_handler,
            metadata=new_metadata,
            priority=new_priority,
            source_module=source_module,
            registration_time=datetime.now(),
            is_canonical=True,
            promotion_history=current_history,  # Use current history from manager
            performance_data=existing_entry.performance_data or {},
        )

        # Handle alias conflicts
        conflicts = []
        for alias in new_metadata.aliases:
            # This would need to be handled by the alias manager
            # For now, just record potential conflicts
            conflicts.append(f"Alias '{alias}' may need reassignment")

        result = RegistrationResult(
            success=True,
            action="replaced",
            message=f"Replaced attack '{attack_type}' with higher priority version ({new_priority.name} > {existing_priority.name})",
            attack_type=attack_type,
            conflicts=conflicts,
            previous_priority=existing_priority,
            new_priority=new_priority,
        )

        result.add_component_action("PriorityManager", "replaced_higher_priority")
        return result

    def _handle_equal_priority(
        self,
        attack_type: str,
        existing_entry: AttackEntry,
        new_priority: RegistrationPriority,
        source_module: str,
    ) -> RegistrationResult:
        """
        Handle registration with equal priority (skip with warning).

        Args:
            attack_type: Attack type
            existing_entry: Current attack entry
            new_priority: New priority (equal to existing)
            source_module: Source module of new attack

        Returns:
            RegistrationResult for skipped registration
        """
        self.logger.warning(
            f"Skipping duplicate registration of '{attack_type}' with same priority {new_priority.name} from {source_module}"
        )

        result = RegistrationResult(
            success=False,
            action="skipped",
            message=f"Skipped duplicate attack '{attack_type}' (same priority {new_priority.name})",
            attack_type=attack_type,
            conflicts=[
                f"Attack already registered with same priority from {existing_entry.source_module}"
            ],
            previous_priority=existing_entry.priority,
            new_priority=new_priority,
        )

        result.add_component_action("PriorityManager", "skipped_equal_priority")
        return result

    def _handle_lower_priority(
        self,
        attack_type: str,
        existing_entry: AttackEntry,
        new_priority: RegistrationPriority,
        source_module: str,
    ) -> RegistrationResult:
        """
        Handle registration with lower priority (skip with info).

        Args:
            attack_type: Attack type
            existing_entry: Current attack entry
            new_priority: New priority (lower than existing)
            source_module: Source module of new attack

        Returns:
            RegistrationResult for skipped registration
        """
        existing_priority = existing_entry.priority

        self.logger.debug(
            f"Skipping registration of '{attack_type}' with lower priority {new_priority.name} from {source_module}"
        )

        result = RegistrationResult(
            success=False,
            action="skipped",
            message=f"Skipped attack '{attack_type}' (lower priority {new_priority.name} < {existing_priority.name})",
            attack_type=attack_type,
            conflicts=[f"Existing attack has higher priority ({existing_priority.name})"],
            previous_priority=existing_priority,
            new_priority=new_priority,
        )

        result.add_component_action("PriorityManager", "skipped_lower_priority")
        return result

    def get_all_promotion_history(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get promotion history for all attacks.

        Returns:
            Dictionary mapping attack types to their promotion histories
        """
        return self._promotion_history.copy()

    def clear_promotion_history(self, attack_type: Optional[str] = None) -> None:
        """
        Clear promotion history.

        Args:
            attack_type: Specific attack to clear (clears all if None)
        """
        if attack_type is None:
            self._promotion_history.clear()
            self.logger.info("Cleared all promotion history")
        elif attack_type in self._promotion_history:
            del self._promotion_history[attack_type]
            self.logger.info(f"Cleared promotion history for '{attack_type}'")

    def get_priority_stats(self) -> Dict[str, int]:
        """
        Get statistics about promotion activities.

        Returns:
            Dictionary with promotion statistics
        """
        stats = {
            "total_attacks_with_history": len(self._promotion_history),
            "total_promotions": sum(len(history) for history in self._promotion_history.values()),
            "replacements": 0,
            "promotions": 0,
        }

        for history in self._promotion_history.values():
            for event in history:
                action = event.get("action", "")
                if "replaced" in action:
                    stats["replacements"] += 1
                elif "promoted" in action:
                    stats["promotions"] += 1

        return stats
