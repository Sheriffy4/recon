"""
Attack Parameter Validator for the Attack Registry system.

This module provides validation logic for attack parameters and registry integrity.
Extracted from the monolithic AttackRegistry class to improve separation of concerns.
"""

import logging
from datetime import datetime
from typing import Any, Dict
from .models import AttackMetadata, ValidationResult, RegistrationPriority

logger = logging.getLogger(__name__)


class AttackValidator:
    """
    Validator for attack parameters and registry integrity.

    This class handles all validation logic including:
    - Parameter type and value validation
    - Registry integrity checks
    - Alias consistency verification
    - Handler validation
    """

    def __init__(self):
        """Initialize the validator."""
        self.valid_fooling_methods = [
            "badsum",
            "badseq",
            "badack",
            "datanoack",
            "hopbyhop",
            "md5sig",
            "fakesni",
        ]
        logger.debug("AttackValidator initialized")

    def validate_parameters(
        self, attack_type: str, params: Dict[str, Any], metadata: AttackMetadata
    ) -> ValidationResult:
        """
        Validate parameters for a specific attack type.

        Args:
            attack_type: Type of attack being validated
            params: Parameters to validate
            metadata: Attack metadata containing parameter definitions

        Returns:
            ValidationResult with validation status and any error messages
        """
        # Check required parameters
        for required_param in metadata.required_params:
            if required_param not in params:
                return ValidationResult(
                    is_valid=False,
                    error_message=f"Missing required parameter '{required_param}' for attack '{attack_type}'",
                )

        # Validate parameter values
        return self._validate_parameter_values(attack_type, params, metadata)

    def _validate_parameter_values(
        self, attack_type: str, params: Dict[str, Any], metadata: AttackMetadata
    ) -> ValidationResult:
        """Validate parameter values for a specific attack type."""

        # Validate split_pos
        if "split_pos" in params and params["split_pos"] is not None:
            result = self._validate_split_pos(params)
            if not result.is_valid:
                return result

        # Validate positions for multisplit/multidisorder
        if "positions" in params:
            result = self._validate_positions(params)
            if not result.is_valid:
                return result

        # Validate overlap_size for seqovl
        if "overlap_size" in params:
            result = self._validate_overlap_size(params)
            if not result.is_valid:
                return result

        # Validate TTL
        if "ttl" in params:
            result = self._validate_ttl(params)
            if not result.is_valid:
                return result

        # Validate fooling methods
        if "fooling" in params and params["fooling"] is not None:
            result = self._validate_fooling(params)
            if not result.is_valid:
                return result

        # Validate SNI parameters
        result = self._validate_sni_params(params)
        if not result.is_valid:
            return result

        return ValidationResult(is_valid=True, error_message=None)

    def _validate_split_pos(self, params: Dict[str, Any]) -> ValidationResult:
        """Validate split_pos parameter."""
        split_pos = params["split_pos"]

        # Handle list values
        if isinstance(split_pos, list):
            if len(split_pos) == 0:
                return ValidationResult(
                    is_valid=False, error_message="split_pos list cannot be empty"
                )
            split_pos = split_pos[0]
            params["split_pos"] = split_pos
            logger.debug(f"Converted split_pos list to single value: {split_pos}")

        if not isinstance(split_pos, (int, str)):
            return ValidationResult(
                is_valid=False,
                error_message=f"split_pos must be int, str, or list, got {type(split_pos)}",
            )

        # Check special values
        if isinstance(split_pos, str) and split_pos not in [
            "cipher",
            "sni",
            "midsld",
            "random",
        ]:
            try:
                int(split_pos)
            except ValueError:
                return ValidationResult(
                    is_valid=False,
                    error_message=f"Invalid split_pos value: {split_pos}",
                )

        return ValidationResult(is_valid=True, error_message=None)

    def _validate_positions(self, params: Dict[str, Any]) -> ValidationResult:
        """Validate positions parameter for multisplit/multidisorder."""
        positions = params["positions"]

        if positions is None:
            return ValidationResult(is_valid=True, error_message=None)

        if not isinstance(positions, list):
            return ValidationResult(
                is_valid=False,
                error_message=f"positions must be a list, got {type(positions)}",
            )

        special_values = ["cipher", "sni", "midsld"]
        for pos in positions:
            if isinstance(pos, int):
                if pos < 1:
                    return ValidationResult(
                        is_valid=False,
                        error_message=f"Position values must be >= 1, got {pos}",
                    )
            elif isinstance(pos, str):
                if pos not in special_values:
                    try:
                        int(pos)
                    except ValueError:
                        return ValidationResult(
                            is_valid=False,
                            error_message=f"Invalid position value: {pos}. Must be int or one of {special_values}",
                        )
            else:
                return ValidationResult(
                    is_valid=False,
                    error_message=f"All positions must be int or str, got {type(pos)}",
                )

        return ValidationResult(is_valid=True, error_message=None)

    def _validate_overlap_size(self, params: Dict[str, Any]) -> ValidationResult:
        """Validate overlap_size parameter for seqovl."""
        overlap_size = params["overlap_size"]
        if not isinstance(overlap_size, int) or overlap_size < 0:
            return ValidationResult(
                is_valid=False,
                error_message=f"overlap_size must be non-negative int, got {overlap_size}",
            )
        return ValidationResult(is_valid=True, error_message=None)

    def _validate_ttl(self, params: Dict[str, Any]) -> ValidationResult:
        """Validate TTL parameter."""
        ttl = params["ttl"]
        if not isinstance(ttl, int) or not (1 <= ttl <= 255):
            return ValidationResult(
                is_valid=False,
                error_message=f"ttl must be int between 1 and 255, got {ttl}",
            )
        return ValidationResult(is_valid=True, error_message=None)

    def _validate_fooling(self, params: Dict[str, Any]) -> ValidationResult:
        """Validate fooling methods parameter."""
        fooling = params["fooling"]

        if not isinstance(fooling, list):
            return ValidationResult(
                is_valid=False,
                error_message=f"fooling must be a list, got {type(fooling)}",
            )

        for method in fooling:
            if method not in self.valid_fooling_methods:
                return ValidationResult(
                    is_valid=False,
                    error_message=f"Invalid fooling method '{method}'. Valid methods: {self.valid_fooling_methods}",
                )

        return ValidationResult(is_valid=True, error_message=None)

    def _validate_sni_params(self, params: Dict[str, Any]) -> ValidationResult:
        """Validate custom_sni and fake_sni parameters."""
        sni_params = ["custom_sni", "fake_sni"]

        for param_name in sni_params:
            if param_name in params and params[param_name] is not None:
                sni_value = params[param_name]

                if not isinstance(sni_value, str):
                    return ValidationResult(
                        is_valid=False,
                        error_message=f"{param_name} must be a string, got {type(sni_value)}",
                    )

                # Validate SNI format
                try:
                    from ..filtering.custom_sni import CustomSNIHandler

                    sni_handler = CustomSNIHandler()
                    if not sni_handler.validate_sni(sni_value):
                        return ValidationResult(
                            is_valid=False,
                            error_message=f"Invalid {param_name} format: '{sni_value}'. Must be a valid domain name.",
                        )
                except ImportError:
                    logger.warning("CustomSNIHandler not available, skipping SNI validation")

        return ValidationResult(is_valid=True, error_message=None)

    def validate_registry_integrity(
        self, attacks: Dict, alias_mapping: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        Check registry integrity and identify potential conflicts.

        Checks:
        1. All aliases point to existing attacks
        2. No circular references in aliases
        3. All handlers are callable
        4. Metadata is correct
        5. Priorities match sources

        Args:
            attacks: Dictionary of registered attacks
            alias_mapping: Dictionary of alias to attack mappings

        Returns:
            Dictionary with check results and found issues
        """
        issues = []
        warnings = []
        stats = {
            "total_attacks": len(attacks),
            "total_aliases": len(alias_mapping),
            "priority_distribution": {},
            "source_modules": set(),
            "categories": set(),
        }

        # Count priority statistics
        for entry in attacks.values():
            priority_name = entry.priority.name
            stats["priority_distribution"][priority_name] = (
                stats["priority_distribution"].get(priority_name, 0) + 1
            )
            stats["source_modules"].add(entry.source_module)
            stats["categories"].add(entry.metadata.category)

        # Check aliases
        for alias, target in alias_mapping.items():
            if target not in attacks:
                issues.append(f"Alias '{alias}' points to non-existent attack '{target}'")
            elif alias == target:
                warnings.append(f"Alias '{alias}' points to itself")

        # Check handlers
        for attack_type, entry in attacks.items():
            if not callable(entry.handler):
                issues.append(
                    f"Attack '{attack_type}' has non-callable handler: {type(entry.handler)}"
                )

            # Check priority and source consistency
            if (
                entry.priority == RegistrationPriority.CORE
                and "primitives" not in entry.source_module
            ):
                warnings.append(
                    f"Attack '{attack_type}' has CORE priority but not from primitives module: {entry.source_module}"
                )

        # Check for duplicate aliases in metadata
        all_aliases = []
        for entry in attacks.values():
            all_aliases.extend(entry.metadata.aliases)

        duplicate_aliases = []
        seen_aliases = set()
        for alias in all_aliases:
            if alias in seen_aliases:
                duplicate_aliases.append(alias)
            seen_aliases.add(alias)

        if duplicate_aliases:
            warnings.append(f"Duplicate aliases found in metadata: {duplicate_aliases}")

        # Convert sets to lists for JSON serialization
        stats["source_modules"] = list(stats["source_modules"])
        stats["categories"] = list(stats["categories"])

        return {
            "is_valid": len(issues) == 0,
            "issues": issues,
            "warnings": warnings,
            "stats": stats,
            "timestamp": datetime.now().isoformat(),
        }
