#!/usr/bin/env python3
"""
Parameter Normalizer for Attack System

A single source of truth for normalizing and validating attack parameters.
Addresses issues identified in CURRENT_BEHAVIOR_ANALYSIS.md:
- Parameter chaos (ttl vs fake_ttl, list vs int)
- Implicit conversions (list[0] extraction)
- Special value resolution (sni, cipher, midsld)
- Missing validation

Author: Attack Refactoring Team
Status: Task 10.2 - Parameter Normalization System
"""

import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field


@dataclass
class ValidationResult:
    """
    Result of parameter validation and normalization.

    Enhanced to document all parameter transformations.
    This makes the system transparent - instead of "silent" conversions,
    we explicitly report what was changed.
    """

    is_valid: bool
    error_message: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    normalized_params: Optional[Dict[str, Any]] = None
    transformations: List[str] = field(default_factory=list)

    def add_warning(self, message: str):
        """Add a warning about parameter handling."""
        self.warnings.append(message)

    def add_transformation(
        self, param_name: str, old_value: Any, new_value: Any, reason: str
    ):
        """
        Document a parameter transformation.

        Example:
        - "Converted list 'split_pos' [3, 5] to first element: 3"
        - "Resolved special value 'sni' to position: 43"
        - "Converted alias 'ttl' to 'fake_ttl': 3"
        """
        transformation = f"{param_name}: {reason} ({old_value} → {new_value})"
        self.transformations.append(transformation)
        self.add_warning(transformation)


class ParameterNormalizer:
    """
    A single source of truth for normalizing and validating attack parameters.

    This component addresses the "parameter chaos" identified in analysis:
    - Resolves aliases (ttl → fake_ttl)
    - Converts types (string → int)
    - Handles lists (extract first element with warning)
    - Resolves special values (sni, cipher, midsld)
    - Validates bounds and ranges
    """

    # Parameter aliases mapping
    ALIASES = {
        "ttl": "fake_ttl",  # For fakeddisorder and other fake attacks
        "fooling": "fooling_methods",
        "overlap_size": "split_seqovl",  # Zapret compatibility
        "seqovl": "split_seqovl",  # Alternative name
        "window": "window_size",  # For wssize_limit
        "win_size": "window_size",  # Alternative name
        "ack": "ack_first",  # For disorder2
    }

    # Special position values and their byte positions
    SPECIAL_POSITIONS = {
        "sni": 43,  # TLS SNI extension position
        "cipher": 11,  # TLS cipher suites position
        "midsld": None,  # Calculated as payload_len // 2
    }

    def __init__(self, strict_mode: bool = False):
        """
        Initialize ParameterNormalizer

        Args:
            strict_mode: If True, ambiguous parameters cause errors instead of warnings.
                        Useful for CI/CD to catch "sloppy" configurations.
        """
        self.logger = logging.getLogger("ParameterNormalizer")
        self.strict_mode = strict_mode

    def normalize(
        self,
        attack_type: str,
        params: Dict[str, Any],
        payload_len: Optional[int] = None,
    ) -> ValidationResult:
        """
        Normalize parameters for attack with comprehensive validation.

        Steps:
        1. Resolve parameter aliases
        2. Convert types
        3. Handle lists
        4. Resolve special values
        5. Validate bounds
        6. Convert to canonical format

        Args:
            attack_type: Type of attack (fakeddisorder, disorder, etc.)
            params: Raw parameters from user/config
            payload_len: Length of payload (needed for special values)

        Returns:
            ValidationResult with normalized params and warnings
        """
        result = ValidationResult(is_valid=True, normalized_params=params.copy())

        try:
            # Step 1: Resolve aliases
            result.normalized_params = self._resolve_aliases(
                result.normalized_params, result
            )

            # Step 2: Handle list parameters
            result.normalized_params = self._handle_list_parameters(
                result.normalized_params, result
            )

            # Check if strict mode caused an error
            if not result.is_valid:
                return result

            # Step 3: Resolve special values
            result.normalized_params = self._resolve_special_values(
                result.normalized_params, payload_len, result
            )

            # Step 4: Validate bounds
            validation_errors = self._validate_bounds(
                result.normalized_params, payload_len
            )
            if validation_errors:
                result.is_valid = False
                result.error_message = "; ".join(validation_errors)
                return result

            # Step 5: Convert to canonical format
            result.normalized_params = self._convert_to_canonical_format(
                attack_type, result.normalized_params, result
            )

            self.logger.debug(
                f"Normalized {attack_type} params: "
                f"{len(result.transformations)} transformations, "
                f"{len(result.warnings)} warnings"
            )

        except Exception as e:
            result.is_valid = False
            result.error_message = f"Normalization failed: {str(e)}"
            self.logger.error(f"Parameter normalization error: {e}")

        return result

    def _resolve_aliases(
        self, params: Dict[str, Any], result: ValidationResult
    ) -> Dict[str, Any]:
        """
        Resolve parameter aliases to canonical names.

        Aliases:
        - ttl → fake_ttl (for fakeddisorder)
        - fooling → fooling_methods
        - overlap_size → split_seqovl (for zapret compatibility)
        """
        normalized = params.copy()

        for alias, canonical in self.ALIASES.items():
            if alias in normalized and canonical not in normalized:
                old_value = normalized[alias]
                normalized[canonical] = normalized.pop(alias)
                result.add_transformation(
                    alias,
                    old_value,
                    normalized[canonical],
                    f"Resolved alias '{alias}' to '{canonical}'",
                )
                self.logger.debug(f"Resolved alias: {alias} → {canonical}")

        return normalized

    def _handle_list_parameters(
        self, params: Dict[str, Any], result: ValidationResult
    ) -> Dict[str, Any]:
        """
        Handle list-to-value conversions with warnings.

        For split_pos: If it's a list, extract first element and warn.
        For positions: Keep as list (canonical format).
        """
        normalized = params.copy()

        # Handle split_pos as list (common mistake)
        if "split_pos" in normalized and isinstance(normalized["split_pos"], list):
            old_value = normalized["split_pos"]
            if old_value:
                if self.strict_mode:
                    # In strict mode, this is an error
                    result.is_valid = False
                    result.error_message = (
                        f"Ambiguous parameter: 'split_pos' is a list {old_value}. "
                        f"Use a single integer value or 'positions' for multiple values."
                    )
                    return normalized

                # Non-strict: convert with warning
                normalized["split_pos"] = old_value[0]
                result.add_transformation(
                    "split_pos",
                    old_value,
                    normalized["split_pos"],
                    "Converted list to first element",
                )
                self.logger.warning(
                    f"Parameter 'split_pos' was a list, using first element: "
                    f"{normalized['split_pos']}"
                )
            else:
                # Empty list, remove parameter
                del normalized["split_pos"]
                result.add_warning("Removed empty 'split_pos' list")

        # Ensure fooling_methods is a list and filter out 'None' strings
        if "fooling_methods" in normalized:
            if isinstance(normalized["fooling_methods"], str):
                old_value = normalized["fooling_methods"]
                # Filter out 'None' strings
                if old_value.lower() in ['none', 'null', '']:
                    normalized["fooling_methods"] = ["badsum"]  # Default
                    result.add_transformation(
                        "fooling_methods", old_value, ["badsum"], "Replaced 'None' with default"
                    )
                else:
                    normalized["fooling_methods"] = [old_value]
                    result.add_transformation(
                        "fooling_methods",
                        old_value,
                        normalized["fooling_methods"],
                        "Converted string to list",
                    )
            elif isinstance(normalized["fooling_methods"], list):
                # Filter out 'None' strings from list
                old_value = normalized["fooling_methods"]
                filtered_methods = [
                    method for method in old_value 
                    if method and str(method).lower() not in ['none', 'null', '']
                ]
                if not filtered_methods:
                    normalized["fooling_methods"] = ["badsum"]  # Default if all were None
                    result.add_transformation(
                        "fooling_methods", old_value, ["badsum"], "Replaced all 'None' values with default"
                    )
                elif len(filtered_methods) != len(old_value):
                    normalized["fooling_methods"] = filtered_methods
                    result.add_transformation(
                        "fooling_methods", old_value, filtered_methods, "Filtered out 'None' values"
                    )
            elif normalized["fooling_methods"] is None:
                normalized["fooling_methods"] = ["badsum"]  # Default
                result.add_transformation(
                    "fooling_methods", None, ["badsum"], "Set default value"
                )

        return normalized

    def _resolve_special_values(
        self,
        params: Dict[str, Any],
        payload_len: Optional[int],
        result: ValidationResult,
    ) -> Dict[str, Any]:
        """
        Resolve special position values (sni, cipher, midsld).

        This logic was previously hidden in attack_dispatcher.py.
        Now it's explicit and centralized.

        Special values:
        - "sni": Position 43 (TLS SNI extension)
        - "cipher": Position 11 (TLS cipher suites)
        - "midsld": Middle of payload (payload_len // 2)
        """
        normalized = params.copy()

        # Resolve split_pos special values
        if "split_pos" in normalized and isinstance(normalized["split_pos"], str):
            special_value = normalized["split_pos"].lower()

            if special_value in self.SPECIAL_POSITIONS:
                old_value = normalized["split_pos"]

                if special_value == "midsld":
                    if payload_len is None:
                        result.add_warning(
                            "Cannot resolve 'midsld' without payload_len, "
                            "will be resolved at execution time"
                        )
                        return normalized
                    new_value = payload_len // 2
                else:
                    new_value = self.SPECIAL_POSITIONS[special_value]

                # Check if position is valid for payload
                if payload_len and new_value >= payload_len:
                    # Fall back to middle
                    new_value = payload_len // 2
                    result.add_warning(
                        f"Special value '{special_value}' position {self.SPECIAL_POSITIONS[special_value]} "
                        f"exceeds payload length {payload_len}, using middle: {new_value}"
                    )

                normalized["split_pos"] = new_value
                result.add_transformation(
                    "split_pos",
                    old_value,
                    new_value,
                    f"Resolved special value '{special_value}'",
                )
                self.logger.debug(
                    f"Resolved special value '{special_value}' to position {new_value}"
                )
            else:
                result.add_warning(
                    f"Unknown special value '{special_value}' for split_pos, "
                    "will be treated as invalid"
                )

        # Resolve positions list special values
        if "positions" in normalized and isinstance(normalized["positions"], list):
            positions = normalized["positions"]
            resolved_positions = []
            
            for i, pos in enumerate(positions):
                if isinstance(pos, str):
                    special_value = pos.lower()
                    
                    if special_value in self.SPECIAL_POSITIONS:
                        if special_value == "midsld":
                            if payload_len is None:
                                result.add_warning(
                                    f"Cannot resolve 'midsld' in positions[{i}] without payload_len, "
                                    "will be resolved at execution time"
                                )
                                resolved_positions.append(pos)  # Keep as string for later resolution
                                continue
                            new_value = payload_len // 2
                        else:
                            new_value = self.SPECIAL_POSITIONS[special_value]

                        # Check if position is valid for payload
                        if payload_len and new_value >= payload_len:
                            # Fall back to middle
                            new_value = payload_len // 2
                            result.add_warning(
                                f"Special value '{special_value}' in positions[{i}] position {self.SPECIAL_POSITIONS[special_value]} "
                                f"exceeds payload length {payload_len}, using middle: {new_value}"
                            )

                        resolved_positions.append(new_value)
                        result.add_transformation(
                            f"positions[{i}]",
                            pos,
                            new_value,
                            f"Resolved special value '{special_value}'",
                        )
                        self.logger.debug(
                            f"Resolved special value '{special_value}' in positions[{i}] to position {new_value}"
                        )
                    else:
                        result.add_warning(
                            f"Unknown special value '{special_value}' in positions[{i}], "
                            "will be treated as invalid"
                        )
                        resolved_positions.append(pos)  # Keep as string for later handling
                else:
                    resolved_positions.append(pos)
            
            normalized["positions"] = resolved_positions

        return normalized

    def _validate_bounds(
        self, params: Dict[str, Any], payload_len: Optional[int]
    ) -> List[str]:
        """
        Validate parameter bounds and ranges for all attack types.

        Validations:
        - TTL values: 1-255 (ttl, fake_ttl)
        - Position values: 1 to payload_len-1 (split_pos, positions)
        - Overlap values: 0 to payload_len (split_seqovl, overlap_size)
        - Window size: 1 to reasonable limit (window_size)
        - Boolean flags: ack_first
        - Fooling methods: valid method names
        """
        errors = []

        # Validate TTL values
        for ttl_param in ["ttl", "fake_ttl"]:
            if ttl_param in params:
                ttl = params[ttl_param]
                if not isinstance(ttl, int):
                    try:
                        ttl = int(ttl)
                        params[ttl_param] = ttl
                    except (ValueError, TypeError):
                        errors.append(
                            f"{ttl_param} must be an integer, got {type(ttl)}"
                        )
                        continue

                if not (1 <= ttl <= 255):
                    errors.append(f"{ttl_param} must be between 1 and 255, got {ttl}")

        # Validate split_pos
        if "split_pos" in params:
            split_pos = params["split_pos"]

            # Skip validation if it's None or a string (special value that couldn't be resolved)
            if split_pos is None:
                # None values are handled at execution time or by other parameters
                pass
            elif isinstance(split_pos, str):
                # Special values that couldn't be resolved will be handled at execution time
                # Don't treat as error
                pass
            elif not isinstance(split_pos, int):
                try:
                    split_pos = int(split_pos)
                    params["split_pos"] = split_pos
                except (ValueError, TypeError):
                    errors.append(
                        f"split_pos must be an integer, got {type(split_pos)}"
                    )
                    return errors

            # Only validate numeric split_pos
            if isinstance(split_pos, int):
                if split_pos < 1:
                    errors.append(f"split_pos must be >= 1, got {split_pos}")

                if payload_len and split_pos >= payload_len:
                    errors.append(
                        f"split_pos ({split_pos}) must be less than payload length ({payload_len})"
                    )

        # Validate overlap parameters (split_seqovl, overlap_size)
        for overlap_param in ["split_seqovl", "overlap_size"]:
            if overlap_param in params:
                overlap = params[overlap_param]
                if not isinstance(overlap, int):
                    try:
                        overlap = int(overlap)
                        params[overlap_param] = overlap
                    except (ValueError, TypeError):
                        errors.append(
                            f"{overlap_param} must be an integer, got {type(overlap)}"
                        )
                        continue

                if overlap < 0:
                    errors.append(f"{overlap_param} must be >= 0, got {overlap}")

                if payload_len and overlap > payload_len:
                    errors.append(
                        f"{overlap_param} ({overlap}) cannot exceed payload length ({payload_len})"
                    )

        # Validate positions list
        if "positions" in params:
            positions = params["positions"]
            if not isinstance(positions, list):
                errors.append(f"positions must be a list, got {type(positions)}")
            else:
                for i, pos in enumerate(positions):
                    if not isinstance(pos, int):
                        errors.append(
                            f"positions[{i}] must be an integer, got {type(pos)}"
                        )
                    elif pos < 0:
                        errors.append(f"positions[{i}] must be >= 0, got {pos}")
                    elif payload_len and pos >= payload_len:
                        errors.append(
                            f"positions[{i}] ({pos}) must be less than payload length ({payload_len})"
                        )

        # Validate window_size for wssize_limit
        if "window_size" in params:
            window_size = params["window_size"]
            if not isinstance(window_size, int):
                try:
                    window_size = int(window_size)
                    params["window_size"] = window_size
                except (ValueError, TypeError):
                    errors.append(
                        f"window_size must be an integer, got {type(window_size)}"
                    )
                    return errors

            if window_size < 1:
                errors.append(f"window_size must be >= 1, got {window_size}")
            elif window_size > 65535:  # Reasonable upper limit
                errors.append(f"window_size must be <= 65535, got {window_size}")

        # Validate ack_first boolean
        if "ack_first" in params:
            ack_first = params["ack_first"]
            if not isinstance(ack_first, bool):
                # Try to convert string/int to bool
                if isinstance(ack_first, str):
                    if ack_first.lower() in ["true", "1", "yes", "on"]:
                        params["ack_first"] = True
                    elif ack_first.lower() in ["false", "0", "no", "off"]:
                        params["ack_first"] = False
                    else:
                        errors.append(f"ack_first must be a boolean, got '{ack_first}'")
                elif isinstance(ack_first, int):
                    params["ack_first"] = bool(ack_first)
                else:
                    errors.append(f"ack_first must be a boolean, got {type(ack_first)}")

        # Validate fooling methods
        if "fooling_methods" in params:
            fooling = params["fooling_methods"]
            if fooling is not None:
                if not isinstance(fooling, list):
                    errors.append(
                        f"fooling_methods must be a list, got {type(fooling)}"
                    )
                else:
                    valid_methods = [
                        "badsum",
                        "badseq",
                        "badack",
                        "datanoack",
                        "hopbyhop",
                        "md5sig",
                        "fakesni",
                    ]
                    for method in fooling:
                        if not isinstance(method, str):
                            errors.append(
                                f"fooling method must be a string, got {type(method)}"
                            )
                        elif method.lower() not in ['none', 'null', ''] and method not in valid_methods:
                            # Only validate non-None values
                            errors.append(
                                f"Invalid fooling method '{method}'. Valid methods: {valid_methods}"
                            )

        return errors

    def _convert_to_canonical_format(
        self, attack_type: str, params: Dict[str, Any], result: ValidationResult
    ) -> Dict[str, Any]:
        """
        Convert parameters to canonical format for attack type.

        Attack type specific conversions:

        For multisplit/multidisorder:
        - split_pos → positions: [split_pos]
        - split_count → positions: [generated positions]

        For fakeddisorder/seqovl/disorder/disorder2/split:
        - Keep split_pos as is (single position)
        - Ensure fake_ttl is set for fake attacks

        For fake/race attacks:
        - Ensure ttl parameter is set
        - Convert to fake_ttl if needed

        For wssize_limit:
        - Ensure window_size parameter

        For tlsrec_split:
        - Ensure split_pos for TLS record splitting
        """
        normalized = params.copy()

        # Normalize attack type aliases
        attack_type = self._normalize_attack_type_alias(attack_type)

        # For multi-attacks, convert to positions list
        if attack_type in ["multisplit", "multidisorder"]:
            if "positions" not in normalized:
                if "split_pos" in normalized:
                    # Convert single split_pos to positions list
                    old_value = normalized["split_pos"]
                    normalized["positions"] = [old_value]
                    del normalized["split_pos"]
                    result.add_transformation(
                        "split_pos",
                        old_value,
                        normalized["positions"],
                        "Converted to positions list for multi-attack",
                    )
                    self.logger.debug(
                        f"Converted split_pos to positions for {attack_type}"
                    )
                elif "split_count" in normalized:
                    # Generate positions from count
                    # This would need payload_len, so we'll handle it at execution time
                    result.add_warning(
                        "split_count will be converted to positions at execution time "
                        "(requires payload length)"
                    )

        # For fake attacks, ensure fake_ttl is set
        if attack_type in ["fakeddisorder", "fake", "seqovl"]:
            if "fake_ttl" not in normalized and "ttl" in normalized:
                # Already handled in alias resolution, but double-check
                pass
            elif "fake_ttl" not in normalized:
                # Set default fake_ttl
                normalized["fake_ttl"] = 3
                result.add_transformation(
                    "fake_ttl", None, 3, "Set default fake_ttl for fake attack"
                )

        # For disorder2, ensure ack_first parameter
        if attack_type == "disorder2":
            if "ack_first" not in normalized:
                normalized["ack_first"] = True
                result.add_transformation(
                    "ack_first", None, True, "Set default ack_first=True for disorder2"
                )

        # For wssize_limit, ensure window_size
        if attack_type == "wssize_limit":
            if "window_size" not in normalized:
                normalized["window_size"] = 1
                result.add_transformation(
                    "window_size", None, 1, "Set default window_size for wssize_limit"
                )

        # For tlsrec_split, ensure split_pos
        if attack_type == "tlsrec_split":
            if "split_pos" not in normalized:
                normalized["split_pos"] = 5
                result.add_transformation(
                    "split_pos", None, 5, "Set default split_pos for tlsrec_split"
                )

        return normalized

    def _normalize_attack_type_alias(self, attack_type: str) -> str:
        """
        Normalize attack type aliases to canonical names.

        This handles common aliases used in the system.
        """
        aliases = {
            "fake_disorder": "fakeddisorder",
            "fakedisorder": "fakeddisorder",
            "fake_packet_race": "fake",
            "seq_overlap": "seqovl",
            "sequence_overlap": "seqovl",
            "multi_split": "multisplit",
            "multi_disorder": "multidisorder",
            "simple_disorder": "disorder",
            "tls_record_split": "tlsrec_split",
            "window_size_limit": "wssize_limit",
        }

        return aliases.get(attack_type.lower(), attack_type.lower())


# Convenience function for quick normalization
def normalize_attack_params(
    attack_type: str,
    params: Dict[str, Any],
    payload_len: Optional[int] = None,
    strict_mode: bool = False,
) -> ValidationResult:
    """
    Convenience function for normalizing attack parameters.

    Args:
        attack_type: Type of attack
        params: Raw parameters
        payload_len: Optional payload length for validation
        strict_mode: If True, ambiguous parameters cause errors.
                    Useful for CI/CD to catch configuration issues.

    Returns:
        ValidationResult with normalized params
    """
    normalizer = ParameterNormalizer(strict_mode=strict_mode)
    return normalizer.normalize(attack_type, params, payload_len)
