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

    def add_transformation(self, param_name: str, old_value: Any, new_value: Any, reason: str):
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

    # Canonical allowed special tokens for split_pos/positions.
    # IMPORTANT: do NOT map these tokens to hardcoded integers here.
    # Actual resolution must be done by TLSFieldLocator (it parses payload properly).
    _ALLOWED_SPECIAL_TOKENS = {"sni", "cipher", "midsld", "random"}

    # Parameter alias mapping.
    # Canonical keys are: split_pos, split_count, fooling, attack_type, overlap_size
    # Keep aliases for backward compatibility; normalization should COPY, not delete.
    ALIASES = {
        # overlap_size canonical
        "split_seqovl": "overlap_size",
        "seqovl": "overlap_size",
        # fooling canonical
        "fooling_methods": "fooling",
        "window": "window_size",  # For wssize_limit
        "win_size": "window_size",  # Alternative name
        "ack": "ack_first",  # For disorder2
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
        params = params or {}
        result = ValidationResult(is_valid=True, normalized_params=dict(params))

        try:
            # Step 1: Resolve aliases
            result.normalized_params = self._resolve_aliases(result.normalized_params, result)

            # Step 2: Handle list parameters
            result.normalized_params = self._handle_list_parameters(
                result.normalized_params, result
            )

            # Step 2.5: Synchronize commonly-dual params for compatibility:
            # ttl <-> fake_ttl, overlap_size <-> split_seqovl, fooling <-> fooling_methods
            result.normalized_params = self._synchronize_compat_params(
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
            validation_errors = self._validate_bounds(result.normalized_params, payload_len, result)
            if validation_errors:
                result.is_valid = False
                result.error_message = "; ".join(validation_errors)
                return result

            # Step 5: Convert to canonical format
            result.normalized_params = self._convert_to_canonical_format(
                attack_type, result.normalized_params, result
            )

            # IMPORTANT:
            # Applying registry defaults must be done by AttackDispatcher, because only it has access
            # to the active UnifiedAttackRegistry instance. Keeping it here caused wrong imports
            # and semantic drift.
            self.logger.debug(
                "Normalized %s params: %d transformations, %d warnings",
                attack_type,
                len(result.transformations),
                len(result.warnings),
            )

        except Exception as e:
            result.is_valid = False
            result.error_message = f"Normalization failed: {str(e)}"
            self.logger.error("Parameter normalization error: %s", e)

        return result

    def _resolve_aliases(self, params: Dict[str, Any], result: ValidationResult) -> Dict[str, Any]:
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
                # Copy semantics: keep alias key too to preserve backward compatibility.
                normalized[canonical] = old_value
                result.add_transformation(
                    alias,
                    old_value,
                    normalized[canonical],
                    f"Resolved alias '{alias}' to '{canonical}'",
                )
                self.logger.debug("Resolved alias: %s -> %s", alias, canonical)

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
        if "split_pos" in normalized and isinstance(normalized["split_pos"], (list, tuple)):
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
                    "Parameter 'split_pos' was a list/tuple, using first element: %r",
                    normalized["split_pos"],
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
                if old_value.lower() in ["none", "null", ""]:
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
                    method
                    for method in old_value
                    if method and str(method).lower() not in ["none", "null", ""]
                ]
                if not filtered_methods:
                    normalized["fooling_methods"] = ["badsum"]  # Default if all were None
                    result.add_transformation(
                        "fooling_methods",
                        old_value,
                        ["badsum"],
                        "Replaced all 'None' values with default",
                    )
                elif len(filtered_methods) != len(old_value):
                    normalized["fooling_methods"] = filtered_methods
                    result.add_transformation(
                        "fooling_methods", old_value, filtered_methods, "Filtered out 'None' values"
                    )
            elif normalized["fooling_methods"] is None:
                normalized["fooling_methods"] = ["badsum"]  # Default
                result.add_transformation("fooling_methods", None, ["badsum"], "Set default value")

        return normalized

    def _synchronize_compat_params(
        self, params: Dict[str, Any], result: ValidationResult
    ) -> Dict[str, Any]:
        """
        Keep canonical names, but ensure legacy aliases are present when possible.
        Canonical:
          - fooling (str|list[str])
          - overlap_size (int)
        Legacy mirrors:
          - fooling_methods (list[str])
          - split_seqovl (int)
        Also keep ttl and fake_ttl both when one is provided.
        """
        p = dict(params)

        # ttl <-> fake_ttl
        if "ttl" in p and "fake_ttl" not in p:
            p["fake_ttl"] = p["ttl"]
            result.add_transformation("fake_ttl", None, p["fake_ttl"], "Mirrored from ttl")
        if "fake_ttl" in p and "ttl" not in p:
            p["ttl"] = p["fake_ttl"]
            result.add_transformation("ttl", None, p["ttl"], "Mirrored from fake_ttl")

        # overlap_size <-> split_seqovl
        if "overlap_size" in p and "split_seqovl" not in p:
            p["split_seqovl"] = p["overlap_size"]
            result.add_transformation("split_seqovl", None, p["split_seqovl"], "Mirrored from overlap_size")
        if "split_seqovl" in p and "overlap_size" not in p:
            p["overlap_size"] = p["split_seqovl"]
            result.add_transformation("overlap_size", None, p["overlap_size"], "Mirrored from split_seqovl")

        # fooling <-> fooling_methods
        # Canonical: fooling
        fooling = p.get("fooling")
        fooling_methods = p.get("fooling_methods")

        # Normalize fooling_methods to list[str] if present as str
        if isinstance(fooling_methods, str):
            p["fooling_methods"] = [fooling_methods] if fooling_methods else []

        # If only fooling_methods present, provide fooling
        if fooling is None and isinstance(p.get("fooling_methods"), list) and p["fooling_methods"]:
            p["fooling"] = p["fooling_methods"][:]  # keep as list for multi-method
            result.add_transformation("fooling", None, p["fooling"], "Mirrored from fooling_methods")

        # If only fooling present, provide fooling_methods as list
        if fooling is not None and "fooling_methods" not in p:
            if isinstance(fooling, str):
                p["fooling_methods"] = [fooling] if fooling else []
            elif isinstance(fooling, (list, tuple)):
                p["fooling_methods"] = [str(x) for x in fooling if x]
            else:
                p["fooling_methods"] = []
            result.add_transformation("fooling_methods", None, p["fooling_methods"], "Mirrored from fooling")

        return p

    def _resolve_special_values(
        self,
        params: Dict[str, Any],
        payload_len: Optional[int],
        result: ValidationResult,
    ) -> Dict[str, Any]:
        """
        Resolve special position values (sni, cipher, midsld, random).

        IMPORTANT: This method does NOT convert tokens to hardcoded integers.
        It only validates that tokens are known and converts numeric strings to int.
        Actual resolution is done by TLSFieldLocator based on real TLS payload.

        Special values:
        - "sni": TLS SNI extension position (resolved by TLSFieldLocator)
        - "cipher": TLS cipher suites position (resolved by TLSFieldLocator)
        - "midsld": Middle of payload (resolved by TLSFieldLocator)
        - "random": Random position (resolved by TLSFieldLocator)
        """
        normalized = params.copy()

        # Resolve split_pos: numeric strings -> int; known tokens are left intact for TLSFieldLocator.
        if "split_pos" in normalized and isinstance(normalized["split_pos"], str):
            raw = normalized["split_pos"]
            token = raw.strip().lower()
            if token in self._ALLOWED_SPECIAL_TOKENS:
                # Keep token for TLSFieldLocator.
                normalized["split_pos"] = token
            else:
                # Try numeric string
                try:
                    iv = int(token)
                except ValueError:
                    if self.strict_mode:
                        result.is_valid = False
                        result.error_message = f"Invalid split_pos token: {raw!r}"
                        return normalized
                    result.add_warning(f"Unknown split_pos token {raw!r}; will be handled later")
                else:
                    normalized["split_pos"] = iv
                    result.add_transformation("split_pos", raw, iv, "Converted numeric string to int")

        # Resolve positions list: numeric strings -> int; known tokens left intact.
        if "positions" in normalized and isinstance(normalized["positions"], list):
            positions = normalized["positions"]
            resolved_positions = []

            for i, pos in enumerate(positions):
                if isinstance(pos, str):
                    token = pos.strip().lower()
                    if token in self._ALLOWED_SPECIAL_TOKENS:
                        resolved_positions.append(token)
                    else:
                        try:
                            iv = int(token)
                        except ValueError:
                            if self.strict_mode:
                                result.is_valid = False
                                result.error_message = f"Invalid positions[{i}] token: {pos!r}"
                                return normalized
                            result.add_warning(f"Unknown positions[{i}] token {pos!r}; will be handled later")
                            resolved_positions.append(pos)
                        else:
                            resolved_positions.append(iv)
                            result.add_transformation(
                                f"positions[{i}]",
                                pos,
                                iv,
                                "Converted numeric string to int",
                            )
                else:
                    resolved_positions.append(pos)

            normalized["positions"] = resolved_positions

        return normalized

    def _validate_bounds(
        self, params: Dict[str, Any], payload_len: Optional[int], result: ValidationResult
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
                        errors.append(f"{ttl_param} must be an integer, got {type(ttl)}")
                        continue

                if not (1 <= ttl <= 255):
                    errors.append(f"{ttl_param} must be between 1 and 255, got {ttl}")

        # Validate split_pos
        if "split_pos" in params:
            split_pos = params["split_pos"]

            # Only validate numeric split_pos
            if isinstance(split_pos, int):
                if split_pos < 1:
                    errors.append(f"split_pos must be >= 1, got {split_pos}")

                if payload_len and split_pos >= payload_len:
                    # Non-fatal: clamp and warn (do not fail normalization).
                    clamped = max(1, payload_len - 1)
                    params["split_pos"] = clamped
                    result.add_transformation(
                        "split_pos",
                        split_pos,
                        clamped,
                        "Clamped to payload_len-1",
                    )

            # Skip validation if it's None or a string (special value that couldn't be resolved)
            elif split_pos is None:
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
                    errors.append(f"split_pos must be an integer, got {type(split_pos)}")
                    return errors

            # Only validate numeric split_pos
            if isinstance(split_pos, int):
                if split_pos < 1:
                    errors.append(f"split_pos must be >= 1, got {split_pos}")

                if payload_len and split_pos >= payload_len:
                    # Для split_pos тоже делаем предупреждение вместо ошибки
                    errors.append(
                        f"split_pos ({split_pos}) is >= payload length ({payload_len}), will be clamped"
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
                        errors.append(f"{overlap_param} must be an integer, got {type(overlap)}")
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
            if positions is None:
                # None is acceptable for positions - the attack handler will convert it
                # from split_pos or use defaults
                pass
            elif not isinstance(positions, list):
                errors.append(f"positions must be a list, got {type(positions)}")
            else:
                for i, pos in enumerate(positions):
                    if not isinstance(pos, int):
                        errors.append(f"positions[{i}] must be an integer, got {type(pos)}")
                    elif pos < 0:
                        errors.append(f"positions[{i}] must be >= 0, got {pos}")
                    elif payload_len and pos >= payload_len:
                        # Non-fatal: clamp and warn (do not fail normalization).
                        clamped = max(0, payload_len - 1)
                        params["positions"][i] = clamped
                        result.add_transformation(
                            f"positions[{i}]",
                            pos,
                            clamped,
                            "Clamped to payload_len-1",
                        )

        # Validate window_size for wssize_limit
        if "window_size" in params:
            window_size = params["window_size"]
            if not isinstance(window_size, int):
                try:
                    window_size = int(window_size)
                    params["window_size"] = window_size
                except (ValueError, TypeError):
                    errors.append(f"window_size must be an integer, got {type(window_size)}")
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
                    errors.append(f"fooling_methods must be a list, got {type(fooling)}")
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
                            errors.append(f"fooling method must be a string, got {type(method)}")
                        elif (
                            method.lower() not in ["none", "null", ""]
                            and method not in valid_methods
                        ):
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
            # IMPORTANT: do not delete split_pos (it is canonical in configs and used widely).
            # Provide positions as a compatibility hint for handlers that accept it.
            if "positions" not in normalized and "split_pos" in normalized:
                old_value = normalized["split_pos"]
                normalized["positions"] = [old_value]
                result.add_transformation(
                    "positions",
                    None,
                    normalized["positions"],
                    "Derived positions from split_pos (compat)",
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

    def _apply_defaults(
        self, attack_type: str, params: Dict[str, Any], result: ValidationResult
    ) -> Dict[str, Any]:
        """
        Deprecated in engine layer.
        Registry defaults are applied in AttackDispatcher (it owns UnifiedAttackRegistry).
        """
        return params


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
