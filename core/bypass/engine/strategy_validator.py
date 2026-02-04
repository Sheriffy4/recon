#!/usr/bin/env python3
"""
Strategy validation utilities.

This module provides validation functions for bypass strategy parameters.
Extracted from base_engine.py to reduce god class complexity and improve
maintainability of validation logic.
"""

import logging
from typing import Any, Dict, List, Optional


def validate_ttl_parameter(params: Dict[str, Any], ttl_param: str, logger: logging.Logger) -> bool:
    """
    Validate TTL parameter value.

    Args:
        params: Strategy parameters dictionary
        ttl_param: Name of TTL parameter to validate
        logger: Logger instance

    Returns:
        True if valid, False otherwise
    """
    if ttl_param in params:
        ttl = params[ttl_param]
        if isinstance(ttl, str):
            try:
                ttl = int(ttl)
                params[ttl_param] = ttl
            except ValueError:
                logger.error(
                    "Invalid %s string: %s (must be int 1-255)",
                    ttl_param,
                    ttl,
                )
                return False
        if not isinstance(ttl, int) or ttl < 1 or ttl > 255:
            logger.error("Invalid %s: %s (must be int 1-255)", ttl_param, ttl)
            return False
    return True


def validate_autottl_parameter(params: Dict[str, Any], logger: logging.Logger) -> bool:
    """
    Validate autottl parameter value.

    Args:
        params: Strategy parameters dictionary
        logger: Logger instance

    Returns:
        True if valid, False otherwise
    """
    if "autottl" in params:
        autottl = params["autottl"]
        if isinstance(autottl, str):
            try:
                autottl = int(autottl)
                params["autottl"] = autottl
            except ValueError:
                logger.error("Invalid autottl string: %s (must be int)", autottl)
                return False
        if not isinstance(autottl, int):
            logger.error("Invalid autottl: %s (must be int)", autottl)
            return False
    return True


def validate_fooling_parameter(params: Dict[str, Any], logger: logging.Logger) -> bool:
    """
    Validate fooling parameter value.

    Args:
        params: Strategy parameters dictionary
        logger: Logger instance

    Returns:
        True if valid, False otherwise
    """
    if "fooling" in params:
        fooling = params["fooling"]
        # Keep superset for compatibility with various generators/registries.
        valid_fooling = [
            "md5sig",
            "badsum",
            "badseq",
            "badack",
            "datanoack",
            "hopbyhop",
            "fakesni",
            "ts",
            "none",
        ]

        if isinstance(fooling, str):
            if fooling not in valid_fooling:
                logger.error(
                    "Invalid fooling method: '%s' (valid: %s)",
                    fooling,
                    valid_fooling,
                )
                return False
        elif isinstance(fooling, (list, tuple)):
            for method in fooling:
                if method not in valid_fooling:
                    logger.error(
                        "Invalid fooling method in list: '%s' (valid: %s)",
                        method,
                        valid_fooling,
                    )
                    return False
        else:
            logger.error(
                "Invalid fooling type: %s (must be str or list/tuple)",
                type(fooling),
            )
            return False
    return True


def validate_disorder_method_parameter(params: Dict[str, Any], logger: logging.Logger) -> bool:
    """
    Validate disorder_method parameter value.

    Args:
        params: Strategy parameters dictionary
        logger: Logger instance

    Returns:
        True if valid, False otherwise
    """
    if "disorder_method" in params:
        disorder_method = params["disorder_method"]
        valid_methods = ["swap", "reverse", "random"]
        if disorder_method not in valid_methods:
            logger.error(
                "Invalid disorder_method: '%s' (valid: %s)",
                disorder_method,
                valid_methods,
            )
            return False
    return True


def validate_overlap_size_parameter(params: Dict[str, Any], logger: logging.Logger) -> bool:
    """
    Validate overlap_size parameter value.

    Args:
        params: Strategy parameters dictionary
        logger: Logger instance

    Returns:
        True if valid, False otherwise
    """
    if "overlap_size" in params:
        overlap_size = params["overlap_size"]
        if isinstance(overlap_size, str):
            try:
                overlap_size = int(overlap_size)
                params["overlap_size"] = overlap_size
            except ValueError:
                logger.error(
                    "Invalid overlap_size string: %s (must be int >= 0)",
                    overlap_size,
                )
                return False
        if not isinstance(overlap_size, int) or overlap_size < 0:
            logger.error("Invalid overlap_size: %s (must be int >= 0)", overlap_size)
            return False
    return True


def validate_split_pos_parameter(params: Dict[str, Any], logger: logging.Logger) -> bool:
    """
    Validate split_pos parameter value.

    Args:
        params: Strategy parameters dictionary
        logger: Logger instance

    Returns:
        True if valid, False otherwise
    """
    if "split_pos" in params:
        split_pos = params["split_pos"]
        if isinstance(split_pos, str):
            # allow special string values
            if split_pos in ("cipher", "midsld", "sni", "random"):
                return True
            try:
                split_pos_i = int(split_pos)
                params["split_pos"] = split_pos_i
                split_pos = split_pos_i
            except ValueError:
                logger.error("Invalid split_pos string: %s (must be int or special)", split_pos)
                return False
        if not isinstance(split_pos, int) or split_pos <= 0:
            logger.error("Invalid split_pos: %s (must be int > 0)", split_pos)
            return False
    return True


def validate_strategy_params(
    strategy_type: str, params: Dict[str, Any], logger: logging.Logger
) -> bool:
    """
    Validate strategy parameters based on strategy type.

    Args:
        strategy_type: Type of bypass strategy
        params: Strategy parameters dictionary
        logger: Logger instance

    Returns:
        True if all parameters are valid, False otherwise
    """
    # Validate split_pos if present
    if "split_pos" in params:
        split_pos = params["split_pos"]

        if isinstance(split_pos, int):
            if split_pos < 0:
                logger.error("Invalid split_pos: %s (must be >= 0)", split_pos)
                return False
        elif isinstance(split_pos, str):
            # Допускаем специальные значения и числовые строки
            valid_special = ["cipher", "midsld", "sni"]
            if split_pos in valid_special:
                pass
            else:
                try:
                    int(split_pos)
                except ValueError:
                    logger.error(
                        "Invalid split_pos string: '%s' (valid specials: %s or int)",
                        split_pos,
                        valid_special,
                    )
                    return False
        elif isinstance(split_pos, list):
            if not all(isinstance(p, int) and p >= 0 for p in split_pos):
                logger.error(
                    "Invalid split_pos list: %s (all entries must be int >= 0)",
                    split_pos,
                )
                return False
        else:
            logger.error(
                "Invalid split_pos type: %s (must be int, str, or list)",
                type(split_pos),
            )
            return False

    # Validate split_count if present
    if "split_count" in params:
        split_count = params["split_count"]
        if split_count is None:
            logger.warning("⚠️ split_count is None, setting default value: 8")
            params["split_count"] = 8
        else:
            if isinstance(split_count, str):
                try:
                    split_count = int(split_count)
                    params["split_count"] = split_count
                except ValueError:
                    logger.error(
                        "Invalid split_count string: %s (must be int >= 1)",
                        split_count,
                    )
                    return False
            if not isinstance(split_count, int) or split_count < 1:
                logger.error("Invalid split_count: %s (must be int >= 1)", split_count)
                return False

    # Validate common TTL parameters
    if not validate_ttl_parameter(params, "fake_ttl", logger):
        return False
    if not validate_ttl_parameter(params, "ttl", logger):
        return False

    # Validate autottl
    if not validate_autottl_parameter(params, logger):
        return False

    # Validate fooling
    if not validate_fooling_parameter(params, logger):
        return False

    # Validate disorder_method
    if not validate_disorder_method_parameter(params, logger):
        return False

    # Validate overlap_size
    if not validate_overlap_size_parameter(params, logger):
        return False

    # Validate positions if present (for multisplit)
    if "positions" in params:
        positions = params["positions"]

        if positions is None:
            split_count = params.get("split_count", 8)
            if isinstance(split_count, str):
                try:
                    split_count = int(split_count)
                    params["split_count"] = split_count
                except ValueError:
                    logger.warning(
                        "Invalid split_count string for positions default: %s, using 8",
                        split_count,
                    )
                    split_count = 8
            split_pos = params.get("split_pos", 3)
            if isinstance(split_pos, str):
                try:
                    split_pos = int(split_pos)
                except ValueError:
                    split_pos = 3
            default_positions = [int(split_pos) + i * 6 for i in range(split_count)]
            logger.warning("⚠️ positions is None, generating default: %s", default_positions)
            params["positions"] = default_positions
        elif not isinstance(positions, list):
            logger.error("Invalid positions: %s (must be list)", positions)
            return False
        else:
            normalized_positions = []
            for p in positions:
                if isinstance(p, str):
                    try:
                        p = int(p)
                    except ValueError:
                        logger.error("Invalid position value: %s (must be int >= 0)", p)
                        return False
                if not isinstance(p, int) or p < 0:
                    logger.error(
                        "Invalid positions list: %s (all must be int >= 0)",
                        positions,
                    )
                    return False
                normalized_positions.append(p)
            params["positions"] = normalized_positions

    return True


class StrategyValidationResult:
    """Validation result for StrategyValidator (domain_rules parity checks)."""

    def __init__(
        self,
        valid: bool,
        reason: Optional[str] = None,
        warning: Optional[str] = None,
        recommendation: Optional[str] = None,
        mismatches: Optional[List[str]] = None,
    ):
        self.valid = valid
        self.reason = reason
        self.warning = warning
        self.recommendation = recommendation
        self.mismatches = mismatches or []

    def __repr__(self) -> str:
        if self.valid:
            return f"StrategyValidationResult(valid=True, warning={self.warning!r})"
        else:
            return f"StrategyValidationResult(valid=False, reason={self.reason!r})"

    @classmethod
    def success(cls, warning: Optional[str] = None, recommendation: Optional[str] = None):
        """Create a successful validation result."""
        return cls(valid=True, warning=warning, recommendation=recommendation)

    @classmethod
    def failure(
        cls,
        reason: str,
        recommendation: Optional[str] = None,
        mismatches: Optional[List[str]] = None,
    ):
        """Create a failed validation result."""
        return cls(valid=False, reason=reason, recommendation=recommendation, mismatches=mismatches)


# Backward-compatible alias (older code expects ValidationResult name from this module).
ValidationResult = StrategyValidationResult


class StrategyValidator:
    """
    DomainStrategyEngine-compatible validator.

    IMPORTANT:
    - This validator is intentionally "fail-open" for mismatches: it will return valid=True
      with warnings for non-critical discrepancies to avoid breaking runtime traffic.
    - It only returns valid=False for gross errors (missing type/invalid structure).
    """

    def __init__(self, domain_rules_path: str = "domain_rules.json"):
        self.domain_rules_path = domain_rules_path
        self.logger = logging.getLogger(__name__)
        self.domain_rules: Dict[str, Any] = {}
        self.reload_domain_rules()

    def reload_domain_rules(self) -> None:
        from pathlib import Path
        import json

        path = Path(self.domain_rules_path)
        if not path.exists():
            self.domain_rules = {}
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict) and "domain_rules" in data and isinstance(data["domain_rules"], dict):
                # canonical schema
                self.domain_rules = data["domain_rules"]
            elif isinstance(data, dict):
                # legacy schema (flat mapping)
                self.domain_rules = data
            else:
                self.domain_rules = {}
        except Exception as e:
            self.logger.warning("Failed to load domain rules from %s: %s", path, e)
            self.domain_rules = {}

    def validate_strategy_application(
        self,
        domain: str,
        applied_strategy: Dict[str, Any],
        match_type: str = "none",
    ) -> ValidationResult:
        # Basic structure validation (fail-closed only here)
        if not isinstance(applied_strategy, dict):
            return ValidationResult.failure(
                reason=f"applied_strategy must be dict, got {type(applied_strategy)}",
                recommendation="Ensure domain_rules.json strategies are dicts",
            )
        if "type" not in applied_strategy:
            return ValidationResult.failure(
                reason="strategy missing required field 'type'",
                recommendation="Fix domain_rules.json entry: add 'type'",
            )

        # Soft validation against expected rule (fail-open)
        expected = self.domain_rules.get(domain) if domain else None
        mismatches: List[str] = []

        if match_type == "exact" and isinstance(expected, dict):
            if expected.get("type") != applied_strategy.get("type"):
                mismatches.append(
                    f"type mismatch: expected={expected.get('type')}, applied={applied_strategy.get('type')}"
                )

            expected_params = (
                expected.get("params", {}) if isinstance(expected.get("params", {}), dict) else {}
            )
            applied_params = (
                applied_strategy.get("params", {})
                if isinstance(applied_strategy.get("params", {}), dict)
                else {}
            )

            # compare only "core" knobs (avoid noisy mismatches on harmless params)
            keys = ("split_pos", "split_count", "ttl", "fake_ttl", "fooling", "overlap_size")
            for k in keys:
                if k in expected_params and expected_params.get(k) != applied_params.get(k):
                    mismatches.append(
                        f"param '{k}' mismatch: expected={expected_params.get(k)!r}, applied={applied_params.get(k)!r}"
                    )

        if mismatches:
            return ValidationResult(
                valid=True,
                warning="strategy differs from expected domain_rules.json entry",
                recommendation="Review domain_rules.json for testing/production parity",
                mismatches=mismatches,
            )

        return ValidationResult.success()
