# File: core/testing/testing_mode_adapter.py
"""
Testing mode compatibility adapter.

This module provides functions to ensure strategy configurations are compatible
with testing mode, preventing discrepancies between testing and production modes.
"""

import logging
from typing import Dict, Any

LOG = logging.getLogger("testing_mode_adapter")


def ensure_testing_mode_compatibility(
    forced_config: Dict[str, Any],
    logger: logging.Logger = None,
) -> Dict[str, Any]:
    """
    Ensure strategy configuration is 100% compatible with testing mode.

    This function applies all necessary transformations to make a strategy
    configuration identical to how it would be processed in service mode,
    preventing discrepancies between testing and production.

    Key transformations:
    1. Force no_fallbacks and forced flags
    2. Normalize fooling parameter to list
    3. Set fake_ttl defaults for disorder attacks
    4. Convert split_pos to safe format
    5. Fix overlap_size for fakeddisorder (CRITICAL)
    6. Apply low-level defaults (repeats, tcp_flags, window_div, ipid_step)

    Args:
        forced_config: Strategy configuration dictionary
        logger: Optional logger instance

    Returns:
        Modified configuration dictionary with testing mode compatibility

    Examples:
        >>> config = {"type": "fakeddisorder", "params": {"ttl": 5}}
        >>> result = ensure_testing_mode_compatibility(config)
        >>> result["no_fallbacks"]
        True
        >>> result["params"]["fake_ttl"]
        5

    Requirements: 11.1, 11.4, 11.5, 12.1
    """
    logger = logger or LOG

    config = forced_config.copy()
    params = config.get("params", {}).copy()
    attack_type = (config.get("type") or "").lower()

    # 1) Force critical flags
    config["no_fallbacks"] = True
    config["forced"] = True

    # 2) Normalize fooling parameter to list
    if "fooling" in params:
        fool = params["fooling"]
        if isinstance(fool, str):
            if fool.lower() in ("none", ""):
                params["fooling"] = []
            else:
                params["fooling"] = [x.strip() for x in fool.split(",") if x.strip()]
        elif not isinstance(fool, (list, tuple)):
            params["fooling"] = [str(fool)]

    # 3) Set fake_ttl defaults for disorder attacks
    if attack_type in (
        "fakeddisorder",
        "fake",
        "disorder",
        "multidisorder",
        "disorder2",
        "seqovl",
    ):
        if "fake_ttl" not in params and "ttl" in params and params["ttl"] is not None:
            params["fake_ttl"] = params["ttl"]
        elif "fake_ttl" not in params and "autottl" not in params:
            params["fake_ttl"] = 3  # Default to 3 for consistency

    # 4) Convert split_pos to safe format
    if "split_pos" in params and params["split_pos"] is not None:
        from core.bypass.engine.base_engine import safe_split_pos_conversion

        sp_val = params["split_pos"]
        if isinstance(sp_val, list) and sp_val:
            sp_val = sp_val[0]
        params["split_pos"] = safe_split_pos_conversion(sp_val, 3)

    # 5) CRITICAL FIX: overlap_size for fakeddisorder
    # For fakeddisorder attack, overlap_size MUST be 0 to activate
    # correct 'disorder' logic in primitives.py. Remove all interfering parameters.
    if attack_type == "fakeddisorder":
        # Force clear all parameters that can confuse fakeddisorder
        params["overlap_size"] = 0
        params.pop("split_seqovl", None)
        params.pop("split_count", None)
        # Ensure correct disorder logic is used
        logger.debug(
            "✅ FAKEDDISORDER SANITIZED: Removed split_seqovl/split_count, set overlap_size=0"
        )
    elif attack_type in ("disorder", "disorder2", "multidisorder"):
        params["overlap_size"] = 0
        params.pop("split_seqovl", None)
        logger.debug(f"Sanitized for '{attack_type}': overlap_size forced to 0.")
    elif attack_type == "seqovl":
        ovl_raw = params.get("overlap_size", params.get("split_seqovl", 336))
        try:
            params["overlap_size"] = int(ovl_raw)
        except (ValueError, TypeError):
            params["overlap_size"] = 336

    # 6) Apply low-level defaults
    if "repeats" in params:
        try:
            params["repeats"] = max(1, min(int(params["repeats"]), 10))
        except (ValueError, TypeError):
            params["repeats"] = 1

    if "tcp_flags" not in params:
        params["tcp_flags"] = {"psh": True, "ack": True}

    if "window_div" not in params:
        params["window_div"] = 8 if "disorder" in attack_type else 2

    if "ipid_step" not in params:
        params["ipid_step"] = 2048

    config["params"] = params
    logger.debug(f"✅ Testing-compat for '{attack_type}': {params}")

    return config


def normalize_fooling_parameter(fooling: Any) -> list:
    """
    Normalize fooling parameter to list format.

    Args:
        fooling: Fooling parameter (str, list, or other)

    Returns:
        List of fooling values

    Examples:
        >>> normalize_fooling_parameter("md5,badsum")
        ['md5', 'badsum']

        >>> normalize_fooling_parameter("none")
        []

        >>> normalize_fooling_parameter(["md5"])
        ['md5']
    """
    if isinstance(fooling, str):
        if fooling.lower() in ("none", ""):
            return []
        return [x.strip() for x in fooling.split(",") if x.strip()]
    elif isinstance(fooling, (list, tuple)):
        return list(fooling)
    else:
        return [str(fooling)]


def apply_disorder_attack_defaults(
    attack_type: str,
    params: Dict[str, Any],
    logger: logging.Logger = None,
) -> Dict[str, Any]:
    """
    Apply specific defaults for disorder-type attacks.

    Disorder attacks (fakeddisorder, disorder, multidisorder, disorder2, seqovl)
    require specific parameter configurations to work correctly.

    Args:
        attack_type: Attack type string
        params: Parameters dictionary
        logger: Optional logger instance

    Returns:
        Modified parameters dictionary

    Examples:
        >>> params = {"ttl": 5}
        >>> result = apply_disorder_attack_defaults("fakeddisorder", params)
        >>> result["fake_ttl"]
        5
        >>> result["overlap_size"]
        0
    """
    logger = logger or LOG
    params = params.copy()

    # Set fake_ttl for disorder attacks
    if attack_type in (
        "fakeddisorder",
        "fake",
        "disorder",
        "multidisorder",
        "disorder2",
        "seqovl",
    ):
        if "fake_ttl" not in params and "ttl" in params and params["ttl"] is not None:
            params["fake_ttl"] = params["ttl"]
        elif "fake_ttl" not in params and "autottl" not in params:
            params["fake_ttl"] = 3

    # Handle overlap_size based on attack type
    if attack_type == "fakeddisorder":
        params["overlap_size"] = 0
        params.pop("split_seqovl", None)
        params.pop("split_count", None)
        logger.debug("FAKEDDISORDER: Set overlap_size=0, removed split_seqovl/split_count")
    elif attack_type in ("disorder", "disorder2", "multidisorder"):
        params["overlap_size"] = 0
        params.pop("split_seqovl", None)
        logger.debug(f"{attack_type}: Set overlap_size=0")
    elif attack_type == "seqovl":
        ovl_raw = params.get("overlap_size", params.get("split_seqovl", 336))
        try:
            params["overlap_size"] = int(ovl_raw)
        except (ValueError, TypeError):
            params["overlap_size"] = 336

    return params


def apply_low_level_defaults(
    attack_type: str,
    params: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Apply low-level default parameters for all attacks.

    These defaults ensure consistent behavior across testing and production modes.

    Args:
        attack_type: Attack type string
        params: Parameters dictionary

    Returns:
        Modified parameters dictionary

    Examples:
        >>> params = {}
        >>> result = apply_low_level_defaults("fakeddisorder", params)
        >>> result["tcp_flags"]
        {'psh': True, 'ack': True}
        >>> result["window_div"]
        8
    """
    params = params.copy()

    # Repeats: 1-10 range
    if "repeats" in params:
        try:
            params["repeats"] = max(1, min(int(params["repeats"]), 10))
        except (ValueError, TypeError):
            params["repeats"] = 1

    # TCP flags
    if "tcp_flags" not in params:
        params["tcp_flags"] = {"psh": True, "ack": True}

    # Window divisor (higher for disorder attacks)
    if "window_div" not in params:
        params["window_div"] = 8 if "disorder" in attack_type else 2

    # IP ID step
    if "ipid_step" not in params:
        params["ipid_step"] = 2048

    return params
