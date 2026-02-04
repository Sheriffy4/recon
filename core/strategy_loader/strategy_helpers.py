# Файл: core/strategy_loader/strategy_helpers.py
"""
Strategy Helper Utilities

This module contains utility functions for strategy manipulation and normalization.
"""

import logging
from typing import Dict, Any, List, Optional


def sanitize_strategy_name(
    name: str, debug: bool = False, logger: Optional[logging.Logger] = None
) -> str:
    """
    Remove 'existing_' prefix from strategy name.

    This is a defensive measure to prevent corrupted strategy names
    from causing errors in the attack dispatcher.

    Args:
        name: Strategy name to sanitize
        debug: Enable debug logging
        logger: Logger instance

    Returns:
        Sanitized strategy name
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    if isinstance(name, str):
        # Keep removing 'existing_' prefix until there are no more
        while name.startswith("existing_"):
            name = name.replace("existing_", "", 1)
            if debug:
                logger.warning(f"Removed 'existing_' prefix from strategy name: {name}")
    return name


def normalize_attack_parameters(attacks: List[str], params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize attack parameters to ensure required parameters are present.

    Args:
        attacks: List of attack types
        params: Current parameters

    Returns:
        Normalized parameters with required values added
    """
    normalized = params.copy()

    # Fix disorder attacks missing disorder_method
    disorder_attacks = ["disorder", "multidisorder", "fakeddisorder"]
    if any(attack in attacks for attack in disorder_attacks):
        if "disorder_method" not in normalized:
            normalized["disorder_method"] = "reverse"

    # Fix fake attacks missing TTL parameters
    fake_attacks = ["fake", "fakeddisorder"]
    if any(attack in attacks for attack in fake_attacks):
        if not any(ttl_param in normalized for ttl_param in ["ttl", "fake_ttl", "autottl"]):
            normalized["fake_ttl"] = 3

    # Fix seqovl attacks missing parameters
    if "seqovl" in attacks:
        if "overlap_size" not in normalized:
            normalized["overlap_size"] = 2
        if "fake_ttl" not in normalized:
            normalized["fake_ttl"] = 3
        if "fooling" not in normalized:
            normalized["fooling"] = ["badsum"]

    # Fix split attacks missing split_pos
    split_attacks = ["split", "multisplit"]
    if any(attack in attacks for attack in split_attacks):
        if "split_pos" not in normalized and "positions" not in normalized:
            normalized["split_pos"] = 3

    return normalized


def create_forced_override_config(
    strategy: Any,
    debug: bool = False,
    logger: Optional[logging.Logger] = None,
) -> Dict[str, Any]:
    """
    Create a forced override configuration from a strategy.

    Args:
        strategy: Strategy object (NormalizedStrategy or dict)
        debug: Enable debug logging
        logger: Logger instance

    Returns:
        Forced override configuration dictionary

    Raises:
        ValueError: If strategy type is invalid
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    # Import here to avoid circular dependency
    from core.unified_strategy_loader import NormalizedStrategy

    if isinstance(strategy, NormalizedStrategy):
        base_config = strategy.to_engine_format()
    elif isinstance(strategy, dict):
        base_config = strategy.copy()
    else:
        raise ValueError(f"Invalid strategy type for forced override: {type(strategy)}")

    forced_config = {
        "type": base_config.get("type", "fakeddisorder"),
        "params": base_config.get("params", {}),
        "no_fallbacks": True,
        "forced": True,
        "override_mode": True,
    }

    # CRITICAL FIX: Include 'attacks' field for combination attacks
    # This ensures testing-production parity for combo strategies
    if "attacks" in base_config:
        forced_config["attacks"] = base_config["attacks"]
        if debug:
            logger.debug(f"Included attacks field in forced override: {base_config['attacks']}")

    if debug:
        logger.debug(f"Created forced override: {forced_config}")
    return forced_config


def normalize_strategy_dict_format(
    strategy_dict: Dict[str, Any],
    debug: bool = False,
    logger: Optional[logging.Logger] = None,
) -> Any:
    """
    Normalize a strategy dictionary to standard format.

    This function handles various dictionary formats and ensures
    they are normalized to the standard NormalizedStrategy format.

    Args:
        strategy_dict: Strategy dictionary to normalize
        debug: Enable debug logging
        logger: Logger instance

    Returns:
        NormalizedStrategy object

    Raises:
        ValueError: If dictionary format is invalid
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    # Import here to avoid circular dependency
    from core.unified_strategy_loader import NormalizedStrategy

    # Handle different dict formats
    if "attack_type" in strategy_dict:
        # ParsedStrategy-like format
        attack_type = strategy_dict["attack_type"]
        attacks = strategy_dict.get(
            "attacks", [attack_type]
        )  # Preserve attacks or default to single
        return NormalizedStrategy(
            type=attack_type,
            params=strategy_dict.get("params", {}),
            attacks=attacks,  # Include attacks field
            no_fallbacks=True,
            forced=True,
            raw_string=strategy_dict.get("raw_string", ""),
            source_format=strategy_dict.get("syntax_type", "dict"),
        )
    elif "type" in strategy_dict:
        # Direct format
        attack_type = strategy_dict["type"]
        attacks = strategy_dict.get(
            "attacks", [attack_type]
        )  # Preserve attacks or default to single
        return NormalizedStrategy(
            type=attack_type,
            params=strategy_dict.get("params", {}),
            attacks=attacks,  # Include attacks field
            no_fallbacks=True,
            forced=True,
            raw_string=str(strategy_dict),
            source_format="dict",
        )
    else:
        raise ValueError(f"Invalid strategy dict format: {strategy_dict}")
