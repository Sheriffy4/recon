"""
File I/O Operations Module for UnifiedStrategyLoader.

This module contains all file input/output operations for loading and saving strategies.
"""

import json
import logging
from typing import Dict, Any, Optional, Union
from pathlib import Path
from datetime import datetime


def load_strategies_from_file(
    file_path: Union[str, Path],
    load_strategy_func: callable,
    logger: logging.Logger,
    debug: bool = False,
) -> Dict[str, Any]:
    """
    Load multiple strategies from a JSON file.

    Args:
        file_path: Path to JSON file containing strategies
        load_strategy_func: Function to load individual strategies
        logger: Logger instance
        debug: Enable debug logging

    Returns:
        Dict mapping domain/key to normalized strategy

    Raises:
        Exception: If file cannot be loaded (StrategyLoadError)
    """
    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(f"Strategy file not found: {file_path}")

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise json.JSONDecodeError(f"Invalid JSON in strategy file {file_path}", e.doc, e.pos)
    except OSError as e:
        raise OSError(f"Failed to read strategy file {file_path}: {e}")

    strategies = {}

    # Handle different JSON formats
    if isinstance(data, dict):
        for key, value in data.items():
            try:
                if isinstance(value, str):
                    # String strategy
                    strategies[key] = load_strategy_func(value)
                elif isinstance(value, dict):
                    # Dict strategy or nested structure
                    if "strategy" in value:
                        # Nested format: {"domain": {"strategy": "..."}}
                        strategies[key] = load_strategy_func(value["strategy"])
                    else:
                        # Direct dict format
                        strategies[key] = load_strategy_func(value)
                else:
                    logger.warning(f"Skipping invalid strategy for {key}: {value}")
            except Exception as e:
                logger.error(f"Failed to load strategy for {key}: {e}")
                # Continue loading other strategies

    if debug:
        logger.debug(f"Loaded {len(strategies)} strategies from {file_path}")

    return strategies


def load_all_strategies_from_domain_file(
    file_path: str,
    load_strategy_func: callable,
    logger: logging.Logger,
    debug: bool = False,
) -> Dict[str, Any]:
    """
    Load all strategies from domain_strategies.json file.

    Args:
        file_path: Path to the strategies JSON file (default: domain_strategies.json)
        load_strategy_func: Function to load individual strategies
        logger: Logger instance
        debug: Enable debug logging

    Returns:
        Dict mapping domain to normalized strategy

    Raises:
        Exception: If file cannot be loaded or parsed (StrategyLoadError)
    """
    file_path = Path(file_path)

    if not file_path.exists():
        logger.warning(f"Strategy file not found: {file_path}")
        return {}

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise json.JSONDecodeError(f"Invalid JSON in strategy file {file_path}", e.doc, e.pos)
    except OSError as e:
        raise OSError(f"Failed to read strategy file {file_path}: {e}")

    strategies = {}

    # Handle domain_strategies.json format
    if "domain_strategies" in data:
        # New format with metadata
        domain_strategies = data["domain_strategies"]
        for domain, strategy_data in domain_strategies.items():
            try:
                if isinstance(strategy_data, dict) and "strategy" in strategy_data:
                    # Extract strategy string from nested structure
                    strategy_str = strategy_data["strategy"]
                    strategies[domain] = load_strategy_func(strategy_str)
                elif isinstance(strategy_data, str):
                    # Direct strategy string
                    strategies[domain] = load_strategy_func(strategy_data)
                elif isinstance(strategy_data, dict):
                    # Dict format strategy
                    strategies[domain] = load_strategy_func(strategy_data)
                else:
                    logger.warning(f"Skipping invalid strategy for {domain}: {strategy_data}")
            except Exception as e:
                logger.error(f"Failed to load strategy for {domain}: {e}")
                # Continue loading other strategies
    else:
        # Legacy format - direct domain to strategy mapping
        for domain, strategy_data in data.items():
            # Skip metadata fields
            if domain in ["version", "last_updated"]:
                continue

            try:
                if isinstance(strategy_data, str):
                    strategies[domain] = load_strategy_func(strategy_data)
                elif isinstance(strategy_data, dict):
                    if "strategy" in strategy_data:
                        strategies[domain] = load_strategy_func(strategy_data["strategy"])
                    else:
                        strategies[domain] = load_strategy_func(strategy_data)
                else:
                    logger.warning(f"Skipping invalid strategy for {domain}: {strategy_data}")
            except Exception as e:
                logger.error(f"Failed to load strategy for {domain}: {e}")
                # Continue loading other strategies

    if debug:
        logger.debug(f"Loaded {len(strategies)} strategies from {file_path}")

    return strategies


def save_strategy_to_file(
    domain: str,
    strategy: Any,  # Union[str, Dict[str, Any], NormalizedStrategy]
    file_path: str,
    load_strategy_func: callable,
    logger: logging.Logger,
    debug: bool = False,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Save a strategy for a domain to domain_strategies.json file.

    Args:
        domain: Domain name
        strategy: Strategy to save (string, dict, or NormalizedStrategy)
        file_path: Path to the strategies JSON file
        load_strategy_func: Function to load/validate strategies
        logger: Logger instance
        debug: Enable debug logging
        metadata: Optional metadata to save with the strategy

    Raises:
        Exception: If file cannot be written (StrategyLoadError)
    """
    file_path = Path(file_path)

    # Load existing strategies
    existing_data = {}
    if file_path.exists():
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                existing_data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Failed to read existing strategies from {file_path}: {e}")
            existing_data = {}

    # Ensure domain_strategies structure exists
    if "domain_strategies" not in existing_data:
        existing_data["domain_strategies"] = {}

    # Normalize the strategy
    # Check if it's a NormalizedStrategy object (has raw_string attribute)
    if hasattr(strategy, "raw_string"):
        strategy_str = strategy.raw_string
    elif isinstance(strategy, dict):
        # Convert dict to string format
        normalized = load_strategy_func(strategy)
        strategy_str = normalized.raw_string
    elif isinstance(strategy, str):
        # Validate the strategy string
        normalized = load_strategy_func(strategy)
        strategy_str = strategy
    else:
        raise ValueError(
            f"Invalid strategy type: {type(strategy)}. Must be str, dict, or NormalizedStrategy"
        )

    # Create strategy entry
    strategy_entry = {
        "domain": domain,
        "strategy": strategy_str,
        "last_tested": datetime.now().isoformat(),
    }

    # Add metadata if provided
    if metadata:
        strategy_entry.update(metadata)

    # Update domain_strategies
    existing_data["domain_strategies"][domain] = strategy_entry

    # Update file metadata
    existing_data["last_updated"] = datetime.now().isoformat()
    if "version" not in existing_data:
        existing_data["version"] = "2.0"

    # Write to file
    try:
        # Create parent directory if it doesn't exist
        file_path.parent.mkdir(parents=True, exist_ok=True)

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(existing_data, f, indent=2, ensure_ascii=False)

        if debug:
            logger.debug(f"Saved strategy for {domain} to {file_path}: {strategy_str}")
    except OSError as e:
        raise OSError(f"Failed to write strategy file {file_path}: {e}")


def save_all_strategies_to_file(
    strategies: Dict[str, Any],  # Dict[str, Union[str, Dict[str, Any], NormalizedStrategy]]
    file_path: str,
    load_strategy_func: callable,
    logger: logging.Logger,
    debug: bool = False,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Save multiple strategies to domain_strategies.json file.

    Args:
        strategies: Dict mapping domain to strategy
        file_path: Path to the strategies JSON file
        load_strategy_func: Function to load/validate strategies
        logger: Logger instance
        debug: Enable debug logging
        metadata: Optional global metadata

    Raises:
        Exception: If file cannot be written (StrategyLoadError)
    """
    file_path = Path(file_path)

    # Load existing data to preserve metadata
    existing_data = {}
    if file_path.exists():
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                existing_data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Failed to read existing strategies from {file_path}: {e}")
            existing_data = {}

    # Ensure structure
    if "domain_strategies" not in existing_data:
        existing_data["domain_strategies"] = {}

    # Process each strategy
    for domain, strategy in strategies.items():
        try:
            # Normalize the strategy
            # Check if it's a NormalizedStrategy object (has raw_string attribute)
            if hasattr(strategy, "raw_string"):
                strategy_str = strategy.raw_string
            elif isinstance(strategy, dict):
                if "strategy" in strategy:
                    # Already in correct format
                    existing_data["domain_strategies"][domain] = strategy
                    continue
                else:
                    # Convert dict to string format
                    normalized = load_strategy_func(strategy)
                    strategy_str = normalized.raw_string
            elif isinstance(strategy, str):
                # Validate the strategy string
                normalized = load_strategy_func(strategy)
                strategy_str = strategy
            else:
                logger.warning(f"Skipping invalid strategy for {domain}: {type(strategy)}")
                continue

            # Create strategy entry
            strategy_entry = {
                "domain": domain,
                "strategy": strategy_str,
                "last_tested": datetime.now().isoformat(),
            }

            # Add per-domain metadata if available
            if metadata and domain in metadata:
                strategy_entry.update(metadata[domain])

            existing_data["domain_strategies"][domain] = strategy_entry

        except Exception as e:
            logger.error(f"Failed to process strategy for {domain}: {e}")
            # Continue with other strategies

    # Update file metadata
    existing_data["last_updated"] = datetime.now().isoformat()
    if "version" not in existing_data:
        existing_data["version"] = "2.0"

    # Write to file
    try:
        # Create parent directory if it doesn't exist
        file_path.parent.mkdir(parents=True, exist_ok=True)

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(existing_data, f, indent=2, ensure_ascii=False)

        if debug:
            logger.debug(f"Saved {len(strategies)} strategies to {file_path}")
    except OSError as e:
        raise OSError(f"Failed to write strategy file {file_path}: {e}")
