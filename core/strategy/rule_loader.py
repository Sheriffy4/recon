"""
Rule Loader
Loads default rules from JSON file.
"""

import logging
from pathlib import Path
from typing import List

from .models import Rule
from .rule_evaluator import RuleCondition

LOG = logging.getLogger("strategy_rule_engine.loader")


def load_default_rules() -> List[Rule]:
    """
    Load default strategy rules from JSON file.

    Returns:
        List of Rule objects

    Raises:
        FileNotFoundError: If default_rules.json not found
        ValueError: If rules data is invalid
    """
    # Find default_rules.json in the same directory as this module
    current_dir = Path(__file__).parent
    rules_file = current_dir / "default_rules.json"

    if not rules_file.exists():
        raise FileNotFoundError(f"Default rules file not found: {rules_file}")

    # Use RulePersistence to load rules
    from .rule_persistence import RulePersistence

    try:
        # Load rules from JSON
        rules = RulePersistence.load_rules_from_file(str(rules_file), Rule)

        # Convert condition strings to RuleCondition enums
        for rule in rules:
            for condition in rule.conditions:
                if isinstance(condition["condition"], str):
                    condition["condition"] = RuleCondition(condition["condition"])

        LOG.info(f"Loaded {len(rules)} default rules from {rules_file.name}")
        return rules

    except Exception as e:
        LOG.error(f"Failed to load default rules: {e}")
        raise ValueError(f"Invalid default rules data: {e}") from e


def get_default_rules_path() -> Path:
    """
    Get the path to the default rules JSON file.

    Returns:
        Path to default_rules.json
    """
    return Path(__file__).parent / "default_rules.json"
