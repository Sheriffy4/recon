"""
Rule Persistence
Handles loading and saving rules to/from JSON files.
"""

import logging
import json
from typing import List
from enum import Enum

LOG = logging.getLogger("strategy_rule_engine.persistence")


class RulePersistence:
    """Handles rule serialization and deserialization."""

    @staticmethod
    def load_rules_from_file(file_path: str, rule_class):
        """
        Load rules from JSON file.

        Args:
            file_path: Path to JSON file
            rule_class: Rule class to instantiate

        Returns:
            List of Rule objects

        Raises:
            FileNotFoundError: If file doesn't exist
            json.JSONDecodeError: If file contains invalid JSON
            ValueError: If rule data is invalid
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                rules_data = json.load(f)

            rules = []
            for rule_dict in rules_data:
                rule = rule_class(**rule_dict)
                rules.append(rule)

            LOG.info(f"Loaded {len(rules)} rules from {file_path}")
            return rules

        except FileNotFoundError:
            LOG.error(f"Rule file not found: {file_path}")
            raise
        except json.JSONDecodeError as e:
            LOG.error(f"Invalid JSON in rule file {file_path}: {e}")
            raise
        except (TypeError, ValueError) as e:
            LOG.error(f"Invalid rule data in {file_path}: {e}")
            raise

    @staticmethod
    def save_rules_to_file(rules: List, file_path: str):
        """
        Save rules to JSON file.

        Args:
            rules: List of Rule objects
            file_path: Path to save JSON file

        Raises:
            IOError: If file cannot be written
        """
        try:
            rules_data = []
            for rule in rules:
                # Ensure JSON-serializable condition types (RuleCondition Enum -> str)
                conditions = []
                for cond in getattr(rule, "conditions", []) or []:
                    if isinstance(cond, dict):
                        cond_copy = cond.copy()
                        ctype = cond_copy.get("condition")
                        if isinstance(ctype, Enum):
                            cond_copy["condition"] = ctype.value
                        conditions.append(cond_copy)
                    else:
                        conditions.append(cond)

                rule_dict = {
                    "rule_id": rule.rule_id,
                    "name": rule.name,
                    "description": rule.description,
                    "conditions": conditions,
                    "recommendations": rule.recommendations,
                    "priority": rule.priority,
                    "confidence_modifier": rule.confidence_modifier,
                    "enabled": rule.enabled,
                }
                rules_data.append(rule_dict)

            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(rules_data, f, indent=2, ensure_ascii=False)

            LOG.info(f"Saved {len(rules)} rules to {file_path}")

        except IOError as e:
            LOG.error(f"Failed to save rules to {file_path}: {e}")
            raise
        except Exception as e:
            LOG.error(f"Unexpected error saving rules to {file_path}: {e}")
            raise
