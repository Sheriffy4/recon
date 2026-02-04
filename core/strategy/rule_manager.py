"""
Rule Manager
Handles CRUD operations for strategy rules.
"""

import logging
from typing import List, Dict, Any

from .models import Rule

LOG = logging.getLogger("strategy_rule_engine.manager")


class RuleManager:
    """Manages a collection of rules with CRUD operations."""

    def __init__(self):
        self.rules: List[Rule] = []
        self.rule_stats = {
            "evaluations": 0,
            "rule_matches": 0,
            "recommendations_generated": 0,
        }

    def add_rule(self, rule: Rule):
        """Add a new rule to the collection"""
        self.rules.append(rule)
        LOG.info(f"Added rule: {rule.name}")

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by ID"""
        for i, rule in enumerate(self.rules):
            if rule.rule_id == rule_id:
                removed_rule = self.rules.pop(i)
                LOG.info(f"Removed rule: {removed_rule.name}")
                return True
        return False

    def enable_rule(self, rule_id: str) -> bool:
        """Enable a rule by ID"""
        for rule in self.rules:
            if rule.rule_id == rule_id:
                rule.enabled = True
                LOG.info(f"Enabled rule: {rule.name}")
                return True
        return False

    def disable_rule(self, rule_id: str) -> bool:
        """Disable a rule by ID"""
        for rule in self.rules:
            if rule.rule_id == rule_id:
                rule.enabled = False
                LOG.info(f"Disabled rule: {rule.name}")
                return True
        return False

    def get_rule_statistics(self) -> Dict[str, Any]:
        """Get statistics about the rule collection"""
        return {
            "total_rules": len(self.rules),
            "enabled_rules": len([r for r in self.rules if r.enabled]),
            "disabled_rules": len([r for r in self.rules if not r.enabled]),
            "rule_stats": self.rule_stats.copy(),
        }

    def increment_evaluations(self):
        """Increment evaluation counter"""
        self.rule_stats["evaluations"] += 1

    def increment_matches(self):
        """Increment match counter"""
        self.rule_stats["rule_matches"] += 1

    def increment_recommendations(self, count: int):
        """Increment recommendations counter"""
        self.rule_stats["recommendations_generated"] += count
