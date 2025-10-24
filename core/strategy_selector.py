"""
StrategySelector - Core class for strategy selection with priority logic.

This module implements the priority-based strategy selection system:
1. Domain rules (exact match) - highest priority
2. Domain rules (wildcard match) - second priority
3. IP rules - third priority
4. Global/fallback strategy - lowest priority

Requirements addressed: 1.1, 1.2, 1.3, 1.4, 1.5, 4.1, 4.2, 4.3, 6.1, 6.2, 6.3, 6.4
"""

import logging
import fnmatch
from typing import Dict, Optional, Any, List
from dataclasses import dataclass
from datetime import datetime


@dataclass
class StrategyResult:
    """Result of strategy selection with metadata."""

    strategy: str
    source: str  # 'domain_exact', 'domain_wildcard', 'ip', 'global'
    domain_matched: Optional[str] = None
    ip_matched: Optional[str] = None
    priority: int = 0
    timestamp: float = 0.0

    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = datetime.now().timestamp()


@dataclass
class DomainRule:
    """Domain rule with wildcard support."""

    pattern: str
    strategy: str
    priority: int = 1
    is_wildcard: bool = False
    success_rate: float = 0.0
    last_updated: Optional[datetime] = None

    def __post_init__(self):
        self.is_wildcard = "*" in self.pattern
        if self.last_updated is None:
            self.last_updated = datetime.now()


class StrategySelector:
    """
    Core strategy selector with priority logic: domain > IP > global.

    Implements requirements:
    - 1.1: Domain rules checked first
    - 1.2: Exact domain match over wildcard
    - 1.3: IP rules as fallback
    - 1.4: Global strategy as final fallback
    - 4.1-4.3: Wildcard pattern support
    - 6.1-6.4: Comprehensive logging
    """

    def __init__(
        self,
        domain_rules: Optional[Dict[str, str]] = None,
        ip_rules: Optional[Dict[str, str]] = None,
        global_strategy: Optional[str] = None,
    ):
        """
        Initialize StrategySelector.

        Args:
            domain_rules: Dict mapping domain patterns to strategies
            ip_rules: Dict mapping IP addresses to strategies
            global_strategy: Fallback strategy string
        """
        self.logger = logging.getLogger(__name__)

        # Initialize rule sets
        self.domain_rules: Dict[str, DomainRule] = {}
        self.ip_rules: Dict[str, str] = ip_rules or {}
        self.global_strategy = (
            global_strategy or "--dpi-desync=badsum_race --dpi-desync-ttl=4"
        )

        # Load domain rules
        if domain_rules:
            self.load_domain_rules(domain_rules)

        # Statistics
        self.stats = {
            "total_selections": 0,
            "domain_exact_matches": 0,
            "domain_wildcard_matches": 0,
            "ip_matches": 0,
            "global_fallbacks": 0,
        }

        self.logger.info(
            f"StrategySelector initialized with {len(self.domain_rules)} domain rules, "
            f"{len(self.ip_rules)} IP rules, global: {self.global_strategy}"
        )

    def load_domain_rules(self, rules: Dict[str, str]) -> None:
        """
        Load domain rules from dictionary.

        Args:
            rules: Dict mapping domain patterns to strategy strings
        """
        self.domain_rules.clear()

        for pattern, strategy in rules.items():
            if isinstance(strategy, dict):
                # Handle new format with metadata
                strategy_str = strategy.get("strategy", "")
                priority = strategy.get("priority", 1)
                success_rate = strategy.get("success_rate", 0.0)
            else:
                # Handle simple string format
                strategy_str = strategy
                priority = 1
                success_rate = 0.0

            rule = DomainRule(
                pattern=pattern.lower().strip(),
                strategy=strategy_str,
                priority=priority,
                success_rate=success_rate,
            )
            self.domain_rules[rule.pattern] = rule

        # Sort rules by priority (exact matches get higher priority than wildcards)
        self._sort_domain_rules()

        self.logger.info(f"Loaded {len(self.domain_rules)} domain rules")
        self._log_rule_summary()

    def _sort_domain_rules(self) -> None:
        """Sort domain rules by priority: exact > wildcard, then by priority value."""
        # Convert to list, sort, and rebuild dict
        rules_list = list(self.domain_rules.items())

        def rule_sort_key(item):
            pattern, rule = item
            # Exact matches get priority 0, wildcards get priority 1
            wildcard_penalty = 1 if rule.is_wildcard else 0
            return (wildcard_penalty, -rule.priority, pattern)

        rules_list.sort(key=rule_sort_key)
        self.domain_rules = dict(rules_list)

    def _log_rule_summary(self) -> None:
        """Log summary of loaded rules."""
        exact_rules = sum(
            1 for rule in self.domain_rules.values() if not rule.is_wildcard
        )
        wildcard_rules = sum(
            1 for rule in self.domain_rules.values() if rule.is_wildcard
        )

        self.logger.debug(
            f"Rule summary: {exact_rules} exact, {wildcard_rules} wildcard, "
            f"{len(self.ip_rules)} IP rules"
        )

        # Log some example rules
        for i, (pattern, rule) in enumerate(self.domain_rules.items()):
            if i < 5:  # Log first 5 rules
                rule_type = "wildcard" if rule.is_wildcard else "exact"
                strategy_str = rule.strategy
                strategy_preview = (
                    strategy_str[:50] if len(strategy_str) > 50 else strategy_str
                )
                self.logger.debug(f"  {rule_type}: {pattern} -> {strategy_preview}...")

    def select_strategy(self, sni: Optional[str], dst_ip: str) -> StrategyResult:
        """
        Select strategy based on priority: domain > IP > global.

        Args:
            sni: Server Name Indication from TLS ClientHello
            dst_ip: Destination IP address

        Returns:
            StrategyResult with selected strategy and metadata

        Requirements: 1.1, 1.2, 1.3, 1.4, 6.1, 6.2, 6.3, 6.4
        """
        self.stats["total_selections"] += 1

        # Priority 1: Domain rules (if SNI available)
        if sni:
            sni_lower = sni.lower().strip()

            # Check exact domain match first
            result = self._check_exact_domain_match(sni_lower)
            if result:
                self.stats["domain_exact_matches"] += 1
                self.logger.info(f"Domain strategy for SNI={sni}: {result.strategy}")
                return result

            # Check wildcard domain match
            result = self._check_wildcard_domain_match(sni_lower)
            if result:
                self.stats["domain_wildcard_matches"] += 1
                self.logger.info(
                    f"Wildcard strategy for SNI={sni} (pattern={result.domain_matched}): {result.strategy}"
                )
                return result

        # Priority 2: IP rules
        if dst_ip in self.ip_rules:
            self.stats["ip_matches"] += 1
            strategy = self.ip_rules[dst_ip]
            result = StrategyResult(
                strategy=strategy, source="ip", ip_matched=dst_ip, priority=2
            )
            self.logger.info(f"IP strategy for {dst_ip}: {strategy}")
            return result

        # Priority 3: Global fallback
        self.stats["global_fallbacks"] += 1
        result = StrategyResult(
            strategy=self.global_strategy, source="global", priority=3
        )
        self.logger.info(
            f"Fallback strategy for SNI={sni}/IP={dst_ip}: {self.global_strategy}"
        )
        return result

    def _check_exact_domain_match(self, sni: str) -> Optional[StrategyResult]:
        """Check for exact domain match."""
        if sni in self.domain_rules:
            rule = self.domain_rules[sni]
            if not rule.is_wildcard:  # Ensure it's an exact match
                return StrategyResult(
                    strategy=rule.strategy,
                    source="domain_exact",
                    domain_matched=sni,
                    priority=1,
                )
        return None

    def _check_wildcard_domain_match(self, sni: str) -> Optional[StrategyResult]:
        """Check for wildcard domain match."""
        for pattern, rule in self.domain_rules.items():
            if rule.is_wildcard and self._matches_wildcard_pattern(sni, pattern):
                return StrategyResult(
                    strategy=rule.strategy,
                    source="domain_wildcard",
                    domain_matched=pattern,
                    priority=1,
                )
        return None

    def _matches_wildcard_pattern(self, domain: str, pattern: str) -> bool:
        """
        Check if domain matches wildcard pattern.

        Supports patterns like:
        - *.twimg.com matches abs.twimg.com, pbs.twimg.com, etc.
        - *.googleapis.com matches youtubei.googleapis.com, etc.

        Requirements: 4.1, 4.2, 4.3
        """
        try:
            # Use fnmatch for simple wildcard matching
            if fnmatch.fnmatch(domain, pattern):
                return True

            # Additional logic for subdomain matching
            if pattern.startswith("*."):
                base_domain = pattern[2:]  # Remove *.
                if domain == base_domain or domain.endswith("." + base_domain):
                    return True

        except Exception as e:
            self.logger.warning(
                f"Error matching pattern {pattern} against {domain}: {e}"
            )

        return False

    def supports_wildcard(self, pattern: str) -> bool:
        """Check if pattern contains wildcard characters."""
        return "*" in pattern or "?" in pattern

    def add_domain_rule(self, pattern: str, strategy: str, priority: int = 1) -> None:
        """Add or update domain rule."""
        rule = DomainRule(
            pattern=pattern.lower().strip(), strategy=strategy, priority=priority
        )
        self.domain_rules[rule.pattern] = rule
        self._sort_domain_rules()

        rule_type = "wildcard" if rule.is_wildcard else "exact"
        self.logger.info(f"Added {rule_type} domain rule: {pattern} -> {strategy}")

    def add_ip_rule(self, ip: str, strategy: str) -> None:
        """Add or update IP rule."""
        self.ip_rules[ip] = strategy
        self.logger.info(f"Added IP rule: {ip} -> {strategy}")

    def remove_domain_rule(self, pattern: str) -> bool:
        """Remove domain rule."""
        pattern = pattern.lower().strip()
        if pattern in self.domain_rules:
            del self.domain_rules[pattern]
            self.logger.info(f"Removed domain rule: {pattern}")
            return True
        return False

    def remove_ip_rule(self, ip: str) -> bool:
        """Remove IP rule."""
        if ip in self.ip_rules:
            del self.ip_rules[ip]
            self.logger.info(f"Removed IP rule: {ip}")
            return True
        return False

    def get_statistics(self) -> Dict[str, Any]:
        """Get selection statistics."""
        total = self.stats["total_selections"]
        if total == 0:
            return self.stats.copy()

        stats = self.stats.copy()
        stats.update(
            {
                "domain_exact_percentage": (self.stats["domain_exact_matches"] / total)
                * 100,
                "domain_wildcard_percentage": (
                    self.stats["domain_wildcard_matches"] / total
                )
                * 100,
                "ip_percentage": (self.stats["ip_matches"] / total) * 100,
                "global_percentage": (self.stats["global_fallbacks"] / total) * 100,
                "total_domain_rules": len(self.domain_rules),
                "total_ip_rules": len(self.ip_rules),
            }
        )
        return stats

    def get_matching_domains(self, pattern: str) -> List[str]:
        """Get all domain rules that would match the given pattern."""
        matches = []
        pattern_lower = pattern.lower().strip()

        for rule_pattern in self.domain_rules.keys():
            rule = self.domain_rules[rule_pattern]
            if rule.is_wildcard:
                if self._matches_wildcard_pattern(pattern_lower, rule_pattern):
                    matches.append(rule_pattern)
            else:
                if rule_pattern == pattern_lower:
                    matches.append(rule_pattern)

        return matches

    def validate_configuration(self) -> List[str]:
        """Validate current configuration and return list of issues."""
        issues = []

        # Check for empty strategies
        for pattern, rule in self.domain_rules.items():
            if not rule.strategy.strip():
                issues.append(f"Empty strategy for domain pattern: {pattern}")

        for ip, strategy in self.ip_rules.items():
            if not strategy.strip():
                issues.append(f"Empty strategy for IP: {ip}")

        if not self.global_strategy.strip():
            issues.append("Empty global strategy")

        # Check for duplicate patterns (case insensitive)
        patterns_seen = set()
        for pattern in self.domain_rules.keys():
            if pattern in patterns_seen:
                issues.append(f"Duplicate domain pattern: {pattern}")
            patterns_seen.add(pattern)

        # Check wildcard pattern validity
        for pattern, rule in self.domain_rules.items():
            if rule.is_wildcard:
                try:
                    # Test pattern with a sample domain
                    self._matches_wildcard_pattern("test.example.com", pattern)
                except Exception as e:
                    issues.append(f"Invalid wildcard pattern {pattern}: {e}")

        return issues

    def reset_statistics(self) -> None:
        """Reset selection statistics."""
        self.stats = {
            "total_selections": 0,
            "domain_exact_matches": 0,
            "domain_wildcard_matches": 0,
            "ip_matches": 0,
            "global_fallbacks": 0,
        }
        self.logger.info("Statistics reset")

    def __str__(self) -> str:
        """String representation of StrategySelector."""
        return (
            f"StrategySelector(domain_rules={len(self.domain_rules)}, "
            f"ip_rules={len(self.ip_rules)}, "
            f"global_strategy='{self.global_strategy[:30]}...')"
        )

    def __repr__(self) -> str:
        """Detailed representation of StrategySelector."""
        return self.__str__()
