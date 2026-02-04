"""
Strategy Configuration Validator

This module provides comprehensive validation for strategy configurations,
including syntax validation, performance analysis, and optimization recommendations.
"""

import re
import logging
from typing import List, Optional
from dataclasses import dataclass

from .strategy_config_manager import (
    StrategyConfiguration,
)

logger = logging.getLogger(__name__)


@dataclass
class ValidationIssue:
    """Represents a validation issue found in configuration."""

    severity: str  # 'error', 'warning', 'info'
    category: str  # 'syntax', 'performance', 'optimization', 'compatibility'
    message: str
    location: str  # Where the issue was found
    suggestion: Optional[str] = None


@dataclass
class ValidationResult:
    """Result of configuration validation."""

    is_valid: bool
    issues: List[ValidationIssue]
    score: float  # Overall configuration quality score (0-100)
    recommendations: List[str]


class StrategyValidator:
    """Comprehensive strategy configuration validator."""

    # Known strategy patterns and their parameters
    STRATEGY_PATTERNS = {
        "multisplit": {
            "required_params": ["--dpi-desync=multisplit"],
            "optional_params": [
                "--dpi-desync-split-count",
                "--dpi-desync-split-seqovl",
                "--dpi-desync-fooling",
                "--dpi-desync-repeats",
                "--dpi-desync-ttl",
            ],
            "param_ranges": {
                "--dpi-desync-split-count": (2, 10),
                "--dpi-desync-split-seqovl": (5, 50),
                "--dpi-desync-repeats": (1, 5),
                "--dpi-desync-ttl": (1, 255),
            },
        },
        "fakedisorder": {
            "required_params": ["--dpi-desync=fake", "--dpi-desync=fakeddisorder"],
            "optional_params": [
                "--dpi-desync-split-pos",
                "--dpi-desync-fooling",
                "--dpi-desync-ttl",
            ],
            "param_ranges": {
                "--dpi-desync-split-pos": (1, 20),
                "--dpi-desync-ttl": (1, 255),
            },
        },
        "seqovl": {
            "required_params": ["--dpi-desync=fake", "--dpi-desync=disorder"],
            "optional_params": [
                "--dpi-desync-split-pos",
                "--dpi-desync-split-seqovl",
                "--dpi-desync-fooling",
                "--dpi-desync-ttl",
            ],
            "param_ranges": {
                "--dpi-desync-split-pos": (1, 20),
                "--dpi-desync-split-seqovl": (5, 50),
                "--dpi-desync-ttl": (1, 255),
            },
        },
        "badsum_race": {
            "required_params": ["--dpi-desync=fake", "--dpi-desync-fooling=badsum"],
            "optional_params": ["--dpi-desync-ttl", "--dpi-desync-split-pos"],
            "param_ranges": {
                "--dpi-desync-ttl": (1, 255),
                "--dpi-desync-split-pos": (1, 20),
            },
        },
    }

    # Known fooling methods
    FOOLING_METHODS = ["badsum", "badseq", "md5sig", "hopbyhop", "destopt"]

    # Performance thresholds
    PERFORMANCE_THRESHOLDS = {
        "min_success_rate": 0.7,
        "max_latency_ms": 500.0,
        "min_test_count": 10,
    }

    def __init__(self):
        """Initialize the validator."""
        self.issues = []
        self.recommendations = []

    def validate_configuration(self, config: StrategyConfiguration) -> ValidationResult:
        """
        Perform comprehensive validation of strategy configuration.

        Args:
            config: Configuration to validate

        Returns:
            ValidationResult with issues and recommendations
        """
        self.issues = []
        self.recommendations = []

        # Basic structure validation
        self._validate_structure(config)

        # Strategy syntax validation
        self._validate_strategy_syntax(config)

        # Performance validation
        self._validate_performance(config)

        # Optimization opportunities
        self._analyze_optimization_opportunities(config)

        # Compatibility checks
        self._validate_compatibility(config)

        # Calculate overall score
        score = self._calculate_quality_score()

        # Determine if configuration is valid (no errors)
        is_valid = not any(issue.severity == "error" for issue in self.issues)

        return ValidationResult(
            is_valid=is_valid,
            issues=self.issues.copy(),
            score=score,
            recommendations=self.recommendations.copy(),
        )

    def _validate_structure(self, config: StrategyConfiguration):
        """Validate basic configuration structure."""
        # Check version
        if config.version not in ["2.0", "3.0"]:
            self.issues.append(
                ValidationIssue(
                    severity="warning",
                    category="compatibility",
                    message=f"Unknown configuration version: {config.version}",
                    location="root.version",
                    suggestion="Use version 3.0 for latest features",
                )
            )

        # Check strategy priority
        if not config.strategy_priority:
            self.issues.append(
                ValidationIssue(
                    severity="warning",
                    category="syntax",
                    message="Missing strategy priority configuration",
                    location="root.strategy_priority",
                    suggestion="Add strategy_priority: ['domain', 'ip', 'global']",
                )
            )
        else:
            valid_priorities = {"domain", "ip", "global"}
            invalid_priorities = set(config.strategy_priority) - valid_priorities
            if invalid_priorities:
                self.issues.append(
                    ValidationIssue(
                        severity="error",
                        category="syntax",
                        message=f"Invalid strategy priorities: {invalid_priorities}",
                        location="root.strategy_priority",
                    )
                )

        # Check for empty configurations
        if not config.domain_strategies and not config.ip_strategies and not config.global_strategy:
            self.issues.append(
                ValidationIssue(
                    severity="error",
                    category="syntax",
                    message="Configuration has no strategies defined",
                    location="root",
                    suggestion="Add at least a global fallback strategy",
                )
            )

    def _validate_strategy_syntax(self, config: StrategyConfiguration):
        """Validate strategy syntax for all rules."""
        # Validate domain strategies
        for pattern, rule in config.domain_strategies.items():
            self._validate_single_strategy(rule.strategy, f"domain_strategies.{pattern}")
            self._validate_domain_pattern(pattern, f"domain_strategies.{pattern}")

        # Validate IP strategies
        for pattern, rule in config.ip_strategies.items():
            self._validate_single_strategy(rule.strategy, f"ip_strategies.{pattern}")
            self._validate_ip_pattern(pattern, f"ip_strategies.{pattern}")

        # Validate global strategy
        if config.global_strategy:
            self._validate_single_strategy(config.global_strategy.strategy, "global_strategy")

    def _validate_single_strategy(self, strategy: str, location: str):
        """Validate syntax of a single strategy string."""
        if not strategy or not strategy.strip():
            self.issues.append(
                ValidationIssue(
                    severity="error",
                    category="syntax",
                    message="Empty strategy string",
                    location=location,
                )
            )
            return

        # Check for basic zapret parameters
        if not re.search(r"--dpi-desync=\w+", strategy):
            self.issues.append(
                ValidationIssue(
                    severity="error",
                    category="syntax",
                    message="Missing --dpi-desync parameter",
                    location=location,
                    suggestion="Add --dpi-desync parameter (e.g., --dpi-desync=multisplit)",
                )
            )

        # Validate parameter values
        self._validate_strategy_parameters(strategy, location)

        # Check for deprecated parameters
        deprecated_params = ["--dpi-desync-window-div", "--dpi-desync-delay"]
        for param in deprecated_params:
            if param in strategy:
                self.issues.append(
                    ValidationIssue(
                        severity="warning",
                        category="compatibility",
                        message=f"Deprecated parameter: {param}",
                        location=location,
                        suggestion="Consider removing deprecated parameters",
                    )
                )

    def _validate_strategy_parameters(self, strategy: str, location: str):
        """Validate individual strategy parameters."""
        # Extract parameters
        params = {}

        # Parse --dpi-desync-split-count
        match = re.search(r"--dpi-desync-split-count=(\d+)", strategy)
        if match:
            count = int(match.group(1))
            if count < 2 or count > 10:
                self.issues.append(
                    ValidationIssue(
                        severity="warning",
                        category="performance",
                        message=f"Split count {count} may be suboptimal (recommended: 2-10)",
                        location=location,
                    )
                )

        # Parse --dpi-desync-split-seqovl
        match = re.search(r"--dpi-desync-split-seqovl=(\d+)", strategy)
        if match:
            seqovl = int(match.group(1))
            if seqovl < 5 or seqovl > 50:
                self.issues.append(
                    ValidationIssue(
                        severity="warning",
                        category="performance",
                        message=f"Sequence overlap {seqovl} may be suboptimal (recommended: 5-50)",
                        location=location,
                    )
                )

        # Parse --dpi-desync-ttl
        match = re.search(r"--dpi-desync-ttl=(\d+)", strategy)
        if match:
            ttl = int(match.group(1))
            if ttl < 1 or ttl > 255:
                self.issues.append(
                    ValidationIssue(
                        severity="error",
                        category="syntax",
                        message=f"Invalid TTL value: {ttl} (must be 1-255)",
                        location=location,
                    )
                )

        # Validate fooling methods
        match = re.search(r"--dpi-desync-fooling=([^\s]+)", strategy)
        if match:
            fooling_methods = match.group(1).split(",")
            for method in fooling_methods:
                if method not in self.FOOLING_METHODS:
                    self.issues.append(
                        ValidationIssue(
                            severity="warning",
                            category="syntax",
                            message=f"Unknown fooling method: {method}",
                            location=location,
                            suggestion=f"Valid methods: {', '.join(self.FOOLING_METHODS)}",
                        )
                    )

    def _validate_domain_pattern(self, pattern: str, location: str):
        """Validate domain pattern syntax."""
        if not pattern:
            self.issues.append(
                ValidationIssue(
                    severity="error",
                    category="syntax",
                    message="Empty domain pattern",
                    location=location,
                )
            )
            return

        # Check for valid domain characters
        if not re.match(r"^[a-zA-Z0-9.*-]+$", pattern):
            self.issues.append(
                ValidationIssue(
                    severity="warning",
                    category="syntax",
                    message=f"Domain pattern contains unusual characters: {pattern}",
                    location=location,
                )
            )

        # Check wildcard usage
        if "*" in pattern:
            if pattern.count("*") > 1:
                self.issues.append(
                    ValidationIssue(
                        severity="warning",
                        category="syntax",
                        message=f"Multiple wildcards in pattern may be too broad: {pattern}",
                        location=location,
                        suggestion="Consider using more specific patterns",
                    )
                )

            if not pattern.startswith("*."):
                self.issues.append(
                    ValidationIssue(
                        severity="warning",
                        category="syntax",
                        message=f"Wildcard not at subdomain level: {pattern}",
                        location=location,
                        suggestion="Use *.domain.com format for subdomains",
                    )
                )

    def _validate_ip_pattern(self, pattern: str, location: str):
        """Validate IP pattern syntax."""
        # Basic IP/CIDR validation
        if "/" in pattern:
            # CIDR notation
            try:
                ip, prefix = pattern.split("/")
                prefix_len = int(prefix)
                if prefix_len < 0 or prefix_len > 32:
                    self.issues.append(
                        ValidationIssue(
                            severity="error",
                            category="syntax",
                            message=f"Invalid CIDR prefix length: {prefix_len}",
                            location=location,
                        )
                    )
            except ValueError:
                self.issues.append(
                    ValidationIssue(
                        severity="error",
                        category="syntax",
                        message=f"Invalid CIDR notation: {pattern}",
                        location=location,
                    )
                )
        else:
            # Single IP validation
            parts = pattern.split(".")
            if len(parts) != 4:
                self.issues.append(
                    ValidationIssue(
                        severity="error",
                        category="syntax",
                        message=f"Invalid IP address format: {pattern}",
                        location=location,
                    )
                )

    def _validate_performance(self, config: StrategyConfiguration):
        """Validate performance-related aspects."""
        # Check for performance data
        strategies_with_data = 0
        low_performance_strategies = []

        for pattern, rule in config.domain_strategies.items():
            if rule.metadata.success_rate > 0:
                strategies_with_data += 1

                # Check success rate
                if rule.metadata.success_rate < self.PERFORMANCE_THRESHOLDS["min_success_rate"]:
                    low_performance_strategies.append(pattern)

                # Check latency
                if (
                    rule.metadata.avg_latency_ms > 0
                    and rule.metadata.avg_latency_ms > self.PERFORMANCE_THRESHOLDS["max_latency_ms"]
                ):
                    self.issues.append(
                        ValidationIssue(
                            severity="warning",
                            category="performance",
                            message=f"High latency for {pattern}: {rule.metadata.avg_latency_ms:.1f}ms",
                            location=f"domain_strategies.{pattern}",
                            suggestion="Consider optimizing strategy parameters",
                        )
                    )

                # Check test count
                if rule.metadata.test_count < self.PERFORMANCE_THRESHOLDS["min_test_count"]:
                    self.issues.append(
                        ValidationIssue(
                            severity="info",
                            category="performance",
                            message=f"Low test count for {pattern}: {rule.metadata.test_count}",
                            location=f"domain_strategies.{pattern}",
                            suggestion="Run more tests to improve confidence in metrics",
                        )
                    )

        # Overall performance warnings
        if strategies_with_data == 0:
            self.issues.append(
                ValidationIssue(
                    severity="warning",
                    category="performance",
                    message="No performance data available for any strategies",
                    location="root",
                    suggestion="Run tests to collect performance metrics",
                )
            )

        if low_performance_strategies:
            self.issues.append(
                ValidationIssue(
                    severity="warning",
                    category="performance",
                    message=f"Low success rate strategies: {', '.join(low_performance_strategies)}",
                    location="domain_strategies",
                    suggestion="Consider optimizing or replacing underperforming strategies",
                )
            )

    def _analyze_optimization_opportunities(self, config: StrategyConfiguration):
        """Analyze configuration for optimization opportunities."""
        # Check for wildcard consolidation opportunities
        domain_groups = {}
        for pattern in config.domain_strategies.keys():
            if not pattern.startswith("*") and "." in pattern:
                parts = pattern.split(".")
                if len(parts) >= 2:
                    base_domain = ".".join(parts[-2:])
                    if base_domain not in domain_groups:
                        domain_groups[base_domain] = []
                    domain_groups[base_domain].append(pattern)

        for base_domain, domains in domain_groups.items():
            if len(domains) > 2:
                self.recommendations.append(
                    f"Consider consolidating {len(domains)} {base_domain} subdomains "
                    f"with *.{base_domain} wildcard pattern"
                )

        # Check for missing Twitter optimizations
        twitter_patterns = ["x.com", "*.twimg.com", "twitter.com"]
        missing_twitter = []
        for pattern in twitter_patterns:
            if pattern not in config.domain_strategies:
                missing_twitter.append(pattern)

        if missing_twitter:
            self.recommendations.append(
                f"Add optimized strategies for Twitter/X.com: {', '.join(missing_twitter)}"
            )

        # Check for outdated strategy types
        outdated_strategies = []
        for pattern, rule in config.domain_strategies.items():
            if "seqovl" in rule.strategy and "twimg.com" in pattern:
                outdated_strategies.append(pattern)

        if outdated_strategies:
            self.recommendations.append(
                f"Update seqovl strategies to multisplit for better performance: "
                f"{', '.join(outdated_strategies)}"
            )

        # Check for missing global strategy
        if not config.global_strategy:
            self.recommendations.append("Add global fallback strategy for unmatched domains")

    def _validate_compatibility(self, config: StrategyConfiguration):
        """Validate compatibility with different systems."""
        # Check for Windows-specific issues
        for pattern, rule in config.domain_strategies.items():
            if "--filter-udp" in rule.strategy:
                self.issues.append(
                    ValidationIssue(
                        severity="info",
                        category="compatibility",
                        message=f"UDP filtering in {pattern} requires WinDivert on Windows",
                        location=f"domain_strategies.{pattern}",
                        suggestion="Ensure WinDivert is properly installed",
                    )
                )

        # Check for Linux-specific parameters
        linux_params = ["--dpi-desync-any-protocol"]
        for pattern, rule in config.domain_strategies.items():
            for param in linux_params:
                if param in rule.strategy:
                    self.issues.append(
                        ValidationIssue(
                            severity="info",
                            category="compatibility",
                            message=f"Linux-specific parameter {param} in {pattern}",
                            location=f"domain_strategies.{pattern}",
                            suggestion="May not work on Windows systems",
                        )
                    )

    def _calculate_quality_score(self) -> float:
        """Calculate overall configuration quality score (0-100)."""
        base_score = 100.0

        # Deduct points for issues
        for issue in self.issues:
            if issue.severity == "error":
                base_score -= 20
            elif issue.severity == "warning":
                base_score -= 10
            elif issue.severity == "info":
                base_score -= 2

        # Bonus points for good practices
        # (This would be implemented based on specific criteria)

        return max(0.0, min(100.0, base_score))

    def validate_strategy_string(self, strategy: str) -> List[ValidationIssue]:
        """
        Validate a single strategy string.

        Args:
            strategy: Strategy string to validate

        Returns:
            List of validation issues
        """
        self.issues = []
        self._validate_single_strategy(strategy, "strategy")
        return self.issues.copy()

    def suggest_improvements(self, config: StrategyConfiguration) -> List[str]:
        """
        Suggest specific improvements for configuration.

        Args:
            config: Configuration to analyze

        Returns:
            List of improvement suggestions
        """
        suggestions = []

        # Analyze strategy effectiveness
        if config.domain_strategies:
            success_rates = [
                rule.metadata.success_rate
                for rule in config.domain_strategies.values()
                if rule.metadata.success_rate > 0
            ]

            if success_rates:
                avg_success = sum(success_rates) / len(success_rates)
                if avg_success < 0.8:
                    suggestions.append(
                        f"Overall success rate is {avg_success:.1%}. "
                        f"Consider optimizing underperforming strategies."
                    )

        # Check for modern strategy usage
        modern_strategies = ["multisplit", "fakedisorder"]
        legacy_strategies = ["seqovl", "disorder"]

        modern_count = 0
        legacy_count = 0

        for rule in config.domain_strategies.values():
            for modern in modern_strategies:
                if modern in rule.strategy:
                    modern_count += 1
                    break
            for legacy in legacy_strategies:
                if legacy in rule.strategy:
                    legacy_count += 1
                    break

        if legacy_count > modern_count:
            suggestions.append(
                "Consider updating to modern strategy types (multisplit, fakedisorder) "
                "for better performance and reliability."
            )

        return suggestions


def validate_configuration_file(config_file: str) -> ValidationResult:
    """
    Convenience function to validate a configuration file.

    Args:
        config_file: Path to configuration file

    Returns:
        ValidationResult
    """
    from .strategy_config_manager import StrategyConfigManager

    manager = StrategyConfigManager()
    config = manager.load_configuration(config_file)

    validator = StrategyValidator()
    return validator.validate_configuration(config)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python strategy_validator.py <config_file>")
        sys.exit(1)

    config_file = sys.argv[1]

    try:
        result = validate_configuration_file(config_file)

        print(f"Configuration Validation Results for {config_file}")
        print(f"Valid: {result.is_valid}")
        print(f"Quality Score: {result.score:.1f}/100")

        if result.issues:
            print(f"\nIssues Found ({len(result.issues)}):")
            for issue in result.issues:
                print(f"  [{issue.severity.upper()}] {issue.message}")
                if issue.suggestion:
                    print(f"    Suggestion: {issue.suggestion}")

        if result.recommendations:
            print(f"\nRecommendations ({len(result.recommendations)}):")
            for rec in result.recommendations:
                print(f"  • {rec}")

        if result.is_valid:
            print("\n✓ Configuration is valid and ready to use!")
        else:
            print("\n✗ Configuration has errors that need to be fixed.")
            sys.exit(1)

    except Exception as e:
        print(f"Validation failed: {e}")
        sys.exit(1)
