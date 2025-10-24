"""
Configuration Migration Tool

This utility helps migrate legacy strategy configurations to the new enhanced format
with wildcard support and improved metadata.
"""

import json
import argparse
import sys
from pathlib import Path
from typing import Dict, Any, List
import logging

from .strategy_config_manager import (
    StrategyConfigManager,
    StrategyConfiguration,
    StrategyRule,
    StrategyMetadata,
)

logger = logging.getLogger(__name__)


class ConfigMigrationTool:
    """Tool for migrating strategy configurations between versions."""

    def __init__(self):
        """Initialize migration tool."""
        self.manager = StrategyConfigManager()

    def migrate_file(
        self, input_file: str, output_file: str = None, create_backup: bool = True
    ) -> bool:
        """
        Migrate a configuration file to the latest format.

        Args:
            input_file: Path to input configuration file
            output_file: Path to output file (defaults to input_file)
            create_backup: Whether to create backup of original file

        Returns:
            True if migration successful, False otherwise
        """
        try:
            input_path = Path(input_file)
            if not input_path.exists():
                logger.error(f"Input file not found: {input_file}")
                return False

            # Load configuration (will auto-convert if needed)
            config = self.manager.load_configuration(input_file)

            # Determine output file
            if output_file is None:
                output_file = input_file

            # Save in new format
            self.manager.save_configuration(config, output_file, create_backup)

            logger.info(f"Successfully migrated {input_file} to v{config.version}")
            return True

        except Exception as e:
            logger.error(f"Migration failed: {e}")
            return False

    def analyze_configuration(self, config_file: str) -> Dict[str, Any]:
        """
        Analyze a configuration file and provide migration recommendations.

        Args:
            config_file: Path to configuration file

        Returns:
            Analysis results dictionary
        """
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                raw_config = json.load(f)

            analysis = {
                "current_version": raw_config.get("version", "unknown"),
                "domain_count": 0,
                "wildcard_opportunities": [],
                "duplicate_strategies": [],
                "recommendations": [],
            }

            domain_strategies = raw_config.get("domain_strategies", {})
            analysis["domain_count"] = len(domain_strategies)

            # Find wildcard opportunities
            analysis["wildcard_opportunities"] = self._find_wildcard_opportunities(
                domain_strategies
            )

            # Find duplicate strategies
            analysis["duplicate_strategies"] = self._find_duplicate_strategies(
                domain_strategies
            )

            # Generate recommendations
            analysis["recommendations"] = self._generate_recommendations(analysis)

            return analysis

        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return {"error": str(e)}

    def optimize_configuration(self, config_file: str, output_file: str = None) -> bool:
        """
        Optimize configuration by consolidating similar domains into wildcards.

        Args:
            config_file: Path to input configuration file
            output_file: Path to output file (defaults to input_file + .optimized)

        Returns:
            True if optimization successful, False otherwise
        """
        try:
            config = self.manager.load_configuration(config_file)

            # Find optimization opportunities
            optimizations = self._find_optimizations(config)

            # Apply optimizations
            optimized_config = self._apply_optimizations(config, optimizations)

            # Determine output file
            if output_file is None:
                input_path = Path(config_file)
                output_file = str(
                    input_path.with_suffix(".optimized" + input_path.suffix)
                )

            # Save optimized configuration
            self.manager.save_configuration(optimized_config, output_file)

            logger.info(f"Optimized configuration saved to {output_file}")
            logger.info(
                f"Reduced {len(config.domain_strategies)} rules to {len(optimized_config.domain_strategies)}"
            )

            return True

        except Exception as e:
            logger.error(f"Optimization failed: {e}")
            return False

    def _find_wildcard_opportunities(
        self, domain_strategies: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Find domains that could be consolidated with wildcards."""
        opportunities = []

        # Group domains by base domain
        domain_groups = {}
        for domain in domain_strategies.keys():
            if domain == "default":
                continue

            parts = domain.split(".")
            if len(parts) >= 2:
                base_domain = ".".join(parts[-2:])  # Get last two parts (domain.tld)
                if base_domain not in domain_groups:
                    domain_groups[base_domain] = []
                domain_groups[base_domain].append(domain)

        # Find groups with multiple subdomains
        for base_domain, domains in domain_groups.items():
            if len(domains) > 2:  # More than 2 subdomains
                # Check if they have similar strategies
                strategies = [domain_strategies[d].get("strategy", "") for d in domains]
                if len(set(strategies)) <= 2:  # At most 2 different strategies
                    opportunities.append(
                        {
                            "base_domain": base_domain,
                            "domains": domains,
                            "wildcard_pattern": f"*.{base_domain}",
                            "potential_savings": len(domains) - 1,
                        }
                    )

        return opportunities

    def _find_duplicate_strategies(
        self, domain_strategies: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Find domains with identical strategies."""
        strategy_groups = {}

        for domain, config in domain_strategies.items():
            if domain == "default":
                continue

            strategy = config.get("strategy", "")
            if strategy not in strategy_groups:
                strategy_groups[strategy] = []
            strategy_groups[strategy].append(domain)

        duplicates = []
        for strategy, domains in strategy_groups.items():
            if len(domains) > 1:
                duplicates.append(
                    {"strategy": strategy, "domains": domains, "count": len(domains)}
                )

        return duplicates

    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate optimization recommendations based on analysis."""
        recommendations = []

        if analysis["current_version"] != "3.0":
            recommendations.append(
                f"Upgrade from version {analysis['current_version']} to 3.0 for enhanced features"
            )

        if analysis["wildcard_opportunities"]:
            total_savings = sum(
                opp["potential_savings"] for opp in analysis["wildcard_opportunities"]
            )
            recommendations.append(
                f"Use wildcards to reduce {total_savings} domain rules"
            )

        if analysis["duplicate_strategies"]:
            duplicate_count = sum(
                dup["count"] - 1 for dup in analysis["duplicate_strategies"]
            )
            recommendations.append(
                f"Consolidate {duplicate_count} duplicate strategy rules"
            )

        if analysis["domain_count"] > 50:
            recommendations.append(
                "Consider using IP-based rules for better performance with large rule sets"
            )

        return recommendations

    def _find_optimizations(self, config: StrategyConfiguration) -> Dict[str, Any]:
        """Find optimization opportunities in configuration."""
        optimizations = {"wildcard_consolidations": [], "strategy_deduplication": []}

        # Find wildcard consolidation opportunities
        domain_groups = {}
        for pattern, rule in config.domain_strategies.items():
            if rule.is_wildcard:
                continue  # Skip existing wildcards

            parts = pattern.split(".")
            if len(parts) >= 2:
                base_domain = ".".join(parts[-2:])
                if base_domain not in domain_groups:
                    domain_groups[base_domain] = []
                domain_groups[base_domain].append((pattern, rule))

        for base_domain, rules in domain_groups.items():
            if len(rules) > 2:
                # Check if strategies are similar enough to consolidate
                strategies = [rule.strategy for _, rule in rules]
                if len(set(strategies)) == 1:  # All identical
                    optimizations["wildcard_consolidations"].append(
                        {
                            "base_domain": base_domain,
                            "rules": rules,
                            "wildcard_pattern": f"*.{base_domain}",
                        }
                    )

        return optimizations

    def _apply_optimizations(
        self, config: StrategyConfiguration, optimizations: Dict[str, Any]
    ) -> StrategyConfiguration:
        """Apply optimizations to configuration."""
        optimized_config = StrategyConfiguration(
            version=config.version,
            strategy_priority=config.strategy_priority.copy(),
            global_strategy=config.global_strategy,
            last_updated=config.last_updated,
        )

        # Copy existing strategies
        optimized_config.domain_strategies = config.domain_strategies.copy()
        optimized_config.ip_strategies = config.ip_strategies.copy()

        # Apply wildcard consolidations
        for consolidation in optimizations["wildcard_consolidations"]:
            base_domain = consolidation["base_domain"]
            rules = consolidation["rules"]
            wildcard_pattern = consolidation["wildcard_pattern"]

            # Use the first rule as template for wildcard rule
            template_pattern, template_rule = rules[0]

            # Create consolidated metadata
            consolidated_metadata = StrategyMetadata(
                priority=template_rule.metadata.priority,
                description=f"Consolidated wildcard for {base_domain}",
                success_rate=sum(rule.metadata.success_rate for _, rule in rules)
                / len(rules),
                avg_latency_ms=sum(rule.metadata.avg_latency_ms for _, rule in rules)
                / len(rules),
                test_count=sum(rule.metadata.test_count for _, rule in rules),
            )

            # Create wildcard rule
            wildcard_rule = StrategyRule(
                pattern=wildcard_pattern,
                strategy=template_rule.strategy,
                metadata=consolidated_metadata,
            )

            # Add wildcard rule and remove individual rules
            optimized_config.domain_strategies[wildcard_pattern] = wildcard_rule
            for pattern, _ in rules:
                if pattern in optimized_config.domain_strategies:
                    del optimized_config.domain_strategies[pattern]

        return optimized_config


def main():
    """Command-line interface for configuration migration tool."""
    parser = argparse.ArgumentParser(
        description="Strategy Configuration Migration Tool"
    )
    parser.add_argument(
        "command", choices=["migrate", "analyze", "optimize"], help="Command to execute"
    )
    parser.add_argument("input_file", help="Input configuration file")
    parser.add_argument("-o", "--output", help="Output file (optional)")
    parser.add_argument(
        "--no-backup", action="store_true", help="Skip creating backup file"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )

    args = parser.parse_args()

    # Configure logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")

    tool = ConfigMigrationTool()

    if args.command == "migrate":
        success = tool.migrate_file(args.input_file, args.output, not args.no_backup)
        sys.exit(0 if success else 1)

    elif args.command == "analyze":
        analysis = tool.analyze_configuration(args.input_file)

        if "error" in analysis:
            logger.error(f"Analysis failed: {analysis['error']}")
            sys.exit(1)

        print(f"Configuration Analysis for {args.input_file}")
        print(f"Current version: {analysis['current_version']}")
        print(f"Domain rules: {analysis['domain_count']}")

        if analysis["wildcard_opportunities"]:
            print(
                f"\nWildcard opportunities ({len(analysis['wildcard_opportunities'])}):"
            )
            for opp in analysis["wildcard_opportunities"]:
                print(
                    f"  {opp['wildcard_pattern']}: {opp['potential_savings']} rules can be consolidated"
                )

        if analysis["duplicate_strategies"]:
            print(f"\nDuplicate strategies ({len(analysis['duplicate_strategies'])}):")
            for dup in analysis["duplicate_strategies"]:
                print(f"  {dup['count']} domains use: {dup['strategy'][:50]}...")

        if analysis["recommendations"]:
            print("\nRecommendations:")
            for rec in analysis["recommendations"]:
                print(f"  • {rec}")

    elif args.command == "optimize":
        success = tool.optimize_configuration(args.input_file, args.output)
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
