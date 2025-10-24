"""
Integration helper for StrategySelector with existing bypass engine.

This module provides utilities to integrate the new StrategySelector
with the existing BypassEngine and strategy management systems.
"""

import json
import logging
from typing import Dict, Optional, Any
from pathlib import Path
from strategy_selector import StrategySelector


class StrategyIntegrationHelper:
    """Helper class to integrate StrategySelector with existing systems."""

    def __init__(self, strategies_file: str = "domain_strategies.json"):
        self.strategies_file = Path(strategies_file)
        self.logger = logging.getLogger(__name__)
        self.selector: Optional[StrategySelector] = None

    def create_selector_from_existing_config(self) -> StrategySelector:
        """
        Create StrategySelector from existing domain_strategies.json.

        Returns:
            Configured StrategySelector instance
        """
        domain_rules = self._load_domain_strategies()
        ip_rules = self._load_ip_strategies()
        global_strategy = self._get_global_strategy(domain_rules)

        self.selector = StrategySelector(
            domain_rules=domain_rules,
            ip_rules=ip_rules,
            global_strategy=global_strategy,
        )

        self.logger.info(
            f"Created StrategySelector with {len(domain_rules)} domain rules"
        )
        return self.selector

    def _load_domain_strategies(self) -> Dict[str, str]:
        """Load domain strategies from JSON file."""
        if not self.strategies_file.exists():
            self.logger.warning(f"Strategies file {self.strategies_file} not found")
            return {}

        try:
            with open(self.strategies_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            domain_strategies = {}
            for domain, strategy_data in data.get("domain_strategies", {}).items():
                if isinstance(strategy_data, dict):
                    strategy = strategy_data.get("strategy", "")
                else:
                    strategy = str(strategy_data)

                if strategy.strip():
                    domain_strategies[domain] = strategy

            self.logger.info(f"Loaded {len(domain_strategies)} domain strategies")
            return domain_strategies

        except Exception as e:
            self.logger.error(f"Error loading domain strategies: {e}")
            return {}

    def _load_ip_strategies(self) -> Dict[str, str]:
        """Load IP-specific strategies (placeholder for future implementation)."""
        # This could be extended to load IP strategies from a separate file
        # or from a different section of the configuration
        return {}

    def _get_global_strategy(self, domain_strategies: Dict[str, str]) -> str:
        """
        Determine global fallback strategy.

        Uses the 'default' domain strategy if available, otherwise uses badsum_race.
        """
        default_strategy = domain_strategies.get("default")
        if default_strategy:
            return default_strategy

        # Fallback to a proven strategy
        return "--dpi-desync=badsum_race --dpi-desync-ttl=4 --dpi-desync-split-pos=3"

    def get_strategy_for_connection(self, sni: Optional[str], dst_ip: str) -> str:
        """
        Get strategy string for a connection.

        This is the main integration point for the bypass engine.

        Args:
            sni: Server Name Indication from TLS ClientHello
            dst_ip: Destination IP address

        Returns:
            Strategy string to use for this connection
        """
        if not self.selector:
            self.create_selector_from_existing_config()

        result = self.selector.select_strategy(sni, dst_ip)
        return result.strategy

    def get_strategy_with_metadata(
        self, sni: Optional[str], dst_ip: str
    ) -> Dict[str, Any]:
        """
        Get strategy with full metadata for logging/debugging.

        Args:
            sni: Server Name Indication from TLS ClientHello
            dst_ip: Destination IP address

        Returns:
            Dict with strategy and metadata
        """
        if not self.selector:
            self.create_selector_from_existing_config()

        result = self.selector.select_strategy(sni, dst_ip)

        return {
            "strategy": result.strategy,
            "source": result.source,
            "priority": result.priority,
            "domain_matched": result.domain_matched,
            "ip_matched": result.ip_matched,
            "timestamp": result.timestamp,
        }

    def add_optimized_twitter_strategies(self) -> None:
        """
        Add optimized Twitter/X.com strategies as per requirements 2.1-2.4.

        This replaces existing individual Twitter domain entries with
        optimized multisplit strategies and wildcard patterns.
        """
        if not self.selector:
            self.create_selector_from_existing_config()

        # Add optimized strategies for Twitter/X.com
        twitter_strategies = {
            "x.com": "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=20 --dpi-desync-fooling=badseq --dpi-desync-repeats=2 --dpi-desync-ttl=4",
            "*.twimg.com": "--dpi-desync=multisplit --dpi-desync-split-count=7 --dpi-desync-split-seqovl=30 --dpi-desync-fooling=badsum --dpi-desync-repeats=3 --dpi-desync-ttl=4",
        }

        for domain, strategy in twitter_strategies.items():
            self.selector.add_domain_rule(domain, strategy, priority=1)

        self.logger.info("Added optimized Twitter/X.com strategies")

    def migrate_to_new_format(
        self, output_file: str = "domain_strategies_v3.json"
    ) -> None:
        """
        Migrate existing strategies to new format with wildcard support.

        Args:
            output_file: Output file for new format
        """
        if not self.selector:
            self.create_selector_from_existing_config()

        # Create new format with metadata
        new_format = {
            "version": "3.0",
            "description": "Enhanced strategy configuration with wildcard support and priorities",
            "strategy_priority": ["domain_exact", "domain_wildcard", "ip", "global"],
            "domain_strategies": {},
            "ip_strategies": {},
            "global_strategy": {
                "strategy": self.selector.global_strategy,
                "description": "Fallback strategy when no specific rules match",
            },
        }

        # Add domain rules with metadata
        for pattern, rule in self.selector.domain_rules.items():
            new_format["domain_strategies"][pattern] = {
                "strategy": rule.strategy,
                "priority": rule.priority,
                "is_wildcard": rule.is_wildcard,
                "success_rate": rule.success_rate,
                "description": f"{'Wildcard' if rule.is_wildcard else 'Exact'} match for {pattern}",
            }

        # Add IP rules
        for ip, strategy in self.selector.ip_rules.items():
            new_format["ip_strategies"][ip] = {
                "strategy": strategy,
                "description": f"IP-specific strategy for {ip}",
            }

        # Save new format
        output_path = Path(output_file)
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(new_format, f, indent=2, ensure_ascii=False)

            self.logger.info(f"Migrated configuration to {output_file}")

        except Exception as e:
            self.logger.error(f"Error saving migrated configuration: {e}")

    def get_statistics_report(self) -> Dict[str, Any]:
        """Get comprehensive statistics report."""
        if not self.selector:
            return {"error": "StrategySelector not initialized"}

        stats = self.selector.get_statistics()
        validation_issues = self.selector.validate_configuration()

        return {
            "selection_stats": stats,
            "configuration_issues": validation_issues,
            "total_rules": {
                "domain_rules": len(self.selector.domain_rules),
                "ip_rules": len(self.selector.ip_rules),
            },
            "wildcard_rules": sum(
                1 for rule in self.selector.domain_rules.values() if rule.is_wildcard
            ),
            "exact_rules": sum(
                1
                for rule in self.selector.domain_rules.values()
                if not rule.is_wildcard
            ),
        }


def demo_integration():
    """Demonstrate integration with existing system."""
    print("=== StrategySelector Integration Demo ===\n")

    # Set up logging
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    # Create integration helper
    helper = StrategyIntegrationHelper("domain_strategies.json")

    # Create selector from existing config
    print("1. Creating StrategySelector from existing configuration...")
    selector = helper.create_selector_from_existing_config()

    # Test integration methods
    print("\n2. Testing integration methods:")

    test_connections = [
        ("x.com", "104.244.42.1"),
        ("abs.twimg.com", "104.244.42.1"),
        ("unknown.com", "1.2.3.4"),
    ]

    for sni, ip in test_connections:
        print(f"\n   Connection: SNI={sni}, IP={ip}")

        # Get simple strategy string (main integration point)
        strategy = helper.get_strategy_for_connection(sni, ip)
        print(f"   Strategy: {strategy[:60]}...")

        # Get full metadata for debugging
        metadata = helper.get_strategy_with_metadata(sni, ip)
        print(f"   Source: {metadata['source']}, Priority: {metadata['priority']}")

    # Add Twitter optimizations
    print("\n3. Adding optimized Twitter strategies...")
    helper.add_optimized_twitter_strategies()

    # Test Twitter domains after optimization
    print("\n4. Testing Twitter domains after optimization:")
    twitter_domains = ["x.com", "abs.twimg.com", "pbs.twimg.com"]

    for domain in twitter_domains:
        metadata = helper.get_strategy_with_metadata(domain, "104.244.42.1")
        print(f"   {domain}: {metadata['source']} -> multisplit strategy")

    # Show statistics
    print("\n5. Statistics Report:")
    report = helper.get_statistics_report()

    print(f"   Total domain rules: {report['total_rules']['domain_rules']}")
    print(f"   Exact rules: {report['exact_rules']}")
    print(f"   Wildcard rules: {report['wildcard_rules']}")
    print(f"   Configuration issues: {len(report['configuration_issues'])}")

    # Migrate to new format
    print("\n6. Migrating to new configuration format...")
    helper.migrate_to_new_format("domain_strategies_v3_demo.json")

    print("\n=== Integration Demo Complete ===")


if __name__ == "__main__":
    demo_integration()
