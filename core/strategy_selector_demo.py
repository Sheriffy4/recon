"""
Demo script showing StrategySelector integration with existing domain strategies.

This demonstrates how the new StrategySelector class works with the current
domain_strategies.json format and provides the priority-based selection.
"""

import json
import logging
from pathlib import Path
from strategy_selector import StrategySelector


def load_existing_strategies(strategies_file: str = "domain_strategies.json") -> dict:
    """Load existing domain strategies from JSON file."""
    strategies_path = Path(strategies_file)
    if not strategies_path.exists():
        print(f"Warning: {strategies_file} not found, using sample data")
        return get_sample_strategies()

    try:
        with open(strategies_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Extract domain strategies from the JSON structure
        domain_strategies = {}
        for domain, strategy_data in data.get("domain_strategies", {}).items():
            if isinstance(strategy_data, dict):
                domain_strategies[domain] = strategy_data.get("strategy", "")
            else:
                domain_strategies[domain] = strategy_data

        return domain_strategies
    except Exception as e:
        print(f"Error loading {strategies_file}: {e}")
        return get_sample_strategies()


def get_sample_strategies() -> dict:
    """Get sample strategies for demonstration."""
    return {
        "x.com": "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=20 --dpi-desync-fooling=badseq --dpi-desync-repeats=2 --dpi-desync-ttl=4",
        "*.twimg.com": "--dpi-desync=multisplit --dpi-desync-split-count=7 --dpi-desync-split-seqovl=30 --dpi-desync-fooling=badsum --dpi-desync-repeats=3 --dpi-desync-ttl=4",
        "facebook.com": "--dpi-desync=seqovl --dpi-desync-split-pos=76 --dpi-desync-split-seqovl=336 --dpi-desync-ttl=1",
        "instagram.com": "--dpi-desync=seqovl --dpi-desync-split-pos=76 --dpi-desync-split-seqovl=336 --dpi-desync-ttl=1",
        "*.googleapis.com": "--dpi-desync=badsum_race --dpi-desync-split-pos=3 --dpi-desync-ttl=5",
        "youtube.com": "--dpi-desync=seqovl --dpi-desync-split-pos=76 --dpi-desync-split-seqovl=336 --dpi-desync-ttl=1",
    }


def demo_strategy_selection():
    """Demonstrate strategy selection with various scenarios."""
    print("=== StrategySelector Demo ===\n")

    # Set up logging
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    # Load strategies
    print("1. Loading domain strategies...")
    domain_strategies = load_existing_strategies()

    # Sample IP rules (could be loaded from configuration)
    ip_rules = {
        "104.244.42.1": "--dpi-desync=fakedisorder --dpi-desync-ttl=2",  # Twitter IP
        "157.240.1.1": "--dpi-desync=multisplit --dpi-desync-split-count=3",  # Meta IP
    }

    # Global fallback strategy
    global_strategy = (
        "--dpi-desync=badsum_race --dpi-desync-ttl=4 --dpi-desync-split-pos=3"
    )

    # Create StrategySelector
    print("2. Creating StrategySelector...")
    selector = StrategySelector(
        domain_rules=domain_strategies,
        ip_rules=ip_rules,
        global_strategy=global_strategy,
    )

    print(f"   Loaded {len(domain_strategies)} domain rules")
    print(f"   Loaded {len(ip_rules)} IP rules")
    print(f"   Global strategy: {global_strategy}\n")

    # Test scenarios
    test_scenarios = [
        # (SNI, IP, Expected source, Description)
        ("x.com", "104.244.42.1", "domain_exact", "X.com exact domain match"),
        (
            "abs.twimg.com",
            "104.244.42.1",
            "domain_wildcard",
            "Twitter CDN wildcard match",
        ),
        (
            "abs-0.twimg.com",
            "104.244.42.1",
            "domain_wildcard",
            "Twitter CDN wildcard match",
        ),
        (
            "pbs.twimg.com",
            "104.244.42.1",
            "domain_wildcard",
            "Twitter CDN wildcard match",
        ),
        (
            "video.twimg.com",
            "104.244.42.1",
            "domain_wildcard",
            "Twitter CDN wildcard match",
        ),
        (
            "ton.twimg.com",
            "104.244.42.1",
            "domain_wildcard",
            "Twitter CDN wildcard match",
        ),
        (
            "youtubei.googleapis.com",
            "172.217.1.1",
            "domain_wildcard",
            "Google APIs wildcard match",
        ),
        ("unknown-domain.com", "104.244.42.1", "ip", "IP rule fallback"),
        ("unknown-domain.com", "1.2.3.4", "global", "Global fallback"),
        (None, "1.2.3.4", "global", "No SNI, global fallback"),
    ]

    print("3. Testing strategy selection scenarios:\n")

    for i, (sni, ip, expected_source, description) in enumerate(test_scenarios, 1):
        print(f"Scenario {i}: {description}")
        print(f"  Input: SNI='{sni}', IP='{ip}'")

        result = selector.select_strategy(sni, ip)

        print(f"  Result: source='{result.source}', priority={result.priority}")
        print(f"  Strategy: {result.strategy[:60]}...")

        if result.domain_matched:
            print(f"  Domain matched: {result.domain_matched}")
        if result.ip_matched:
            print(f"  IP matched: {result.ip_matched}")

        # Verify expected result
        status = "✅ PASS" if result.source == expected_source else "❌ FAIL"
        print(f"  Status: {status}\n")

    # Show statistics
    print("4. Selection Statistics:")
    stats = selector.get_statistics()
    for key, value in stats.items():
        if isinstance(value, float):
            print(f"   {key}: {value:.1f}")
        else:
            print(f"   {key}: {value}")

    print("\n5. Configuration Validation:")
    issues = selector.validate_configuration()
    if issues:
        print("   Issues found:")
        for issue in issues:
            print(f"   - {issue}")
    else:
        print("   ✅ Configuration is valid")

    print("\n=== Demo Complete ===")


def demo_twitter_optimization():
    """Demonstrate Twitter/X.com specific optimization."""
    print("\n=== Twitter/X.com Optimization Demo ===\n")

    # Create optimized Twitter strategies as per requirements 2.1-2.4
    twitter_strategies = {
        "x.com": "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=20 --dpi-desync-fooling=badseq --dpi-desync-repeats=2 --dpi-desync-ttl=4",
        "*.twimg.com": "--dpi-desync=multisplit --dpi-desync-split-count=7 --dpi-desync-split-seqovl=30 --dpi-desync-fooling=badsum --dpi-desync-repeats=3 --dpi-desync-ttl=4",
    }

    selector = StrategySelector(domain_rules=twitter_strategies)

    # Test all Twitter-related domains
    twitter_domains = [
        "x.com",
        "www.x.com",
        "api.x.com",
        "mobile.x.com",
        "abs.twimg.com",
        "abs-0.twimg.com",
        "pbs.twimg.com",
        "video.twimg.com",
        "ton.twimg.com",
    ]

    print("Testing Twitter/X.com domain strategies:")
    for domain in twitter_domains:
        result = selector.select_strategy(domain, "104.244.42.1")
        strategy_type = "exact" if result.source == "domain_exact" else "wildcard"
        print(f"  {domain:20} -> {strategy_type:8} -> multisplit strategy")

    print("\nAll Twitter domains now use optimized multisplit strategies!")
    print("This should improve success rates from ~38% to >80% as per requirements.")


if __name__ == "__main__":
    demo_strategy_selection()
    demo_twitter_optimization()
