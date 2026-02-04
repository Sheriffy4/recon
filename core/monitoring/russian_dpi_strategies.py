"""
Russian DPI Strategies

Proven strategies that work against Russian DPI systems like
Roskomnadzor, ISP-level filtering, and corporate firewalls.

Based on real-world testing and community feedback.
"""

from core.optimization.models import Strategy


def get_russian_dpi_strategies() -> list[Strategy]:
    """
    Get list of strategies proven to work against Russian DPI systems.

    Ordered by effectiveness (most effective first).
    Updated with strategies proven to work in December 2024.

    Returns:
        List of Strategy objects
    """
    return [
        # Strategy 1: PROVEN WORKING - Split + Fake combo with TTL=1 (December 2024)
        # This was found by manual testing with 'cli.py auto nnmclub.to'
        Strategy(
            type="split,fake",
            attacks=["split", "fake"],
            params={"ttl": 1, "fooling": "badseq", "split_pos": 3, "split_count": 2},
        ),
        # Strategy 2: Variation of proven strategy with different split position
        Strategy(
            type="split,fake",
            attacks=["split", "fake"],
            params={"ttl": 1, "fooling": "badseq", "split_pos": 2, "split_count": 2},
        ),
        # Strategy 3: Variation with TTL=3 (sometimes more stable)
        Strategy(
            type="split,fake",
            attacks=["split", "fake"],
            params={"ttl": 3, "fooling": "badseq", "split_pos": 3, "split_count": 2},
        ),
        # Strategy 4: Simple disorder (very effective for many sites)
        Strategy(
            type="disorder",
            attacks=["disorder"],
            params={"split_pos": 1, "disorder_method": "reverse"},
        ),
        # Strategy 5: Multisplit with proven parameters
        Strategy(
            type="multisplit", attacks=["multisplit"], params={"split_pos": 3, "split_count": 6}
        ),
        # Strategy 6: Low TTL fake (works against some DPI)
        Strategy(type="fake", attacks=["fake"], params={"ttl": 1, "fooling": "badseq"}),
        # Strategy 7: High TTL fake (bypasses TTL-based filtering)
        Strategy(type="fake", attacks=["fake"], params={"ttl": 8, "fooling": "badsum"}),
        # Strategy 8: Disorder at position 3 (for SNI bypass)
        Strategy(
            type="disorder",
            attacks=["disorder"],
            params={"split_pos": 3, "disorder_method": "reverse"},
        ),
        # Strategy 9: Basic split at position 1
        Strategy(type="split", attacks=["split"], params={"split_pos": 1, "split_count": 2}),
        # Strategy 10: Passthrough (always works, no bypass)
        Strategy(type="passthrough", attacks=["passthrough"], params={}),
    ]


def get_domain_specific_strategies(domain: str) -> list[Strategy]:
    """
    Get domain-specific strategies based on known working configurations.

    Args:
        domain: Domain name

    Returns:
        List of strategies likely to work for this domain
    """
    strategies = []

    # Rutracker-specific strategies
    if "rutracker" in domain.lower():
        strategies.extend(
            [
                Strategy(
                    type="disorder",
                    attacks=["disorder"],
                    params={"split_pos": 1, "disorder_method": "reverse"},
                ),
                Strategy(type="fake", attacks=["fake"], params={"ttl": 8, "fooling": "badsum"}),
            ]
        )

    # NNMClub-specific strategies (updated with proven working strategy)
    elif "nnmclub" in domain.lower():
        strategies.extend(
            [
                # PROVEN WORKING: Found by manual testing December 2024
                Strategy(
                    type="split,fake",
                    attacks=["split", "fake"],
                    params={"ttl": 1, "fooling": "badseq", "split_pos": 3, "split_count": 2},
                ),
                # Alternative with different split position
                Strategy(
                    type="split,fake",
                    attacks=["split", "fake"],
                    params={"ttl": 1, "fooling": "badseq", "split_pos": 2, "split_count": 2},
                ),
                # Fallback to multisplit
                Strategy(
                    type="multisplit",
                    attacks=["multisplit"],
                    params={"split_pos": 3, "split_count": 6},
                ),
            ]
        )

    # YouTube/Google domains
    elif any(x in domain.lower() for x in ["youtube", "googlevideo", "ytimg"]):
        strategies.extend(
            [
                Strategy(type="fake", attacks=["fake"], params={"ttl": 3, "fooling": "badsum"}),
                Strategy(
                    type="disorder",
                    attacks=["disorder"],
                    params={"split_pos": 3, "disorder_method": "reverse"},
                ),
            ]
        )

    # Social networks (VK, Facebook, etc.)
    elif any(x in domain.lower() for x in ["vk.com", "facebook", "instagram", "twitter"]):
        strategies.extend(
            [
                Strategy(
                    type="split", attacks=["split"], params={"split_pos": 1, "split_count": 2}
                ),
                Strategy(type="fake", attacks=["fake"], params={"ttl": 6, "fooling": "badsum"}),
            ]
        )

    # Add general strategies if no specific ones found
    if not strategies:
        strategies = get_russian_dpi_strategies()[:5]  # Top 5 general strategies

    return strategies


def get_fallback_strategies() -> list[Strategy]:
    """
    Get fallback strategies when everything else fails.

    Returns:
        List of last-resort strategies
    """
    return [
        # Passthrough - always works but no bypass
        Strategy(type="passthrough", attacks=["passthrough"], params={}),
        # Very simple split
        Strategy(type="split", attacks=["split"], params={"split_pos": 1, "split_count": 2}),
        # Basic fake
        Strategy(type="fake", attacks=["fake"], params={"ttl": 5, "fooling": "badsum"}),
    ]


def is_strategy_likely_to_work(strategy: Strategy, domain: str) -> float:
    """
    Estimate likelihood that strategy will work for domain.

    Args:
        strategy: Strategy to evaluate
        domain: Target domain

    Returns:
        Probability from 0.0 to 1.0
    """
    score = 0.5  # Base score

    # Passthrough always works (but doesn't bypass)
    if strategy.attacks == ["passthrough"]:
        return 1.0

    # PROVEN WORKING STRATEGY: split+fake with TTL=1 (December 2024)
    if (
        strategy.attacks == ["split", "fake"]
        and strategy.params.get("ttl") == 1
        and strategy.params.get("fooling") == "badseq"
        and strategy.params.get("split_pos") == 3
        and strategy.params.get("split_count") == 2
    ):
        return 0.95  # Very high confidence - proven to work

    # Variations of proven strategy
    if (
        strategy.attacks == ["split", "fake"]
        and strategy.params.get("ttl") in [1, 3]
        and strategy.params.get("fooling") == "badseq"
    ):
        score += 0.4  # High confidence for similar strategies

    # Split + fake combo is generally effective
    if strategy.attacks == ["split", "fake"]:
        score += 0.3

    # Disorder is very effective against Russian DPI
    if "disorder" in strategy.attacks:
        score += 0.3

    # Fake packets work well with proper TTL
    if "fake" in strategy.attacks:
        ttl = strategy.params.get("ttl", 3)
        if ttl == 1:  # Proven effective
            score += 0.3
        elif 3 <= ttl <= 8:  # Sweet spot for Russian DPI
            score += 0.2

    # Multisplit is effective but resource-intensive
    if "multisplit" in strategy.attacks:
        split_count = strategy.params.get("split_count", 2)
        if split_count >= 6:  # High fragmentation
            score += 0.2
        else:
            score += 0.1

    # Split at position 3 is often effective (proven)
    if strategy.params.get("split_pos") == 3:
        score += 0.2
    # Split at position 1 is also effective
    elif strategy.params.get("split_pos") == 1:
        score += 0.1

    # Domain-specific adjustments
    if "rutracker" in domain.lower() and "disorder" in strategy.attacks:
        score += 0.2

    if "nnmclub" in domain.lower():
        # Prioritize proven working strategy for nnmclub
        if strategy.attacks == ["split", "fake"] and strategy.params.get("ttl") == 1:
            score += 0.3
        elif "multisplit" in strategy.attacks:
            score += 0.1

    return min(score, 1.0)
