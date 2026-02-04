#!/usr/bin/env python3
"""
Zapret Strategy Normalization Utility
Ensures strategy parameters are within safe and effective ranges
"""

import re
from typing import List, Dict, Any


def normalize_zapret_string(strategy: str) -> str:
    """
    Normalize zapret strategy string to ensure parameters are within safe ranges.

    Args:
        strategy: Original zapret strategy string

    Returns:
        Normalized strategy string with corrected parameters
    """
    if not strategy:
        return strategy

    # Fix split-count values < 3 (no bypass benefit)
    strategy = re.sub(r"--dpi-desync-split-count=([0-2])", "--dpi-desync-split-count=3", strategy)

    # Normalize TTL to reasonable range (3-8)
    def normalize_ttl(match):
        ttl = int(match.group(1))
        normalized_ttl = min(8, max(3, ttl))
        return f"--dpi-desync-ttl={normalized_ttl}"

    strategy = re.sub(r"--dpi-desync-ttl=(\d+)", normalize_ttl, strategy)

    # Normalize seqovl to reasonable range (10-50)
    def normalize_seqovl(match):
        seqovl = int(match.group(1))
        normalized_seqovl = min(50, max(10, seqovl))
        return f"--dpi-desync-split-seqovl={normalized_seqovl}"

    strategy = re.sub(r"--dpi-desync-split-seqovl=(\d+)", normalize_seqovl, strategy)

    # Normalize split-count for multisplit to effective range (3-7)
    def normalize_multisplit_count(match):
        count = int(match.group(1))
        normalized_count = min(7, max(3, count))
        return f"--dpi-desync-split-count={normalized_count}"

    if "multisplit" in strategy:
        strategy = re.sub(r"--dpi-desync-split-count=(\d+)", normalize_multisplit_count, strategy)

    # Convert legacy disorder to fakedisorder for compatibility
    strategy = re.sub(r"--dpi-desync=disorder\b", "--dpi-desync=fakedisorder", strategy)

    return strategy


def normalize_strategy_batch(strategies: List[str]) -> List[str]:
    """
    Normalize a batch of strategy strings.

    Args:
        strategies: List of strategy strings to normalize

    Returns:
        List of normalized strategy strings
    """
    return [normalize_zapret_string(strategy) for strategy in strategies]


def validate_strategy_parameters(strategy: str) -> Dict[str, Any]:
    """
    Validate strategy parameters and return validation results.

    Args:
        strategy: Strategy string to validate

    Returns:
        Dict with validation results and issues found
    """
    issues = []
    recommendations = []

    # Check for problematic split-count
    split_count_match = re.search(r"--dpi-desync-split-count=(\d+)", strategy)
    if split_count_match:
        count = int(split_count_match.group(1))
        if count < 3:
            issues.append(f"Split count {count} is too low (no bypass benefit)")
            recommendations.append("Use split-count >= 3 or switch to fakedisorder")
        elif count > 7:
            issues.append(f"Split count {count} is too high (may cause instability)")
            recommendations.append("Use split-count <= 7 for stability")

    # Check TTL values
    ttl_match = re.search(r"--dpi-desync-ttl=(\d+)", strategy)
    if ttl_match:
        ttl = int(ttl_match.group(1))
        if ttl < 3:
            issues.append(f"TTL {ttl} is too low (may affect legitimate traffic)")
            recommendations.append("Use TTL >= 3")
        elif ttl > 8:
            issues.append(f"TTL {ttl} is too high (may not be effective)")
            recommendations.append("Use TTL <= 8 for better effectiveness")

    # Check seqovl values
    seqovl_match = re.search(r"--dpi-desync-split-seqovl=(\d+)", strategy)
    if seqovl_match:
        seqovl = int(seqovl_match.group(1))
        if seqovl < 10:
            issues.append(f"Sequence overlap {seqovl} is too low")
            recommendations.append("Use seqovl >= 10 for better reliability")
        elif seqovl > 50:
            issues.append(f"Sequence overlap {seqovl} is too high")
            recommendations.append("Use seqovl <= 50 to avoid excessive overhead")

    # Check for legacy methods that need updating
    if re.search(r"--dpi-desync=disorder\b", strategy):
        issues.append("Using legacy 'disorder' method")
        recommendations.append("Use 'fakedisorder' instead of 'disorder' for better compatibility")

    return {
        "valid": len(issues) == 0,
        "issues": issues,
        "recommendations": recommendations,
        "normalized": normalize_zapret_string(strategy),
    }


def get_strategy_complexity_score(strategy: str) -> float:
    """
    Calculate complexity score for a strategy (0.0 = simple, 1.0 = very complex).

    Args:
        strategy: Strategy string to analyze

    Returns:
        Complexity score between 0.0 and 1.0
    """
    complexity = 0.0

    # Base method complexity
    if "multisplit" in strategy:
        complexity += 0.3
    elif "fakedisorder" in strategy:
        complexity += 0.2
    elif "fake" in strategy:
        complexity += 0.1

    # Parameter complexity
    if "--dpi-desync-split-count=" in strategy:
        count_match = re.search(r"--dpi-desync-split-count=(\d+)", strategy)
        if count_match:
            count = int(count_match.group(1))
            complexity += min(0.2, count * 0.03)

    if "--dpi-desync-split-seqovl=" in strategy:
        complexity += 0.1

    if "--dpi-desync-fooling=" in strategy:
        fooling_methods = len(re.findall(r"(badsum|badseq|md5sig)", strategy))
        complexity += min(0.2, fooling_methods * 0.1)

    # TTL manipulation
    if "--dpi-desync-ttl=" in strategy:
        complexity += 0.1

    return min(1.0, complexity)


def recommend_strategy_for_hints(hints: List[str]) -> str:
    """
    Recommend an optimal strategy based on fingerprinting hints.

    Args:
        hints: List of strategy hints from fingerprinting

    Returns:
        Recommended strategy string
    """
    if "cdn_multisplit" in hints:
        return "--dpi-desync=multisplit --dpi-desync-split-count=7 --dpi-desync-split-seqovl=30 --dpi-desync-ttl=4 --dpi-desync-fooling=badseq"

    if "split_tls_sni" in hints:
        return "--dpi-desync=multisplit --dpi-desync-split-count=5 --dpi-desync-split-seqovl=20 --dpi-desync-ttl=4 --dpi-desync-fooling=badseq --dpi-desync-split-tls=sni"

    if "disable_quic" in hints:
        return "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-ttl=4 --dpi-desync-fooling=badseq"

    if "prefer_http11" in hints:
        return "--dpi-desync=fake,fakeddisorder --dpi-desync-split-pos=3 --dpi-desync-ttl=4 --dpi-desync-fooling=badsum"

    # Default recommendation
    return (
        "--dpi-desync=fake --dpi-desync-split-pos=3 --dpi-desync-ttl=4 --dpi-desync-fooling=badsum"
    )


if __name__ == "__main__":
    # Test the normalization functions
    test_strategies = [
        "--dpi-desync=multisplit --dpi-desync-split-count=1 --dpi-desync-ttl=15",
        "--dpi-desync=disorder --dpi-desync-split-pos=3",
        "--dpi-desync=fake --dpi-desync-ttl=2 --dpi-desync-split-seqovl=5",
        "--dpi-desync=multisplit --dpi-desync-split-count=10 --dpi-desync-ttl=1",
    ]

    print("Strategy Normalization Test:")
    print("=" * 50)

    for strategy in test_strategies:
        print(f"\nOriginal:   {strategy}")
        normalized = normalize_zapret_string(strategy)
        print(f"Normalized: {normalized}")

        validation = validate_strategy_parameters(strategy)
        if validation["issues"]:
            print(f"Issues:     {validation['issues']}")
            print(f"Recommendations: {validation['recommendations']}")

        complexity = get_strategy_complexity_score(normalized)
        print(f"Complexity: {complexity:.2f}")
        print("-" * 50)
