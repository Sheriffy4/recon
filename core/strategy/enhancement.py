# Файл: core/strategy/enhancement.py
"""
Strategy enhancement utilities using attack registry and fingerprints.

This module provides functions for enhancing strategies based on DPI fingerprints
and available attacks from the registry.
"""

import logging
from typing import List, Optional, Any

LOG = logging.getLogger(__name__)


def enhance_strategies_with_registry(
    strategies: List[str],
    fingerprint: Optional[Any],  # DPIFingerprint
    domain: str,
    port: int,
    attack_registry: Optional[Any],
    task_to_str_func: callable,
    logger: Optional[logging.Logger] = None,
) -> List[str]:
    """
    Enhance strategies using the modern attack registry and fingerprint data.

    Args:
        strategies: List of strategy strings to enhance
        fingerprint: Optional DPI fingerprint with detection results
        domain: Target domain
        port: Target port
        attack_registry: Attack registry instance
        task_to_str_func: Function to convert task dict to string
        logger: Optional logger instance

    Returns:
        List of enhanced strategy strings with duplicates removed

    Examples:
        >>> strategies = ["--dpi-desync=split"]
        >>> enhanced = enhance_strategies_with_registry(
        ...     strategies=strategies,
        ...     fingerprint=fingerprint,
        ...     domain="example.com",
        ...     port=443,
        ...     attack_registry=registry,
        ...     task_to_str_func=lambda s: s
        ... )
        >>> len(enhanced) >= len(strategies)
        True
    """
    if logger is None:
        logger = LOG

    if not attack_registry:
        # Normalize in case dicts were passed
        return [s if isinstance(s, str) else task_to_str_func(s) for s in strategies]

    normalized_in: List[str] = [
        s if isinstance(s, str) else task_to_str_func(s) for s in strategies
    ]
    enhanced_strategies: List[str] = []

    # Fast fingerprint-based templates
    if fingerprint:
        fingerprint_strategies = _generate_fingerprint_strategies(fingerprint)
        enhanced_strategies.extend(fingerprint_strategies)

    # Get available attacks from registry
    available_attacks = attack_registry.list_attacks(enabled_only=True)
    logger.info(f"Found {len(available_attacks)} available attacks in registry")

    # Enhance each input strategy
    for strategy in normalized_in:
        enhanced_strategy = enhance_single_strategy(strategy, available_attacks, fingerprint)
        if enhanced_strategy:
            enhanced_strategies.append(enhanced_strategy)

    # Generate registry-based strategies if possible
    if fingerprint and available_attacks:
        try:
            # Try to generate registry strategies if method exists
            if hasattr(attack_registry, "generate_strategies"):
                registry_strategies = attack_registry.generate_strategies(
                    available_attacks, fingerprint, domain, port
                )
                enhanced_strategies.extend(registry_strategies)
        except Exception as e:
            logger.debug(f"Registry strategy generation failed: {e}")

    # Remove duplicates while preserving order
    from core.utils.strategy_utils import deduplicate_preserve_order

    unique_strategies = deduplicate_preserve_order(enhanced_strategies + normalized_in)

    logger.info(
        f"Enhanced {len(strategies)} strategies to {len(unique_strategies)} "
        f"registry-optimized strategies"
    )
    return unique_strategies


def _generate_fingerprint_strategies(fingerprint: Any) -> List[str]:
    """
    Generate strategy strings based on DPI fingerprint detection results.

    Args:
        fingerprint: DPI fingerprint with detection flags

    Returns:
        List of strategy strings tailored to detected DPI behavior

    Examples:
        >>> fingerprint = type('obj', (), {
        ...     'rst_injection_detected': True,
        ...     'tcp_window_manipulation': False
        ... })()
        >>> strategies = _generate_fingerprint_strategies(fingerprint)
        >>> len(strategies) > 0
        True
    """
    strategies: List[str] = []

    # RST injection detected - use fake packets with TTL manipulation
    if getattr(fingerprint, "rst_injection_detected", False):
        strategies.extend(
            [
                "--dpi-desync=fake --dpi-desync-ttl=1 --dpi-desync-fooling=badsum",
                "--dpi-desync=fake --dpi-desync-ttl=2 --dpi-desync-fooling=badsum,badseq",
            ]
        )

    # TCP window manipulation detected - use multisplit with overlap
    if getattr(fingerprint, "tcp_window_manipulation", False):
        strategies.append(
            "--dpi-desync=multisplit --dpi-desync-split-count=3 --dpi-desync-split-seqovl=10"
        )

    # HTTP header filtering detected - use fake+disorder with split
    if getattr(fingerprint, "http_header_filtering", False):
        strategies.append(
            "--dpi-desync=fake,disorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badsum"
        )

    # DNS hijacking detected - enable DoH
    if getattr(fingerprint, "dns_hijacking_detected", False):
        strategies.append("--dns-over-https=on --dpi-desync=fake --dpi-desync-ttl=2")

    # SNI sensitivity detected - use midsld split position
    try:
        sni_sens = fingerprint.raw_metrics.get("sni_sensitivity", {})
        if sni_sens.get("likely") or sni_sens.get("confirmed"):
            strategies.extend(
                [
                    "--dpi-desync=split --dpi-desync-split-pos=midsld",
                    "--dpi-desync=fake,split --dpi-desync-split-pos=midsld --dpi-desync-ttl=1",
                    "--dpi-desync=fake,disorder --dpi-desync-split-pos=midsld --dpi-desync-ttl=2",
                ]
            )

        # QUIC blocking detected - add UDP filter
        quic_blocked = fingerprint.raw_metrics.get("quic_probe", {}).get("blocked")
        if quic_blocked:
            strategies.append("--filter-udp=443 --dpi-desync=fake,disorder --dpi-desync-ttl=1")
    except (AttributeError, KeyError):
        # Fingerprint doesn't have raw_metrics or expected structure
        pass

    return strategies


def enhance_single_strategy(
    strategy: str, available_attacks: List[str], fingerprint: Optional[Any]
) -> Optional[str]:
    """
    Enhance a single strategy using registry information.

    Currently a pass-through that returns the strategy unchanged.
    Future implementations could:
    - Add attack combinations based on available_attacks
    - Adjust parameters based on fingerprint
    - Validate strategy compatibility

    Args:
        strategy: Strategy string to enhance
        available_attacks: List of available attack names from registry
        fingerprint: Optional DPI fingerprint

    Returns:
        Enhanced strategy string (currently unchanged)

    Examples:
        >>> strategy = "--dpi-desync=split"
        >>> enhanced = enhance_single_strategy(strategy, ["fake", "split"], None)
        >>> enhanced == strategy
        True
    """
    # TODO: Implement actual enhancement logic
    # For now, just return the strategy unchanged
    return strategy
