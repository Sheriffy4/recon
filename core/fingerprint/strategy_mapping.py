# core/fingerprint/strategy_mapping.py
"""
Strategy Mapping - Maps fingerprint signals to concrete bypass strategies.
Provides the "cheat sheet" for converting DPI characteristics into working bypasses.
"""

from typing import Dict, List, Any
from enum import Enum


class DPICharacteristic(Enum):
    """Common DPI characteristics"""

    TLS_HANDSHAKE_TIMEOUT = "tls_handshake_timeout"
    HTTP_PORT_80_WORKS = "http_port_80_works"
    RST_INJECTION_LOW_TTL = "rst_injection_low_ttl"
    RST_INJECTION_HIGH_TTL = "rst_injection_high_ttl"
    SNI_FILTERING = "sni_filtering"
    CONTENT_TYPE_FILTERING = "content_type_filtering"
    TRANSFER_ENCODING_FILTERING = "transfer_encoding_filtering"
    REDIRECT_INJECTION = "redirect_injection"
    SILENT_DROP = "silent_drop"
    FRAGMENTATION_VULNERABLE = "fragmentation_vulnerable"


# Strategy mapping: DPI characteristic → recommended strategies
STRATEGY_MAP: Dict[DPICharacteristic, List[Dict[str, Any]]] = {
    # TLS handshake timeout (HTTPS), but HTTP:80 works → TLS-specific DPI
    DPICharacteristic.TLS_HANDSHAKE_TIMEOUT: [
        {
            "name": "fakeddisorder_cipher",
            "type": "fakeddisorder",
            "params": {"ttl": 1, "split_pos": "cipher", "fooling": ["badsum"]},
            "priority": 90,
            "reasoning": "TLS-specific blocking, fake disorder at cipher position",
        },
        {
            "name": "seqovl_small",
            "type": "seqovl",
            "params": {
                "ttl": 1,
                "split_pos": 3,
                "overlap_size": 20,
                "fooling": ["badsum"],
            },
            "priority": 85,
            "reasoning": "Sequence overlap with small TTL for TLS blocking",
        },
        {
            "name": "tlsrec_split",
            "type": "tlsrec_split",
            "params": {"split_pos": 5},
            "priority": 80,
            "reasoning": "TLS record splitting for handshake manipulation",
        },
    ],
    # RST injection with low TTL (≤10) → Race condition attacks
    DPICharacteristic.RST_INJECTION_LOW_TTL: [
        {
            "name": "fakeddisorder_ttl1",
            "type": "fakeddisorder",
            "params": {"ttl": 1, "split_pos": "midsld", "fooling": ["badsum"]},
            "priority": 95,
            "reasoning": "Low TTL RST injection, use TTL=1 fake packets",
        },
        {
            "name": "badsum_race",
            "type": "fake",
            "params": {"ttl": 2, "fooling": ["badsum"]},
            "priority": 90,
            "reasoning": "Bad checksum race with TTL=2",
        },
        {
            "name": "ip_fragmentation",
            "type": "ipfrag",
            "params": {"frag_size": 24},
            "priority": 85,
            "reasoning": "IP fragmentation to bypass low-TTL DPI",
        },
    ],
    # RST injection with high TTL → More sophisticated DPI
    DPICharacteristic.RST_INJECTION_HIGH_TTL: [
        {
            "name": "multisplit",
            "type": "multisplit",
            "params": {"positions": [3, 7, 11], "fooling": []},
            "priority": 85,
            "reasoning": "High TTL RST, use multi-position splitting",
        },
        {
            "name": "seqovl_large",
            "type": "seqovl",
            "params": {"ttl": 4, "split_pos": 3, "overlap_size": 336, "fooling": []},
            "priority": 80,
            "reasoning": "Large sequence overlap for sophisticated DPI",
        },
    ],
    # SNI filtering detected
    DPICharacteristic.SNI_FILTERING: [
        {
            "name": "fakeddisorder_sni",
            "type": "fakeddisorder",
            "params": {"ttl": 1, "split_pos": "sni", "fooling": ["badsum"]},
            "priority": 95,
            "reasoning": "SNI-based blocking, split at SNI extension",
        },
        {
            "name": "multidisorder_sni",
            "type": "multidisorder",
            "params": {"positions": [5, 10, 15], "fooling": ["badsum"]},
            "priority": 90,
            "reasoning": "Multiple disorder points for SNI obfuscation",
        },
        {
            "name": "split_sld",
            "type": "split",
            "params": {"split_pos": "sld", "fooling": []},
            "priority": 85,
            "reasoning": "Split at second-level domain in SNI",
        },
    ],
    # Content-type or transfer-encoding filtering
    DPICharacteristic.CONTENT_TYPE_FILTERING: [
        {
            "name": "multisplit_small_delay",
            "type": "multisplit",
            "params": {"positions": [3, 7], "delay": 0.01, "fooling": []},
            "priority": 85,
            "reasoning": "Content inspection, use multi-split with delay",
        },
        {
            "name": "tlsrec_split_content",
            "type": "tlsrec_split",
            "params": {"split_pos": 12, "fooling": []},
            "priority": 80,
            "reasoning": "TLS record split for content filtering bypass",
        },
    ],
    # Transfer encoding filtering
    DPICharacteristic.TRANSFER_ENCODING_FILTERING: [
        {
            "name": "multisplit_reversed",
            "type": "multisplit",
            "params": {"positions": [3, 7, 11], "reverse": True, "fooling": []},
            "priority": 85,
            "reasoning": "Transfer encoding filter, use reversed multi-split",
        },
        {
            "name": "multidisorder_transfer",
            "type": "multidisorder",
            "params": {"positions": [5, 10], "fooling": []},
            "priority": 80,
            "reasoning": "Disorder for transfer encoding bypass",
        },
    ],
    # Redirect injection detected
    DPICharacteristic.REDIRECT_INJECTION: [
        {
            "name": "multidisorder_redirect",
            "type": "multidisorder",
            "params": {"positions": [3, 7, 11], "fooling": ["badsum"]},
            "priority": 90,
            "reasoning": "Redirect injection, use multi-disorder",
        },
        {
            "name": "fake_poison",
            "type": "fake",
            "params": {"ttl": 1, "fooling": ["badsum"], "poison": True},
            "priority": 85,
            "reasoning": "Poison fake packet to confuse redirect injection",
        },
    ],
    # Silent drop (no RST, just timeout)
    DPICharacteristic.SILENT_DROP: [
        {
            "name": "multisplit_silent",
            "type": "multisplit",
            "params": {"positions": [3, 7, 11], "fooling": []},
            "priority": 85,
            "reasoning": "Silent drop, use multi-split",
        },
        {
            "name": "seqovl_large_silent",
            "type": "seqovl",
            "params": {"ttl": 4, "split_pos": 3, "overlap_size": 336, "fooling": []},
            "priority": 80,
            "reasoning": "Large overlap for silent drop bypass",
        },
    ],
    # Fragmentation vulnerable
    DPICharacteristic.FRAGMENTATION_VULNERABLE: [
        {
            "name": "multisplit_frag",
            "type": "multisplit",
            "params": {"positions": [3, 7, 11, 15], "fooling": []},
            "priority": 90,
            "reasoning": "DPI vulnerable to fragmentation",
        },
        {
            "name": "ipfrag",
            "type": "ipfrag",
            "params": {"frag_size": 24},
            "priority": 85,
            "reasoning": "IP-level fragmentation",
        },
    ],
}


def get_strategies_for_fingerprint(
    fingerprint_data: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Map fingerprint data to recommended strategies.

    Args:
        fingerprint_data: Fingerprint analysis results

    Returns:
        List of recommended strategies with priorities
    """
    strategies = []
    detected_characteristics = []

    # Extract characteristics from fingerprint
    tcp_analysis = fingerprint_data.get("tcp_analysis", {})
    http_analysis = fingerprint_data.get("http_analysis", {})
    tls_analysis = fingerprint_data.get("tls_analysis", {})

    # Check for TLS handshake timeout
    if tls_analysis.get("handshake_timeout") or http_analysis.get("http_blocking_detected"):
        detected_characteristics.append(DPICharacteristic.TLS_HANDSHAKE_TIMEOUT)

    # Check for RST injection
    if tcp_analysis.get("rst_injection_detected"):
        rst_ttl = tcp_analysis.get("rst_ttl", 0)
        if rst_ttl and rst_ttl <= 10:
            detected_characteristics.append(DPICharacteristic.RST_INJECTION_LOW_TTL)
        else:
            detected_characteristics.append(DPICharacteristic.RST_INJECTION_HIGH_TTL)

    # Check for SNI filtering
    if tls_analysis.get("sni_blocking_detected") or http_analysis.get("sni_host_mismatch_blocking"):
        detected_characteristics.append(DPICharacteristic.SNI_FILTERING)

    # Check for content filtering
    if http_analysis.get("content_type_filtering"):
        detected_characteristics.append(DPICharacteristic.CONTENT_TYPE_FILTERING)

    # Check for transfer encoding filtering
    if http_analysis.get("transfer_encoding_filtering"):
        detected_characteristics.append(DPICharacteristic.TRANSFER_ENCODING_FILTERING)

    # Check for redirect injection
    if http_analysis.get("redirect_injection"):
        detected_characteristics.append(DPICharacteristic.REDIRECT_INJECTION)

    # Check for silent drop
    if tcp_analysis.get("timeout") and not tcp_analysis.get("rst_injection_detected"):
        detected_characteristics.append(DPICharacteristic.SILENT_DROP)

    # Check for fragmentation vulnerability
    if tcp_analysis.get("fragmentation_vulnerable"):
        detected_characteristics.append(DPICharacteristic.FRAGMENTATION_VULNERABLE)

    # Collect strategies for detected characteristics
    seen_strategies = set()
    for characteristic in detected_characteristics:
        for strategy in STRATEGY_MAP.get(characteristic, []):
            strategy_key = f"{strategy['type']}_{strategy['name']}"
            if strategy_key not in seen_strategies:
                strategies.append(strategy)
                seen_strategies.add(strategy_key)

    # Sort by priority
    strategies.sort(key=lambda s: s.get("priority", 0), reverse=True)

    return strategies


def get_fallback_strategies() -> List[Dict[str, Any]]:
    """
    Get universal fallback strategies when fingerprinting provides no clear signals.

    Returns:
        List of generic high-probability strategies
    """
    return [
        {
            "name": "fakeddisorder_universal",
            "type": "fakeddisorder",
            "params": {"ttl": 1, "split_pos": "midsld", "fooling": ["badsum"]},
            "priority": 80,
            "reasoning": "Universal fallback: fake disorder with bad checksum",
        },
        {
            "name": "multisplit_universal",
            "type": "multisplit",
            "params": {"positions": [3, 7, 11], "fooling": []},
            "priority": 75,
            "reasoning": "Universal fallback: multi-position split",
        },
        {
            "name": "seqovl_universal",
            "type": "seqovl",
            "params": {
                "ttl": 2,
                "split_pos": 3,
                "overlap_size": 20,
                "fooling": ["badsum"],
            },
            "priority": 70,
            "reasoning": "Universal fallback: sequence overlap",
        },
    ]
