"""
Validation rule evaluation utilities.

This module provides functions for evaluating validation rules from attack specifications,
extracted from PacketValidator to reduce feature envy and clarify parameter usage.
"""

from typing import List, Dict, Any
from .safe_eval import safe_eval_expr, as_attrdict


def evaluate_checksum_rule(rule_str: str, packets: List[Any]) -> bool:
    """
    Evaluate checksum validation rule.

    Args:
        rule_str: Rule string to evaluate
        packets: List of PacketData objects

    Returns:
        True if rule passes, False otherwise
    """
    # Check if all packets have valid checksums
    if "all(" in rule_str and "checksum_valid" in rule_str:
        return all(p.checksum_valid for p in packets)

    # Check fake packet checksum validity
    if "fake_packet.checksum_valid" in rule_str:
        if packets:
            fake_packet = packets[0]  # Assume first is fake
            if "== False" in rule_str:
                return not fake_packet.checksum_valid
            elif "== True" in rule_str:
                return fake_packet.checksum_valid

    return True


def evaluate_ttl_rule(rule_str: str, packets: List[Any], params: Dict[str, Any]) -> bool:
    """
    Evaluate TTL validation rule.

    Args:
        rule_str: Rule string to evaluate
        packets: List of PacketData objects
        params: Attack parameters (used for expected TTL values)

    Returns:
        True if rule passes, False otherwise
    """
    # Check fake packet TTL
    if "fake_packet.ttl" in rule_str and packets:
        fake_packet = packets[0]
        expected_ttl = params.get("ttl") or params.get("fake_ttl", 1)
        return fake_packet.ttl == expected_ttl

    # Check if all packets have TTL in expected range
    if "all(" in rule_str and ".ttl in" in rule_str:
        return all(p.ttl in [64, 128] for p in packets)

    return True


def evaluate_seq_rule(rule_str: str, packets: List[Any]) -> bool:
    """
    Evaluate sequence number validation rule.

    Args:
        rule_str: Rule string to evaluate
        packets: List of PacketData objects

    Returns:
        True if rule passes, False otherwise
    """
    if len(packets) < 2:
        return True

    # Check if fake and real packets have same sequence number
    if "fake_packet.seq == real_packet.seq" in rule_str:
        return packets[0].sequence_num == packets[1].sequence_num

    # Check if packets are in order
    if "packets[0].seq < packets[1].seq" in rule_str:
        return packets[0].sequence_num < packets[1].sequence_num

    return True


def extract_expected_count(rule_str: str, params: Dict[str, Any], spec: Any) -> int:
    """
    Extract expected packet count from spec.

    Args:
        rule_str: Rule string (unused, kept for API compatibility)
        params: Attack parameters
        spec: Attack specification

    Returns:
        Expected packet count
    """
    expected_packets = spec.expected_packets
    count = expected_packets.get("count", 0)

    # Handle dynamic counts
    if isinstance(count, str):
        try:
            params_obj = as_attrdict(params)
            val = safe_eval_expr(
                count,
                {
                    "params": params_obj,
                    "len": len,
                    "range": range,
                    "True": True,
                    "False": False,
                    "None": None,
                },
            )
            return int(val)
        except Exception:
            return 0

    return count
