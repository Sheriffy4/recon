"""
Packet validation utilities.

This package provides modular validation components for DPI bypass attacks.
"""

# Re-export for backward compatibility
from .checksum_utils import calculate_tcp_checksum, validate_tcp_checksum
from .pcap_parser import PacketData, parse_pcap_file, parse_single_packet, parse_network_packet
from .rule_evaluators import (
    evaluate_checksum_rule,
    evaluate_ttl_rule,
    evaluate_seq_rule,
    extract_expected_count,
)
from .attack_validator import AttackValidator
from .diff_generator import DiffGenerator
from .spec_validator import SpecValidator

__all__ = [
    "calculate_tcp_checksum",
    "validate_tcp_checksum",
    "PacketData",
    "parse_pcap_file",
    "parse_single_packet",
    "parse_network_packet",
    "evaluate_checksum_rule",
    "evaluate_ttl_rule",
    "evaluate_seq_rule",
    "extract_expected_count",
    "AttackValidator",
    "DiffGenerator",
    "SpecValidator",
]
