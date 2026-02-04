"""
Telemetry initialization utilities for bypass engine.

This module provides telemetry structure initialization functions.
Extracted from base_engine.py to reduce god class complexity.
"""

import time
from collections import defaultdict
from typing import Any, Dict


def create_telemetry_structure(max_targets: int = 1000) -> Dict[str, Any]:
    """
    Create initial telemetry data structure for bypass engine.

    This function initializes a comprehensive telemetry dictionary that tracks
    various metrics during DPI bypass operations, including:
    - Packet counts (segments, fake packets, QUIC)
    - TTL values for fake and real packets
    - Sequence offsets and overlaps
    - TLS handshake messages (ClientHello, ServerHello)
    - RST packet counts
    - Retransmission detection
    - Per-target statistics

    Args:
        max_targets: Maximum number of target IPs to track individually.
                    Used for memory management. Default: 1000.

    Returns:
        Dictionary containing initialized telemetry structure with:
        - start_ts: Timestamp when telemetry was initialized
        - strategy_key: Current strategy identifier (initially None)
        - aggregate: Global counters for all operations
        - ttls: TTL values used for fake and real packets
        - seq_offsets: TCP sequence number offsets
        - overlaps: Packet overlap counts
        - clienthellos: Count of TLS ClientHello messages
        - serverhellos: Count of TLS ServerHello messages
        - rst_count: Count of RST packets received
        - packets_captured: Total packets captured
        - total_retransmissions_detected: Count of detected retransmissions
        - per_target: Per-IP statistics (defaultdict with lazy initialization)

    Example:
        >>> telemetry = create_telemetry_structure()
        >>> telemetry['aggregate']['segments_sent'] += 1
        >>> telemetry['per_target']['192.168.1.1']['segments_sent'] += 1
    """
    return {
        # Timestamp when telemetry was initialized
        "start_ts": time.time(),
        # Current strategy identifier
        "strategy_key": None,
        # Aggregate counters across all targets
        "aggregate": {
            "segments_sent": 0,  # Total TCP segments sent
            "fake_packets_sent": 0,  # Total fake packets sent
            "modified_packets_sent": 0,  # Total modified packets sent
            "quic_segments_sent": 0,  # Total QUIC segments sent
        },
        # TTL (Time To Live) values used
        "ttls": {
            "fake": defaultdict(int),  # TTL values for fake packets
            "real": defaultdict(int),  # TTL values for real packets
        },
        # TCP sequence number offsets
        "seq_offsets": defaultdict(int),
        # Packet overlap counts (for overlap-based attacks)
        "overlaps": defaultdict(int),
        # TLS handshake message counts
        "clienthellos": 0,  # Count of TLS ClientHello messages
        "serverhellos": 0,  # Count of TLS ServerHello (IMPORTANT for validation)
        # RST packet count
        "rst_count": 0,  # Count of RST packets received
        # General packet counters
        "packets_captured": 0,  # Total packets captured (IMPORTANT)
        # Retransmission detection
        "total_retransmissions_detected": 0,  # Total retransmissions (IMPORTANT)
        # Per-target (per-IP) statistics
        "per_target": defaultdict(
            lambda: {
                "segments_sent": 0,
                "fake_packets_sent": 0,
                "seq_offsets": defaultdict(int),
                "ttls_fake": defaultdict(int),
                "ttls_real": defaultdict(int),
                "overlaps": defaultdict(int),
                "last_outcome": None,  # Last operation outcome (success/failure)
                "last_outcome_ts": None,  # Timestamp of last outcome
            }
        ),
    }
