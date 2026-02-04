"""
Telemetry reporting utilities.

This module provides functions for generating telemetry snapshots and reports.
Extracted from base_engine.py to reduce god class complexity.
"""

import time
from typing import Any, Dict


def get_empty_telemetry_snapshot() -> Dict[str, Any]:
    """
    Get empty telemetry snapshot for error cases.

    Returns:
        Dictionary with empty/zero telemetry values
    """
    return {
        "start_ts": time.time(),
        "duration_sec": 0.0,
        "clienthellos": 0,
        "serverhellos": 0,
        "rst_count": 0,
        "packets_captured": 0,
        "total_retransmissions_detected": 0,
        "aggregate": {
            "segments_sent": 0,
            "fake_packets_sent": 0,
            "modified_packets_sent": 0,
            "quic_segments_sent": 0,
        },
        "ttls": {"fake": {}, "real": {}},
        "seq_offsets": {},
        "overlaps": {},
        "per_target": {},
        "enhanced_metrics": {
            "handshake_success_rate": 0.0,
            "retransmission_rate": 0.0,
            "packet_efficiency": 0.0,
            "total_handshakes_attempted": 0,
            "total_handshakes_successful": 0,
            "total_packets_processed": 0,
            "total_fake_packets_sent": 0,
            "total_segments_sent": 0,
            "bytes_processed_estimate": 0,
            "connection_attempts": 0,
            "successful_connections": 0,
        },
    }
