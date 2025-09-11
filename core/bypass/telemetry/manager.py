"""Telemetry management for bypass engine."""

import time
import threading
import copy
from collections import defaultdict
from typing import Dict, Any, Optional, Set
from dataclasses import dataclass, field


@dataclass
class TelemetryData:
    """Container for telemetry data."""
    start_ts: float = field(default_factory=time.time)
    strategy_key: Optional[str] = None

    # Aggregate counters
    segments_sent: int = 0
    fake_packets_sent: int = 0
    modified_packets_sent: int = 0
    quic_segments_sent: int = 0

    # Protocol events
    clienthellos: int = 0
    serverhellos: int = 0
    rst_count: int = 0

    # Detailed metrics
    ttls_fake: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    ttls_real: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    seq_offsets: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    overlaps: Dict[int, int] = field(default_factory=lambda: defaultdict(int))

    # Per-target metrics
    per_target: Dict[str, Dict[str, Any]] = field(default_factory=dict)


class TelemetryManager:
    """
    Manages telemetry collection and reporting for bypass engine.
    Thread-safe implementation with automatic cleanup.
    """

    def __init__(self, max_targets: int = 1000):
        self.max_targets = max_targets
        self._lock = threading.Lock()
        self._data = self._init_data()

    def _init_data(self) -> Dict[str, Any]:
        """Initialize telemetry data structure."""
        return {
            "start_ts": time.time(),
            "strategy_key": None,
            "aggregate": {
                "segments_sent": 0,
                "fake_packets_sent": 0,
                "modified_packets_sent": 0,
                "quic_segments_sent": 0
            },
            "ttls": {
                "fake": defaultdict(int),
                "real": defaultdict(int)
            },
            "seq_offsets": defaultdict(int),
            "overlaps": defaultdict(int),
            "clienthellos": 0,
            "serverhellos": 0,
            "rst_count": 0,
            "per_target": defaultdict(lambda: {
                "segments_sent": 0,
                "fake_packets_sent": 0,
                "seq_offsets": defaultdict(int),
                "ttls_fake": defaultdict(int),
                "ttls_real": defaultdict(int),
                "overlaps": defaultdict(int),
                "last_outcome": None,
                "last_outcome_ts": None
            })
        }

    def reset(self):
        """Reset all telemetry data."""
        with self._lock:
            self._data = self._init_data()

    def record_segment_sent(self, target_ip: str, seq_offset: int = 0,
                           ttl: Optional[int] = None, is_fake: bool = False):
        """Record a sent segment."""
        with self._lock:
            self._data["aggregate"]["segments_sent"] += 1

            if is_fake:
                self._data["aggregate"]["fake_packets_sent"] += 1
                if ttl is not None:
                    self._data["ttls"]["fake"][ttl] += 1
            else:
                if ttl is not None:
                    self._data["ttls"]["real"][ttl] += 1

            self._data["seq_offsets"][seq_offset] += 1

            # Per-target accounting
            target = self._data["per_target"][target_ip]
            target["segments_sent"] += 1
            if is_fake:
                target["fake_packets_sent"] += 1
                if ttl is not None:
                    target["ttls_fake"][ttl] += 1
            else:
                if ttl is not None:
                    target["ttls_real"][ttl] += 1
            target["seq_offsets"][seq_offset] += 1

            self._cleanup_old_targets()

    def record_fake_packet(self, target_ip: str, ttl: int):
        """Record a fake packet sent."""
        with self._lock:
            self._data["aggregate"]["fake_packets_sent"] += 1
            self._data["ttls"]["fake"][ttl] += 1

            target = self._data["per_target"][target_ip]
            target["fake_packets_sent"] += 1
            target["ttls_fake"][ttl] += 1

    def record_modified_packet(self, target_ip: str):
        """Record a modified packet sent."""
        with self._lock:
            self._data["aggregate"]["modified_packets_sent"] += 1

    def record_quic_segments(self, count: int):
        """Record QUIC segments sent."""
        with self._lock:
            self._data["aggregate"]["quic_segments_sent"] += count

    def record_clienthello(self, target_ip: str):
        """Record ClientHello detection."""
        with self._lock:
            self._data["clienthellos"] += 1
            # Ensure target entry exists
            _ = self._data["per_target"][target_ip]

    def record_serverhello(self):
        """Record ServerHello reception."""
        with self._lock:
            self._data["serverhellos"] += 1

    def record_rst(self):
        """Record RST packet."""
        with self._lock:
            self._data["rst_count"] += 1

    def record_overlap(self, overlap_size: int):
        """Record overlap size used."""
        with self._lock:
            self._data["overlaps"][overlap_size] += 1

    def record_outcome(self, target_ip: str, outcome: str):
        """Record outcome for a target."""
        with self._lock:
            target = self._data["per_target"][target_ip]
            target["last_outcome"] = outcome
            target["last_outcome_ts"] = time.time()

    def set_strategy_key(self, key: str):
        """Set current strategy key."""
        with self._lock:
            self._data["strategy_key"] = key

    def get_snapshot(self) -> Dict[str, Any]:
        """Get telemetry snapshot."""
        with self._lock:
            snapshot = copy.deepcopy(self._data)

        # Convert defaultdicts to regular dicts for serialization
        snapshot["duration_sec"] = time.time() - snapshot.get("start_ts", time.time())
        snapshot["ttls"]["fake"] = dict(snapshot["ttls"]["fake"])
        snapshot["ttls"]["real"] = dict(snapshot["ttls"]["real"])
        snapshot["seq_offsets"] = dict(snapshot["seq_offsets"])
        snapshot["overlaps"] = dict(snapshot["overlaps"])

        # Convert per-target defaultdicts
        snapshot["per_target"] = {
            target: {
                **metrics,
                "seq_offsets": dict(metrics.get("seq_offsets", {})),
                "ttls_fake": dict(metrics.get("ttls_fake", {})),
                "ttls_real": dict(metrics.get("ttls_real", {})),
                "overlaps": dict(metrics.get("overlaps", {}))
            }
            for target, metrics in snapshot["per_target"].items()
        }

        return snapshot

    def _cleanup_old_targets(self):
        """Remove old targets to prevent memory leak."""
        if len(self._data["per_target"]) > self.max_targets:
            # Sort by last outcome timestamp, treating targets without an outcome as the newest
            sorted_targets = sorted(
                self._data["per_target"].items(),
                key=lambda x: x[1].get("last_outcome_ts") or time.time(),
                reverse=True
            )

            # Clear the existing defaultdict and update it with the newest items
            per_target_dict = self._data["per_target"]
            per_target_dict.clear()
            per_target_dict.update(dict(sorted_targets[:self.max_targets]))
