"""Flow state management for bypass engine."""

import time
import threading
from typing import Dict, Tuple, Optional, Set, Any
from dataclasses import dataclass


@dataclass
class FlowInfo:
    """Information about a network flow."""

    start_ts: float
    key: str  # Domain or IP
    strategy: Dict[str, Any]
    outcome: Optional[str] = None
    outcome_ts: Optional[float] = None


FlowId = Tuple[str, int, str, int]  # (src_addr, src_port, dst_addr, dst_port)


class FlowManager:
    """
    Manages network flow states and early stopping events.
    Thread-safe implementation with automatic cleanup.
    """

    def __init__(self, ttl_sec: float = 3.0):
        self.ttl_sec = ttl_sec
        self._flows: Dict[FlowId, FlowInfo] = {}
        self._active_flows: Set[FlowId] = set()
        self._lock = threading.Lock()

        # For early stopping events
        self._events: Dict[FlowId, threading.Event] = {}
        self._results: Dict[FlowId, str] = {}

        # Cleanup thread
        self._cleanup_timer = None
        self._start_cleanup_timer()

    def register_flow(self, flow_id: FlowId, key: str, strategy: Dict[str, Any]) -> bool:
        """
        Register a new flow.

        Args:
            flow_id: Flow identifier tuple
            key: Domain or IP key
            strategy: Strategy being applied

        Returns:
            True if flow was registered, False if already active
        """
        with self._lock:
            if flow_id in self._active_flows:
                return False

            self._flows[flow_id] = FlowInfo(start_ts=time.time(), key=key, strategy=strategy)
            self._active_flows.add(flow_id)

            # Schedule individual cleanup
            threading.Timer(self.ttl_sec, lambda: self._cleanup_flow(flow_id)).start()

            return True

    def is_flow_active(self, flow_id: FlowId) -> bool:
        """Check if flow is active."""
        with self._lock:
            return flow_id in self._active_flows

    def get_flow(self, flow_id: FlowId) -> Optional[FlowInfo]:
        """Get flow information."""
        with self._lock:
            return self._flows.get(flow_id)

    def pop_flow(self, flow_id: FlowId) -> Optional[FlowInfo]:
        """Remove and return flow information."""
        with self._lock:
            self._active_flows.discard(flow_id)
            return self._flows.pop(flow_id, None)

    def set_outcome(self, flow_id: FlowId, outcome: str):
        """
        Set flow outcome and trigger early stopping event.

        Args:
            flow_id: Flow identifier
            outcome: Outcome string ('ok', 'rst', etc.)
        """
        with self._lock:
            if flow_id in self._flows:
                self._flows[flow_id].outcome = outcome
                self._flows[flow_id].outcome_ts = time.time()

            # Store result and trigger event
            self._results[flow_id] = outcome
            event = self._events.get(flow_id)
            if event:
                event.set()

    def get_event(self, flow_id: FlowId) -> threading.Event:
        """Get or create early stopping event for flow."""
        with self._lock:
            if flow_id not in self._events:
                self._events[flow_id] = threading.Event()
            return self._events[flow_id]

    def get_result(self, flow_id: FlowId) -> Optional[str]:
        """Get flow result if available."""
        with self._lock:
            return self._results.get(flow_id)

    def clear_event(self, flow_id: FlowId):
        """Clear event and result for flow."""
        with self._lock:
            event = self._events.get(flow_id)
            if event:
                event.clear()
            self._results.pop(flow_id, None)

    def cleanup_old_flows(self, max_age_sec: float = 30.0):
        """Clean up flows older than max_age_sec."""
        current_time = time.time()
        with self._lock:
            old_flows = [
                fid
                for fid, info in self._flows.items()
                if current_time - info.start_ts > max_age_sec
            ]
            for fid in old_flows:
                self._cleanup_flow_unsafe(fid)

    def _cleanup_flow(self, flow_id: FlowId):
        """Clean up a specific flow (thread-safe)."""
        with self._lock:
            self._cleanup_flow_unsafe(flow_id)

    def _cleanup_flow_unsafe(self, flow_id: FlowId):
        """Clean up a specific flow (requires lock)."""
        self._active_flows.discard(flow_id)
        self._flows.pop(flow_id, None)
        self._events.pop(flow_id, None)
        self._results.pop(flow_id, None)

    def _start_cleanup_timer(self):
        """Start periodic cleanup timer."""
        self.cleanup_old_flows()
        self._cleanup_timer = threading.Timer(
            30.0, self._start_cleanup_timer  # Cleanup every 30 seconds
        )
        self._cleanup_timer.daemon = True
        self._cleanup_timer.start()

    def shutdown(self):
        """Shutdown flow manager and cleanup resources."""
        if self._cleanup_timer:
            self._cleanup_timer.cancel()
        with self._lock:
            self._flows.clear()
            self._active_flows.clear()
            self._events.clear()
            self._results.clear()
