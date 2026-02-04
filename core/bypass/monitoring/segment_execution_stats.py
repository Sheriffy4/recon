#!/usr/bin/env python3
"""
Segment execution statistics and monitoring system.

Provides comprehensive statistics collection and monitoring for segment execution
in the Native Attack Orchestration system.
"""

import time
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from collections import defaultdict, deque
from enum import Enum
import statistics


class ExecutionPhase(Enum):
    """Phases of segment execution."""

    VALIDATION = "validation"
    CONSTRUCTION = "construction"
    TIMING = "timing"
    TRANSMISSION = "transmission"
    COMPLETE = "complete"


class ExecutionStatus(Enum):
    """Status of segment execution."""

    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass
class SegmentExecutionMetrics:
    """Metrics for a single segment execution."""

    segment_id: int
    session_id: str
    payload_size: int
    seq_offset: int
    options: Dict[str, Any]

    # Timing metrics
    start_time: float
    end_time: Optional[float] = None
    phase_times: Dict[ExecutionPhase, float] = field(default_factory=dict)

    # Execution metrics
    status: ExecutionStatus = ExecutionStatus.SUCCESS
    error_message: Optional[str] = None

    # Performance metrics
    construction_time_ms: float = 0.0
    timing_accuracy_error_ms: float = 0.0
    transmission_time_ms: float = 0.0

    # Packet metrics
    packet_size: int = 0
    ttl_modified: bool = False
    checksum_corrupted: bool = False
    tcp_flags_modified: bool = False
    window_size_modified: bool = False

    @property
    def total_execution_time_ms(self) -> float:
        """Calculate total execution time in milliseconds."""
        if self.end_time is None:
            return 0.0
        return (self.end_time - self.start_time) * 1000

    @property
    def is_completed(self) -> bool:
        """Check if segment execution is completed."""
        return self.end_time is not None


@dataclass
class SessionExecutionStats:
    """Statistics for a complete session execution."""

    session_id: str
    connection_id: str
    start_time: float
    end_time: Optional[float] = None

    # Segment metrics
    total_segments: int = 0
    successful_segments: int = 0
    failed_segments: int = 0

    # Timing metrics
    total_execution_time_ms: float = 0.0
    avg_segment_time_ms: float = 0.0
    min_segment_time_ms: float = float("inf")
    max_segment_time_ms: float = 0.0

    # Performance metrics
    total_payload_bytes: int = 0
    total_packet_bytes: int = 0
    throughput_segments_per_sec: float = 0.0
    throughput_bytes_per_sec: float = 0.0

    # Modification statistics
    ttl_modifications: int = 0
    checksum_corruptions: int = 0
    tcp_flags_modifications: int = 0
    window_size_modifications: int = 0

    # Timing accuracy
    avg_timing_accuracy_error_ms: float = 0.0
    timing_accuracy_percent: float = 100.0

    @property
    def success_rate_percent(self) -> float:
        """Calculate success rate percentage."""
        if self.total_segments == 0:
            return 0.0
        return (self.successful_segments / self.total_segments) * 100

    @property
    def is_completed(self) -> bool:
        """Check if session is completed."""
        return self.end_time is not None


@dataclass
class GlobalExecutionStats:
    """Global statistics across all sessions."""

    # Session metrics
    total_sessions: int = 0
    active_sessions: int = 0
    completed_sessions: int = 0
    failed_sessions: int = 0

    # Segment metrics
    total_segments_processed: int = 0
    total_successful_segments: int = 0
    total_failed_segments: int = 0

    # Performance metrics
    avg_session_duration_ms: float = 0.0
    avg_segments_per_session: float = 0.0
    global_throughput_segments_per_sec: float = 0.0
    global_throughput_bytes_per_sec: float = 0.0

    # Timing metrics
    global_avg_timing_accuracy_percent: float = 100.0
    global_avg_construction_time_ms: float = 0.0
    global_avg_transmission_time_ms: float = 0.0

    # Modification statistics
    total_ttl_modifications: int = 0
    total_checksum_corruptions: int = 0
    total_tcp_flags_modifications: int = 0
    total_window_size_modifications: int = 0

    # Error statistics
    error_rate_percent: float = 0.0
    common_errors: Dict[str, int] = field(default_factory=dict)

    @property
    def global_success_rate_percent(self) -> float:
        """Calculate global success rate percentage."""
        if self.total_segments_processed == 0:
            return 0.0
        return (self.total_successful_segments / self.total_segments_processed) * 100


class SegmentExecutionStatsCollector:
    """Collects and manages segment execution statistics."""

    def __init__(self, max_history_size: int = 1000):
        self.max_history_size = max_history_size
        self._lock = threading.RLock()

        # Current metrics
        self._active_segments: Dict[str, SegmentExecutionMetrics] = {}
        self._active_sessions: Dict[str, SessionExecutionStats] = {}

        # Historical data
        self._completed_segments: deque = deque(maxlen=max_history_size)
        self._completed_sessions: deque = deque(maxlen=max_history_size)

        # Global statistics
        self._global_stats = GlobalExecutionStats()

        # Performance tracking
        self._recent_throughput_samples: deque = deque(maxlen=100)
        self._last_throughput_calculation = time.time()

    def start_segment_execution(
        self,
        segment_id: int,
        session_id: str,
        payload_size: int,
        seq_offset: int,
        options: Dict[str, Any],
    ) -> SegmentExecutionMetrics:
        """Start tracking a segment execution."""
        with self._lock:
            metrics = SegmentExecutionMetrics(
                segment_id=segment_id,
                session_id=session_id,
                payload_size=payload_size,
                seq_offset=seq_offset,
                options=options.copy(),
                start_time=time.time(),
            )

            segment_key = f"{session_id}_{segment_id}"
            self._active_segments[segment_key] = metrics

            return metrics

    def update_segment_phase(
        self,
        metrics: SegmentExecutionMetrics,
        phase: ExecutionPhase,
        duration_ms: float,
    ):
        """Update segment execution phase timing."""
        with self._lock:
            metrics.phase_times[phase] = duration_ms

            # Update specific metrics based on phase
            if phase == ExecutionPhase.CONSTRUCTION:
                metrics.construction_time_ms = duration_ms
            elif phase == ExecutionPhase.TRANSMISSION:
                metrics.transmission_time_ms = duration_ms

    def complete_segment_execution(
        self,
        metrics: SegmentExecutionMetrics,
        status: ExecutionStatus,
        error_message: Optional[str] = None,
        packet_size: int = 0,
        ttl_modified: bool = False,
        checksum_corrupted: bool = False,
        tcp_flags_modified: bool = False,
        window_size_modified: bool = False,
        timing_accuracy_error_ms: float = 0.0,
    ):
        """Complete segment execution tracking."""
        with self._lock:
            metrics.end_time = time.time()
            metrics.status = status
            metrics.error_message = error_message
            metrics.packet_size = packet_size
            metrics.ttl_modified = ttl_modified
            metrics.checksum_corrupted = checksum_corrupted
            metrics.tcp_flags_modified = tcp_flags_modified
            metrics.window_size_modified = window_size_modified
            metrics.timing_accuracy_error_ms = timing_accuracy_error_ms

            # Remove from active tracking
            segment_key = f"{metrics.session_id}_{metrics.segment_id}"
            if segment_key in self._active_segments:
                del self._active_segments[segment_key]

            # Add to completed history
            self._completed_segments.append(metrics)

            # Update global statistics
            self._update_global_stats_for_segment(metrics)

            # Update session statistics
            self._update_session_stats_for_segment(metrics)

    def start_session(self, session_id: str, connection_id: str) -> SessionExecutionStats:
        """Start tracking a session execution."""
        with self._lock:
            session_stats = SessionExecutionStats(
                session_id=session_id,
                connection_id=connection_id,
                start_time=time.time(),
            )

            self._active_sessions[session_id] = session_stats
            self._global_stats.total_sessions += 1
            self._global_stats.active_sessions += 1

            return session_stats

    def complete_session(self, session_id: str) -> Optional[SessionExecutionStats]:
        """Complete session execution tracking."""
        with self._lock:
            if session_id not in self._active_sessions:
                return None

            session_stats = self._active_sessions[session_id]
            session_stats.end_time = time.time()

            # Calculate final session metrics
            self._finalize_session_stats(session_stats)

            # Remove from active tracking
            del self._active_sessions[session_id]

            # Add to completed history
            self._completed_sessions.append(session_stats)

            # Update global statistics
            self._global_stats.active_sessions -= 1
            self._global_stats.completed_sessions += 1

            return session_stats

    def get_segment_metrics(
        self, session_id: str, segment_id: int
    ) -> Optional[SegmentExecutionMetrics]:
        """Get metrics for a specific segment."""
        with self._lock:
            segment_key = f"{session_id}_{segment_id}"
            return self._active_segments.get(segment_key)

    def get_session_stats(self, session_id: str) -> Optional[SessionExecutionStats]:
        """Get statistics for a specific session."""
        with self._lock:
            return self._active_sessions.get(session_id)

    def get_global_stats(self) -> GlobalExecutionStats:
        """Get global execution statistics."""
        with self._lock:
            # Update real-time metrics
            self._update_global_realtime_stats()
            return self._global_stats

    def get_recent_sessions(self, count: int = 10) -> List[SessionExecutionStats]:
        """Get recent completed sessions."""
        with self._lock:
            return list(self._completed_sessions)[-count:]

    def get_recent_segments(self, count: int = 50) -> List[SegmentExecutionMetrics]:
        """Get recent completed segments."""
        with self._lock:
            return list(self._completed_segments)[-count:]

    def get_performance_summary(self) -> Dict[str, Any]:
        """Get comprehensive performance summary."""
        with self._lock:
            recent_sessions = list(self._completed_sessions)[-10:]
            recent_segments = list(self._completed_segments)[-100:]

            if not recent_sessions:
                return {"error": "No completed sessions available"}

            # Calculate recent performance metrics
            recent_success_rate = 0.0
            recent_avg_time = 0.0
            recent_throughput = 0.0

            if recent_segments:
                successful_segments = [
                    s for s in recent_segments if s.status == ExecutionStatus.SUCCESS
                ]
                recent_success_rate = (len(successful_segments) / len(recent_segments)) * 100

                if successful_segments:
                    recent_avg_time = statistics.mean(
                        [s.total_execution_time_ms for s in successful_segments]
                    )

                # Calculate recent throughput
                if len(recent_segments) > 1:
                    time_span = recent_segments[-1].start_time - recent_segments[0].start_time
                    if time_span > 0:
                        recent_throughput = len(recent_segments) / time_span

            return {
                "global_stats": self._global_stats,
                "recent_performance": {
                    "success_rate_percent": recent_success_rate,
                    "avg_execution_time_ms": recent_avg_time,
                    "throughput_segments_per_sec": recent_throughput,
                    "active_sessions": len(self._active_sessions),
                    "active_segments": len(self._active_segments),
                },
                "timing_analysis": self._get_timing_analysis(),
                "modification_analysis": self._get_modification_analysis(),
                "error_analysis": self._get_error_analysis(),
            }

    def reset_statistics(self):
        """Reset all statistics."""
        with self._lock:
            self._active_segments.clear()
            self._active_sessions.clear()
            self._completed_segments.clear()
            self._completed_sessions.clear()
            self._global_stats = GlobalExecutionStats()
            self._recent_throughput_samples.clear()

    def _update_global_stats_for_segment(self, metrics: SegmentExecutionMetrics):
        """Update global statistics for a completed segment."""
        self._global_stats.total_segments_processed += 1

        if metrics.status == ExecutionStatus.SUCCESS:
            self._global_stats.total_successful_segments += 1
        else:
            self._global_stats.total_failed_segments += 1

            # Track error types
            if metrics.error_message:
                error_type = metrics.error_message.split(":")[0]  # Get error type
                self._global_stats.common_errors[error_type] = (
                    self._global_stats.common_errors.get(error_type, 0) + 1
                )

        # Update modification statistics
        if metrics.ttl_modified:
            self._global_stats.total_ttl_modifications += 1
        if metrics.checksum_corrupted:
            self._global_stats.total_checksum_corruptions += 1
        if metrics.tcp_flags_modified:
            self._global_stats.total_tcp_flags_modifications += 1
        if metrics.window_size_modified:
            self._global_stats.total_window_size_modifications += 1

    def _update_session_stats_for_segment(self, metrics: SegmentExecutionMetrics):
        """Update session statistics for a completed segment."""
        if metrics.session_id not in self._active_sessions:
            return

        session_stats = self._active_sessions[metrics.session_id]
        session_stats.total_segments += 1

        if metrics.status == ExecutionStatus.SUCCESS:
            session_stats.successful_segments += 1
        else:
            session_stats.failed_segments += 1

        # Update timing metrics
        execution_time = metrics.total_execution_time_ms
        session_stats.min_segment_time_ms = min(session_stats.min_segment_time_ms, execution_time)
        session_stats.max_segment_time_ms = max(session_stats.max_segment_time_ms, execution_time)

        # Update payload and packet sizes
        session_stats.total_payload_bytes += metrics.payload_size
        session_stats.total_packet_bytes += metrics.packet_size

        # Update modification statistics
        if metrics.ttl_modified:
            session_stats.ttl_modifications += 1
        if metrics.checksum_corrupted:
            session_stats.checksum_corruptions += 1
        if metrics.tcp_flags_modified:
            session_stats.tcp_flags_modifications += 1
        if metrics.window_size_modified:
            session_stats.window_size_modifications += 1

    def _finalize_session_stats(self, session_stats: SessionExecutionStats):
        """Finalize session statistics calculations."""
        if session_stats.total_segments > 0:
            # Calculate average segment time
            total_time = 0.0
            timing_errors = []

            # Get all segments for this session
            session_segments = [
                s for s in self._completed_segments if s.session_id == session_stats.session_id
            ]

            if session_segments:
                total_time = sum(s.total_execution_time_ms for s in session_segments)
                session_stats.avg_segment_time_ms = total_time / len(session_segments)

                # Calculate timing accuracy
                timing_errors = [
                    abs(s.timing_accuracy_error_ms)
                    for s in session_segments
                    if s.timing_accuracy_error_ms != 0
                ]

                if timing_errors:
                    session_stats.avg_timing_accuracy_error_ms = statistics.mean(timing_errors)
                    # Calculate accuracy percentage (assuming requested delays are reasonable)
                    avg_requested_delay = (
                        statistics.mean(
                            [
                                s.options.get("delay_ms", 0)
                                for s in session_segments
                                if s.options.get("delay_ms", 0) > 0
                            ]
                        )
                        if any(s.options.get("delay_ms", 0) > 0 for s in session_segments)
                        else 1.0
                    )

                    if avg_requested_delay > 0:
                        error_percent = (
                            session_stats.avg_timing_accuracy_error_ms / avg_requested_delay
                        ) * 100
                        session_stats.timing_accuracy_percent = max(0, 100 - error_percent)

        # Calculate session duration and throughput
        if session_stats.end_time:
            session_duration = session_stats.end_time - session_stats.start_time
            session_stats.total_execution_time_ms = session_duration * 1000

            if session_duration > 0:
                session_stats.throughput_segments_per_sec = (
                    session_stats.total_segments / session_duration
                )
                session_stats.throughput_bytes_per_sec = (
                    session_stats.total_payload_bytes / session_duration
                )

    def _update_global_realtime_stats(self):
        """Update global real-time statistics."""
        if not self._completed_sessions:
            return

        # Calculate averages from completed sessions
        completed_sessions = list(self._completed_sessions)

        if completed_sessions:
            session_durations = [
                s.total_execution_time_ms for s in completed_sessions if s.is_completed
            ]
            if session_durations:
                self._global_stats.avg_session_duration_ms = statistics.mean(session_durations)

            segments_per_session = [s.total_segments for s in completed_sessions]
            if segments_per_session:
                self._global_stats.avg_segments_per_session = statistics.mean(segments_per_session)

        # Calculate global throughput
        current_time = time.time()
        if current_time - self._last_throughput_calculation > 1.0:  # Update every second
            recent_segments = [
                s for s in self._completed_segments if current_time - s.start_time < 60
            ]  # Last minute

            if len(recent_segments) > 1:
                time_span = recent_segments[-1].start_time - recent_segments[0].start_time
                if time_span > 0:
                    self._global_stats.global_throughput_segments_per_sec = (
                        len(recent_segments) / time_span
                    )

                    total_bytes = sum(s.payload_size for s in recent_segments)
                    self._global_stats.global_throughput_bytes_per_sec = total_bytes / time_span

            self._last_throughput_calculation = current_time

        # Update error rate
        if self._global_stats.total_segments_processed > 0:
            self._global_stats.error_rate_percent = (
                self._global_stats.total_failed_segments
                / self._global_stats.total_segments_processed
            ) * 100

    def _get_timing_analysis(self) -> Dict[str, Any]:
        """Get detailed timing analysis."""
        recent_segments = list(self._completed_segments)[-100:]

        if not recent_segments:
            return {"error": "No segments available for timing analysis"}

        construction_times = [
            s.construction_time_ms for s in recent_segments if s.construction_time_ms > 0
        ]
        transmission_times = [
            s.transmission_time_ms for s in recent_segments if s.transmission_time_ms > 0
        ]
        total_times = [s.total_execution_time_ms for s in recent_segments]
        timing_errors = [
            abs(s.timing_accuracy_error_ms)
            for s in recent_segments
            if s.timing_accuracy_error_ms != 0
        ]

        return {
            "construction_time_ms": {
                "avg": statistics.mean(construction_times) if construction_times else 0,
                "min": min(construction_times) if construction_times else 0,
                "max": max(construction_times) if construction_times else 0,
                "samples": len(construction_times),
            },
            "transmission_time_ms": {
                "avg": statistics.mean(transmission_times) if transmission_times else 0,
                "min": min(transmission_times) if transmission_times else 0,
                "max": max(transmission_times) if transmission_times else 0,
                "samples": len(transmission_times),
            },
            "total_execution_time_ms": {
                "avg": statistics.mean(total_times) if total_times else 0,
                "min": min(total_times) if total_times else 0,
                "max": max(total_times) if total_times else 0,
                "samples": len(total_times),
            },
            "timing_accuracy_error_ms": {
                "avg": statistics.mean(timing_errors) if timing_errors else 0,
                "min": min(timing_errors) if timing_errors else 0,
                "max": max(timing_errors) if timing_errors else 0,
                "samples": len(timing_errors),
            },
        }

    def _get_modification_analysis(self) -> Dict[str, Any]:
        """Get detailed modification analysis."""
        recent_segments = list(self._completed_segments)[-100:]

        if not recent_segments:
            return {"error": "No segments available for modification analysis"}

        ttl_modified = sum(1 for s in recent_segments if s.ttl_modified)
        checksum_corrupted = sum(1 for s in recent_segments if s.checksum_corrupted)
        tcp_flags_modified = sum(1 for s in recent_segments if s.tcp_flags_modified)
        window_size_modified = sum(1 for s in recent_segments if s.window_size_modified)

        total_segments = len(recent_segments)

        return {
            "ttl_modifications": {
                "count": ttl_modified,
                "percentage": ((ttl_modified / total_segments) * 100 if total_segments > 0 else 0),
            },
            "checksum_corruptions": {
                "count": checksum_corrupted,
                "percentage": (
                    (checksum_corrupted / total_segments) * 100 if total_segments > 0 else 0
                ),
            },
            "tcp_flags_modifications": {
                "count": tcp_flags_modified,
                "percentage": (
                    (tcp_flags_modified / total_segments) * 100 if total_segments > 0 else 0
                ),
            },
            "window_size_modifications": {
                "count": window_size_modified,
                "percentage": (
                    (window_size_modified / total_segments) * 100 if total_segments > 0 else 0
                ),
            },
            "total_segments_analyzed": total_segments,
        }

    def _get_error_analysis(self) -> Dict[str, Any]:
        """Get detailed error analysis."""
        recent_segments = list(self._completed_segments)[-100:]

        if not recent_segments:
            return {"error": "No segments available for error analysis"}

        error_counts = defaultdict(int)
        status_counts = defaultdict(int)

        for segment in recent_segments:
            status_counts[segment.status.value] += 1

            if segment.error_message:
                error_type = segment.error_message.split(":")[0]
                error_counts[error_type] += 1

        total_segments = len(recent_segments)

        return {
            "status_distribution": dict(status_counts),
            "error_types": dict(error_counts),
            "error_rate_percent": (
                (status_counts.get("failed", 0) / total_segments) * 100 if total_segments > 0 else 0
            ),
            "success_rate_percent": (
                (status_counts.get("success", 0) / total_segments) * 100
                if total_segments > 0
                else 0
            ),
            "total_segments_analyzed": total_segments,
        }


# Global instance
_global_stats_collector: Optional[SegmentExecutionStatsCollector] = None
_stats_lock = threading.Lock()


def get_segment_stats_collector() -> SegmentExecutionStatsCollector:
    """Get the global segment execution statistics collector."""
    global _global_stats_collector

    with _stats_lock:
        if _global_stats_collector is None:
            _global_stats_collector = SegmentExecutionStatsCollector()
        return _global_stats_collector


def reset_global_stats():
    """Reset global statistics collector."""
    global _global_stats_collector

    with _stats_lock:
        if _global_stats_collector is not None:
            _global_stats_collector.reset_statistics()
