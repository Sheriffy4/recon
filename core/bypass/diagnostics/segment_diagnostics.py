#!/usr/bin/env python3
"""
Segment Execution Diagnostics System.

Provides comprehensive logging and monitoring for segment-based attack execution,
including detailed analysis of timing, packet construction, and transmission.
"""

import time
import logging
import threading
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum

# Optional imports: do not fail module import if these components are unavailable.
# This module is used by CLI tooling and should degrade gracefully.
try:
    from core.bypass.attacks.segment_packet_builder import SegmentPacketInfo  # type: ignore
except Exception as e:  # pragma: no cover
    SegmentPacketInfo = Any  # type: ignore
    _SEGMENT_PACKET_INFO_IMPORT_ERROR = e

try:
    from core.bypass.attacks.timing_controller import TimingMeasurement  # type: ignore
except Exception as e:  # pragma: no cover
    TimingMeasurement = Any  # type: ignore
    _TIMING_MEASUREMENT_IMPORT_ERROR = e


class SegmentExecutionPhase(Enum):
    """Phases of segment execution."""

    VALIDATION = "validation"
    CONSTRUCTION = "construction"
    TIMING = "timing"
    TRANSMISSION = "transmission"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class SegmentExecutionEvent:
    """Event during segment execution."""

    timestamp: float
    segment_id: int
    phase: SegmentExecutionPhase
    event_type: str
    message: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    duration_ms: Optional[float] = None
    error: Optional[str] = None


@dataclass
class SegmentDiagnosticData:
    """Comprehensive diagnostic data for a segment."""

    segment_id: int
    payload_size: int
    seq_offset: int
    options: Dict[str, Any]

    # Execution phases
    validation_time_ms: Optional[float] = None
    construction_time_ms: Optional[float] = None
    timing_delay_ms: Optional[float] = None
    transmission_time_ms: Optional[float] = None
    total_execution_time_ms: Optional[float] = None

    # Packet information
    packet_info: Optional[SegmentPacketInfo] = None
    timing_measurement: Optional[TimingMeasurement] = None

    # Results
    success: bool = False
    error_message: Optional[str] = None

    # Events log
    events: List[SegmentExecutionEvent] = field(default_factory=list)


@dataclass
class SegmentExecutionSummary:
    """Summary of segment execution session."""

    session_id: str
    connection_id: str
    total_segments: int
    successful_segments: int
    failed_segments: int

    # Timing analysis
    total_execution_time_ms: float
    average_segment_time_ms: float
    min_segment_time_ms: float
    max_segment_time_ms: float

    # Packet analysis
    total_packets_built: int
    total_bytes_transmitted: int
    ttl_modifications: int
    checksum_corruptions: int
    timing_delays_applied: int

    # Accuracy analysis
    timing_accuracy_average: float
    timing_errors: int
    construction_errors: int
    transmission_errors: int

    # Performance metrics
    packets_per_second: float
    bytes_per_second: float

    # Detailed breakdown
    segments_data: List[SegmentDiagnosticData] = field(default_factory=list)


class SegmentDiagnosticLogger:
    """
    Advanced diagnostic logger for segment execution.

    Provides detailed logging, analysis, and reporting capabilities
    for segment-based attack orchestration.
    """

    def __init__(self, logger_name: str = "SegmentDiagnostics"):
        """
        Initialize segment diagnostic logger.

        Args:
            logger_name: Name for the logger instance
        """
        self.logger = logging.getLogger(logger_name)
        self.session_data: Dict[str, List[SegmentDiagnosticData]] = {}
        self.active_sessions: Dict[str, float] = {}  # session_id -> start_time
        self._session_connection_ids: Dict[str, str] = {}  # session_id -> connection_id
        self.lock = threading.Lock()

        # Configuration
        self.max_events_per_segment = 100
        self.max_sessions_history = 50
        self.detailed_logging = True

        # Statistics
        self.total_sessions = 0
        self.total_segments_processed = 0
        self.total_execution_time_ms = 0.0

    def start_session(self, session_id: str, connection_id: str) -> None:
        """
        Start a new diagnostic session.

        Args:
            session_id: Unique session identifier
            connection_id: Connection identifier
        """
        with self.lock:
            self.active_sessions[session_id] = time.time()
            self._session_connection_ids[session_id] = connection_id
            self.session_data[session_id] = []
            self.total_sessions += 1

            if self.detailed_logging:
                self.logger.info(
                    f"Started diagnostic session {session_id} for connection {connection_id}"
                )

    def log_segment_start(
        self,
        session_id: str,
        segment_id: int,
        payload_size: int,
        seq_offset: int,
        options: Dict[str, Any],
    ) -> SegmentDiagnosticData:
        """
        Log the start of segment execution.

        Args:
            session_id: Session identifier
            segment_id: Segment identifier
            payload_size: Size of segment payload
            seq_offset: TCP sequence offset
            options: Segment options

        Returns:
            SegmentDiagnosticData object for this segment
        """
        segment_data = SegmentDiagnosticData(
            segment_id=segment_id,
            payload_size=payload_size,
            seq_offset=seq_offset,
            options=options.copy(),
        )

        # Add start event
        event = SegmentExecutionEvent(
            timestamp=time.time(),
            segment_id=segment_id,
            phase=SegmentExecutionPhase.VALIDATION,
            event_type="segment_start",
            message=f"Starting segment {segment_id} execution",
            metadata={
                "payload_size": payload_size,
                "seq_offset": seq_offset,
                "options": options,
            },
        )
        segment_data.events.append(event)

        with self.lock:
            if session_id in self.session_data:
                self.session_data[session_id].append(segment_data)

            self.total_segments_processed += 1

        if self.detailed_logging:
            self.logger.debug(
                f"Session {session_id}: Started segment {segment_id} "
                f"(payload: {payload_size} bytes, offset: {seq_offset})"
            )

        return segment_data

    def log_validation_phase(
        self,
        segment_data: SegmentDiagnosticData,
        validation_time_ms: float,
        success: bool,
        error_message: Optional[str] = None,
    ) -> None:
        """
        Log segment validation phase.

        Args:
            segment_data: Segment diagnostic data
            validation_time_ms: Time spent in validation
            success: Whether validation succeeded
            error_message: Error message if validation failed
        """
        segment_data.validation_time_ms = validation_time_ms

        event = SegmentExecutionEvent(
            timestamp=time.time(),
            segment_id=segment_data.segment_id,
            phase=SegmentExecutionPhase.VALIDATION,
            event_type="validation_complete",
            message=f"Validation {'succeeded' if success else 'failed'}",
            duration_ms=validation_time_ms,
            error=error_message,
        )
        segment_data.events.append(event)

        if not success:
            segment_data.error_message = error_message

        if self.detailed_logging:
            status = "succeeded" if success else f"failed: {error_message}"
            self.logger.debug(
                f"Segment {segment_data.segment_id} validation {status} "
                f"({validation_time_ms:.3f}ms)"
            )

    def log_construction_phase(
        self, segment_data: SegmentDiagnosticData, packet_info: SegmentPacketInfo
    ) -> None:
        """
        Log packet construction phase.

        Args:
            segment_data: Segment diagnostic data
            packet_info: Constructed packet information
        """
        segment_data.construction_time_ms = packet_info.construction_time_ms
        segment_data.packet_info = packet_info

        event = SegmentExecutionEvent(
            timestamp=time.time(),
            segment_id=segment_data.segment_id,
            phase=SegmentExecutionPhase.CONSTRUCTION,
            event_type="construction_complete",
            message=f"Packet constructed ({packet_info.packet_size} bytes)",
            duration_ms=packet_info.construction_time_ms,
            metadata={
                "packet_size": packet_info.packet_size,
                "tcp_seq": packet_info.tcp_seq,
                "tcp_ack": packet_info.tcp_ack,
                "ttl": packet_info.ttl,
                "checksum_corrupted": packet_info.checksum_corrupted,
                "options_applied": packet_info.options_applied,
            },
        )
        segment_data.events.append(event)

        if self.detailed_logging:
            modifications = []
            if packet_info.ttl != 64:
                modifications.append(f"TTL={packet_info.ttl}")
            if packet_info.checksum_corrupted:
                modifications.append("bad_checksum")

            mod_str = f" ({', '.join(modifications)})" if modifications else ""

            self.logger.debug(
                f"Segment {segment_data.segment_id} packet constructed: "
                f"{packet_info.packet_size} bytes, seq={packet_info.tcp_seq}"
                f"{mod_str} ({packet_info.construction_time_ms:.3f}ms)"
            )

    def log_timing_phase(
        self, segment_data: SegmentDiagnosticData, timing_measurement: TimingMeasurement
    ) -> None:
        """
        Log timing delay phase.

        Args:
            segment_data: Segment diagnostic data
            timing_measurement: Timing measurement result
        """
        segment_data.timing_delay_ms = timing_measurement.actual_delay_ms
        segment_data.timing_measurement = timing_measurement

        event = SegmentExecutionEvent(
            timestamp=time.time(),
            segment_id=segment_data.segment_id,
            phase=SegmentExecutionPhase.TIMING,
            event_type="timing_complete",
            message=f"Timing delay applied ({timing_measurement.actual_delay_ms:.3f}ms)",
            duration_ms=timing_measurement.actual_delay_ms,
            metadata={
                "requested_delay_ms": timing_measurement.requested_delay_ms,
                "actual_delay_ms": timing_measurement.actual_delay_ms,
                "accuracy_error_ms": timing_measurement.accuracy_error_ms,
                "strategy_used": timing_measurement.strategy_used.value,
            },
        )
        segment_data.events.append(event)

        if self.detailed_logging:
            accuracy = abs(timing_measurement.accuracy_error_ms)
            self.logger.debug(
                f"Segment {segment_data.segment_id} timing delay: "
                f"requested={timing_measurement.requested_delay_ms:.3f}ms, "
                f"actual={timing_measurement.actual_delay_ms:.3f}ms, "
                f"error={accuracy:.3f}ms, strategy={timing_measurement.strategy_used.value}"
            )

    def log_transmission_phase(
        self,
        segment_data: SegmentDiagnosticData,
        transmission_time_ms: float,
        success: bool,
        error_message: Optional[str] = None,
    ) -> None:
        """
        Log packet transmission phase.

        Args:
            segment_data: Segment diagnostic data
            transmission_time_ms: Time spent in transmission
            success: Whether transmission succeeded
            error_message: Error message if transmission failed
        """
        segment_data.transmission_time_ms = transmission_time_ms
        segment_data.success = success

        if not success and error_message:
            segment_data.error_message = error_message

        phase = SegmentExecutionPhase.COMPLETED if success else SegmentExecutionPhase.FAILED

        event = SegmentExecutionEvent(
            timestamp=time.time(),
            segment_id=segment_data.segment_id,
            phase=phase,
            event_type="transmission_complete",
            message=f"Transmission {'succeeded' if success else 'failed'}",
            duration_ms=transmission_time_ms,
            error=error_message,
        )
        segment_data.events.append(event)

        # Calculate total execution time
        if segment_data.events:
            start_time = segment_data.events[0].timestamp
            end_time = event.timestamp
            segment_data.total_execution_time_ms = (end_time - start_time) * 1000

        if self.detailed_logging:
            status = "succeeded" if success else f"failed: {error_message}"
            self.logger.debug(
                f"Segment {segment_data.segment_id} transmission {status} "
                f"({transmission_time_ms:.3f}ms)"
            )

            if success and segment_data.total_execution_time_ms:
                self.logger.info(
                    f"Segment {segment_data.segment_id} completed successfully "
                    f"(total: {segment_data.total_execution_time_ms:.3f}ms)"
                )

    def get_session_snapshot(self, session_id: str) -> Dict[str, Any]:
        """
        Non-destructive summary for active sessions (useful for CLI).
        Does not end the session.

        Args:
            session_id: Session identifier

        Returns:
            Dictionary with current session statistics
        """
        with self.lock:
            segments = self.session_data.get(session_id, [])
            total_segments = len(segments)
            successful = sum(1 for s in segments if s.success)
            failed = total_segments - successful
            start_time = self.active_sessions.get(session_id)
            now = time.time()
            elapsed_ms = (now - start_time) * 1000 if start_time else 0.0
            return {
                "session_id": session_id,
                "connection_id": self._session_connection_ids.get(session_id, session_id),
                "total_segments": total_segments,
                "successful_segments": successful,
                "failed_segments": failed,
                "elapsed_ms": elapsed_ms,
            }

    def end_session(self, session_id: str) -> SegmentExecutionSummary:
        """
        End diagnostic session and generate summary.

        Args:
            session_id: Session identifier

        Returns:
            Comprehensive execution summary
        """
        with self.lock:
            if session_id not in self.session_data:
                raise ValueError(f"Session {session_id} not found")

            segments_data = self.session_data[session_id]
            start_time = self.active_sessions.get(session_id, time.time())
            end_time = time.time()

            # Calculate summary statistics
            total_segments = len(segments_data)
            successful_segments = sum(1 for s in segments_data if s.success)
            failed_segments = total_segments - successful_segments

            # Timing analysis
            execution_times = [
                s.total_execution_time_ms
                for s in segments_data
                if s.total_execution_time_ms is not None
            ]

            total_execution_time_ms = (end_time - start_time) * 1000
            avg_segment_time = sum(execution_times) / len(execution_times) if execution_times else 0
            min_segment_time = min(execution_times) if execution_times else 0
            max_segment_time = max(execution_times) if execution_times else 0

            # Packet analysis
            total_packets_built = sum(1 for s in segments_data if s.packet_info is not None)
            total_bytes = sum(
                s.packet_info.packet_size for s in segments_data if s.packet_info is not None
            )
            ttl_mods = sum(1 for s in segments_data if s.packet_info and s.packet_info.ttl != 64)
            checksum_corruptions = sum(
                1 for s in segments_data if s.packet_info and s.packet_info.checksum_corrupted
            )
            timing_delays = sum(1 for s in segments_data if s.timing_measurement is not None)

            # Accuracy analysis
            timing_measurements = [
                s.timing_measurement for s in segments_data if s.timing_measurement is not None
            ]
            timing_accuracy = 0.0
            if timing_measurements:
                errors = [abs(tm.accuracy_error_ms) for tm in timing_measurements]
                timing_accuracy = 100.0 - (sum(errors) / len(errors))
                if timing_accuracy < 0:
                    timing_accuracy = 0.0
                if timing_accuracy > 100:
                    timing_accuracy = 100.0

            timing_errors = sum(
                1
                for s in segments_data
                if s.timing_measurement and abs(s.timing_measurement.accuracy_error_ms) > 1.0
            )
            construction_errors = sum(
                1 for s in segments_data if s.construction_time_ms is None and not s.success
            )
            transmission_errors = sum(
                1 for s in segments_data if not s.success and s.transmission_time_ms is not None
            )

            # Performance metrics
            duration_seconds = total_execution_time_ms / 1000.0
            packets_per_second = (
                total_packets_built / duration_seconds if duration_seconds > 0 else 0
            )
            bytes_per_second = total_bytes / duration_seconds if duration_seconds > 0 else 0

            # Create summary
            summary = SegmentExecutionSummary(
                session_id=session_id,
                connection_id=self._session_connection_ids.get(session_id, "unknown"),
                total_segments=total_segments,
                successful_segments=successful_segments,
                failed_segments=failed_segments,
                total_execution_time_ms=total_execution_time_ms,
                average_segment_time_ms=avg_segment_time,
                min_segment_time_ms=min_segment_time,
                max_segment_time_ms=max_segment_time,
                total_packets_built=total_packets_built,
                total_bytes_transmitted=total_bytes,
                ttl_modifications=ttl_mods,
                checksum_corruptions=checksum_corruptions,
                timing_delays_applied=timing_delays,
                timing_accuracy_average=timing_accuracy,
                timing_errors=timing_errors,
                construction_errors=construction_errors,
                transmission_errors=transmission_errors,
                packets_per_second=packets_per_second,
                bytes_per_second=bytes_per_second,
                segments_data=segments_data.copy(),
            )

            # Update global statistics
            self.total_execution_time_ms += total_execution_time_ms

            # Clean up session data (keep limited history)
            del self.active_sessions[session_id]
            self._session_connection_ids.pop(session_id, None)
            if len(self.session_data) > self.max_sessions_history:
                # dict preserves insertion order in Python 3.7+
                try:
                    oldest_session = next(iter(self.session_data))
                    del self.session_data[oldest_session]
                except StopIteration:
                    pass

            if self.detailed_logging:
                self.logger.info(
                    f"Session {session_id} completed: {successful_segments}/{total_segments} "
                    f"segments successful ({total_execution_time_ms:.1f}ms total)"
                )

            return summary

    def log_execution_summary(self, summary: SegmentExecutionSummary) -> None:
        """
        Log comprehensive execution summary.

        Args:
            summary: Execution summary to log
        """
        success_rate = (
            (summary.successful_segments / summary.total_segments * 100)
            if summary.total_segments > 0
            else 0
        )

        self.logger.info("=" * 60)
        self.logger.info(f"SEGMENT EXECUTION SUMMARY - Session {summary.session_id}")
        self.logger.info("=" * 60)
        self.logger.info(f"Connection: {summary.connection_id}")
        self.logger.info(
            f"Segments: {summary.successful_segments}/{summary.total_segments} successful ({success_rate:.1f}%)"
        )
        self.logger.info(f"Total execution time: {summary.total_execution_time_ms:.1f}ms")
        self.logger.info(f"Average segment time: {summary.average_segment_time_ms:.1f}ms")
        self.logger.info(
            f"Segment time range: {summary.min_segment_time_ms:.1f}ms - {summary.max_segment_time_ms:.1f}ms"
        )

        self.logger.info("\nPacket Analysis:")
        self.logger.info(f"  - Packets built: {summary.total_packets_built}")
        self.logger.info(f"  - Bytes transmitted: {summary.total_bytes_transmitted}")
        self.logger.info(f"  - TTL modifications: {summary.ttl_modifications}")
        self.logger.info(f"  - Checksum corruptions: {summary.checksum_corruptions}")
        self.logger.info(f"  - Timing delays applied: {summary.timing_delays_applied}")

        self.logger.info("\nAccuracy Analysis:")
        self.logger.info(f"  - Timing accuracy: {summary.timing_accuracy_average:.1f}%")
        self.logger.info(f"  - Timing errors: {summary.timing_errors}")
        self.logger.info(f"  - Construction errors: {summary.construction_errors}")
        self.logger.info(f"  - Transmission errors: {summary.transmission_errors}")

        self.logger.info("\nPerformance Metrics:")
        self.logger.info(f"  - Packets/second: {summary.packets_per_second:.1f}")
        self.logger.info(f"  - Bytes/second: {summary.bytes_per_second:.1f}")

        self.logger.info("=" * 60)

    def get_global_statistics(self) -> Dict[str, Any]:
        """
        Get global diagnostic statistics.

        Returns:
            Global statistics dictionary
        """
        with self.lock:
            return {
                "total_sessions": self.total_sessions,
                "active_sessions": len(self.active_sessions),
                "total_segments_processed": self.total_segments_processed,
                "total_execution_time_ms": self.total_execution_time_ms,
                "average_execution_time_per_session_ms": (
                    self.total_execution_time_ms / self.total_sessions
                    if self.total_sessions > 0
                    else 0
                ),
                "sessions_in_history": len(self.session_data),
            }

    def configure(self, **kwargs) -> None:
        """
        Configure diagnostic logger settings.

        Args:
            **kwargs: Configuration parameters
        """
        if "detailed_logging" in kwargs:
            self.detailed_logging = kwargs["detailed_logging"]
        if "max_events_per_segment" in kwargs:
            self.max_events_per_segment = kwargs["max_events_per_segment"]
        if "max_sessions_history" in kwargs:
            self.max_sessions_history = kwargs["max_sessions_history"]

        self.logger.debug(f"Diagnostic logger configured: {kwargs}")


# Global diagnostic logger instance
_global_diagnostic_logger: Optional[SegmentDiagnosticLogger] = None


def get_segment_diagnostic_logger() -> SegmentDiagnosticLogger:
    """Get global segment diagnostic logger instance."""
    global _global_diagnostic_logger
    if _global_diagnostic_logger is None:
        _global_diagnostic_logger = SegmentDiagnosticLogger()
    return _global_diagnostic_logger


def configure_segment_diagnostics(**kwargs) -> None:
    """Configure global segment diagnostics."""
    logger = get_segment_diagnostic_logger()
    logger.configure(**kwargs)


class SegmentDiagnostics(SegmentDiagnosticLogger):
    """
    Backward-compatible facade used by CLI tooling.

    Expected usage in CLI:
      d = SegmentDiagnostics()
      d.start_session(session_id)
      d.get_session_summary(session_id)
    """

    def start_session(self, session_id: str, connection_id: Optional[str] = None) -> None:
        """
        Start a new diagnostic session.

        Args:
            session_id: Unique session identifier
            connection_id: Optional connection identifier (defaults to session_id)
        """
        # CLI historically passes only one id; treat it as both session and connection id.
        super().start_session(session_id, connection_id or session_id)

    def get_session_summary(self, session_id: str) -> Dict[str, Any]:
        """
        Get session summary without ending the session.

        Args:
            session_id: Session identifier

        Returns:
            Dictionary with session statistics
        """
        return self.get_session_snapshot(session_id)
