"""
Dispatcher Observability - Extracted from AttackDispatcher (Step 6)

Responsibilities:
- Generate correlation IDs for request tracking
- Log dispatch lifecycle events (start, success, error)
- Log segment details for debugging
- Log operations for offline PCAP validation
- Save PCAP metadata for analysis

This module handles all logging and observability concerns,
keeping the main dispatcher focused on attack execution logic.
"""

from __future__ import annotations

import logging
import time
import traceback
import uuid
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Type aliases
SegmentTuple = Tuple[bytes, int, Dict[str, Any]]
AttackRecipe = List[SegmentTuple]
AttackSequence = List[Tuple[str, Dict[str, Any]]]

# Check if operation logger is available
try:
    from core.validation.operation_logger import get_operation_logger

    OPERATION_LOGGER_AVAILABLE = True
except ImportError:
    OPERATION_LOGGER_AVAILABLE = False
    logger.debug("Operation logger not available")


class DispatcherObservability:
    """
    Handles all observability concerns for AttackDispatcher.

    Provides logging, correlation tracking, and metadata persistence
    for attack dispatch operations.
    """

    def __init__(self, log_segment_preview_bytes: int = 32):
        """
        Initialize observability handler.

        Args:
            log_segment_preview_bytes: Number of bytes to show in segment previews
        """
        self.log_segment_preview_bytes = log_segment_preview_bytes

    @staticmethod
    def generate_correlation_id() -> str:
        """
        Generate unique correlation ID for request tracking.

        Returns:
            8-character correlation ID
        """
        return str(uuid.uuid4())[:8]

    def log_dispatch_start(
        self,
        correlation_id: str,
        task_type: str,
        payload: bytes,
        packet_info: Dict[str, Any],
        params: Dict[str, Any],
    ) -> None:
        """
        Log the start of an attack dispatch operation.

        Args:
            correlation_id: Unique ID for this dispatch
            task_type: Type of attack being dispatched
            payload: Packet payload
            packet_info: Packet metadata (src, dst, etc.)
            params: Attack parameters
        """
        src = f"{packet_info.get('src_addr', 'unknown')}:{packet_info.get('src_port', 'unknown')}"
        dst = f"{packet_info.get('dst_addr', 'unknown')}:{packet_info.get('dst_port', 'unknown')}"
        logger.info(
            f"[CID:{correlation_id}] Dispatch: type='{task_type}', "
            f"payload={len(payload)} bytes, {src} -> {dst}"
        )
        logger.info(f"[CID:{correlation_id}] Parameters: {params}")

    def log_dispatch_success(
        self,
        correlation_id: str,
        task_type: str,
        segments: AttackRecipe,
        start_time: float,
        attack_mode: str = "",
    ) -> None:
        """
        Log successful completion of attack dispatch.

        Args:
            correlation_id: Unique ID for this dispatch
            task_type: Type of attack that was dispatched
            segments: Generated attack segments
            start_time: Timestamp when dispatch started
            attack_mode: Mode used (e.g., "advanced", "primitive")
        """
        elapsed = time.time() - start_time
        mode = f" ({attack_mode})" if attack_mode else ""
        logger.info(
            f"[CID:{correlation_id}] Attack '{task_type}'{mode} completed: "
            f"{len(segments)} segments in {elapsed:.3f}s"
        )

    def log_dispatch_error(
        self,
        correlation_id: str,
        task_type: str,
        error: Exception,
        params: Dict[str, Any],
        payload: bytes,
        packet_info: Dict[str, Any],
        start_time: float,
    ) -> None:
        """
        Log error during attack dispatch.

        Args:
            correlation_id: Unique ID for this dispatch
            task_type: Type of attack that failed
            error: Exception that occurred
            params: Attack parameters
            payload: Packet payload
            packet_info: Packet metadata
            start_time: Timestamp when dispatch started
        """
        elapsed = time.time() - start_time
        logger.error(
            f"[CID:{correlation_id}] Attack '{task_type}' failed after "
            f"{elapsed:.3f}s: {type(error).__name__}: {error}"
        )
        logger.debug(f"[CID:{correlation_id}] Parameters: {params}")
        logger.debug(f"[CID:{correlation_id}] Payload size: {len(payload)}")
        logger.debug(f"[CID:{correlation_id}] Packet info: {packet_info}")
        logger.debug(traceback.format_exc())

    def log_segment_details(
        self,
        segments: AttackRecipe,
        correlation_id: str,
    ) -> None:
        """
        Log detailed information about generated segments.

        Only logs at DEBUG level to avoid verbosity.

        Args:
            segments: Generated attack segments
            correlation_id: Unique ID for this dispatch
        """
        if not segments:
            return

        # Segment-by-segment logging is very verbose; keep it on DEBUG.
        if not logger.isEnabledFor(logging.DEBUG):
            return

        logger.debug(f"[CID:{correlation_id}] Segment details ({len(segments)} total):")
        for i, (data, offset, options) in enumerate(segments, start=1):
            flags = options.get("flags", "N/A")
            seq = options.get("tcp_seq", "N/A")
            ack = options.get("tcp_ack", "N/A")
            logger.debug(
                f"   Segment {i}/{len(segments)}: len={len(data)}, "
                f"offset={offset}, seq={seq}, ack={ack}, flags={flags}"
            )

            if logger.isEnabledFor(logging.DEBUG) and data:
                preview_len = min(self.log_segment_preview_bytes, len(data))
                hex_preview = " ".join(f"{b:02x}" for b in data[:preview_len])
                if len(data) > preview_len:
                    hex_preview += "..."
                logger.debug(f"      Data preview: {hex_preview}")

    def log_operations_for_validation(
        self,
        strategy_id: Optional[str],
        operation_type: str,
        parameters: Dict[str, Any],
        segments: AttackRecipe,
        correlation_id: Optional[str] = None,
    ) -> None:
        """
        Log operations for offline PCAP validation.

        Logs one event per generated segment for detailed validation.

        Args:
            strategy_id: Strategy identifier for validation
            operation_type: Type of operation performed
            parameters: Operation parameters
            segments: Generated segments
            correlation_id: Unique ID for this dispatch
        """
        if not OPERATION_LOGGER_AVAILABLE or not strategy_id:
            return

        try:
            operation_logger = get_operation_logger()
            for i, (data, offset, options) in enumerate(segments, start=1):
                op_params = {
                    "operation_type": operation_type,
                    "offset": offset,
                    "data_length": len(data),
                    **parameters,
                    **options,
                }
                operation_logger.log_operation(
                    strategy_id=strategy_id,
                    operation_type=operation_type,
                    parameters=op_params,
                    segment_number=i,
                    correlation_id=correlation_id,
                )
        except Exception as e:
            logger.warning(f"[CID:{correlation_id}] Failed to log operations for validation: {e}")

    def save_metadata_if_needed(
        self,
        packet_info: Dict[str, Any],
        correlation_id: str,
        task_type: str,
        resolved_attacks: AttackSequence,
        original_params: Dict[str, Any],
        segments: AttackRecipe,
        start_time: float,
    ) -> None:
        """
        Save PCAP metadata for analysis if strategy_id is present.

        Args:
            packet_info: Packet metadata (must contain strategy_id)
            correlation_id: Unique ID for this dispatch
            task_type: Type of attack executed
            resolved_attacks: Sequence of attacks that were resolved
            original_params: Original parameters passed to dispatch
            segments: Generated segments
            start_time: Timestamp when dispatch started
        """
        strategy_id = packet_info.get("strategy_id")
        if not strategy_id:
            return

        try:
            from core.pcap.metadata_saver import save_pcap_metadata

            save_pcap_metadata(
                strategy_id=strategy_id,
                domain=packet_info.get("domain"),
                executed_attacks=task_type,
                strategy_name=packet_info.get("strategy_name"),
                additional_data={
                    "correlation_id": correlation_id,
                    "attacks": [a[0] for a in resolved_attacks],
                    "parameters": original_params,
                    "segment_count": len(segments),
                    "execution_time": time.time() - start_time,
                },
            )
        except Exception as e:
            logger.debug(f"Failed to save PCAP metadata: {e}")
