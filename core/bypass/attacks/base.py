"""
Base classes for all DPI bypass attacks.
Unified interface that combines all legacy attack systems.
"""

import time
import logging
import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict, replace
from typing import Dict, Any, Optional, List, Union, TYPE_CHECKING, Tuple, Type
from enum import Enum

if TYPE_CHECKING:
    from core.bypass.handlers.tls_handler import TLSHandler


class BlockType(Enum):
    """Types of blocking detected during testing."""

    NONE = "none"
    HTTP_ERROR = "http_error"
    TIMEOUT = "timeout"
    RST = "rst"
    CONTENT = "content"
    CONNECTION_REFUSED = "connection_refused"
    INVALID = "invalid"


class BypassMode(Enum):
    """Modes of bypass operation."""

    NONE = "none"
    EXTERNAL_TOOL = "external"
    NATIVE_PYDIVERT = "native"
    HYBRID = "hybrid"


SegmentTuple = Tuple[bytes, int, Dict[str, Any]]
'\nSegment tuple format: (payload_data, seq_offset, options_dict)\n- payload_data: bytes - Raw bytes to send\n- seq_offset: int - TCP sequence offset from original packet  \n- options_dict: Dict[str, Any] - Transmission options:\n  - "ttl": int - IP Time To Live value\n  - "bad_checksum": bool - Corrupt TCP checksum\n  - "delay_ms": float - Delay before sending (milliseconds)\n  - "window_size": int - TCP window size override\n  - "flags": int - TCP flags override\n'


class AttackStatus(Enum):
    """Статус выполнения атаки."""

    SUCCESS = "success"
    FAILURE = "failure"
    ERROR = "error"
    TIMEOUT = "timeout"
    BLOCKED = "blocked"
    INVALID_PARAMS = "invalid_params"
    NOT_FOUND = "not_found"
    SKIPPED = "skipped"


@dataclass
class AttackContext:
    """
    Context for attack execution.
    Enhanced with complete TCP session information for segments orchestration.
    Contains all necessary information for any type of attack.
    """

    dst_ip: str
    dst_port: int
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    domain: Optional[str] = None
    payload: bytes = b""
    raw_packet: Optional[bytes] = None
    protocol: str = "tcp"
    seq: Optional[int] = None
    ack: Optional[int] = None
    flags: str = "PA"
    window: int = 65535
    tcp_seq: int = 0
    tcp_ack: int = 0
    tcp_flags: int = 24
    tcp_window_size: int = 65535
    tcp_urgent_pointer: int = 0
    tcp_options: bytes = b""
    ttl: Optional[int] = None
    connection_id: str = ""
    packet_id: int = 0
    session_established: bool = False
    initial_seq: Optional[int] = None
    current_seq_offset: int = 0
    expected_ack: Optional[int] = None
    params: Dict[str, Any] = field(default_factory=dict)
    rate_limiter: Optional[Any] = None
    timeout: float = 5.0
    engine_type: str = "local"
    debug: bool = False
    tls_handler: Optional["TLSHandler"] = None

    @classmethod
    def from_compat(cls: Type["AttackContext"], **kwargs: Any) -> "AttackContext":
        if "target_ip" in kwargs and "dst_ip" not in kwargs:
            kwargs["dst_ip"] = kwargs.pop("target_ip")
        if "target_port" in kwargs and "dst_port" not in kwargs:
            kwargs["dst_port"] = kwargs.pop("target_port")
        return cls(**kwargs)

    def copy(self) -> "AttackContext":
        """
        Создает поверхностную копию (shallow copy) этого AttackContext.
        Идеально для создания нового контекста для каждой атаки,
        чтобы избежать побочных эффектов при изменении параметров.
        """
        return replace(self)

    def get_next_seq(self, payload_len: int) -> int:
        """
        Calculate next sequence number after sending payload.

        Args:
            payload_len: Length of payload being sent

        Returns:
            Next sequence number
        """
        return self.tcp_seq + payload_len

    def advance_seq(self, payload_len: int) -> None:
        """
        Advance TCP sequence number after sending payload.

        Args:
            payload_len: Length of payload that was sent
        """
        self.tcp_seq += payload_len
        self.current_seq_offset += payload_len

    def get_seq_with_offset(self, offset: int) -> int:
        """
        Get sequence number with specific offset.

        Args:
            offset: Offset from current sequence number

        Returns:
            Sequence number with offset applied
        """
        return self.tcp_seq + offset

    def set_tcp_flags(self, flags: Union[int, str]) -> None:
        """
        Set TCP flags from integer or string representation.

        Args:
            flags: TCP flags as int (0x18) or string ("PSH,ACK")
        """
        if isinstance(flags, str):
            flag_map = {
                "FIN": 1,
                "SYN": 2,
                "RST": 4,
                "PSH": 8,
                "ACK": 16,
                "URG": 32,
                "ECE": 64,
                "CWR": 128,
            }
            tcp_flags = 0
            for flag in flags.upper().split(","):
                flag = flag.strip()
                if flag in flag_map:
                    tcp_flags |= flag_map[flag]
            self.tcp_flags = tcp_flags
        else:
            self.tcp_flags = flags

    def get_tcp_flags_string(self) -> str:
        """
        Get TCP flags as human-readable string.

        Returns:
            String representation of TCP flags (e.g., "PSH,ACK")
        """
        flags = []
        flag_map = {
            1: "FIN",
            2: "SYN",
            4: "RST",
            8: "PSH",
            16: "ACK",
            32: "URG",
            64: "ECE",
            128: "CWR",
        }
        for bit, name in flag_map.items():
            if self.tcp_flags & bit:
                flags.append(name)
        return ",".join(flags) if flags else "NONE"

    def create_connection_id(self) -> str:
        """
        Create unique connection identifier.

        Returns:
            Connection ID string
        """
        if not self.connection_id:
            self.connection_id = f"{self.src_ip or 'unknown'}:{self.src_port or 0}->{self.dst_ip}:{self.dst_port}"
        return self.connection_id

    def increment_packet_id(self) -> int:
        """
        Increment and return packet ID for this connection.

        Returns:
            New packet ID
        """
        self.packet_id += 1
        return self.packet_id

    def reset_sequence_tracking(self) -> None:
        """Reset sequence number tracking to initial state."""
        if self.initial_seq is not None:
            self.tcp_seq = self.initial_seq
        self.current_seq_offset = 0
        self.packet_id = 0

    def validate_tcp_session(self) -> bool:
        """
        Validate that TCP session information is consistent.

        Returns:
            True if session info is valid, False otherwise
        """
        if not self.dst_ip or not self.dst_port:
            return False
        if self.tcp_seq < 0 or self.tcp_ack < 0:
            return False
        if self.tcp_window_size < 0 or self.tcp_window_size > 65535:
            return False
        if self.tcp_flags < 0 or self.tcp_flags > 255:
            return False
        return True

    def copy_tcp_session(self) -> "AttackContext":
        """
        Create a copy of this context with same TCP session info.

        Returns:
            New AttackContext with copied TCP session information
        """
        return AttackContext(
            dst_ip=self.dst_ip,
            dst_port=self.dst_port,
            src_ip=self.src_ip,
            src_port=self.src_port,
            domain=self.domain,
            payload=self.payload,
            protocol=self.protocol,
            tcp_seq=self.tcp_seq,
            tcp_ack=self.tcp_ack,
            tcp_flags=self.tcp_flags,
            tcp_window_size=self.tcp_window_size,
            tcp_urgent_pointer=self.tcp_urgent_pointer,
            tcp_options=self.tcp_options,
            connection_id=self.connection_id,
            packet_id=self.packet_id,
            session_established=self.session_established,
            initial_seq=self.initial_seq,
            current_seq_offset=self.current_seq_offset,
            expected_ack=self.expected_ack,
            params=self.params.copy(),
            timeout=self.timeout,
            engine_type=self.engine_type,
            debug=self.debug,
        )

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert context to dictionary for logging/debugging.

        Returns:
            Dictionary representation of context
        """
        return {
            "connection": {
                "src": f"{self.src_ip}:{self.src_port}",
                "dst": f"{self.dst_ip}:{self.dst_port}",
                "domain": self.domain,
                "protocol": self.protocol,
            },
            "tcp_session": {
                "seq": self.tcp_seq,
                "ack": self.tcp_ack,
                "flags": self.get_tcp_flags_string(),
                "window": self.tcp_window_size,
                "urgent": self.tcp_urgent_pointer,
                "options_len": len(self.tcp_options),
            },
            "state": {
                "connection_id": self.connection_id,
                "packet_id": self.packet_id,
                "session_established": self.session_established,
                "seq_offset": self.current_seq_offset,
                "initial_seq": self.initial_seq,
                "expected_ack": self.expected_ack,
            },
            "payload_size": len(self.payload),
            "params": self.params,
            "timing": {"timeout": self.timeout},
            "engine": {"type": self.engine_type, "debug": self.debug},
        }

    def get_tcp_header_info(self) -> Dict[str, Any]:
        """
        Get complete TCP header information for packet construction.

        Returns:
            Dictionary with TCP header fields
        """
        return {
            "seq": self.tcp_seq,
            "ack": self.tcp_ack,
            "flags": self.tcp_flags,
            "window": self.tcp_window_size,
            "urgent": self.tcp_urgent_pointer,
            "options": self.tcp_options,
            "flags_string": self.get_tcp_flags_string(),
        }

    def update_from_packet(
        self, seq: int, ack: int, flags: int, window: int = None
    ) -> None:
        """
        Update TCP session info from received packet.

        Args:
            seq: Sequence number from packet
            ack: Acknowledgment number from packet
            flags: TCP flags from packet
            window: Window size from packet (optional)
        """
        self.tcp_seq = seq
        self.tcp_ack = ack
        self.tcp_flags = flags
        if window is not None:
            self.tcp_window_size = window
        if flags & 2:
            if not self.session_established:
                self.initial_seq = seq
                self.session_established = True
        if flags & 8:
            self.expected_ack = seq + len(self.payload)

    def create_response_context(self, response_payload: bytes = b"") -> "AttackContext":
        """
        Create a response context for bidirectional communication.

        Args:
            response_payload: Payload for the response

        Returns:
            New AttackContext configured for response
        """
        response_context = AttackContext(
            dst_ip=self.src_ip or "127.0.0.1",
            dst_port=self.src_port or 0,
            src_ip=self.dst_ip,
            src_port=self.dst_port,
            domain=self.domain,
            payload=response_payload,
            protocol=self.protocol,
            tcp_seq=self.tcp_ack,
            tcp_ack=self.tcp_seq + len(self.payload),
            tcp_flags=24,
            tcp_window_size=self.tcp_window_size,
            connection_id=self.connection_id,
            session_established=self.session_established,
            timeout=self.timeout,
            engine_type=self.engine_type,
            debug=self.debug,
        )
        return response_context

    def calculate_checksum_fields(self) -> Dict[str, int]:
        """
        Calculate fields needed for TCP checksum computation.

        Returns:
            Dictionary with checksum-related fields
        """
        return {
            "src_ip": self.src_ip or "0.0.0.0",
            "dst_ip": self.dst_ip,
            "src_port": self.src_port or 0,
            "dst_port": self.dst_port,
            "seq": self.tcp_seq,
            "ack": self.tcp_ack,
            "flags": self.tcp_flags,
            "window": self.tcp_window_size,
            "urgent": self.tcp_urgent_pointer,
            "payload_len": len(self.payload),
        }

    def is_handshake_packet(self) -> bool:
        """
        Check if this context represents a TCP handshake packet.

        Returns:
            True if this is a handshake packet (SYN, SYN-ACK, or final ACK)
        """
        if self.tcp_flags == 2:
            return True
        if self.tcp_flags == 18:
            return True
        if self.tcp_flags == 16 and len(self.payload) == 0:
            return True
        return False

    def is_data_packet(self) -> bool:
        """
        Check if this context represents a data packet.

        Returns:
            True if this packet carries data (PSH flag set and payload present, or just payload)
        """
        has_payload = len(self.payload) > 0
        has_psh_flag = self.tcp_flags & 8 != 0
        if self.is_handshake_packet():
            return False
        return has_payload or (has_psh_flag and self.session_established)

    def is_fin_packet(self) -> bool:
        """
        Check if this context represents a FIN packet (connection termination).

        Returns:
            True if FIN flag is set
        """
        return self.tcp_flags & 1 != 0

    def is_rst_packet(self) -> bool:
        """
        Check if this context represents a RST packet (connection reset).

        Returns:
            True if RST flag is set
        """
        return self.tcp_flags & 4 != 0


@dataclass
class AttackResult:
    """
    Result of attack execution.
    Standardized across all attack types.

    Enhanced with segments support for TCP session orchestration.
    """

    status: AttackStatus
    latency_ms: float = 0.0
    packets_sent: int = 0
    bytes_sent: int = 0
    response_received: bool = False
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    processing_time_ms: float = 0.0
    technique_used: Optional[str] = None
    connection_established: bool = False
    data_transmitted: bool = False
    modified_payload: Optional[bytes] = None

    def __post_init__(self):
        """Ensure proper initialization of metadata."""
        if self.metadata is None:
            self.metadata = {}

    def set_metadata(self, key: str, value: Any) -> None:
        """Safely set a single metadata value."""
        if self.metadata is None:
            self.metadata = {}
        self.metadata[key] = value

    def update_metadata(self, updates: Dict[str, Any]) -> None:
        """Safely update multiple metadata values from a dictionary."""
        if self.metadata is None:
            self.metadata = {}
        self.metadata.update(updates)

    def get_metadata(self, key: str, default: Any = None) -> Any:
        """
        Safely get metadata value.

        Args:
            key: Metadata key
            default: Default value if key not found

        Returns:
            Metadata value or default
        """
        if self.metadata is None:
            return default
        return self.metadata.get(key, default)

    def has_metadata(self, key: str) -> bool:
        """
        Check if metadata key exists.

        Args:
            key: Metadata key to check

        Returns:
            True if key exists, False otherwise
        """
        if self.metadata is None:
            return False
        return key in self.metadata

    def create_segments_from_modified_payload(
        self, modified_payload: bytes, original_payload: bytes
    ) -> None:
        """
        Create segments from a modified payload for backward compatibility.
        This allows old-style attacks to work with new segment-based execution.

        Args:
            modified_payload: The modified payload from old-style attack
            original_payload: The original payload for reference
        """
        if not modified_payload:
            return
        self.segments = [(modified_payload, 0, {})]

    def ensure_segments_or_fallback(self, original_payload: bytes) -> None:
        """
        Ensure segments are present, creating them from modified_payload if needed.
        This provides backward compatibility for old attacks.

        Args:
            original_payload: Original payload for fallback creation
        """
        if self.has_segments():
            return
        if self.modified_payload:
            self.create_segments_from_modified_payload(
                self.modified_payload, original_payload
            )
        elif self.metadata and "modified_payload" in self.metadata:
            modified = self.metadata["modified_payload"]
            if isinstance(modified, bytes):
                self.create_segments_from_modified_payload(modified, original_payload)

    @property
    def segments(self) -> Optional[List[SegmentTuple]]:
        """
        Get segments list from metadata for TCP session orchestration.

        Each segment is a tuple: (payload_data, seq_offset, options_dict)
        - payload_data: bytes - Raw bytes to send
        - seq_offset: int - TCP sequence offset from original packet
        - options_dict: Dict[str, Any] - Transmission options
          - "ttl": int - IP Time To Live value
          - "bad_checksum": bool - Corrupt TCP checksum
          - "delay_ms": float - Delay before sending (milliseconds)
          - "window_size": int - TCP window size override
          - "flags": int - TCP flags override

        Returns:
            List of segment tuples or None if not set
        """
        return self.metadata.get("segments") if self.metadata else None

    @segments.setter
    def segments(self, value: Optional[List[SegmentTuple]]) -> None:
        """
        Set segments list in metadata.

        Args:
            value: List of segment tuples or None to clear
        """
        if self.metadata is None:
            self.metadata = {}
        if value is None:
            self.metadata.pop("segments", None)
        else:
            if not isinstance(value, list):
                raise ValueError("Segments must be a list")
            for i, segment in enumerate(value):
                if not isinstance(segment, tuple) or len(segment) != 3:
                    raise ValueError(
                        f"Segment {i} must be a tuple of length 3: (payload_data, seq_offset, options_dict)"
                    )
                payload_data, seq_offset, options_dict = segment
                if not isinstance(payload_data, bytes):
                    raise ValueError(f"Segment {i} payload_data must be bytes")
                if not isinstance(seq_offset, int):
                    raise ValueError(f"Segment {i} seq_offset must be int")
                if not isinstance(options_dict, dict):
                    raise ValueError(f"Segment {i} options_dict must be dict")
            self.metadata["segments"] = value

    def add_segment(
        self,
        payload_data: bytes,
        seq_offset: int = 0,
        options: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Add a segment to the segments list.

        Args:
            payload_data: Raw bytes to send
            seq_offset: TCP sequence offset from original packet
            options: Transmission options dict
        """
        if options is None:
            options = {}
        segment = (payload_data, seq_offset, options)
        if self.segments is None:
            self.segments = [segment]
        else:
            current_segments = list(self.segments)
            current_segments.append(segment)
            self.segments = current_segments

    def has_segments(self) -> bool:
        """
        Check if attack result contains segments for orchestrated execution.

        Returns:
            True if result has segments to execute
        """
        if self.metadata and "segments" in self.metadata:
            segments = self.metadata["segments"]
            return segments is not None and len(segments) > 0
        if hasattr(self, "segments") and self.segments:
            return len(self.segments) > 0
        return False

    

    def get_segment_count(self) -> int:
        """
        Get the number of segments in this result.

        Returns:
            Number of segments, 0 if no segments
        """
        segments = self.segments
        return len(segments) if segments else 0

    def clear_segments(self) -> None:
        """Clear all segments from this result."""
        self.segments = None

    def validate_structure(self) -> bool:
        """
        Validate that the AttackResult has proper structure.

        Returns:
            True if structure is valid, False otherwise
        """
        try:
            if not isinstance(self.status, AttackStatus):
                return False
            if self.metadata is not None and (not isinstance(self.metadata, dict)):
                return False
            if not isinstance(self.latency_ms, (int, float)):
                return False
            return True
        except Exception:
            return False


class AttackResultHelper:
    """Helper class for working with AttackResult objects safely."""

    @staticmethod
    def validate_result(result: Any) -> bool:
        """Validate that object is a proper AttackResult."""
        return (
            hasattr(result, "status")
            and hasattr(result, "metadata")
            and isinstance(result.status, AttackStatus)
        )

    @staticmethod
    def create_success_result(
        technique_used: str = "",
        metadata: Optional[Dict[str, Any]] = None,
        latency_ms: float = 0.0,
        packets_sent: int = 0,
        segments: Optional[List[tuple]] = None,
    ) -> AttackResult:
        """
        Create a successful AttackResult.

        Args:
            technique_used: Name of the technique used
            metadata: Additional metadata
            latency_ms: Execution latency
            packets_sent: Number of packets sent
            segments: List of segment tuples for orchestration
        """
        result = AttackResult(
            status=AttackStatus.SUCCESS,
            technique_used=technique_used,
            metadata=metadata or {},
            latency_ms=latency_ms,
            packets_sent=packets_sent,
        )
        if segments is not None:
            result.segments = segments
        return result

    @staticmethod
    def create_failure_result(
        error_message: str,
        technique_used: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AttackResult:
        """Create a failed AttackResult."""
        return AttackResult(
            status=AttackStatus.FAILURE,
            technique_used=technique_used,
            error_message=error_message,
            metadata=metadata or {},
            latency_ms=0.0,
        )

    @staticmethod
    def ensure_metadata(result: AttackResult) -> None:
        """
        Ensure metadata is initialized for an AttackResult.

        Args:
            result: AttackResult object to check
        """
        if not isinstance(result, AttackResult):
            raise TypeError(f"Expected AttackResult, got {type(result)}")
        if result.metadata is None:
            result.metadata = {}

    @staticmethod
    def set_metadata(result: AttackResult, key: str, value: Any) -> None:
        """
        Safely set metadata value on an AttackResult.

        Args:
            result: AttackResult object
            key: Metadata key
            value: Metadata value
        """
        if not isinstance(result, AttackResult):
            raise TypeError(f"Expected AttackResult, got {type(result)}")
        AttackResultHelper.ensure_metadata(result)
        result.metadata[key] = value

    @staticmethod
    def get_metadata(result: AttackResult, key: str, default: Any = None) -> Any:
        """
        Safely get metadata value from an AttackResult.

        Args:
            result: AttackResult object
            key: Metadata key
            default: Default value if key not found

        Returns:
            Metadata value or default
        """
        if not isinstance(result, AttackResult):
            raise TypeError(f"Expected AttackResult, got {type(result)}")
        if result.metadata is None:
            return default
        return result.metadata.get(key, default)

    @staticmethod
    def has_metadata(result: AttackResult, key: str) -> bool:
        """
        Check if AttackResult has a specific metadata key.

        Args:
            result: AttackResult object
            key: Metadata key to check

        Returns:
            True if key exists, False otherwise
        """
        if not isinstance(result, AttackResult):
            return False
        if result.metadata is None:
            return False
        return key in result.metadata

    @staticmethod
    def update_metadata(result: AttackResult, updates: Dict[str, Any]) -> None:
        """
        Safely update multiple metadata values on an AttackResult.

        Args:
            result: AttackResult object
            updates: Dictionary of key-value pairs to update
        """
        if not isinstance(result, AttackResult):
            raise TypeError(f"Expected AttackResult, got {type(result)}")
        AttackResultHelper.ensure_metadata(result)
        result.metadata.update(updates)

    @staticmethod
    def create_segments_result(
        technique_used: str,
        segments: List[tuple],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AttackResult:
        """
        Create a successful AttackResult with segments for orchestration.

        Args:
            technique_used: Name of the technique used
            segments: List of segment tuples (payload_data, seq_offset, options_dict)
            metadata: Additional metadata

        Returns:
            AttackResult configured for segment orchestration
        """
        result_metadata = metadata or {}
        result = AttackResult(
            status=AttackStatus.SUCCESS,
            technique_used=technique_used,
            metadata=result_metadata,
            packets_sent=len(segments),
        )
        result.segments = segments
        return result

    @staticmethod
    def has_segments(result: AttackResult) -> bool:
        """
        Check if AttackResult has segments for orchestration.

        Args:
            result: AttackResult object to check

        Returns:
            True if result has segments, False otherwise
        """
        if not isinstance(result, AttackResult):
            return False
        return result.has_segments()

    @staticmethod
    def get_segments(result: AttackResult) -> Optional[List[tuple]]:
        """
        Get segments from AttackResult.

        Args:
            result: AttackResult object

        Returns:
            List of segment tuples or None
        """
        if not isinstance(result, AttackResult):
            return None
        return result.segments

    @staticmethod
    def add_segment(
        result: AttackResult,
        payload_data: bytes,
        seq_offset: int = 0,
        options: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Add a segment to AttackResult.

        Args:
            result: AttackResult object
            payload_data: Raw bytes to send
            seq_offset: TCP sequence offset
            options: Transmission options

        Returns:
            True if successful, False otherwise
        """
        try:
            if not isinstance(result, AttackResult):
                return False
            result.add_segment(payload_data, seq_offset, options)
            return True
        except Exception:
            return False

    @staticmethod
    def validate_segments(segments: List[tuple]) -> bool:
        """
        Validate segments format.

        Args:
            segments: List of segment tuples to validate

        Returns:
            True if valid, False otherwise
        """
        try:
            if not isinstance(segments, list):
                return False
            for segment in segments:
                if not isinstance(segment, tuple) or len(segment) != 3:
                    return False
                payload_data, seq_offset, options_dict = segment
                if not isinstance(payload_data, bytes):
                    return False
                if not isinstance(seq_offset, int):
                    return False
                if not isinstance(options_dict, dict):
                    return False
            return True
        except Exception:
            return False

    @staticmethod
    def safe_access(result: Any, operation: str, *args, **kwargs) -> Any:
        """
        Safely perform operations on AttackResult objects with error handling.

        Args:
            result: Object to operate on
            operation: Operation name ('get_metadata', 'set_metadata', 'get_segments', etc.)
            *args: Operation arguments
            **kwargs: Operation keyword arguments

        Returns:
            Operation result or None if failed
        """
        try:
            if not AttackResultHelper.validate_result(result):
                return None
            if operation == "get_metadata":
                return AttackResultHelper.get_metadata(result, *args, **kwargs)
            elif operation == "set_metadata":
                AttackResultHelper.set_metadata(result, *args, **kwargs)
                return True
            elif operation == "has_metadata":
                return AttackResultHelper.has_metadata(result, *args, **kwargs)
            elif operation == "update_metadata":
                AttackResultHelper.update_metadata(result, *args, **kwargs)
                return True
            elif operation == "get_segments":
                return AttackResultHelper.get_segments(result)
            elif operation == "has_segments":
                return AttackResultHelper.has_segments(result)
            elif operation == "add_segment":
                return AttackResultHelper.add_segment(result, *args, **kwargs)
            else:
                return None
        except Exception as e:
            import logging

            logger = logging.getLogger("AttackResultHelper")
            logger.error(f"Safe access operation '{operation}' failed: {e}")
            return None


class BaseAttack(ABC):
    """
    Base class for all DPI bypass attacks.

    This unified interface replaces all legacy attack systems:
    - core/attacks/tcp_attacks.py
    - core/attacks/tls_attacks.py
    - core/fast_bypass/techniques/
    - core/zapret_fooling.py
    - All BypassTechniques from fast_bypass.py
    """

    def __init__(self):
        self.logger = logging.getLogger(
            f"{self.__class__.__module__}.{self.__class__.__name__}"
        )
        self._stats = {
            "executions": 0,
            "successes": 0,
            "failures": 0,
            "total_latency": 0.0,
        }

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique name for this attack."""
        pass

    @property
    def description(self) -> str:
        """Human-readable description of the attack."""
        return f"{self.name} attack"

    @property
    def category(self) -> str:
        """Attack category (tcp, ip, tls, http, payload, tunneling, combo)."""
        return "unknown"

    @property
    def supported_protocols(self) -> List[str]:
        """List of supported protocols."""
        return ["tcp"]

    @property
    def legacy_name(self) -> Optional[str]:
        """
        Legacy or simple name for the attack, for reporting and backward compatibility.
        Returns the main 'name' by default if not overridden.
        """
        return self.name

    @abstractmethod
    def execute(self, context: AttackContext) -> AttackResult:
        """
        Sync execute interface. If you need async, wrap in execute_with_network_validation.
        """
        pass

    def validate_context(self, context: AttackContext) -> bool:
        """
        Validate attack context before execution.

        Args:
            context: Attack execution context

        Returns:
            True if context is valid, False otherwise
        """
        if not context.dst_ip or not context.dst_port:
            return False
        if context.protocol not in self.supported_protocols:
            return False
        return True

    def get_stats(self) -> Dict[str, Any]:
        """Get attack execution statistics."""
        stats = self._stats.copy()
        if stats["executions"] > 0:
            stats["success_rate"] = stats["successes"] / stats["executions"]
            stats["avg_latency"] = stats["total_latency"] / stats["executions"]
        else:
            stats["success_rate"] = 0.0
            stats["avg_latency"] = 0.0
        return stats

    def _update_stats(self, result: AttackResult):
        """Update internal statistics."""
        self._stats["executions"] += 1
        if result.status == AttackStatus.SUCCESS:
            self._stats["successes"] += 1
        else:
            self._stats["failures"] += 1
        self._stats["total_latency"] += result.latency_ms

    def _execute_with_stats(self, context: AttackContext) -> AttackResult:
        """Execute attack with automatic statistics tracking."""
        start_time = time.time()
        try:
            if not self.validate_context(context):
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message="Invalid attack context",
                )
            result = self.execute(context)
            result.processing_time_ms = (time.time() - start_time) * 1000
            result.technique_used = self.name
            self._update_stats(result)
            return result
        except Exception as e:
            self.logger.error(f"Attack execution failed: {e}", exc_info=context.debug)
            result = AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                processing_time_ms=(time.time() - start_time) * 1000,
                technique_used=self.name,
            )
            self._update_stats(result)
            return result

    def to_zapret_command(self, params: Optional[Dict[str, Any]] = None) -> str:
        """
        Генерирует эквивалентную команду для zapret/nfqws, если это возможно.
        Принимает параметры для более точной генерации.
        """
        return f"# Advanced technique '{self.name}' succeeded. No direct zapret command, requires custom client."

    async def execute_with_network_validation(
        self, context: AttackContext, strict_mode: bool = False
    ) -> AttackResult:
        """
        Execute attack with network connectivity validation.
        """
        start_time = time.time()
        try:
            if not self.validate_context(context):
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message="Invalid attack context",
                )
            result = await asyncio.to_thread(self.execute, context)
            result.processing_time_ms = (time.time() - start_time) * 1000
            result.technique_used = self.name
            self._update_stats(result)
        except Exception as e:
            self.logger.error(f"Attack execution failed: {e}", exc_info=context.debug)
            result = AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                processing_time_ms=(time.time() - start_time) * 1000,
                technique_used=self.name,
            )
            self._update_stats(result)
            return result
        if result.status != AttackStatus.SUCCESS:
            return result
        from core.bypass.attacks.real_effectiveness_tester import (
            RealEffectivenessTester,
        )

        tester = RealEffectivenessTester(timeout=context.timeout)
        try:
            baseline = await tester.test_baseline(context.domain, context.dst_port)
            bypass = await tester.test_with_bypass(
                context.domain, context.dst_port, result
            )
            effectiveness = await tester.compare_results(baseline, bypass)
            result.metadata["bypass_results"] = (
                effectiveness.to_dict()
                if hasattr(effectiveness, "to_dict")
                else asdict(effectiveness)
            )
            result.connection_established = effectiveness.bypass.success
            result.data_transmitted = effectiveness.bypass.success
            result.response_received = effectiveness.bypass.success
            if not effectiveness.bypass_effective and strict_mode:
                result.status = AttackStatus.BLOCKED
                result.error_message = (
                    "Bypass was not effective against detected blocking."
                )
        finally:
            await tester.close()
        return result


class SegmentationAttack(BaseAttack):
    """
    Base class for attacks that segment payloads.

    Migrated from:
    - FakedDisorderAttack, DripFeedAttack (tcp_attacks.py)
    - FakeDisorderTechnique, MultiSplitTechnique, etc. (fast_bypass)
    """

    @property
    def category(self) -> str:
        return "tcp"

    def create_segments(self, payload: bytes, positions: List[int]) -> List[tuple]:
        """
        Create payload segments based on split positions.

        Args:
            payload: Original payload
            positions: List of split positions

        Returns:
            List of (segment_data, offset) tuples
        """
        if not positions:
            return [(payload, 0)]
        segments = []
        last_pos = 0
        for pos in sorted(positions):
            if pos > last_pos and pos < len(payload):
                segment_data = payload[last_pos:pos]
                segments.append((segment_data, last_pos))
                last_pos = pos
        if last_pos < len(payload):
            segment_data = payload[last_pos:]
            segments.append((segment_data, last_pos))
        return segments


class TimingAttack(BaseAttack):
    """
    Base class for timing-based attacks.

    Migrated from:
    - apply_timing_based_evasion, apply_burst_timing_evasion (fast_bypass.py)
    """

    @property
    def category(self) -> str:
        return "tcp"

    def apply_delay(self, delay_ms: float):
        """Apply timing delay."""
        if delay_ms > 0:
            time.sleep(delay_ms / 1000.0)


class ManipulationAttack(BaseAttack):
    """
    Base class for packet manipulation attacks.

    Migrated from:
    - apply_tcp_window_scaling, apply_urgent_pointer_manipulation, etc. (fast_bypass.py)
    - apply_md5sig, apply_badsum, apply_badseq, apply_ttl (zapret_fooling.py)
    """

    @property
    def category(self) -> str:
        return "tcp"


class PayloadAttack(BaseAttack):
    """
    Base class for payload manipulation attacks.

    Migrated from:
    - apply_payload_encryption, apply_payload_obfuscation, apply_noise_injection (fast_bypass.py)
    """

    @property
    def category(self) -> str:
        return "payload"

    def xor_encrypt(self, data: bytes, key: bytes) -> bytes:
        """Simple XOR encryption."""
        if not key:
            return data
        return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

    def obfuscate_bytes(self, data: bytes, shift: int = 13) -> bytes:
        """Simple byte obfuscation using rotation."""
        return bytes([(b + shift) % 256 for b in data])


class TunnelingAttack(BaseAttack):
    """
    Base class for tunneling attacks.

    Migrated from:
    - apply_protocol_tunneling, apply_dns_tunneling (fast_bypass.py)
    """

    @property
    def category(self) -> str:
        return "tunneling"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp", "udp"]


class ComboAttack(BaseAttack):
    """
    Base class for combination attacks.

    Migrated from:
    - ComboAttacker (combo_attacker.py)
    - apply_decoy_packets (fast_bypass.py)
    """

    @property
    def category(self) -> str:
        return "combo"

    def __init__(self, attacks: List[BaseAttack]):
        super().__init__()
        self.attacks = attacks

    @property
    def supported_protocols(self) -> List[str]:
        """Combine supported protocols from all sub-attacks."""
        protocols = set()
        for attack in self.attacks:
            protocols.update(attack.supported_protocols)
        return list(protocols)


class SegmentOrchestrationHelper:
    """Helper for creating segment orchestration plans."""

    @staticmethod
    def create_simple_segments(
        payload: bytes, chunk_size: int = 0
    ) -> List[SegmentTuple]:
        """Create simple segments without modifications."""
        if chunk_size <= 0:
            return [(payload, 0, {})]
        segments = []
        for i in range(0, len(payload), chunk_size):
            chunk = payload[i : i + chunk_size]
            segments.append((chunk, i, {}))
        return segments

    @staticmethod
    def create_timed_segments(
        payload: bytes, chunk_size: int, delay_ms: float
    ) -> List[SegmentTuple]:
        """Create segments with timing delays."""
        segments = []
        for i in range(0, len(payload), chunk_size):
            chunk = payload[i : i + chunk_size]
            options = {"delay_ms": delay_ms} if i > 0 else {}
            segments.append((chunk, i, options))
        return segments

    @staticmethod
    def apply_modifications_to_segments(
        segments: List[SegmentTuple],
        ttl: Optional[int] = None,
        bad_checksum: bool = False,
        delay_ms: Optional[float] = None,
    ) -> List[SegmentTuple]:
        """Apply modifications to existing segments."""
        modified = []
        for payload, offset, options in segments:
            new_options = options.copy()
            if ttl is not None:
                new_options["ttl"] = ttl
            if bad_checksum:
                new_options["bad_checksum"] = True
            if delay_ms is not None and offset > 0:
                new_options["delay_ms"] = delay_ms
            modified.append((payload, offset, new_options))
        return modified


@dataclass
class BaselineResult:
    """Result of baseline testing without bypass."""

    domain: str
    success: bool
    latency_ms: float
    error: Optional[str] = None
    status_code: Optional[int] = None
    block_type: Optional[BlockType] = None
    response_size: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    content_preview: str = ""
    rst_ttl_distance: Optional[int] = None
    sni_consistency_blocked: Optional[bool] = None
    response_timing_pattern: Optional[str] = None
    server_ip: Optional[str] = None
    timestamp: float = field(default_factory=time.time)


@dataclass
class BypassResult:
    """Result of testing with bypass applied."""

    domain: str
    success: bool
    latency_ms: float
    bypass_applied: bool
    attack_name: Optional[str] = None
    error: Optional[str] = None
    status_code: Optional[int] = None
    block_type: Optional[BlockType] = None
    response_size: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    content_preview: str = ""
    rst_ttl_distance: Optional[int] = None
    sni_consistency_blocked: Optional[bool] = None
    response_timing_pattern: Optional[str] = None
    server_ip: Optional[str] = None
    timestamp: float = field(default_factory=time.time)


@dataclass
class EffectivenessResult:
    """Comprehensive effectiveness analysis result with enhanced failure analysis data."""

    domain: str
    baseline: BaselineResult
    bypass: BypassResult
    effectiveness_score: float
    bypass_effective: bool
    improvement_type: str
    latency_improvement_ms: float = 0.0
    latency_improvement_percent: float = 0.0
    analysis_notes: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    fingerprint: Optional[Dict[str, Any]] = None
    failure_patterns: Dict[str, Any] = field(default_factory=dict)
    block_classification: Dict[str, Any] = field(default_factory=dict)
    timing_analysis: Dict[str, Any] = field(default_factory=dict)
    content_analysis: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TestRequest:
    """Request for testing a domain."""

    domain: str
    port: int = 443
    strategy: Optional[Dict[str, Any]] = None
    timeout: float = 10.0
    max_retries: int = 2

    @property
    def url(self) -> str:
        """Get full URL for the request."""
        protocol = "https" if self.port == 443 else "http"
        return f"{protocol}://{self.domain}/"


@dataclass
class BatchTestResult:
    """Result of testing multiple sites."""

    total_sites: int
    successful_sites: int
    failed_sites: int
    results: Dict[str, BypassResult] = field(default_factory=dict)
    execution_time_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)

    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        if self.total_sites == 0:
            return 0.0
        return self.successful_sites / self.total_sites

    @property
    def summary(self) -> str:
        """Get summary string."""
        return f"{self.successful_sites}/{self.total_sites} sites accessible ({self.success_rate:.1%})"


@dataclass
class EngineHealth:
    """Health status of a bypass engine."""

    engine_type: str
    is_healthy: bool
    error_message: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def status_emoji(self) -> str:
        """Get status emoji."""
        return "✅" if self.is_healthy else "❌"


LegacyAttackStatus = AttackStatus
LegacyAttackResult = AttackResult
LegacyAttackContext = AttackContext
LegacyBaseAttack = BaseAttack
__all__ = [
    "AttackStatus",
    "AttackContext",
    "AttackResult",
    "BaseAttack",
    "AttackResultHelper",
    "SegmentTuple",
    "BlockType",
    "BypassMode",
    "BaselineResult",
    "BypassResult",
    "EffectivenessResult",
    "TestRequest",
    "BatchTestResult",
    "EngineHealth",
    "LegacyAttackStatus",
    "LegacyAttackResult",
    "LegacyAttackContext",
    "LegacyBaseAttack",
]
