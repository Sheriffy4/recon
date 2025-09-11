"""Data types for packet specifications."""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List


@dataclass
class PacketMetadata:
    """Metadata extracted from original packet."""
    ip_header_len: int
    tcp_header_len: int
    base_seq: int
    base_ack: int
    base_win: int
    base_ttl: int
    base_ip_id: int
    src_ip: bytes
    dst_ip: bytes
    src_port: int
    dst_port: int


@dataclass
class TCPSegmentSpec:
    """
    Specification for building a TCP segment.
    Contains all parameters needed by PacketBuilder.
    """
    payload: bytes
    rel_seq: int = 0
    flags: int = 0x10  # Default ACK
    ttl: Optional[int] = None  # None means use original TTL
    corrupt_tcp_checksum: bool = False
    add_md5sig_option: bool = False
    seq_extra: int = 0  # Additional SEQ offset (for 'badseq')
    delay_ms_after: int = 0  # Delay in ms after sending this segment
    window_override: Optional[int] = None  # Override window size

    # Advanced options
    tcp_options: Dict[str, Any] = field(default_factory=dict)
    ip_options: Dict[str, Any] = field(default_factory=dict)


@dataclass
class UDPDatagramSpec:
    """Specification for building a UDP datagram."""
    payload: bytes
    ttl: Optional[int] = None
    delay_ms_after: int = 0
    corrupt_checksum: bool = False
