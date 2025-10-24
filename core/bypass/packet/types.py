# File: core/bypass/packet/types.py

from dataclasses import dataclass, field
from typing import Optional, Dict, Any


@dataclass
class TCPSegmentSpec:
    """Specification for a TCP segment to be built and sent"""

    rel_seq: int  # Relative sequence offset from base
    payload: bytes  # Segment payload
    flags: int  # TCP flags (e.g., 0x18 for PSH+ACK)
    ttl: Optional[int] = None  # IP TTL (None = use original)
    corrupt_tcp_checksum: bool = False  # Corrupt checksum for fooling
    add_md5sig_option: bool = False  # Add MD5 signature option
    seq_extra: int = 0  # Additional sequence offset
    fooling_sni: Optional[str] = None  # SNI to inject in fake packets
    is_fake: bool = False  # Mark as fake packet
    delay_ms_after: int = 0  # Delay in ms after sending this segment
    preserve_window_size: bool = True  # Preserve original window size

    # Дополнительные метаданные, которые могут быть полезны для логирования
    metadata: Dict[str, Any] = field(default_factory=dict)
