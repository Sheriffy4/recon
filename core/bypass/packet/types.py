# File: core/bypass/packet/types.py

from dataclasses import dataclass, field
from typing import Optional, Dict, Any


@dataclass
class TCPSegmentSpec:
    """
    Specification for a TCP segment to be built and sent.

    Sequence Number Offset Fields:
    - seq_offset: Modern approach for sequence number manipulation (default: 0)
      * Used for badseq fooling technique to avoid sequence overlaps
      * Recommended value for badseq: 0x10000000 (far-future sequence)
      * Takes precedence over seq_extra when both are specified

    - seq_extra: Legacy approach for sequence number manipulation (default: None)
      * ⚠️  DEPRECATED: Use seq_offset instead
      * Kept for backward compatibility with existing strategies
      * WARNING: seq_extra=-1 creates sequence overlaps and should be avoided
      * Will be removed in a future version
      * Triggers deprecation warnings when used with fake packets (badseq)

    Migration Guide:
    - Old: seq_extra=-1 (creates overlap, breaks YouTube)
    - New: seq_offset=0x10000000 (no overlap, works correctly)
    - See: config/README_PACKET_CONFIG.md for full migration guide

    Deprecation Timeline:
    - Current: seq_extra supported with warnings
    - Next Release: seq_extra will log errors
    - Future Release: seq_extra will be removed
    """

    rel_seq: int  # Relative sequence offset from base
    payload: bytes  # Segment payload
    flags: int  # TCP flags (e.g., 0x18 for PSH+ACK)
    ttl: Optional[int] = None  # IP TTL (None = use original)
    corrupt_tcp_checksum: bool = False  # Corrupt checksum for fooling
    add_md5sig_option: bool = False  # Add MD5 signature option
    seq_offset: int = 0  # NEW: Sequence offset for badseq (replaces seq_extra)
    seq_extra: Optional[int] = (
        None  # DEPRECATED: Legacy sequence offset (for backward compatibility)
    )
    fooling_sni: Optional[str] = None  # SNI to inject in fake packets
    is_fake: bool = False  # Mark as fake packet
    delay_ms_after: int = 0  # Delay in ms after sending this segment
    preserve_window_size: bool = True  # Preserve original window size

    # Дополнительные метаданные, которые могут быть полезны для логирования
    metadata: Dict[str, Any] = field(default_factory=dict)
