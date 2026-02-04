"""
PacketSegment data model.

Type-safe representation of packet segments for transmission.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

from .attack_constants import AttackConstants


@dataclass
class PacketSegment:
    """Packet segment for transmission - simple and type-safe."""

    data: bytes
    offset: int
    ttl: int = AttackConstants.DEFAULT_REAL_TTL
    is_fake: bool = False
    fooling: Optional[str] = None
    tcp_flags: str = "PA"
    fragment_index: int = 0
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def size(self) -> int:
        return len(self.data)

    def to_tuple(self) -> Tuple[bytes, int, Dict[str, Any]]:
        """Convert to legacy tuple format for backward compatibility."""
        options = {
            "ttl": self.ttl,
            "is_fake": self.is_fake,
            "tcp_flags": self.tcp_flags,
            "fragment_index": self.fragment_index,
            **self.extra,
        }
        if self.fooling:
            options["fooling"] = self.fooling
        return (self.data, self.offset, options)

    @classmethod
    def from_tuple(cls, t: Tuple[bytes, int, Dict[str, Any]]) -> "PacketSegment":
        """Create from legacy tuple format."""
        data, offset, options = t
        return cls(
            data=data,
            offset=offset,
            ttl=options.get("ttl", AttackConstants.DEFAULT_REAL_TTL),
            is_fake=options.get("is_fake", False),
            fooling=options.get("fooling"),
            tcp_flags=options.get("tcp_flags", "PA"),
            fragment_index=options.get("fragment_index", 0),
            extra={
                k: v
                for k, v in options.items()
                if k not in ["ttl", "is_fake", "fooling", "tcp_flags", "fragment_index"]
            },
        )
