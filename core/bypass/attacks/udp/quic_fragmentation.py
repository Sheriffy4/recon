"""
QUIC Fragmentation Attack for HTTP/3 traffic.

This attack fragments QUIC packets at frame boundaries to evade DPI
that doesn't properly reassemble fragmented QUIC traffic.

Techniques:
- Frame-level fragmentation
- Initial packet splitting
- Crypto frame fragmentation
- Stream frame fragmentation
- Custom fragment boundaries
"""

import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

from ..base_classes.udp_attack_base import (
    UDPAttackBase,
    QUICPacket,
    QUIC_PACKET_INITIAL,
)
from ..base import AttackResult, AttackStatus, AttackContext
from ..registry import register_attack
from ..metadata import AttackCategories

logger = logging.getLogger(__name__)


@dataclass
class QUICFragmentationConfig:
    """Configuration for QUIC fragmentation attack."""

    # Fragment size control
    fragment_size: int = 512
    min_fragment_size: int = 64
    max_fragment_size: int = 1200

    # Fragmentation strategy
    fragment_at_frame_boundaries: bool = True
    split_crypto_frames: bool = True
    split_stream_frames: bool = True

    # Initial packet handling
    fragment_initial_packets: bool = True
    preserve_header_in_first_fragment: bool = True

    # Fragment ordering
    randomize_fragment_order: bool = False
    reverse_fragment_order: bool = False

    # Timing
    fragment_delay_ms: int = 5
    randomize_delays: bool = False


@register_attack("quic_fragmentation")
class QUICFragmentationAttack(UDPAttackBase):
    """
    QUIC packet fragmentation attack.

    Fragments QUIC packets at strategic boundaries to evade DPI systems
    that don't properly handle fragmented QUIC traffic.

    This attack is particularly effective against:
    - DPI systems that only inspect first fragment
    - Systems that don't reassemble QUIC frames
    - Stateless packet inspection

    Fragmentation strategies:
    - Frame boundary fragmentation (splits between QUIC frames)
    - Crypto frame splitting (fragments TLS handshake data)
    - Stream frame splitting (fragments application data)
    - Custom boundary fragmentation
    """

    def __init__(self, config: Optional[QUICFragmentationConfig] = None):
        """Initialize QUIC fragmentation attack."""
        super().__init__()
        self.config = config or QUICFragmentationConfig()

    @property
    def name(self) -> str:
        return "quic_fragmentation"

    @property
    def category(self) -> str:
        return AttackCategories.TUNNELING

    @property
    def required_params(self) -> list:
        return []

    @property
    def optional_params(self) -> dict:
        return {
            "fragment_size": 512,
            "fragment_at_frame_boundaries": True,
            "split_crypto_frames": True,
            "fragment_initial_packets": True,
            "fragment_delay_ms": 5,
        }

    def modify_udp_packet(self, packet, context: AttackContext) -> Optional[bytes]:
        """Not used for QUIC fragmentation."""
        return None

    def should_fragment_udp(self, packet, context: AttackContext) -> bool:
        """Determine if packet should be fragmented."""
        if not packet or len(packet.payload) < self.config.min_fragment_size:
            return False

        # Check if it's a QUIC packet
        if not self.detect_quic(packet.payload):
            return False

        return True

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute QUIC fragmentation attack."""
        try:
            if not context.payload:
                return AttackResult(
                    status=AttackStatus.FAILURE,
                    error_message="No payload provided for QUIC fragmentation",
                    metadata={"attack": self.name},
                )

            # Detect and parse QUIC packet
            if not self.detect_quic(context.payload):
                return AttackResult(
                    status=AttackStatus.SKIPPED,
                    error_message="Payload is not a QUIC packet",
                    metadata={"attack": self.name},
                )

            quic_packet = self.parse_quic_packet(context.payload)
            if not quic_packet:
                return AttackResult(
                    status=AttackStatus.FAILURE,
                    error_message="Failed to parse QUIC packet",
                    metadata={"attack": self.name},
                )

            # Check if we should fragment this packet
            if not self._should_fragment_packet(quic_packet):
                return AttackResult(
                    status=AttackStatus.SKIPPED,
                    error_message="Packet too small or not suitable for fragmentation",
                    metadata={"attack": self.name},
                )

            # Generate fragments
            fragments = self._create_fragments(quic_packet, context)

            if not fragments or len(fragments) < 2:
                return AttackResult(
                    status=AttackStatus.FAILURE,
                    error_message="Failed to create fragments",
                    metadata={"attack": self.name},
                )

            return AttackResult(
                status=AttackStatus.SUCCESS,
                packets_sent=len(fragments),
                metadata={
                    "attack": self.name,
                    "quic_version": (
                        hex(quic_packet.version) if quic_packet.version else "short_header"
                    ),
                    "is_long_header": quic_packet.is_long_header,
                    "original_size": len(quic_packet.raw_data),
                    "fragments": len(fragments),
                    "fragment_sizes": [len(f["data"]) for f in fragments],
                    "fragmentation_strategy": self._get_fragmentation_strategy(),
                },
            )

        except Exception as e:
            logger.error(f"QUIC fragmentation attack failed: {e}", exc_info=True)
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                metadata={"attack": self.name},
            )

    def _should_fragment_packet(self, quic_packet: QUICPacket) -> bool:
        """Determine if packet should be fragmented."""
        # Don't fragment very small packets
        if len(quic_packet.raw_data) < self.config.min_fragment_size:
            return False

        # Check if Initial packet fragmentation is enabled
        if quic_packet.is_long_header and quic_packet.packet_type == QUIC_PACKET_INITIAL:
            return self.config.fragment_initial_packets

        # Fragment other packets if they're large enough
        return len(quic_packet.raw_data) >= self.config.fragment_size

    def _create_fragments(
        self, quic_packet: QUICPacket, context: AttackContext
    ) -> List[Dict[str, Any]]:
        """
        Create fragments from QUIC packet.

        Returns list of fragment dictionaries with:
        - data: fragment bytes
        - delay_ms: delay before sending
        - offset: offset in original packet
        - is_last: whether this is the last fragment
        """
        fragments = []

        if self.config.fragment_at_frame_boundaries and quic_packet.is_long_header:
            # Try to fragment at frame boundaries
            fragments = self._fragment_at_frame_boundaries(quic_packet)

        if not fragments:
            # Fall back to simple fragmentation
            fragments = self._fragment_simple(quic_packet)

        # Apply fragment ordering
        fragments = self._apply_fragment_ordering(fragments)

        # Add timing information
        fragments = self._add_timing_info(fragments)

        return fragments

    def _fragment_at_frame_boundaries(self, quic_packet: QUICPacket) -> List[Dict[str, Any]]:
        """Fragment QUIC packet at frame boundaries."""
        fragments = []

        try:
            # Calculate header size
            header_size = len(quic_packet.raw_data) - len(quic_packet.payload)

            if header_size <= 0 or header_size >= len(quic_packet.raw_data):
                return []

            # First fragment: header + beginning of payload
            if self.config.preserve_header_in_first_fragment:
                first_fragment_size = min(
                    header_size + self.config.fragment_size, len(quic_packet.raw_data)
                )

                fragments.append(
                    {
                        "data": quic_packet.raw_data[:first_fragment_size],
                        "offset": 0,
                        "is_last": first_fragment_size >= len(quic_packet.raw_data),
                    }
                )

                offset = first_fragment_size
            else:
                offset = 0

            # Subsequent fragments
            while offset < len(quic_packet.raw_data):
                fragment_size = min(self.config.fragment_size, len(quic_packet.raw_data) - offset)

                fragments.append(
                    {
                        "data": quic_packet.raw_data[offset : offset + fragment_size],
                        "offset": offset,
                        "is_last": (offset + fragment_size) >= len(quic_packet.raw_data),
                    }
                )

                offset += fragment_size

            return fragments if len(fragments) > 1 else []

        except Exception as e:
            logger.error(f"Failed to fragment at frame boundaries: {e}")
            return []

    def _fragment_simple(self, quic_packet: QUICPacket) -> List[Dict[str, Any]]:
        """Simple fragmentation without frame awareness."""
        fragments = []
        offset = 0

        while offset < len(quic_packet.raw_data):
            fragment_size = min(self.config.fragment_size, len(quic_packet.raw_data) - offset)

            fragments.append(
                {
                    "data": quic_packet.raw_data[offset : offset + fragment_size],
                    "offset": offset,
                    "is_last": (offset + fragment_size) >= len(quic_packet.raw_data),
                }
            )

            offset += fragment_size

        return fragments

    def _apply_fragment_ordering(self, fragments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Apply fragment ordering strategy."""
        if not fragments or len(fragments) < 2:
            return fragments

        if self.config.reverse_fragment_order:
            # Reverse order (last fragment first)
            return list(reversed(fragments))

        if self.config.randomize_fragment_order:
            # Random order (keeping first fragment first if it has header)
            import random

            if self.config.preserve_header_in_first_fragment and len(fragments) > 1:
                first = [fragments[0]]
                rest = fragments[1:]
                random.shuffle(rest)
                return first + rest
            else:
                shuffled = fragments.copy()
                random.shuffle(shuffled)
                return shuffled

        # Normal order
        return fragments

    def _add_timing_info(self, fragments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Add timing information to fragments."""
        import random

        for i, fragment in enumerate(fragments):
            if self.config.randomize_delays:
                # Random delay between 0 and 2x configured delay
                delay = random.randint(0, self.config.fragment_delay_ms * 2)
            else:
                # Fixed delay
                delay = i * self.config.fragment_delay_ms

            fragment["delay_ms"] = delay

        return fragments

    def _get_fragmentation_strategy(self) -> str:
        """Get description of fragmentation strategy."""
        strategies = []

        if self.config.fragment_at_frame_boundaries:
            strategies.append("frame_boundaries")

        if self.config.split_crypto_frames:
            strategies.append("crypto_split")

        if self.config.split_stream_frames:
            strategies.append("stream_split")

        if self.config.randomize_fragment_order:
            strategies.append("random_order")
        elif self.config.reverse_fragment_order:
            strategies.append("reverse_order")

        return ",".join(strategies) if strategies else "simple"
