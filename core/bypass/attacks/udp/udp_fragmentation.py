"""
Generic UDP Fragmentation Attack.

This attack fragments UDP packets to bypass DPI systems that
don't properly reassemble fragmented UDP traffic.
"""

from core.bypass.attacks.attack_registry import register_attack
import random
from typing import Dict, Any, List, Tuple, Optional
from dataclasses import dataclass

from ..base import BaseAttack, AttackResult, AttackStatus, AttackContext
from ..registry import register_attack


@dataclass
class UDPFragmentationConfig:
    """Configuration for UDP fragmentation attack."""

    fragment_size: int = 32
    fragment_delay: int = 5
    fragment_order: str = "normal"  # normal, reverse, random
    duplicate_fragments: bool = False


@register_attack("udp_fragmentation")
class UDPFragmentationAttack(BaseAttack):
    """
    Generic UDP packet fragmentation attack.

    Fragments UDP packets to bypass DPI systems.
    Effective against DNS, NTP, SNMP, OpenVPN, IPSec, and other UDP protocols.
    """

    def __init__(
        self,
        name: str = "udp_fragmentation",
        config: Optional[UDPFragmentationConfig] = None,
    ):
        super().__init__()
        self.config = config or UDPFragmentationConfig()

    @property
    def name(self) -> str:
        return "udp_fragmentation"

    @property
    def category(self) -> str:
        return "ip"

    @property
    def required_params(self) -> list:
        return []

    @property
    def optional_params(self) -> dict:
        return {
            "fragment_size": 64,
            "fragment_order": "normal",
            "overlap_fragments": False
        }

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute UDP fragmentation attack."""
        try:
            if not context.payload:
                return AttackResult(
                    status=AttackStatus.FAILURE,
                    error_message="No payload provided for UDP fragmentation",
                    metadata={"attack_type": "udp_fragmentation"},
                )

            # Generate fragmented segments
            segments = await self._create_fragmented_segments(context.payload, context)

            return AttackResult(
                status=AttackStatus.SUCCESS,
                packets_sent=len(segments),
                metadata={
                    "attack_type": "udp_fragmentation",
                    "fragment_size": self.config.fragment_size,
                    "fragment_order": self.config.fragment_order,
                    "segments": len(segments),
                    "target_protocol": "UDP",
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                metadata={"attack_type": "udp_fragmentation"},
            )

    async def _create_fragmented_segments(
        self, payload: bytes, context: AttackContext
    ) -> List[Tuple[bytes, int, Dict[str, Any]]]:
        """Create fragmented UDP segments."""
        segments = []

        if len(payload) <= self.config.fragment_size:
            # Payload is small, send as-is
            segments.append(
                (
                    payload,
                    0,
                    {
                        "is_fake": False,
                        "delay_ms": 0,
                        "fragment_index": 0,
                        "total_fragments": 1,
                    },
                )
            )
            return segments

        # Create fragments
        fragments = []
        for i in range(0, len(payload), self.config.fragment_size):
            fragment = payload[i : i + self.config.fragment_size]
            fragments.append((fragment, i))

        # Reorder fragments based on configuration
        if self.config.fragment_order == "reverse":
            fragments.reverse()
        elif self.config.fragment_order == "random":
            random.shuffle(fragments)
        # "normal" order is already correct

        # Create segments from fragments
        for i, (fragment, offset) in enumerate(fragments):
            segments.append(
                (
                    fragment,
                    offset,
                    {
                        "is_fake": False,
                        "delay_ms": i * self.config.fragment_delay,
                        "fragment_index": i,
                        "total_fragments": len(fragments),
                        "original_offset": offset,
                    },
                )
            )

            # Add duplicate fragments if configured
            if self.config.duplicate_fragments:
                segments.append(
                    (
                        fragment,
                        offset,
                        {
                            "is_fake": True,  # Mark duplicate as fake
                            "ttl": 1,  # Low TTL for duplicate
                            "delay_ms": (i * self.config.fragment_delay) + 1,
                            "fragment_index": i,
                            "total_fragments": len(fragments),
                            "original_offset": offset,
                            "is_duplicate": True,
                        },
                    )
                )

        return segments
