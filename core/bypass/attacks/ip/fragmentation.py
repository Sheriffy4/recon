"""
IP Fragmentation Attacks

Migrated and unified from:
- apply_ip_fragmentation_advanced (core/fast_bypass.py)
- apply_ip_fragmentation_disorder (core/fast_bypass.py)
- PacketBuilder.fragment_packet methods

Implements comprehensive IP fragmentation attacks including:
- Standard fragmentation with configurable sizes
- Overlapping fragments
- Out-of-order fragments
- Path MTU Discovery support
"""

import asyncio
import time
import random
import logging
from typing import List, Optional
from core.bypass.attacks.base import (
    BaseAttack,
    AttackContext,
    AttackResult,
    AttackStatus,
)
from core.bypass.attacks.attack_registry import register_attack
from core.bypass.attacks.metadata import AttackCategories, RegistrationPriority
from core.bypass.attacks.base_classes.ip_attack_base import IPAttackBase, IPPacket
from core.bypass.attacks.ip.mtu_discovery import get_mtu_discovery

logger = logging.getLogger(__name__)


@register_attack(
    name="ip_fragmentation",
    category=AttackCategories.IP,
    priority=RegistrationPriority.HIGH,
    required_params=[],
    optional_params={
        "fragment_size": None,  # Auto-detect from MTU if None
        "mtu": 1500,
        "auto_mtu": True,
    },
)
class IPFragmentationAttack(IPAttackBase):
    """
    Standard IP Fragmentation Attack with configurable fragment size and MTU detection.

    This attack fragments IP packets at configurable byte boundaries to evade DPI systems
    that don't properly reassemble fragments. Supports automatic MTU detection and
    configurable fragment sizes.

    Parameters:
        fragment_size: Size of each fragment in bytes (default: MTU/2)
        mtu: Maximum transmission unit (default: 1500)
        auto_mtu: Automatically detect MTU for target (default: True)

    Requirements: 7.1, 7.4, 7.5
    """

    @property
    def name(self) -> str:
        return "ip_fragmentation"

    @property
    def category(self) -> str:
        return AttackCategories.IP

    @property
    def description(self) -> str:
        return "Fragments IP packets at configurable boundaries with automatic MTU detection"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp", "udp", "icmp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> dict:
        return {
            "fragment_size": None,
            "mtu": 1500,
            "auto_mtu": True,
        }

    def modify_ip_packet(self, packet: IPPacket, context: AttackContext) -> Optional[bytes]:
        """Modify IP packet - not used for fragmentation."""
        return None

    def should_fragment(self, packet: IPPacket, context: AttackContext) -> bool:
        """Determine if packet should be fragmented."""
        mtu = self.get_mtu(context)
        return packet.total_length > mtu

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute IP fragmentation attack with MTU detection."""
        start_time = time.time()
        try:
            payload = context.payload

            # Get MTU discovery instance
            mtu_discovery = get_mtu_discovery()

            # Get MTU - auto-detect if enabled
            if context.params.get("auto_mtu", True):
                target_ip = context.params.get("target_ip", "8.8.8.8")
                mtu = mtu_discovery.detect_mtu(target_ip, method="auto")
            else:
                mtu = context.params.get("mtu", self.DEFAULT_MTU)

            # Get fragment size - use MTU discovery helper if not specified
            fragment_size = context.params.get("fragment_size")
            if fragment_size is None:
                target_ip = context.params.get("target_ip", "8.8.8.8")
                fragment_size = mtu_discovery.get_fragment_size(
                    target_ip, overhead=self.IP_HEADER_MIN_LENGTH, alignment=8
                )
            else:
                # Ensure fragment size is multiple of 8 (IP requirement)
                fragment_size = (fragment_size // 8) * 8

            if fragment_size <= 0:
                return AttackResult(
                    status=AttackStatus.ERROR,
                    error_message=f"Invalid fragment size: {fragment_size}",
                    latency_ms=(time.time() - start_time) * 1000,
                )

            # Fragment the payload
            if len(payload) <= fragment_size:
                fragments = [(payload, 0)]
            else:
                fragments = []
                offset = 0
                frag_id = random.randint(0, 65535)

                while offset < len(payload):
                    current_frag_size = min(fragment_size, len(payload) - offset)
                    fragment_data = payload[offset : offset + current_frag_size]

                    # Calculate fragment offset (in 8-byte units)
                    frag_offset = offset // 8

                    # Set MF (More Fragments) flag if not last fragment
                    more_fragments = (offset + current_frag_size) < len(payload)

                    fragments.append(
                        (
                            fragment_data,
                            offset,
                            {
                                "fragment_id": frag_id,
                                "fragment_offset": frag_offset,
                                "more_fragments": more_fragments,
                            },
                        )
                    )
                    offset += current_frag_size

            packets_sent = len(fragments)
            bytes_sent = sum(len(frag[0]) for frag in fragments)

            await asyncio.sleep(0)
            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "fragment_size": fragment_size,
                    "mtu": mtu,
                    "fragments_count": len(fragments),
                    "auto_mtu": context.params.get("auto_mtu", True),
                    "fragments": fragments if context.engine_type != "local" else None,
                },
            )
        except Exception as e:
            logger.error(f"IP fragmentation attack failed: {e}")
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )


@register_attack
class IPFragmentationAdvancedAttack(BaseAttack):
    """
    Advanced IP Fragmentation Attack with overlapping fragments.

    Migrated from:
    - apply_ip_fragmentation_advanced (fast_bypass.py)
    """

    @property
    def name(self) -> str:
        return "ip_fragmentation_advanced"

    @property
    def category(self) -> str:
        return "ip"

    @property
    def description(self) -> str:
        return "Advanced IP fragmentation with overlapping fragments to confuse DPI"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp", "udp", "icmp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> dict:
        return {"frag_size": 8, "overlap_bytes": 4}

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute advanced IP fragmentation attack."""
        start_time = time.time()
        try:
            payload = context.payload
            frag_size = context.params.get("frag_size", 8)
            overlap_bytes = context.params.get("overlap_bytes", 4)
            if len(payload) <= frag_size:
                fragments = [(payload, 0)]
            else:
                fragments = []
                offset = 0
                while offset < len(payload):
                    current_frag_size = min(frag_size, len(payload) - offset)
                    if offset > 0 and overlap_bytes > 0:
                        overlap_start = max(0, offset - overlap_bytes)
                        fragment_data = payload[overlap_start : offset + current_frag_size]
                        fragments.append((fragment_data, overlap_start))
                    else:
                        fragment_data = payload[offset : offset + current_frag_size]
                        fragments.append((fragment_data, offset))
                    offset += current_frag_size
            packets_sent = len(fragments)
            bytes_sent = sum((len(frag[0]) for frag in fragments))
            await asyncio.sleep(0)
            latency = (time.time() - start_time) * 1000
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "frag_size": frag_size,
                    "overlap_bytes": overlap_bytes,
                    "fragments_count": len(fragments),
                    "fragments": fragments if context.engine_type != "local" else None,
                },
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )


@register_attack(
    name="ip_fragment_overlap",
    category=AttackCategories.IP,
    priority=RegistrationPriority.HIGH,
    required_params=[],
    optional_params={
        "fragment_size": 8,
        "overlap_size": 4,
    },
)
class IPFragmentOverlapAttack(IPAttackBase):
    """
    IP Fragment Overlap Attack - creates overlapping fragments to confuse DPI.

    This attack generates IP fragments with overlapping data regions. Different
    implementations handle overlaps differently, which can be exploited to evade
    DPI systems that don't properly handle fragment reassembly.

    Parameters:
        fragment_size: Size of each fragment in bytes (default: 8)
        overlap_size: Number of bytes to overlap between fragments (default: 4)

    Requirements: 7.2, 7.5
    """

    @property
    def name(self) -> str:
        return "ip_fragment_overlap"

    @property
    def category(self) -> str:
        return AttackCategories.IP

    @property
    def description(self) -> str:
        return "Creates overlapping IP fragments to confuse DPI reassembly"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp", "udp", "icmp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> dict:
        return {
            "fragment_size": 8,
            "overlap_size": 4,
        }

    def modify_ip_packet(self, packet: IPPacket, context: AttackContext) -> Optional[bytes]:
        """Modify IP packet - not used for fragmentation."""
        return None

    def should_fragment(self, packet: IPPacket, context: AttackContext) -> bool:
        """Always fragment for overlap attack."""
        return True

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute IP fragment overlap attack."""
        start_time = time.time()
        try:
            payload = context.payload
            fragment_size = context.params.get("fragment_size", 8)
            overlap_size = context.params.get("overlap_size", 4)

            # Validate parameters
            if overlap_size >= fragment_size:
                return AttackResult(
                    status=AttackStatus.ERROR,
                    error_message=f"overlap_size ({overlap_size}) must be less than fragment_size ({fragment_size})",
                    latency_ms=(time.time() - start_time) * 1000,
                )

            # Ensure fragment size is multiple of 8
            fragment_size = (fragment_size // 8) * 8
            if fragment_size <= 0:
                fragment_size = 8

            if len(payload) <= fragment_size:
                fragments = [(payload, 0)]
            else:
                fragments = []
                offset = 0
                frag_id = random.randint(0, 65535)

                while offset < len(payload):
                    current_frag_size = min(fragment_size, len(payload) - offset)

                    # Create overlapping fragment
                    if offset > 0 and overlap_size > 0:
                        # Start from overlap_size bytes before current offset
                        overlap_start = max(0, offset - overlap_size)
                        fragment_data = payload[overlap_start : offset + current_frag_size]
                        frag_offset = overlap_start // 8
                    else:
                        fragment_data = payload[offset : offset + current_frag_size]
                        frag_offset = offset // 8

                    # Set MF flag if not last fragment
                    more_fragments = (offset + current_frag_size) < len(payload)

                    fragments.append(
                        (
                            fragment_data,
                            offset if offset == 0 else overlap_start,
                            {
                                "fragment_id": frag_id,
                                "fragment_offset": frag_offset,
                                "more_fragments": more_fragments,
                                "overlap_size": overlap_size if offset > 0 else 0,
                            },
                        )
                    )
                    offset += current_frag_size

            packets_sent = len(fragments)
            bytes_sent = sum(len(frag[0]) for frag in fragments)

            await asyncio.sleep(0)
            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "fragment_size": fragment_size,
                    "overlap_size": overlap_size,
                    "fragments_count": len(fragments),
                    "fragments": fragments if context.engine_type != "local" else None,
                },
            )
        except Exception as e:
            logger.error(f"IP fragment overlap attack failed: {e}")
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )


@register_attack(
    name="ip_fragment_disorder",
    category=AttackCategories.IP,
    priority=RegistrationPriority.HIGH,
    required_params=[],
    optional_params={
        "fragment_size": 12,
        "order_strategy": "reverse",  # reverse, random, custom
        "custom_order": None,
    },
)
class IPFragmentDisorderAttack(IPAttackBase):
    """
    IP Fragment Disorder Attack - sends fragments in non-sequential order.

    This attack fragments packets and sends them out of order to evade DPI systems
    that expect sequential fragment delivery. Supports multiple ordering strategies:
    - reverse: Send fragments in reverse order
    - random: Send fragments in random order
    - custom: Use custom ordering pattern

    Parameters:
        fragment_size: Size of each fragment in bytes (default: 12)
        order_strategy: Ordering strategy (reverse/random/custom, default: reverse)
        custom_order: Custom order indices for fragments (default: None)

    Requirements: 7.3, 7.5
    """

    @property
    def name(self) -> str:
        return "ip_fragment_disorder"

    @property
    def category(self) -> str:
        return AttackCategories.IP

    @property
    def description(self) -> str:
        return "Fragments payload and sends fragments in non-sequential order"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp", "udp", "icmp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> dict:
        return {
            "fragment_size": 12,
            "order_strategy": "reverse",
            "custom_order": None,
        }

    def modify_ip_packet(self, packet: IPPacket, context: AttackContext) -> Optional[bytes]:
        """Modify IP packet - not used for fragmentation."""
        return None

    def should_fragment(self, packet: IPPacket, context: AttackContext) -> bool:
        """Always fragment for disorder attack."""
        return True

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute IP fragmentation disorder attack."""
        start_time = time.time()
        try:
            payload = context.payload
            fragment_size = context.params.get("fragment_size", 12)
            order_strategy = context.params.get("order_strategy", "reverse")
            custom_order = context.params.get("custom_order")

            # Ensure fragment size is multiple of 8
            fragment_size = (fragment_size // 8) * 8
            if fragment_size <= 0:
                fragment_size = 8

            if len(payload) <= fragment_size:
                fragments = [(payload, 0)]
            else:
                fragments = []
                offset = 0
                frag_id = random.randint(0, 65535)

                while offset < len(payload):
                    current_frag_size = min(fragment_size, len(payload) - offset)
                    fragment_data = payload[offset : offset + current_frag_size]

                    frag_offset = offset // 8
                    more_fragments = (offset + current_frag_size) < len(payload)

                    fragments.append(
                        (
                            fragment_data,
                            offset,
                            {
                                "fragment_id": frag_id,
                                "fragment_offset": frag_offset,
                                "more_fragments": more_fragments,
                                "original_index": len(fragments),
                            },
                        )
                    )
                    offset += current_frag_size

                # Apply ordering strategy
                if order_strategy == "reverse":
                    fragments = fragments[::-1]
                elif order_strategy == "random":
                    random.shuffle(fragments)
                elif order_strategy == "custom" and custom_order:
                    # Reorder based on custom indices
                    if len(custom_order) == len(fragments):
                        try:
                            fragments = [fragments[i] for i in custom_order]
                        except IndexError:
                            logger.warning("Invalid custom_order indices, using reverse order")
                            fragments = fragments[::-1]
                    else:
                        logger.warning("custom_order length mismatch, using reverse order")
                        fragments = fragments[::-1]

            packets_sent = len(fragments)
            bytes_sent = len(payload)

            await asyncio.sleep(0)
            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "fragment_size": fragment_size,
                    "fragments_count": len(fragments),
                    "order_strategy": order_strategy,
                    "disordered": True,
                    "fragments": fragments if context.engine_type != "local" else None,
                },
            )
        except Exception as e:
            logger.error(f"IP fragment disorder attack failed: {e}")
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )


@register_attack
class IPFragmentationRandomAttack(BaseAttack):
    """
    Random IP Fragmentation Attack - fragments with random sizes.
    """

    @property
    def name(self) -> str:
        return "ip_fragmentation_random"

    @property
    def category(self) -> str:
        return "ip"

    @property
    def description(self) -> str:
        return "Fragments payload with random fragment sizes"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp", "udp", "icmp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> dict:
        return {"min_frag_size": 4, "max_frag_size": 16}

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute random IP fragmentation attack."""
        start_time = time.time()
        try:
            payload = context.payload
            min_frag_size = context.params.get("min_frag_size", 4)
            max_frag_size = context.params.get("max_frag_size", 16)
            if len(payload) <= min_frag_size:
                fragments = [(payload, 0)]
            else:
                fragments = []
                offset = 0
                while offset < len(payload):
                    remaining = len(payload) - offset
                    max_size = min(max_frag_size, remaining)
                    frag_size = random.randint(min_frag_size, max(min_frag_size, max_size))
                    fragment_data = payload[offset : offset + frag_size]
                    fragments.append((fragment_data, offset))
                    offset += frag_size
            packets_sent = len(fragments)
            bytes_sent = len(payload)
            await asyncio.sleep(0)
            latency = (time.time() - start_time) * 1000
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "min_frag_size": min_frag_size,
                    "max_frag_size": max_frag_size,
                    "fragments_count": len(fragments),
                    "fragments": fragments if context.engine_type != "local" else None,
                },
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )
