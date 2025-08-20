# recon/core/bypass/attacks/tcp/stateful_attacks.py
"""
Specialized attacks against stateful DPI systems.

These attacks target DPI systems that maintain connection state and track
TCP sequence numbers, packet order, and timing patterns.

Implements Task 17.2: Create attacks against stateful DPI with timeouts
- fakeddisorder/multidisorder for segment order disruption
- seqovl (Sequence Overlap) for TCP stream ambiguity
- timing attacks with non-standard delays
"""

import random
import asyncio
from typing import Any, List, Optional, Tuple
from dataclasses import dataclass

try:
    from scapy.all import IP, TCP, Raw, send, sr1

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from ..base import BaseAttack, AttackContext, AttackResult, AttackStatus
from ..registry import register_attack


@dataclass
class StatefulAttackConfig:
    """Configuration for stateful DPI attacks."""

    # Disorder configuration
    disorder_level: str = "medium"  # "low", "medium", "high"
    max_disorder_packets: int = 5
    disorder_delay_ms: int = 100

    # Sequence overlap configuration
    overlap_size: int = 10
    overlap_method: str = "duplicate"  # "duplicate", "modify", "random"

    # Timing configuration
    timing_jitter: bool = True
    base_delay_ms: int = 50
    max_jitter_ms: int = 200

    # State confusion parameters
    state_confusion: bool = True
    fake_ack_count: int = 3
    window_manipulation: bool = True


@register_attack
class FakeDisorderAttack(BaseAttack):
    """
    Fake + Disorder Attack for Stateful DPI Evasion.

    This attack sends fake packets followed by real packets in disordered sequence
    to confuse stateful DPI systems that track packet order and TCP state.

    The attack works by:
    1. Sending fake packets with incorrect checksums/TTL
    2. Sending real packets out of order
    3. Relying on the target to reassemble correctly while DPI gets confused
    """

    def __init__(self, config: Optional[StatefulAttackConfig] = None):
        super().__init__()
        self.config = config or StatefulAttackConfig()
        self._name = "tcp_fakeddisorder"
        self._category = "tcp"
        self._description = "Fake packets + disorder to confuse stateful DPI"

    @property
    def name(self) -> str:
        return self._name

    @property
    def category(self) -> str:
        return self._category

    @property
    def description(self) -> str:
        return self._description

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute fake disorder attack."""
        if not SCAPY_AVAILABLE:
            return AttackResult(
                status=AttackStatus.ERROR,
                technique_used=self.name,
                error_message="Scapy not available for packet crafting",
            )

        try:
            target_ip = context.dst_ip
            target_port = context.dst_port
            payload = context.payload or b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

            # Split payload into segments for disorder
            segments = self._split_payload_for_disorder(payload)

            # Create fake packets (will be dropped by target due to bad checksum)
            fake_packets = self._create_fake_packets(target_ip, target_port, segments)

            # Create real packets in disordered sequence
            real_packets = self._create_disordered_packets(
                target_ip, target_port, segments
            )

            # Send fake packets first to poison DPI state
            await self._send_fake_packets(fake_packets)

            # Add timing jitter if configured
            if self.config.timing_jitter:
                jitter = random.randint(0, self.config.max_jitter_ms)
                await asyncio.sleep(jitter / 1000.0)

            # Send real packets in disordered sequence
            response = await self._send_disordered_packets(real_packets)

            # Analyze response for success
            success = self._analyze_response(response)

            return AttackResult(
                status=AttackStatus.SUCCESS if success else AttackStatus.ERROR,
                technique_used=self.name,
                metadata={
                    "fake_packet_count": len(fake_packets),
                    "real_packet_count": len(real_packets),
                    "disorder_level": self.config.disorder_level,
                    "timing_jitter_used": self.config.timing_jitter,
                    "segments_created": len(segments),
                    "modified_packets": len(fake_packets + real_packets),
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                technique_used=self.name,
                error_message=f"Fake disorder attack failed: {str(e)}",
            )

    def _split_payload_for_disorder(self, payload: bytes) -> List[bytes]:
        """Split payload into segments for disordered transmission."""
        if len(payload) <= 10:
            return [payload]

        # Determine segment count based on disorder level
        segment_counts = {"low": 2, "medium": 3, "high": 5}
        segment_count = segment_counts.get(self.config.disorder_level, 3)

        segment_size = len(payload) // segment_count
        segments = []

        for i in range(segment_count):
            start = i * segment_size
            if i == segment_count - 1:  # Last segment gets remainder
                end = len(payload)
            else:
                end = start + segment_size
            segments.append(payload[start:end])

        return segments

    def _create_fake_packets(
        self, target_ip: str, target_port: int, segments: List[bytes]
    ) -> List[Any]:
        """Create fake packets with bad checksums to poison DPI state."""
        fake_packets = []
        base_seq = random.randint(1000, 10000)

        for i, segment in enumerate(segments):
            # Create packet with intentionally bad checksum
            packet = (
                IP(dst=target_ip, ttl=1)
                / TCP(dport=target_port, seq=base_seq + i * len(segment), flags="PA")
                / Raw(load=segment)
            )

            # Corrupt checksum to ensure packet is dropped by target
            packet[TCP].chksum = 0xFFFF  # Invalid checksum
            fake_packets.append(packet)

        return fake_packets

    def _create_disordered_packets(
        self, target_ip: str, target_port: int, segments: List[bytes]
    ) -> List[Any]:
        """Create real packets in disordered sequence."""
        real_packets = []
        base_seq = random.randint(10000, 20000)

        # Create packets with correct sequence numbers
        ordered_packets = []
        for i, segment in enumerate(segments):
            packet = (
                IP(dst=target_ip)
                / TCP(dport=target_port, seq=base_seq + i * len(segment), flags="PA")
                / Raw(load=segment)
            )
            ordered_packets.append(packet)

        # Shuffle packets to create disorder
        disordered_packets = ordered_packets.copy()
        random.shuffle(disordered_packets)

        return disordered_packets

    async def _send_fake_packets(self, fake_packets: List[Any]) -> None:
        """Send fake packets to poison DPI state."""
        for packet in fake_packets:
            try:
                send(packet, verbose=0)
                # Small delay between fake packets
                await asyncio.sleep(self.config.disorder_delay_ms / 1000.0)
            except Exception:
                # Continue even if some fake packets fail
                pass

    async def _send_disordered_packets(self, real_packets: List[Any]) -> Optional[Any]:
        """Send real packets in disordered sequence."""
        response = None

        for i, packet in enumerate(real_packets):
            try:
                if i == len(real_packets) - 1:  # Last packet, wait for response
                    response = sr1(packet, timeout=2, verbose=0)
                else:
                    send(packet, verbose=0)

                # Add jitter between packets
                if self.config.timing_jitter and i < len(real_packets) - 1:
                    jitter = random.randint(0, self.config.max_jitter_ms)
                    await asyncio.sleep(jitter / 1000.0)

            except Exception:
                continue

        return response

    def _analyze_response(self, response: Optional[Any]) -> bool:
        """Analyze response to determine attack success."""
        if not response:
            return False

        # Check if we got a valid HTTP response
        if response.haslayer(TCP) and response.haslayer(Raw):
            payload = response[Raw].load
            if b"HTTP" in payload or b"200" in payload:
                return True

        return False


@register_attack
class MultiDisorderAttack(BaseAttack):
    """
    Multiple Disorder Attack for Advanced Stateful DPI Evasion.

    This attack creates multiple streams of disordered packets to overwhelm
    stateful DPI systems that have limited connection tracking capacity.
    """

    def __init__(self, config: Optional[StatefulAttackConfig] = None):
        super().__init__()
        self.config = config or StatefulAttackConfig()
        self._name = "tcp_multidisorder"
        self._category = "tcp"
        self._description = "Multiple disordered streams to overwhelm stateful DPI"

    @property
    def name(self) -> str:
        return self._name

    @property
    def category(self) -> str:
        return self._category

    @property
    def description(self) -> str:
        return self._description

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute multi-disorder attack."""
        if not SCAPY_AVAILABLE:
            return AttackResult(
                status=AttackStatus.ERROR,
                technique_used=self.name,
                error_message="Scapy not available for packet crafting",
            )

        try:
            target_ip = context.dst_ip
            target_port = context.dst_port
            payload = context.payload or b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

            # Create multiple disordered streams
            streams = self._create_multiple_streams(target_ip, target_port, payload)

            # Send all streams concurrently with disorder
            response = await self._send_multiple_disordered_streams(streams)

            success = self._analyze_response(response)

            return AttackResult(
                status=AttackStatus.SUCCESS if success else AttackStatus.ERROR,
                technique_used=self.name,
                metadata={
                    "stream_count": len(streams),
                    "total_packets": sum(len(stream) for stream in streams),
                    "disorder_level": self.config.disorder_level,
                    "state_confusion_enabled": self.config.state_confusion,
                    "modified_packets": sum(len(stream) for stream in streams),
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                technique_used=self.name,
                error_message=f"Multi-disorder attack failed: {str(e)}",
            )

    def _create_multiple_streams(
        self, target_ip: str, target_port: int, payload: bytes
    ) -> List[List[Any]]:
        """Create multiple streams of disordered packets."""
        stream_count = min(self.config.max_disorder_packets, 3)  # Limit to 3 streams
        streams = []

        # Split payload across streams
        payload_per_stream = len(payload) // stream_count

        for stream_id in range(stream_count):
            start_offset = stream_id * payload_per_stream
            if stream_id == stream_count - 1:  # Last stream gets remainder
                stream_payload = payload[start_offset:]
            else:
                stream_payload = payload[
                    start_offset : start_offset + payload_per_stream
                ]

            # Create disordered packets for this stream
            stream_packets = self._create_stream_packets(
                target_ip, target_port, stream_payload, stream_id
            )
            streams.append(stream_packets)

        return streams

    def _create_stream_packets(
        self, target_ip: str, target_port: int, payload: bytes, stream_id: int
    ) -> List[Any]:
        """Create packets for a single disordered stream."""
        packets = []
        base_seq = random.randint(1000 + stream_id * 10000, 5000 + stream_id * 10000)

        # Split payload into smaller segments
        segment_size = max(10, len(payload) // 3)
        segments = [
            payload[i : i + segment_size] for i in range(0, len(payload), segment_size)
        ]

        # Create packets for each segment
        for i, segment in enumerate(segments):
            packet = (
                IP(dst=target_ip)
                / TCP(
                    dport=target_port,
                    seq=base_seq + i * len(segment),
                    flags="PA",
                    sport=54321 + stream_id,  # Different source port per stream
                )
                / Raw(load=segment)
            )
            packets.append(packet)

        # Shuffle packets to create disorder
        random.shuffle(packets)
        return packets

    async def _send_multiple_disordered_streams(
        self, streams: List[List[Any]]
    ) -> Optional[Any]:
        """Send multiple disordered streams concurrently."""
        response = None

        # Interleave packets from different streams
        all_packets = []
        max_stream_len = max(len(stream) for stream in streams)

        for i in range(max_stream_len):
            for stream in streams:
                if i < len(stream):
                    all_packets.append(stream[i])

        # Send interleaved packets
        for i, packet in enumerate(all_packets):
            try:
                if i == len(all_packets) - 1:  # Last packet
                    response = sr1(packet, timeout=3, verbose=0)
                else:
                    send(packet, verbose=0)

                # Small delay between packets
                await asyncio.sleep(
                    self.config.disorder_delay_ms / 2000.0
                )  # Half delay for faster sending

            except Exception:
                continue

        return response

    def _analyze_response(self, response: Optional[Any]) -> bool:
        """Analyze response to determine attack success."""
        if not response:
            return False

        if response.haslayer(TCP) and response.haslayer(Raw):
            payload = response[Raw].load
            if b"HTTP" in payload or b"200" in payload:
                return True

        return False


@register_attack
class SequenceOverlapAttack(BaseAttack):
    """
    Sequence Overlap (seqovl) Attack for TCP Stream Ambiguity.

    This attack creates overlapping TCP sequence numbers to create ambiguity
    in the TCP stream, confusing stateful DPI systems about the actual content.
    """

    def __init__(self, config: Optional[StatefulAttackConfig] = None):
        super().__init__()
        self.config = config or StatefulAttackConfig()
        self._name = "tcp_seqovl"
        self._category = "tcp"
        self._description = "Sequence overlap for TCP stream ambiguity"

    @property
    def name(self) -> str:
        return self._name

    @property
    def category(self) -> str:
        return self._category

    @property
    def description(self) -> str:
        return self._description

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute sequence overlap attack."""
        if not SCAPY_AVAILABLE:
            return AttackResult(
                status=AttackStatus.ERROR,
                technique_used=self.name,
                error_message="Scapy not available for packet crafting",
            )

        try:
            target_ip = context.dst_ip
            target_port = context.dst_port
            payload = context.payload or b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

            # Create overlapping packets
            overlapping_packets = self._create_overlapping_packets(
                target_ip, target_port, payload
            )

            # Send overlapping packets
            response = await self._send_overlapping_packets(overlapping_packets)

            success = self._analyze_response(response)

            return AttackResult(
                status=AttackStatus.SUCCESS if success else AttackStatus.ERROR,
                technique_used=self.name,
                metadata={
                    "overlap_size": self.config.overlap_size,
                    "overlap_method": self.config.overlap_method,
                    "packet_count": len(overlapping_packets),
                    "sequence_manipulation": "aggressive",
                    "modified_packets": len(overlapping_packets),
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                technique_used=self.name,
                error_message=f"Sequence overlap attack failed: {str(e)}",
            )

    def _create_overlapping_packets(
        self, target_ip: str, target_port: int, payload: bytes
    ) -> List[Any]:
        """Create packets with overlapping sequence numbers."""
        packets = []
        base_seq = random.randint(1000, 10000)

        # Split payload for overlap
        split_point = len(payload) // 2
        first_part = payload[: split_point + self.config.overlap_size]
        second_part = payload[split_point:]

        # Create first packet
        packet1 = (
            IP(dst=target_ip)
            / TCP(dport=target_port, seq=base_seq, flags="PA")
            / Raw(load=first_part)
        )
        packets.append(packet1)

        # Create overlapping packet with different content in overlap region
        if self.config.overlap_method == "duplicate":
            # Duplicate the overlapping region
            overlap_packet = (
                IP(dst=target_ip)
                / TCP(dport=target_port, seq=base_seq + split_point, flags="PA")
                / Raw(
                    load=payload[split_point : split_point + self.config.overlap_size]
                )
            )
            packets.append(overlap_packet)

        elif self.config.overlap_method == "modify":
            # Modify the overlapping region
            modified_overlap = b"X" * self.config.overlap_size
            overlap_packet = (
                IP(dst=target_ip)
                / TCP(dport=target_port, seq=base_seq + split_point, flags="PA")
                / Raw(load=modified_overlap)
            )
            packets.append(overlap_packet)

        # Create second packet
        packet2 = (
            IP(dst=target_ip)
            / TCP(dport=target_port, seq=base_seq + split_point, flags="PA")
            / Raw(load=second_part)
        )
        packets.append(packet2)

        return packets

    async def _send_overlapping_packets(self, packets: List[Any]) -> Optional[Any]:
        """Send overlapping packets with timing control."""
        response = None

        for i, packet in enumerate(packets):
            try:
                if i == len(packets) - 1:  # Last packet
                    response = sr1(packet, timeout=3, verbose=0)
                else:
                    send(packet, verbose=0)

                # Add controlled delay between overlapping packets
                if i < len(packets) - 1:
                    delay = self.config.base_delay_ms / 1000.0
                    if self.config.timing_jitter:
                        jitter = random.randint(0, self.config.max_jitter_ms) / 1000.0
                        delay += jitter
                    await asyncio.sleep(delay)

            except Exception:
                continue

        return response

    def _analyze_response(self, response: Optional[Any]) -> bool:
        """Analyze response to determine attack success."""
        if not response:
            return False

        if response.haslayer(TCP) and response.haslayer(Raw):
            payload = response[Raw].load
            if b"HTTP" in payload or b"200" in payload:
                return True

        return False


@register_attack
class TimingManipulationAttack(BaseAttack):
    """
    Timing Manipulation Attack for Stateful DPI Evasion.

    This attack uses non-standard timing patterns to confuse stateful DPI
    systems that rely on timing analysis for detection.
    """

    def __init__(self, config: Optional[StatefulAttackConfig] = None):
        super().__init__()
        self.config = config or StatefulAttackConfig()
        self._name = "tcp_timing_manipulation"
        self._category = "tcp"
        self._description = "Non-standard timing patterns to confuse stateful DPI"

    @property
    def name(self) -> str:
        return self._name

    @property
    def category(self) -> str:
        return self._category

    @property
    def description(self) -> str:
        return self._description

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute timing manipulation attack."""
        if not SCAPY_AVAILABLE:
            return AttackResult(
                status=AttackStatus.ERROR,
                technique_used=self.name,
                error_message="Scapy not available for packet crafting",
            )

        try:
            target_ip = context.dst_ip
            target_port = context.dst_port
            payload = context.payload or b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

            # Create packets with timing manipulation
            timed_packets = self._create_timed_packets(target_ip, target_port, payload)

            # Send packets with controlled timing
            response = await self._send_timed_packets(timed_packets)

            success = self._analyze_response(response)

            return AttackResult(
                status=AttackStatus.SUCCESS if success else AttackStatus.ERROR,
                technique_used=self.name,
                metadata={
                    "timing_pattern": "variable",
                    "base_delay_ms": self.config.base_delay_ms,
                    "max_jitter_ms": self.config.max_jitter_ms,
                    "packet_count": len(timed_packets),
                    "modified_packets": len(timed_packets),
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                technique_used=self.name,
                error_message=f"Timing manipulation attack failed: {str(e)}",
            )

    def _create_timed_packets(
        self, target_ip: str, target_port: int, payload: bytes
    ) -> List[Tuple[Any, float]]:
        """Create packets with associated timing delays."""
        timed_packets = []
        base_seq = random.randint(1000, 10000)

        # Split payload into segments
        segment_size = max(10, len(payload) // 4)
        segments = [
            payload[i : i + segment_size] for i in range(0, len(payload), segment_size)
        ]

        # Create timing patterns
        timing_patterns = self._generate_timing_patterns(len(segments))

        for i, (segment, delay) in enumerate(zip(segments, timing_patterns)):
            packet = (
                IP(dst=target_ip)
                / TCP(dport=target_port, seq=base_seq + i * len(segment), flags="PA")
                / Raw(load=segment)
            )

            timed_packets.append((packet, delay))

        return timed_packets

    def _generate_timing_patterns(self, packet_count: int) -> List[float]:
        """Generate non-standard timing patterns."""
        patterns = []
        base_delay = self.config.base_delay_ms / 1000.0

        for i in range(packet_count):
            if self.config.timing_jitter:
                # Variable timing pattern
                if i % 2 == 0:
                    # Even packets: short delay
                    delay = base_delay * 0.5 + random.uniform(0, 0.1)
                else:
                    # Odd packets: longer delay
                    delay = base_delay * 2.0 + random.uniform(0, 0.2)
            else:
                # Fixed timing pattern
                delay = base_delay

            patterns.append(delay)

        return patterns

    async def _send_timed_packets(
        self, timed_packets: List[Tuple[Any, float]]
    ) -> Optional[Any]:
        """Send packets with precise timing control."""
        response = None

        for i, (packet, delay) in enumerate(timed_packets):
            try:
                if i == len(timed_packets) - 1:  # Last packet
                    response = sr1(packet, timeout=3, verbose=0)
                else:
                    send(packet, verbose=0)
                    await asyncio.sleep(delay)

            except Exception:
                continue

        return response

    def _analyze_response(self, response: Optional[Any]) -> bool:
        """Analyze response to determine attack success."""
        if not response:
            return False

        if response.haslayer(TCP) and response.haslayer(Raw):
            payload = response[Raw].load
            if b"HTTP" in payload or b"200" in payload:
                return True

        return False
