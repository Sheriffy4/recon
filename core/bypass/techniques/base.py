"""Base classes for bypass techniques."""

import abc
from typing import List, Tuple, Optional, Any, Union
import struct
import random
from core.bypass.types import TechniqueParams, TechniqueType
from core.bypass.exceptions import InvalidPacketError


class BaseTechnique(abc.ABC):
    """Abstract base class for bypass techniques."""

    technique_type: TechniqueType = None
    category: str = "general"
    supported_protocols: List[str] = ["tcp"]

    @classmethod
    @abc.abstractmethod
    def apply(cls, packet_data: bytes, params: TechniqueParams) -> Any:
        """Apply technique to packet data."""
        pass

    @classmethod
    def validate_packet(cls, packet_data: bytes, min_size: int = 40) -> None:
        """Validate packet data.

        Raises:
            InvalidPacketError: If packet is invalid
        """
        if not packet_data:
            raise InvalidPacketError("Packet data is empty")
        if len(packet_data) < min_size:
            raise InvalidPacketError(
                f"Packet too small: {len(packet_data)} < {min_size}"
            )

    @classmethod
    def extract_payload(cls, packet_data: bytes) -> bytes:
        """Extract payload from packet."""
        ip_hlen = cls.get_ip_header_length(packet_data)
        protocol = packet_data[9] if len(packet_data) > 9 else 0
        if protocol == 6:
            tcp_hlen = cls.get_tcp_header_length(packet_data, ip_hlen)
            return packet_data[ip_hlen + tcp_hlen :]
        elif protocol == 17:
            return packet_data[ip_hlen + 8 :]
        else:
            return b""

    @classmethod
    def get_ip_header_length(cls, packet_data: bytes) -> int:
        """Get IP header length from packet."""
        if len(packet_data) < 1:
            return 20
        return (packet_data[0] & 15) * 4

    @classmethod
    def get_tcp_header_length(cls, packet_data: bytes, ip_hlen: int) -> int:
        """Get TCP header length from packet."""
        if len(packet_data) < ip_hlen + 13:
            return 20
        return (packet_data[ip_hlen + 12] >> 4 & 15) * 4


class SegmentationTechnique(BaseTechnique):
    """Base class for packet segmentation techniques."""

    category = "segmentation"

    @classmethod
    def create_segments(
        cls, payload: bytes, positions: List[int]
    ) -> List[Tuple[bytes, int]]:
        """Create payload segments at specified positions.

        Returns:
            List of (segment_data, offset) tuples
        """
        if not positions:
            return [(payload, 0)]
        segments = []
        last_pos = 0
        for pos in sorted(positions):
            if pos > last_pos and pos < len(payload):
                segments.append((payload[last_pos:pos], last_pos))
                last_pos = pos
        if last_pos < len(payload):
            segments.append((payload[last_pos:], last_pos))
        return segments

    @classmethod
    def resolve_split_position(cls, payload: bytes, position: Union[int, str]) -> int:
        """Resolve split position (handles special values like 'midsld')."""
        if isinstance(position, int):
            return position
        if position == "midsld":
            return cls._find_midsld_position(payload)
        return 3

    @classmethod
    def _find_midsld_position(cls, payload: bytes) -> int:
        """Find middle of second-level domain in TLS SNI."""
        try:
            pos = payload.find(b"\x00\x00")
            while pos != -1:
                if pos + 9 < len(payload):
                    ext_type = struct.unpack("!H", payload[pos : pos + 2])[0]
                    if ext_type == 0:
                        ext_len = struct.unpack("!H", payload[pos + 2 : pos + 4])[0]
                        list_len = struct.unpack("!H", payload[pos + 4 : pos + 6])[0]
                        name_type = payload[pos + 6]
                        if name_type == 0:
                            name_len = struct.unpack("!H", payload[pos + 7 : pos + 9])[
                                0
                            ]
                            name_start = pos + 9
                            if name_start + name_len <= len(payload):
                                domain_bytes = payload[
                                    name_start : name_start + name_len
                                ]
                                domain_str = domain_bytes.decode(
                                    "ascii", errors="ignore"
                                )
                                parts = domain_str.split(".")
                                if len(parts) >= 2:
                                    sld = parts[-2]
                                    sld_pos = domain_bytes.find(sld.encode())
                                    if sld_pos != -1:
                                        return name_start + sld_pos + len(sld) // 2
                pos = payload.find(b"\x00\x00", pos + 1)
        except Exception:
            pass
        return len(payload) // 2


class RaceConditionTechnique(BaseTechnique):
    """Base class for race condition techniques."""

    category = "race_condition"

    @classmethod
    def create_fake_packet(
        cls,
        packet_data: bytes,
        fake_payload: Optional[bytes] = None,
        ttl: Optional[int] = None,
        modify_checksum: bool = False,
    ) -> bytes:
        """Create a fake packet for race condition.

        Args:
            packet_data: Original packet data
            fake_payload: Fake payload to use
            ttl: TTL value for fake packet
            modify_checksum: Whether to corrupt checksum

        Returns:
            Modified packet data
        """
        if fake_payload is None:
            fake_payload = b"GET / HTTP/1.0\r\n\r\n"
        return packet_data


class TimingTechnique(BaseTechnique):
    """Base class for timing-based techniques."""

    category = "timing"

    @classmethod
    def calculate_delays(
        cls, num_segments: int, total_time_ms: float, pattern: str = "uniform"
    ) -> List[float]:
        """Calculate delays between segments.

        Args:
            num_segments: Number of segments
            total_time_ms: Total time budget in milliseconds
            pattern: Delay pattern ('uniform', 'exponential', 'random')

        Returns:
            List of delays in milliseconds
        """
        if num_segments <= 1:
            return []
        delays = []
        if pattern == "uniform":
            delay = total_time_ms / (num_segments - 1)
            delays = [delay] * (num_segments - 1)
        elif pattern == "exponential":
            base = 2.0
            total = sum((base**i for i in range(num_segments - 1)))
            unit = total_time_ms / total
            delays = [unit * base**i for i in range(num_segments - 1)]
        elif pattern == "random":
            random_values = [random.random() for _ in range(num_segments - 1)]
            total_random = sum(random_values)
            delays = [v / total_random * total_time_ms for v in random_values]
        return delays
