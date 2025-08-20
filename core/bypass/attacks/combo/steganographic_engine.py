# recon/core/bypass/attacks/combo/steganographic_engine.py
"""
Steganographic Engine for Traffic Mimicry

Implements advanced steganographic techniques to embed bypass data within
legitimate application traffic patterns, making detection extremely difficult.
"""

import random
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple
from enum import Enum

LOG = logging.getLogger(__name__)


class SteganographicMethod(Enum):
    """Available steganographic embedding methods."""

    LSB_PAYLOAD = "lsb_payload"  # Least Significant Bit in payload
    TIMING_CHANNEL = "timing_channel"  # Timing-based steganography
    HEADER_MODIFICATION = "header_modification"  # Header field manipulation
    PROTOCOL_EXTENSION = "protocol_extension"  # Protocol-specific extensions
    BEHAVIORAL_PATTERN = "behavioral_pattern"  # Behavioral pattern encoding
    MULTI_LAYER = "multi_layer"  # Combined multiple methods


@dataclass
class SteganographicConfig:
    """Configuration for steganographic embedding."""

    method: SteganographicMethod = SteganographicMethod.MULTI_LAYER
    embedding_rate: float = 0.1  # Percentage of packets to use for embedding
    redundancy_factor: int = 3  # Number of redundant embeddings
    encryption_key: Optional[bytes] = None
    compression_enabled: bool = True
    noise_injection: bool = True
    adaptive_embedding: bool = True

    # Method-specific parameters
    lsb_bits_per_byte: int = 2
    timing_precision_ms: float = 1.0
    header_fields: List[str] = field(
        default_factory=lambda: ["user_agent", "accept", "cache_control"]
    )
    protocol_extensions: List[str] = field(
        default_factory=lambda: ["x-forwarded-for", "x-real-ip"]
    )


@dataclass
class SteganographicResult:
    """Result of steganographic embedding operation."""

    success: bool
    method_used: SteganographicMethod
    data_embedded: int  # bytes embedded
    packets_modified: int
    embedding_efficiency: float  # data_embedded / total_payload_size
    detection_risk: float  # 0.0 = undetectable, 1.0 = easily detectable
    metadata: Dict[str, Any] = field(default_factory=dict)


class SteganographicEngine(ABC):
    """
    Abstract base class for steganographic embedding engines.

    Each engine implements a specific steganographic technique
    for embedding data within legitimate traffic patterns.
    """

    def __init__(self, config: SteganographicConfig):
        self.config = config
        self._embedding_stats = {
            "total_embeddings": 0,
            "successful_embeddings": 0,
            "failed_embeddings": 0,
            "total_data_embedded": 0,
            "average_efficiency": 0.0,
        }

    @abstractmethod
    def can_embed_in_packet(self, packet_data: bytes, context: Dict[str, Any]) -> bool:
        """Check if data can be embedded in this packet."""
        pass

    @abstractmethod
    def embed_data(
        self, packet_data: bytes, data_to_embed: bytes, context: Dict[str, Any]
    ) -> Tuple[bytes, int]:
        """
        Embed data into packet.

        Returns:
            Tuple of (modified_packet, bytes_embedded)
        """
        pass

    @abstractmethod
    def extract_data(
        self, packet_data: bytes, context: Dict[str, Any]
    ) -> Optional[bytes]:
        """Extract embedded data from packet."""
        pass

    def update_stats(self, success: bool, bytes_embedded: int, efficiency: float):
        """Update embedding statistics."""
        self._embedding_stats["total_embeddings"] += 1
        if success:
            self._embedding_stats["successful_embeddings"] += 1
            self._embedding_stats["total_data_embedded"] += bytes_embedded
        else:
            self._embedding_stats["failed_embeddings"] += 1

        # Update average efficiency
        total_successful = self._embedding_stats["successful_embeddings"]
        if total_successful > 0:
            current_avg = self._embedding_stats["average_efficiency"]
            self._embedding_stats["average_efficiency"] = (
                current_avg * (total_successful - 1) + efficiency
            ) / total_successful

    def get_stats(self) -> Dict[str, Any]:
        """Get embedding statistics."""
        return self._embedding_stats.copy()


class LSBSteganographicEngine(SteganographicEngine):
    """
    Least Significant Bit steganographic engine.

    Embeds data in the least significant bits of payload bytes,
    making changes virtually undetectable to human inspection.
    """

    def __init__(self, config: SteganographicConfig):
        super().__init__(config)
        self.bits_per_byte = config.lsb_bits_per_byte

    def can_embed_in_packet(self, packet_data: bytes, context: Dict[str, Any]) -> bool:
        """Check if packet has enough payload for LSB embedding."""
        # Need at least 4 bytes of payload for meaningful embedding
        return len(packet_data) >= 4

    def embed_data(
        self, packet_data: bytes, data_to_embed: bytes, context: Dict[str, Any]
    ) -> Tuple[bytes, int]:
        """Embed data using LSB technique."""
        try:
            # Calculate how much data we can embed
            max_embeddable = (len(packet_data) * self.bits_per_byte) // 8
            data_to_embed = data_to_embed[:max_embeddable]

            if not data_to_embed:
                return packet_data, 0

            # Convert packet to bytearray for modification
            packet_array = bytearray(packet_data)

            # Embed data bit by bit
            data_bits = []
            for byte in data_to_embed:
                for i in range(8):
                    data_bits.append((byte >> i) & 1)

            # Embed bits into packet payload
            for i, bit in enumerate(data_bits):
                if i >= len(packet_array) * self.bits_per_byte:
                    break

                byte_index = i // self.bits_per_byte
                bit_position = i % self.bits_per_byte

                # Clear the target bits and set new bit
                packet_array[byte_index] &= ~(1 << bit_position)
                packet_array[byte_index] |= bit << bit_position

            bytes_embedded = len(data_to_embed)
            efficiency = bytes_embedded / len(packet_data) if packet_data else 0.0

            self.update_stats(True, bytes_embedded, efficiency)

            return bytes(packet_array), bytes_embedded

        except Exception as e:
            LOG.error(f"LSB embedding failed: {e}")
            self.update_stats(False, 0, 0.0)
            return packet_data, 0

    def extract_data(
        self, packet_data: bytes, context: Dict[str, Any]
    ) -> Optional[bytes]:
        """Extract data using LSB technique."""
        try:
            extracted_bits = []

            # Extract bits from packet
            for i in range(len(packet_data) * self.bits_per_byte):
                byte_index = i // self.bits_per_byte
                bit_position = i % self.bits_per_byte

                if byte_index >= len(packet_data):
                    break

                bit = (packet_data[byte_index] >> bit_position) & 1
                extracted_bits.append(bit)

            # Convert bits back to bytes
            extracted_data = bytearray()
            for i in range(0, len(extracted_bits), 8):
                if i + 7 >= len(extracted_bits):
                    break

                byte_val = 0
                for j in range(8):
                    byte_val |= extracted_bits[i + j] << j
                extracted_data.append(byte_val)

            return bytes(extracted_data) if extracted_data else None

        except Exception as e:
            LOG.error(f"LSB extraction failed: {e}")
            return None


class TimingChannelSteganographicEngine(SteganographicEngine):
    """
    Timing-based steganographic engine.

    Embeds data by manipulating inter-packet timing delays,
    making it extremely difficult to detect without precise timing analysis.
    """

    def __init__(self, config: SteganographicConfig):
        super().__init__(config)
        self.timing_precision = config.timing_precision_ms
        self._timing_cache = {}

    def can_embed_in_packet(self, packet_data: bytes, context: Dict[str, Any]) -> bool:
        """Check if timing channel can be used."""
        # Timing channel requires packet sequence context
        return "packet_sequence" in context and len(context["packet_sequence"]) > 0

    def embed_data(
        self, packet_data: bytes, data_to_embed: bytes, context: Dict[str, Any]
    ) -> Tuple[bytes, int]:
        """Embed data using timing channel."""
        try:
            # Calculate timing modifications
            timing_modifications = self._calculate_timing_modifications(data_to_embed)

            # Store timing data in context for later use
            if "timing_modifications" not in context:
                context["timing_modifications"] = []
            context["timing_modifications"].extend(timing_modifications)

            bytes_embedded = len(data_to_embed)
            efficiency = bytes_embedded / len(packet_data) if packet_data else 0.0

            self.update_stats(True, bytes_embedded, efficiency)

            return packet_data, bytes_embedded

        except Exception as e:
            LOG.error(f"Timing channel embedding failed: {e}")
            self.update_stats(False, 0, 0.0)
            return packet_data, 0

    def extract_data(
        self, packet_data: bytes, context: Dict[str, Any]
    ) -> Optional[bytes]:
        """Extract data from timing channel."""
        try:
            if "timing_modifications" not in context:
                return None

            timing_modifications = context["timing_modifications"]
            extracted_data = bytearray()

            # Convert timing modifications back to data
            for timing_mod in timing_modifications:
                byte_val = int(timing_mod / self.timing_precision) & 0xFF
                extracted_data.append(byte_val)

            return bytes(extracted_data) if extracted_data else None

        except Exception as e:
            LOG.error(f"Timing channel extraction failed: {e}")
            return None

    def _calculate_timing_modifications(self, data: bytes) -> List[float]:
        """Calculate timing modifications for data embedding."""
        modifications = []

        for byte in data:
            # Convert byte to timing modification
            base_timing = 10.0  # Base timing in ms
            modification = (byte / 255.0) * 50.0  # 0-50ms range
            modifications.append(base_timing + modification)

        return modifications


class HeaderModificationSteganographicEngine(SteganographicEngine):
    """
    Header modification steganographic engine.

    Embeds data by manipulating HTTP headers and other protocol headers
    in ways that appear legitimate but contain hidden information.
    """

    def __init__(self, config: SteganographicConfig):
        super().__init__(config)
        self.header_fields = config.header_fields

    def can_embed_in_packet(self, packet_data: bytes, context: Dict[str, Any]) -> bool:
        """Check if packet has modifiable headers."""
        # Check if packet contains HTTP headers
        return (
            b"HTTP/" in packet_data or b"GET " in packet_data or b"POST " in packet_data
        )

    def embed_data(
        self, packet_data: bytes, data_to_embed: bytes, context: Dict[str, Any]
    ) -> Tuple[bytes, int]:
        """Embed data using header modifications."""
        try:
            packet_str = packet_data.decode("utf-8", errors="ignore")
            lines = packet_str.split("\r\n")

            # Find header lines to modify
            header_indices = []
            for i, line in enumerate(lines):
                if ":" in line and any(
                    field in line.lower() for field in self.header_fields
                ):
                    header_indices.append(i)

            if not header_indices:
                return packet_data, 0

            # Embed data in headers
            data_index = 0
            for header_idx in header_indices:
                if data_index >= len(data_to_embed):
                    break

                line = lines[header_idx]
                if ":" in line:
                    key, value = line.split(":", 1)
                    # Embed data in header value
                    embedded_value = self._embed_in_header_value(
                        value.strip(), data_to_embed[data_index]
                    )
                    lines[header_idx] = f"{key}: {embedded_value}"
                    data_index += 1

            bytes_embedded = data_index
            modified_packet = "\r\n".join(lines).encode("utf-8")
            efficiency = bytes_embedded / len(packet_data) if packet_data else 0.0

            self.update_stats(True, bytes_embedded, efficiency)

            return modified_packet, bytes_embedded

        except Exception as e:
            LOG.error(f"Header modification embedding failed: {e}")
            self.update_stats(False, 0, 0.0)
            return packet_data, 0

    def extract_data(
        self, packet_data: bytes, context: Dict[str, Any]
    ) -> Optional[bytes]:
        """Extract data from header modifications."""
        try:
            packet_str = packet_data.decode("utf-8", errors="ignore")
            lines = packet_str.split("\r\n")

            extracted_data = bytearray()

            for line in lines:
                if ":" in line and any(
                    field in line.lower() for field in self.header_fields
                ):
                    key, value = line.split(":", 1)
                    # Extract data from header value
                    extracted_byte = self._extract_from_header_value(value.strip())
                    if extracted_byte is not None:
                        extracted_data.append(extracted_byte)

            return bytes(extracted_data) if extracted_data else None

        except Exception as e:
            LOG.error(f"Header modification extraction failed: {e}")
            return None

    def _embed_in_header_value(self, value: str, byte_val: int) -> str:
        """Embed byte in header value."""
        # Simple technique: append encoded data
        encoded = f"{byte_val:03d}"
        return f"{value}; steg={encoded}"

    def _extract_from_header_value(self, value: str) -> Optional[int]:
        """Extract byte from header value."""
        if "steg=" in value:
            try:
                steg_part = value.split("steg=")[1].split(";")[0]
                return int(steg_part)
            except (ValueError, IndexError):
                pass
        return None


class MultiLayerSteganographicEngine(SteganographicEngine):
    """
    Multi-layer steganographic engine.

    Combines multiple steganographic techniques for maximum
    embedding capacity and detection resistance.
    """

    def __init__(self, config: SteganographicConfig):
        super().__init__(config)
        self.engines = {
            SteganographicMethod.LSB_PAYLOAD: LSBSteganographicEngine(config),
            SteganographicMethod.TIMING_CHANNEL: TimingChannelSteganographicEngine(
                config
            ),
            SteganographicMethod.HEADER_MODIFICATION: HeaderModificationSteganographicEngine(
                config
            ),
        }
        self.embedding_order = [
            SteganographicMethod.LSB_PAYLOAD,
            SteganographicMethod.HEADER_MODIFICATION,
            SteganographicMethod.TIMING_CHANNEL,
        ]

    def can_embed_in_packet(self, packet_data: bytes, context: Dict[str, Any]) -> bool:
        """Check if any embedding method can be used."""
        return any(
            engine.can_embed_in_packet(packet_data, context)
            for engine in self.engines.values()
        )

    def embed_data(
        self, packet_data: bytes, data_to_embed: bytes, context: Dict[str, Any]
    ) -> Tuple[bytes, int]:
        """Embed data using multiple layers."""
        try:
            modified_packet = packet_data
            total_embedded = 0
            remaining_data = data_to_embed

            # Try each embedding method in order
            for method in self.embedding_order:
                if not remaining_data:
                    break

                engine = self.engines[method]
                if engine.can_embed_in_packet(modified_packet, context):
                    modified_packet, embedded = engine.embed_data(
                        modified_packet, remaining_data, context
                    )
                    total_embedded += embedded
                    remaining_data = remaining_data[embedded:]

            efficiency = total_embedded / len(packet_data) if packet_data else 0.0
            self.update_stats(True, total_embedded, efficiency)

            return modified_packet, total_embedded

        except Exception as e:
            LOG.error(f"Multi-layer embedding failed: {e}")
            self.update_stats(False, 0, 0.0)
            return packet_data, 0

    def extract_data(
        self, packet_data: bytes, context: Dict[str, Any]
    ) -> Optional[bytes]:
        """Extract data from multiple layers."""
        try:
            extracted_data = bytearray()

            # Extract from each layer in reverse order
            for method in reversed(self.embedding_order):
                engine = self.engines[method]
                layer_data = engine.extract_data(packet_data, context)
                if layer_data:
                    extracted_data.extend(layer_data)

            return bytes(extracted_data) if extracted_data else None

        except Exception as e:
            LOG.error(f"Multi-layer extraction failed: {e}")
            return None


class SteganographicManager:
    """
    Manager for steganographic operations.

    Coordinates multiple steganographic engines and provides
    high-level interface for embedding and extraction.
    """

    def __init__(self, config: Optional[SteganographicConfig] = None):
        self.config = config or SteganographicConfig()
        self.engines = {
            SteganographicMethod.LSB_PAYLOAD: LSBSteganographicEngine(self.config),
            SteganographicMethod.TIMING_CHANNEL: TimingChannelSteganographicEngine(
                self.config
            ),
            SteganographicMethod.HEADER_MODIFICATION: HeaderModificationSteganographicEngine(
                self.config
            ),
            SteganographicMethod.MULTI_LAYER: MultiLayerSteganographicEngine(
                self.config
            ),
        }
        self.active_engine = self.engines[self.config.method]

    def embed_in_packet_sequence(
        self,
        packet_sequence: List[Tuple[bytes, float]],
        data_to_embed: bytes,
        context: Dict[str, Any],
    ) -> Tuple[List[Tuple[bytes, float]], SteganographicResult]:
        """
        Embed data in a packet sequence.

        Args:
            packet_sequence: List of (packet_data, delay) tuples
            data_to_embed: Data to embed
            context: Execution context

        Returns:
            Tuple of (modified_sequence, result)
        """
        try:
            if not data_to_embed:
                return packet_sequence, SteganographicResult(
                    success=True,
                    method_used=self.config.method,
                    data_embedded=0,
                    packets_modified=0,
                    embedding_efficiency=0.0,
                    detection_risk=0.0,
                )

            modified_sequence = []
            total_embedded = 0
            packets_modified = 0
            remaining_data = data_to_embed

            # Add context for timing channel
            context["packet_sequence"] = packet_sequence

            for packet_data, delay in packet_sequence:
                if not remaining_data:
                    # No more data to embed, keep original packet
                    modified_sequence.append((packet_data, delay))
                    continue

                # Decide whether to embed in this packet
                if random.random() < self.config.embedding_rate:
                    modified_packet, embedded = self.active_engine.embed_data(
                        packet_data, remaining_data, context
                    )

                    if embedded > 0:
                        total_embedded += embedded
                        packets_modified += 1
                        remaining_data = remaining_data[embedded:]
                        modified_sequence.append((modified_packet, delay))
                    else:
                        modified_sequence.append((packet_data, delay))
                else:
                    modified_sequence.append((packet_data, delay))

            # Calculate result metrics
            total_payload_size = sum(len(packet) for packet, _ in packet_sequence)
            efficiency = (
                total_embedded / total_payload_size if total_payload_size > 0 else 0.0
            )

            # Estimate detection risk based on embedding method and efficiency
            detection_risk = self._estimate_detection_risk(efficiency, packets_modified)

            result = SteganographicResult(
                success=total_embedded > 0,
                method_used=self.config.method,
                data_embedded=total_embedded,
                packets_modified=packets_modified,
                embedding_efficiency=efficiency,
                detection_risk=detection_risk,
                metadata={
                    "original_sequence_length": len(packet_sequence),
                    "data_remaining": len(remaining_data),
                    "embedding_rate_used": self.config.embedding_rate,
                },
            )

            return modified_sequence, result

        except Exception as e:
            LOG.error(f"Steganographic embedding failed: {e}")
            return packet_sequence, SteganographicResult(
                success=False,
                method_used=self.config.method,
                data_embedded=0,
                packets_modified=0,
                embedding_efficiency=0.0,
                detection_risk=1.0,
                metadata={"error": str(e)},
            )

    def extract_from_packet_sequence(
        self, packet_sequence: List[Tuple[bytes, float]], context: Dict[str, Any]
    ) -> Optional[bytes]:
        """Extract embedded data from packet sequence."""
        try:
            context["packet_sequence"] = packet_sequence
            extracted_data = bytearray()

            for packet_data, _ in packet_sequence:
                data = self.active_engine.extract_data(packet_data, context)
                if data:
                    extracted_data.extend(data)

            return bytes(extracted_data) if extracted_data else None

        except Exception as e:
            LOG.error(f"Steganographic extraction failed: {e}")
            return None

    def _estimate_detection_risk(
        self, efficiency: float, packets_modified: int
    ) -> float:
        """Estimate the risk of steganographic detection."""
        # Base risk on embedding method
        base_risk = {
            SteganographicMethod.LSB_PAYLOAD: 0.1,
            SteganographicMethod.TIMING_CHANNEL: 0.05,
            SteganographicMethod.HEADER_MODIFICATION: 0.2,
            SteganographicMethod.MULTI_LAYER: 0.15,
        }.get(self.config.method, 0.2)

        # Adjust based on efficiency (higher efficiency = higher risk)
        efficiency_risk = min(efficiency * 2.0, 0.5)

        # Adjust based on number of modified packets
        packet_risk = min(packets_modified / 100.0, 0.3)

        total_risk = base_risk + efficiency_risk + packet_risk
        return min(total_risk, 1.0)

    def get_engine_stats(self) -> Dict[str, Any]:
        """Get statistics from all engines."""
        stats = {}
        for method, engine in self.engines.items():
            stats[method.value] = engine.get_stats()
        return stats
