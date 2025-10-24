"""
Configuration data models for DPI strategy components.

This module defines all configuration classes used by the DPI strategy system.
"""

from dataclasses import dataclass, field
from typing import List, Union, Optional, Dict, Any
from enum import Enum


class DesyncMode(Enum):
    """Enumeration of supported desync modes."""

    SPLIT = "split"
    FAKE = "fake"
    DISORDER = "disorder"
    NONE = "none"


class FoolingMethod(Enum):
    """Enumeration of supported fooling methods."""

    BADSUM = "badsum"
    BADSEQ = "badseq"
    MD5SIG = "md5sig"
    HOPBYHOP = "hopbyhop"
    FAKE_PACKETS = "fake_packets"
    DISORDER = "disorder"


@dataclass
class DPIConfig:
    """
    Main configuration class for DPI strategy system.

    This class contains all configuration parameters needed for
    DPI bypass strategy application.
    """

    desync_mode: str = "split"
    split_positions: List[Union[int, str]] = field(default_factory=list)
    fooling_methods: List[str] = field(default_factory=list)
    enabled: bool = True
    ttl: Optional[int] = None
    repeats: int = 1
    split_count: Optional[int] = None
    split_seqovl: Optional[int] = None

    def __post_init__(self):
        """Validate configuration after initialization."""
        self._validate_desync_mode()
        self._validate_split_positions()
        self._validate_fooling_methods()

    def _validate_desync_mode(self):
        """Validate desync mode configuration."""
        valid_modes = [mode.value for mode in DesyncMode]
        if self.desync_mode not in valid_modes:
            raise ValueError(
                f"Invalid desync_mode: {self.desync_mode}. "
                f"Valid modes: {valid_modes}"
            )

    def _validate_split_positions(self):
        """Validate split positions configuration."""
        if not isinstance(self.split_positions, list):
            raise ValueError("split_positions must be a list")

        for pos in self.split_positions:
            if isinstance(pos, int):
                if pos <= 0:
                    raise ValueError(f"Numeric split position must be positive: {pos}")
            elif isinstance(pos, str):
                if pos.lower() not in ["sni"]:
                    raise ValueError(
                        f"Invalid string split position: {pos}. "
                        f"Valid string positions: ['sni']"
                    )
            else:
                raise ValueError(f"Split position must be int or str: {pos}")

    def _validate_fooling_methods(self):
        """Validate fooling methods configuration."""
        if not isinstance(self.fooling_methods, list):
            raise ValueError("fooling_methods must be a list")

        valid_methods = [method.value for method in FoolingMethod]
        for method in self.fooling_methods:
            if method not in valid_methods:
                raise ValueError(
                    f"Invalid fooling method: {method}. "
                    f"Valid methods: {valid_methods}"
                )

    def has_numeric_positions(self) -> bool:
        """Check if configuration has numeric split positions."""
        return any(isinstance(pos, int) for pos in self.split_positions)

    def has_sni_position(self) -> bool:
        """Check if configuration includes SNI split position."""
        return any(
            isinstance(pos, str) and pos.lower() == "sni"
            for pos in self.split_positions
        )

    def get_numeric_positions(self) -> List[int]:
        """Get all numeric split positions."""
        return [pos for pos in self.split_positions if isinstance(pos, int)]

    def has_badsum(self) -> bool:
        """Check if badsum fooling is enabled."""
        return "badsum" in self.fooling_methods

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            "desync_mode": self.desync_mode,
            "split_positions": self.split_positions,
            "fooling_methods": self.fooling_methods,
            "enabled": self.enabled,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DPIConfig":
        """Create configuration from dictionary."""
        return cls(
            desync_mode=data.get("desync_mode", "split"),
            split_positions=data.get("split_positions", []),
            fooling_methods=data.get("fooling_methods", []),
            enabled=data.get("enabled", True),
        )


@dataclass
class SplitConfig:
    """
    Configuration for packet splitting operations.

    This class contains parameters specific to packet splitting,
    including numeric positions and SNI handling.
    """

    numeric_positions: List[int] = field(default_factory=list)
    use_sni: bool = False
    priority_order: List[str] = field(default_factory=lambda: ["sni", "numeric"])
    max_positions_per_packet: int = 3
    min_packet_size: int = 20

    def __post_init__(self):
        """Validate configuration after initialization."""
        self._validate_numeric_positions()
        self._validate_priority_order()
        self._validate_limits()

    def _validate_numeric_positions(self):
        """Validate numeric positions."""
        if not isinstance(self.numeric_positions, list):
            raise ValueError("numeric_positions must be a list")

        for pos in self.numeric_positions:
            if not isinstance(pos, int) or pos <= 0:
                raise ValueError(f"Numeric position must be positive integer: {pos}")

        # Remove duplicates and sort
        self.numeric_positions = sorted(list(set(self.numeric_positions)))

    def _validate_priority_order(self):
        """Validate priority order configuration."""
        if not isinstance(self.priority_order, list):
            raise ValueError("priority_order must be a list")

        valid_priorities = ["sni", "numeric"]
        for priority in self.priority_order:
            if priority not in valid_priorities:
                raise ValueError(
                    f"Invalid priority: {priority}. "
                    f"Valid priorities: {valid_priorities}"
                )

    def _validate_limits(self):
        """Validate limit configurations."""
        if self.max_positions_per_packet <= 0:
            raise ValueError("max_positions_per_packet must be positive")

        if self.min_packet_size <= 0:
            raise ValueError("min_packet_size must be positive")

    def get_effective_positions(
        self, packet_size: int, sni_position: Optional[int] = None
    ) -> List[int]:
        """
        Get effective split positions for a packet based on priority and limits.

        Args:
            packet_size: Size of the packet to split
            sni_position: Position of SNI extension if found

        Returns:
            List of positions to use for splitting
        """
        positions = []

        # Apply priority order
        for priority in self.priority_order:
            if priority == "sni" and self.use_sni and sni_position is not None:
                if sni_position < packet_size - 1:  # Ensure valid split
                    positions.append(sni_position)

            elif priority == "numeric":
                for pos in self.numeric_positions:
                    if pos < packet_size - 1:  # Ensure valid split
                        positions.append(pos)

            # Respect max positions limit
            if len(positions) >= self.max_positions_per_packet:
                break

        # Remove duplicates and sort
        return sorted(list(set(positions)))

    def is_position_valid(self, packet_size: int, position: int) -> bool:
        """
        Check if a position is valid for splitting the packet.

        Args:
            packet_size: Size of the packet
            position: Position to validate

        Returns:
            True if position is valid
        """
        if packet_size < self.min_packet_size:
            return False

        if position <= 0 or position >= packet_size - 1:
            return False

        return True


@dataclass
class FoolingConfig:
    """
    Configuration for packet fooling operations.

    This class contains parameters for various fooling methods
    like badsum, fake packets, and disorder.
    """

    badsum: bool = False
    fake_packets: bool = False
    disorder: bool = False
    badsum_probability: float = 1.0
    fake_packet_count: int = 1
    disorder_window: int = 3

    def __post_init__(self):
        """Validate configuration after initialization."""
        self._validate_probabilities()
        self._validate_counts()

    def _validate_probabilities(self):
        """Validate probability values."""
        if not 0.0 <= self.badsum_probability <= 1.0:
            raise ValueError(
                f"badsum_probability must be between 0.0 and 1.0: {self.badsum_probability}"
            )

    def _validate_counts(self):
        """Validate count values."""
        if self.fake_packet_count < 0:
            raise ValueError(
                f"fake_packet_count must be non-negative: {self.fake_packet_count}"
            )

        if self.disorder_window < 1:
            raise ValueError(
                f"disorder_window must be positive: {self.disorder_window}"
            )

    def should_apply_badsum(self) -> bool:
        """
        Determine if badsum should be applied based on configuration.

        Returns:
            True if badsum should be applied
        """
        if not self.badsum:
            return False

        # For now, always apply if enabled
        # In the future, could use probability for random application
        return True

    def get_active_methods(self) -> List[str]:
        """
        Get list of active fooling methods.

        Returns:
            List of active method names
        """
        methods = []

        if self.badsum:
            methods.append("badsum")

        if self.fake_packets:
            methods.append("fake_packets")

        if self.disorder:
            methods.append("disorder")

        return methods


@dataclass
class PacketSplitResult:
    """
    Result of packet splitting operation.

    This class contains information about how a packet was split
    and what strategies were applied.
    """

    original_packet: bytes
    split_parts: List[bytes]
    split_positions: List[int]
    applied_strategies: List[str]
    sni_position: Optional[int] = None
    sni_value: Optional[str] = None
    processing_time_ms: float = 0.0

    def __post_init__(self):
        """Validate result after initialization."""
        self._validate_consistency()

    def _validate_consistency(self):
        """Validate consistency of split result."""
        if not self.original_packet:
            raise ValueError("original_packet cannot be empty")

        if not self.split_parts:
            raise ValueError("split_parts cannot be empty")

        # Verify that split parts reconstruct original packet
        reconstructed = b"".join(self.split_parts)
        if reconstructed != self.original_packet:
            raise ValueError("Split parts do not reconstruct original packet")

        # Verify split positions match parts
        if len(self.split_positions) != len(self.split_parts) - 1:
            raise ValueError(
                "Number of split positions should be one less than number of parts"
            )

    def get_part_sizes(self) -> List[int]:
        """Get sizes of all split parts."""
        return [len(part) for part in self.split_parts]

    def get_total_size(self) -> int:
        """Get total size of all parts."""
        return sum(self.get_part_sizes())

    def has_sni_split(self) -> bool:
        """Check if SNI-based splitting was used."""
        return self.sni_position is not None

    def get_strategy_summary(self) -> str:
        """Get human-readable summary of applied strategies."""
        if not self.applied_strategies:
            return "No strategies applied"

        summary_parts = []

        if "split" in self.applied_strategies:
            positions_str = ",".join(map(str, self.split_positions))
            summary_parts.append(f"split at positions {positions_str}")

        if "badsum" in self.applied_strategies:
            summary_parts.append("badsum applied")

        if self.has_sni_split():
            summary_parts.append(f"SNI split at position {self.sni_position}")

        return "; ".join(summary_parts)


@dataclass
class TLSPacketInfo:
    """
    Information about a TLS packet.

    This class contains parsed information from TLS packets,
    particularly Client Hello packets.
    """

    is_client_hello: bool = False
    sni_position: Optional[int] = None
    sni_value: Optional[str] = None
    packet_size: int = 0
    extensions: Dict[int, int] = field(default_factory=dict)
    tls_version: Optional[str] = None
    cipher_suites_count: int = 0

    def has_sni(self) -> bool:
        """Check if packet contains SNI extension."""
        return self.sni_position is not None

    def get_sni_extension_info(self) -> Optional[Dict[str, Any]]:
        """Get detailed SNI extension information."""
        if not self.has_sni():
            return None

        return {
            "position": self.sni_position,
            "value": self.sni_value,
            "extension_type": 0x0000,  # SNI extension type
        }

    def get_extensions_summary(self) -> Dict[str, Any]:
        """Get summary of all TLS extensions."""
        return {
            "count": len(self.extensions),
            "types": list(self.extensions.keys()),
            "has_sni": self.has_sni(),
        }


@dataclass
class TCPPacketInfo:
    """
    Information about a TCP packet.

    This class contains parsed TCP header information.
    """

    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    seq_num: int = 0
    ack_num: int = 0
    flags: int = 0
    window_size: int = 0
    checksum: int = 0
    payload: bytes = b""

    def get_flag_names(self) -> List[str]:
        """Get human-readable TCP flag names."""
        flag_names = []

        if self.flags & 0x01:  # FIN
            flag_names.append("FIN")
        if self.flags & 0x02:  # SYN
            flag_names.append("SYN")
        if self.flags & 0x04:  # RST
            flag_names.append("RST")
        if self.flags & 0x08:  # PSH
            flag_names.append("PSH")
        if self.flags & 0x10:  # ACK
            flag_names.append("ACK")
        if self.flags & 0x20:  # URG
            flag_names.append("URG")

        return flag_names

    def is_https_traffic(self) -> bool:
        """Check if this is HTTPS traffic."""
        return self.src_port == 443 or self.dst_port == 443

    def get_connection_tuple(self) -> tuple:
        """Get connection 4-tuple for identification."""
        return (self.src_ip, self.src_port, self.dst_ip, self.dst_port)

    def has_payload(self) -> bool:
        """Check if packet has payload data."""
        return len(self.payload) > 0
