"""
Interfaces for DPI strategy components.

This module defines the core interfaces that all DPI strategy components must implement.
"""

from abc import ABC, abstractmethod
from typing import List, Optional


class IDPIStrategy(ABC):
    """Interface for DPI strategy implementations."""

    @abstractmethod
    def apply_strategy(self, packet: bytes) -> List[bytes]:
        """
        Apply the DPI strategy to a packet.

        Args:
            packet: The original packet bytes

        Returns:
            List of modified packet bytes (may be split into multiple packets)

        Raises:
            DPIStrategyError: If strategy application fails
        """
        pass

    @abstractmethod
    def should_apply(self, packet: bytes) -> bool:
        """
        Determine if this strategy should be applied to the given packet.

        Args:
            packet: The packet bytes to evaluate

        Returns:
            True if strategy should be applied, False otherwise
        """
        pass

    @abstractmethod
    def get_strategy_name(self) -> str:
        """
        Get the name of this strategy.

        Returns:
            String identifier for this strategy
        """
        pass


class IPacketProcessor(ABC):
    """Interface for packet processing components."""

    @abstractmethod
    def process_packet(self, packet: bytes) -> bytes:
        """
        Process a single packet.

        Args:
            packet: The packet bytes to process

        Returns:
            The processed packet bytes

        Raises:
            PacketProcessingError: If packet processing fails
        """
        pass

    @abstractmethod
    def can_process(self, packet: bytes) -> bool:
        """
        Check if this processor can handle the given packet.

        Args:
            packet: The packet bytes to check

        Returns:
            True if processor can handle this packet, False otherwise
        """
        pass


class IPositionResolver(ABC):
    """Interface for resolving split positions in packets."""

    @abstractmethod
    def resolve_positions(self, packet: bytes, config: "SplitConfig") -> List[int]:
        """
        Resolve all split positions for a packet.

        Args:
            packet: The packet bytes to analyze
            config: Split configuration

        Returns:
            List of byte positions where packet should be split
        """
        pass

    @abstractmethod
    def validate_position(self, packet: bytes, position: int) -> bool:
        """
        Validate if a position is valid for splitting the packet.

        Args:
            packet: The packet bytes
            position: The position to validate

        Returns:
            True if position is valid, False otherwise
        """
        pass


class ISNIDetector(ABC):
    """Interface for SNI detection in TLS packets."""

    @abstractmethod
    def find_sni_position(self, tls_packet: bytes) -> Optional[int]:
        """
        Find the position of SNI extension in a TLS Client Hello packet.

        Args:
            tls_packet: The TLS packet bytes

        Returns:
            Position of SNI extension or None if not found
        """
        pass

    @abstractmethod
    def is_client_hello(self, packet: bytes) -> bool:
        """
        Check if packet is a TLS Client Hello.

        Args:
            packet: The packet bytes to check

        Returns:
            True if packet is TLS Client Hello, False otherwise
        """
        pass


class IPacketModifier(ABC):
    """Interface for packet modification operations."""

    @abstractmethod
    def split_packet(self, packet: bytes, positions: List[int]) -> List[bytes]:
        """
        Split a packet at specified positions.

        Args:
            packet: The packet bytes to split
            positions: List of positions where to split

        Returns:
            List of packet parts
        """
        pass

    @abstractmethod
    def create_tcp_segments(
        self, original_packet: bytes, parts: List[bytes]
    ) -> List[bytes]:
        """
        Create TCP segments from packet parts.

        Args:
            original_packet: The original packet for header information
            parts: List of packet parts to convert to TCP segments

        Returns:
            List of complete TCP packets
        """
        pass


class IChecksumFooler(ABC):
    """Interface for checksum manipulation operations."""

    @abstractmethod
    def apply_badsum(self, packet: bytes) -> bytes:
        """
        Apply bad checksum to a TCP packet.

        Args:
            packet: The TCP packet bytes

        Returns:
            Packet with modified checksum
        """
        pass

    @abstractmethod
    def should_apply_badsum(self, packet: bytes, config: "FoolingConfig") -> bool:
        """
        Determine if badsum should be applied to this packet.

        Args:
            packet: The packet bytes to check
            config: Fooling configuration

        Returns:
            True if badsum should be applied, False otherwise
        """
        pass
