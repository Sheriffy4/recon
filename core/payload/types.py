"""
Payload data types and models.

This module defines the core data structures for payload management:
- PayloadType: Enum for different payload protocols (TLS, HTTP, QUIC)
- PayloadInfo: Dataclass containing payload metadata

Requirements: 1.1, 5.1, 5.2, 5.3
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class PayloadType(Enum):
    """
    Enumeration of supported payload types.

    Each type corresponds to a specific protocol that can be used
    for fake payload generation in DPI bypass strategies.

    Requirements: 5.1, 5.2, 5.3
    """

    TLS = "tls"  # TLS ClientHello payloads
    HTTP = "http"  # HTTP request payloads
    QUIC = "quic"  # QUIC Initial payloads
    UNKNOWN = "unknown"  # Unknown or unvalidated payloads

    @classmethod
    def from_string(cls, value: str) -> "PayloadType":
        """
        Convert a string to PayloadType enum.

        Args:
            value: String representation of payload type

        Returns:
            Corresponding PayloadType enum value
        """
        value_lower = value.lower().strip()
        for member in cls:
            if member.value == value_lower:
                return member
        return cls.UNKNOWN


@dataclass
class PayloadInfo:
    """
    Metadata about a payload.

    Contains all information needed to identify, locate, and validate
    a payload file or data.

    Attributes:
        payload_type: Type of payload (TLS, HTTP, QUIC, UNKNOWN)
        source: Origin of payload ("bundled", "captured", "hex", "inline")
        domain: Domain for which payload was captured (optional)
        file_path: Path to payload file on disk (optional)
        size: Size of payload in bytes
        checksum: SHA256 checksum of payload data

    Requirements: 1.1, 5.1, 5.2, 5.3
    """

    payload_type: PayloadType
    source: str
    size: int
    checksum: str
    domain: Optional[str] = None
    file_path: Optional[Path] = None

    def __post_init__(self):
        """Validate and normalize fields after initialization."""
        # Convert string path to Path object if needed
        if self.file_path is not None and isinstance(self.file_path, str):
            self.file_path = Path(self.file_path)

        # Validate source
        valid_sources = {"bundled", "captured", "hex", "inline"}
        if self.source not in valid_sources:
            raise ValueError(
                f"Invalid source '{self.source}'. " f"Must be one of: {', '.join(valid_sources)}"
            )

        # Validate size
        if self.size < 0:
            raise ValueError(f"Size must be non-negative, got {self.size}")

    @property
    def is_file_based(self) -> bool:
        """Check if payload is stored in a file."""
        return self.file_path is not None

    @property
    def is_domain_specific(self) -> bool:
        """Check if payload is associated with a specific domain."""
        return self.domain is not None

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "payload_type": self.payload_type.value,
            "source": self.source,
            "domain": self.domain,
            "file_path": str(self.file_path) if self.file_path else None,
            "size": self.size,
            "checksum": self.checksum,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PayloadInfo":
        """Create PayloadInfo from dictionary."""
        return cls(
            payload_type=PayloadType.from_string(data.get("payload_type", "unknown")),
            source=data.get("source", "inline"),
            domain=data.get("domain"),
            file_path=Path(data["file_path"]) if data.get("file_path") else None,
            size=data.get("size", 0),
            checksum=data.get("checksum", ""),
        )
