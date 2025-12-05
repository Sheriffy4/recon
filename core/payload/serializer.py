"""
Payload serialization module.

This module provides serialization and deserialization for payloads:
- Hex string conversion (to_hex, from_hex)
- Payload parameter parsing (file paths, hex strings, placeholders)
- Zapret-compatible format export

Requirements: 4.1, 4.2, 4.3, 4.5
"""

import re
from pathlib import Path
from typing import Union

from .types import PayloadType, PayloadInfo


class PayloadSerializerError(Exception):
    """Base exception for payload serialization errors."""
    pass


class InvalidHexError(PayloadSerializerError):
    """Raised when hex string is malformed."""
    pass


class InvalidPlaceholderError(PayloadSerializerError):
    """Raised when placeholder is unknown."""
    pass


class PayloadSerializer:
    """
    Serializer for payload data.
    
    Handles conversion between binary payload data and various
    string representations (hex strings, file paths, placeholders).
    
    Requirements: 4.1, 4.2, 4.3, 4.5
    """
    
    # Known placeholders for payload types
    PLACEHOLDERS = {
        "PAYLOADTLS": PayloadType.TLS,
        "PAYLOADHTTP": PayloadType.HTTP,
        "PAYLOADQUIC": PayloadType.QUIC,
    }
    
    # Hex string pattern: 0x followed by hex digits
    HEX_PATTERN = re.compile(r"^0x([0-9a-fA-F]+)$")
    
    def to_hex(self, data: bytes) -> str:
        """
        Convert binary data to hex string format.
        
        Args:
            data: Raw payload bytes
            
        Returns:
            Hex string in "0x..." format
            
        Example:
            >>> serializer.to_hex(b"\\x16\\x03\\x01")
            '0x160301'
            
        Requirements: 4.2
        """
        if not isinstance(data, bytes):
            raise TypeError(f"Expected bytes, got {type(data).__name__}")
        
        return "0x" + data.hex()
    
    def from_hex(self, hex_str: str) -> bytes:
        """
        Parse hex string into binary data.
        
        Args:
            hex_str: Hex string in "0x..." format or plain hex
            
        Returns:
            Raw payload bytes
            
        Raises:
            InvalidHexError: If hex string is malformed
            
        Example:
            >>> serializer.from_hex("0x160301")
            b'\\x16\\x03\\x01'
            
        Requirements: 4.2
        """
        if not isinstance(hex_str, str):
            raise TypeError(f"Expected str, got {type(hex_str).__name__}")
        
        hex_str = hex_str.strip()
        
        # Handle 0x prefix
        if hex_str.startswith("0x") or hex_str.startswith("0X"):
            hex_str = hex_str[2:]
        
        # Validate hex characters
        if not hex_str:
            raise InvalidHexError("Empty hex string")
        
        if not all(c in "0123456789abcdefABCDEF" for c in hex_str):
            raise InvalidHexError(
                f"Invalid hex characters in string: {hex_str[:50]}..."
                if len(hex_str) > 50 else f"Invalid hex characters in string: {hex_str}"
            )
        
        # Hex string must have even length
        if len(hex_str) % 2 != 0:
            raise InvalidHexError(
                f"Hex string has odd length ({len(hex_str)}), must be even"
            )
        
        try:
            return bytes.fromhex(hex_str)
        except ValueError as e:
            raise InvalidHexError(f"Failed to decode hex string: {e}")
    
    def is_hex_string(self, value: str) -> bool:
        """
        Check if value is a valid hex string.
        
        Args:
            value: String to check
            
        Returns:
            True if value is a valid hex string (0x... format)
        """
        if not isinstance(value, str):
            return False
        
        value = value.strip()
        if not value.startswith(("0x", "0X")):
            return False
        
        hex_part = value[2:]
        if not hex_part:
            return False
        
        return all(c in "0123456789abcdefABCDEF" for c in hex_part) and len(hex_part) % 2 == 0
    
    def is_placeholder(self, value: str) -> bool:
        """
        Check if value is a known placeholder.
        
        Args:
            value: String to check
            
        Returns:
            True if value is a known placeholder
        """
        return value.upper() in self.PLACEHOLDERS
    
    def is_file_path(self, value: str) -> bool:
        """
        Check if value looks like a file path.
        
        Args:
            value: String to check
            
        Returns:
            True if value appears to be a file path
        """
        if not isinstance(value, str):
            return False
        
        value = value.strip()
        
        # Not a hex string or placeholder
        if self.is_hex_string(value) or self.is_placeholder(value):
            return False
        
        # Check for path-like patterns
        # Contains path separators or file extension
        if "/" in value or "\\" in value:
            return True
        
        # Has .bin extension (common for payload files)
        if value.endswith(".bin"):
            return True
        
        # Check if it's an existing file
        try:
            return Path(value).exists()
        except (OSError, ValueError):
            return False
    
    def parse_payload_param(self, value: str) -> Union[bytes, Path, str]:
        """
        Parse a payload parameter value.
        
        Handles multiple formats:
        - File path: /path/to/file.bin -> Path object
        - Hex string: 0x1603030200... -> bytes
        - Placeholder: PAYLOADTLS -> str (placeholder name)
        - Special value: ! (for fake-tls-mod) -> str
        
        Args:
            value: Parameter value string
            
        Returns:
            - bytes: If value is a hex string
            - Path: If value is a file path
            - str: If value is a placeholder or special value
            
        Raises:
            InvalidHexError: If hex string is malformed
            InvalidPlaceholderError: If placeholder is unknown
            FileNotFoundError: If file path doesn't exist
            
        Requirements: 4.1, 4.2, 4.3
        """
        if not isinstance(value, str):
            raise TypeError(f"Expected str, got {type(value).__name__}")
        
        value = value.strip()
        
        if not value:
            raise ValueError("Empty payload parameter")
        
        # Special value for fake-tls-mod
        if value == "!":
            return value
        
        # Check for hex string (0x prefix)
        if value.startswith(("0x", "0X")):
            return self.from_hex(value)
        
        # Check for placeholder
        value_upper = value.upper()
        if value_upper in self.PLACEHOLDERS:
            return value_upper
        
        # Treat as file path
        path = Path(value)
        
        # Return path (caller should check existence if needed)
        return path
    
    def get_placeholder_type(self, placeholder: str) -> PayloadType:
        """
        Get the PayloadType for a placeholder.
        
        Args:
            placeholder: Placeholder name (e.g., "PAYLOADTLS")
            
        Returns:
            Corresponding PayloadType
            
        Raises:
            InvalidPlaceholderError: If placeholder is unknown
        """
        placeholder_upper = placeholder.upper()
        if placeholder_upper not in self.PLACEHOLDERS:
            valid = ", ".join(self.PLACEHOLDERS.keys())
            raise InvalidPlaceholderError(
                f"Unknown placeholder '{placeholder}'. Valid placeholders: {valid}"
            )
        return self.PLACEHOLDERS[placeholder_upper]
    
    def to_file_reference(self, payload_info: PayloadInfo) -> str:
        """
        Get file path string for zapret format.
        
        Args:
            payload_info: PayloadInfo with file_path set
            
        Returns:
            File path as string
            
        Raises:
            ValueError: If payload_info has no file_path
        """
        if payload_info.file_path is None:
            raise ValueError("PayloadInfo has no file_path")
        return str(payload_info.file_path)
    
    def format_for_zapret(
        self,
        payload: bytes,
        payload_type: PayloadType,
        use_file: bool = True,
        file_path: str = None
    ) -> str:
        """
        Format payload for zapret command line.
        
        Args:
            payload: Payload bytes
            payload_type: Type of payload (determines parameter name)
            use_file: If True, return file path; if False, return hex string
            file_path: File path to use (required if use_file=True)
            
        Returns:
            Zapret parameter string (e.g., "--dpi-desync-fake-tls=0x...")
            
        Requirements: 4.5
        """
        # Map payload type to zapret parameter
        param_map = {
            PayloadType.TLS: "--dpi-desync-fake-tls",
            PayloadType.HTTP: "--dpi-desync-fake-http",
            PayloadType.QUIC: "--dpi-desync-fake-quic",
            PayloadType.UNKNOWN: "--dpi-desync-fake-tls",  # Default to TLS
        }
        
        param_name = param_map.get(payload_type, "--dpi-desync-fake-tls")
        
        if use_file:
            if file_path is None:
                raise ValueError("file_path required when use_file=True")
            return f"{param_name}={file_path}"
        else:
            hex_str = self.to_hex(payload)
            return f"{param_name}={hex_str}"
