"""
Payload validation module.

This module provides validation for different payload types:
- TLS ClientHello validation (0x16 header, 0x03 version, 0x01 handshake type)
- HTTP request validation
- QUIC Initial packet validation

Requirements: 1.2, 2.5
"""

from dataclasses import dataclass, field
from typing import List

from .types import PayloadType


@dataclass
class ValidationResult:
    """
    Result of payload validation.
    
    Attributes:
        valid: Whether the payload passed validation
        payload_type: Detected or validated payload type
        errors: List of validation errors
        warnings: List of validation warnings
    """
    valid: bool
    payload_type: PayloadType
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class PayloadValidator:
    """
    Validator for payload structure.
    
    Validates payloads against protocol specifications to ensure
    they are well-formed and can be used effectively for DPI bypass.
    
    Requirements: 1.2, 2.5
    """
    
    # TLS Constants
    TLS_CONTENT_TYPE_HANDSHAKE = 0x16
    TLS_VERSION_10 = (0x03, 0x01)
    TLS_VERSION_11 = (0x03, 0x02)
    TLS_VERSION_12 = (0x03, 0x03)
    TLS_HANDSHAKE_CLIENT_HELLO = 0x01
    
    # Minimum sizes
    MIN_TLS_RECORD_SIZE = 5  # Content type (1) + Version (2) + Length (2)
    MIN_TLS_CLIENTHELLO_SIZE = 43  # Minimum valid ClientHello
    
    # HTTP Constants
    HTTP_METHODS = (b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH")
    
    # QUIC Constants
    QUIC_LONG_HEADER_BIT = 0x80
    QUIC_FIXED_BIT = 0x40
    
    def validate(self, data: bytes) -> ValidationResult:
        """
        Validate payload and auto-detect its type.
        
        Args:
            data: Raw payload bytes
            
        Returns:
            ValidationResult with detected type and any errors/warnings
        """
        if not data:
            return ValidationResult(
                valid=False,
                payload_type=PayloadType.UNKNOWN,
                errors=["Empty payload"]
            )
        
        # Try TLS first (most common for DPI bypass)
        tls_result = self.validate_tls_clienthello(data)
        if tls_result.valid:
            return tls_result
        
        # Try HTTP
        http_result = self.validate_http_request(data)
        if http_result.valid:
            return http_result
        
        # Try QUIC
        quic_result = self.validate_quic_initial(data)
        if quic_result.valid:
            return quic_result
        
        # Unknown type - return with warnings from all attempts
        return ValidationResult(
            valid=False,
            payload_type=PayloadType.UNKNOWN,
            errors=["Could not identify payload type"],
            warnings=[
                f"TLS validation: {', '.join(tls_result.errors)}",
                f"HTTP validation: {', '.join(http_result.errors)}",
                f"QUIC validation: {', '.join(quic_result.errors)}",
            ]
        )
    
    def validate_tls_clienthello(self, data: bytes) -> ValidationResult:
        """
        Validate TLS ClientHello structure.
        
        Checks:
        - TLS record header (content type = 0x16)
        - TLS version (0x03 0x01 or 0x03 0x03)
        - Handshake type (0x01 for ClientHello)
        - Minimum length requirements
        
        Args:
            data: Raw payload bytes
            
        Returns:
            ValidationResult indicating if payload is valid TLS ClientHello
            
        Requirements: 1.2, 2.5
        """
        errors: List[str] = []
        warnings: List[str] = []
        
        # Check minimum size for TLS record header
        if len(data) < self.MIN_TLS_RECORD_SIZE:
            errors.append(
                f"Payload too short for TLS record: {len(data)} bytes "
                f"(minimum {self.MIN_TLS_RECORD_SIZE})"
            )
            return ValidationResult(
                valid=False,
                payload_type=PayloadType.TLS,
                errors=errors
            )
        
        # Check content type (byte 0) - must be 0x16 (Handshake)
        content_type = data[0]
        if content_type != self.TLS_CONTENT_TYPE_HANDSHAKE:
            errors.append(
                f"Invalid TLS content type: 0x{content_type:02x} "
                f"(expected 0x{self.TLS_CONTENT_TYPE_HANDSHAKE:02x})"
            )
            return ValidationResult(
                valid=False,
                payload_type=PayloadType.TLS,
                errors=errors
            )
        
        # Check version (bytes 1-2) - must start with 0x03
        version_major = data[1]
        version_minor = data[2]
        if version_major != 0x03:
            errors.append(
                f"Invalid TLS version major byte: 0x{version_major:02x} "
                f"(expected 0x03)"
            )
            return ValidationResult(
                valid=False,
                payload_type=PayloadType.TLS,
                errors=errors
            )
        
        # Warn about unusual minor versions
        if version_minor not in (0x01, 0x02, 0x03):
            warnings.append(
                f"Unusual TLS version minor byte: 0x{version_minor:02x}"
            )
        
        # Get record length (bytes 3-4)
        record_length = (data[3] << 8) | data[4]
        
        # Check if we have enough data for the handshake header
        if len(data) < self.MIN_TLS_RECORD_SIZE + 1:
            errors.append(
                f"Payload too short for handshake header: {len(data)} bytes"
            )
            return ValidationResult(
                valid=False,
                payload_type=PayloadType.TLS,
                errors=errors
            )
        
        # Check handshake type (byte 5) - must be 0x01 (ClientHello)
        handshake_type = data[5]
        if handshake_type != self.TLS_HANDSHAKE_CLIENT_HELLO:
            errors.append(
                f"Invalid handshake type: 0x{handshake_type:02x} "
                f"(expected 0x{self.TLS_HANDSHAKE_CLIENT_HELLO:02x} for ClientHello)"
            )
            return ValidationResult(
                valid=False,
                payload_type=PayloadType.TLS,
                errors=errors
            )
        
        # Check minimum ClientHello size
        if len(data) < self.MIN_TLS_CLIENTHELLO_SIZE:
            warnings.append(
                f"ClientHello smaller than typical: {len(data)} bytes "
                f"(typical minimum {self.MIN_TLS_CLIENTHELLO_SIZE})"
            )
        
        # Validate record length matches actual data
        expected_total = self.MIN_TLS_RECORD_SIZE + record_length
        if len(data) < expected_total:
            warnings.append(
                f"Payload shorter than declared record length: "
                f"{len(data)} bytes (expected {expected_total})"
            )
        elif len(data) > expected_total:
            warnings.append(
                f"Payload longer than declared record length: "
                f"{len(data)} bytes (expected {expected_total})"
            )
        
        return ValidationResult(
            valid=True,
            payload_type=PayloadType.TLS,
            errors=errors,
            warnings=warnings
        )
    
    def validate_http_request(self, data: bytes) -> ValidationResult:
        """
        Validate HTTP request structure.
        
        Checks:
        - HTTP method (GET, POST, etc.)
        - Request line format
        - Presence of Host header
        
        Args:
            data: Raw payload bytes
            
        Returns:
            ValidationResult indicating if payload is valid HTTP request
        """
        errors: List[str] = []
        warnings: List[str] = []
        
        if len(data) < 10:
            errors.append(f"Payload too short for HTTP request: {len(data)} bytes")
            return ValidationResult(
                valid=False,
                payload_type=PayloadType.HTTP,
                errors=errors
            )
        
        # Check for HTTP method at start
        has_method = False
        for method in self.HTTP_METHODS:
            if data.startswith(method + b" "):
                has_method = True
                break
        
        if not has_method:
            errors.append("No valid HTTP method found at start of payload")
            return ValidationResult(
                valid=False,
                payload_type=PayloadType.HTTP,
                errors=errors
            )
        
        # Check for HTTP version in first line
        try:
            first_line_end = data.index(b"\r\n")
            first_line = data[:first_line_end]
            if b"HTTP/" not in first_line:
                errors.append("No HTTP version found in request line")
                return ValidationResult(
                    valid=False,
                    payload_type=PayloadType.HTTP,
                    errors=errors
                )
        except ValueError:
            errors.append("No CRLF found in HTTP request")
            return ValidationResult(
                valid=False,
                payload_type=PayloadType.HTTP,
                errors=errors
            )
        
        # Check for Host header
        if b"Host:" not in data and b"host:" not in data:
            warnings.append("No Host header found in HTTP request")
        
        return ValidationResult(
            valid=True,
            payload_type=PayloadType.HTTP,
            errors=errors,
            warnings=warnings
        )
    
    def validate_quic_initial(self, data: bytes) -> ValidationResult:
        """
        Validate QUIC Initial packet structure.
        
        Checks:
        - Long header format (bit 7 set)
        - Fixed bit (bit 6 set)
        - Version field
        
        Args:
            data: Raw payload bytes
            
        Returns:
            ValidationResult indicating if payload is valid QUIC Initial
        """
        errors: List[str] = []
        warnings: List[str] = []
        
        if len(data) < 5:
            errors.append(f"Payload too short for QUIC packet: {len(data)} bytes")
            return ValidationResult(
                valid=False,
                payload_type=PayloadType.QUIC,
                errors=errors
            )
        
        first_byte = data[0]
        
        # Check long header bit (bit 7)
        if not (first_byte & self.QUIC_LONG_HEADER_BIT):
            errors.append("QUIC long header bit not set (required for Initial)")
            return ValidationResult(
                valid=False,
                payload_type=PayloadType.QUIC,
                errors=errors
            )
        
        # Check fixed bit (bit 6)
        if not (first_byte & self.QUIC_FIXED_BIT):
            warnings.append("QUIC fixed bit not set")
        
        # Check version field (bytes 1-4)
        version = (data[1] << 24) | (data[2] << 16) | (data[3] << 8) | data[4]
        
        # Known QUIC versions
        known_versions = {
            0x00000001: "QUIC v1",
            0xff000000: "QUIC draft",
            0x6b3343cf: "QUIC v2",
        }
        
        # Check for version negotiation (version = 0)
        if version == 0:
            warnings.append("Version negotiation packet (version = 0)")
        elif version not in known_versions and (version >> 24) != 0xff:
            warnings.append(f"Unknown QUIC version: 0x{version:08x}")
        
        return ValidationResult(
            valid=True,
            payload_type=PayloadType.QUIC,
            errors=errors,
            warnings=warnings
        )
