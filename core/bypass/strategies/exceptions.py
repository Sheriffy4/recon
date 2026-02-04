"""
Exception classes for DPI strategy components.

This module defines all custom exceptions used by the DPI strategy system.
"""


class DPIStrategyError(Exception):
    """
    Base exception for DPI strategy errors.

    All DPI strategy-related exceptions should inherit from this class.
    """

    def __init__(self, message: str, details: dict = None):
        """
        Initialize the exception.

        Args:
            message: Error message
            details: Optional dictionary with additional error details
        """
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        """Return string representation of the error."""
        if self.details:
            return f"{self.message} (Details: {self.details})"
        return self.message


class InvalidSplitPositionError(DPIStrategyError):
    """
    Raised when a split position is invalid for the given packet.

    This can occur when:
    - Position is negative
    - Position is larger than packet size
    - Position would create empty packet parts
    """

    def __init__(self, position: int, packet_size: int, message: str = None):
        """
        Initialize the exception.

        Args:
            position: The invalid split position
            packet_size: Size of the packet being split
            message: Optional custom message
        """
        if message is None:
            message = f"Invalid split position {position} for packet of size {packet_size}"

        details = {"position": position, "packet_size": packet_size}

        super().__init__(message, details)
        self.position = position
        self.packet_size = packet_size


class SNINotFoundError(DPIStrategyError):
    """
    Raised when SNI extension is required but not found in TLS packet.

    This occurs when:
    - SNI split position is requested but packet has no SNI
    - Packet is not a valid TLS Client Hello
    - TLS packet is malformed
    """

    def __init__(self, packet_size: int, message: str = None):
        """
        Initialize the exception.

        Args:
            packet_size: Size of the packet that was analyzed
            message: Optional custom message
        """
        if message is None:
            message = f"SNI extension not found in TLS packet of size {packet_size}"

        details = {"packet_size": packet_size, "packet_type": "TLS"}

        super().__init__(message, details)
        self.packet_size = packet_size


class PacketTooSmallError(DPIStrategyError):
    """
    Raised when packet is too small for the requested operation.

    This can occur when:
    - Packet is smaller than minimum required size
    - Packet is smaller than split position
    - Packet doesn't contain expected headers
    """

    def __init__(self, packet_size: int, required_size: int, operation: str = None):
        """
        Initialize the exception.

        Args:
            packet_size: Actual size of the packet
            required_size: Minimum required size
            operation: Optional description of the operation being attempted
        """
        operation_desc = f" for {operation}" if operation else ""
        message = f"Packet too small: {packet_size} bytes, required at least {required_size} bytes{operation_desc}"

        details = {
            "packet_size": packet_size,
            "required_size": required_size,
            "operation": operation,
        }

        super().__init__(message, details)
        self.packet_size = packet_size
        self.required_size = required_size
        self.operation = operation


class ChecksumCalculationError(DPIStrategyError):
    """
    Raised when checksum calculation or manipulation fails.

    This can occur when:
    - TCP header is malformed
    - Packet structure is invalid
    - Checksum algorithm fails
    """

    def __init__(self, packet_size: int, checksum_type: str = "TCP", message: str = None):
        """
        Initialize the exception.

        Args:
            packet_size: Size of the packet being processed
            checksum_type: Type of checksum (TCP, UDP, etc.)
            message: Optional custom message
        """
        if message is None:
            message = (
                f"Failed to calculate {checksum_type} checksum for packet of size {packet_size}"
            )

        details = {"packet_size": packet_size, "checksum_type": checksum_type}

        super().__init__(message, details)
        self.packet_size = packet_size
        self.checksum_type = checksum_type


class PacketProcessingError(DPIStrategyError):
    """
    Raised when general packet processing fails.

    This is a catch-all exception for packet processing errors
    that don't fit into more specific categories.
    """

    def __init__(self, packet_size: int, processor_name: str, message: str = None):
        """
        Initialize the exception.

        Args:
            packet_size: Size of the packet being processed
            processor_name: Name of the processor that failed
            message: Optional custom message
        """
        if message is None:
            message = (
                f"Packet processing failed in {processor_name} for packet of size {packet_size}"
            )

        details = {"packet_size": packet_size, "processor_name": processor_name}

        super().__init__(message, details)
        self.packet_size = packet_size
        self.processor_name = processor_name


class ConfigurationError(DPIStrategyError):
    """
    Raised when DPI strategy configuration is invalid.

    This occurs when:
    - Required configuration is missing
    - Configuration values are invalid
    - Configuration conflicts exist
    """

    def __init__(self, config_field: str, config_value: any = None, message: str = None):
        """
        Initialize the exception.

        Args:
            config_field: Name of the configuration field
            config_value: Invalid configuration value
            message: Optional custom message
        """
        if message is None:
            message = f"Invalid configuration for field '{config_field}': {config_value}"

        details = {"config_field": config_field, "config_value": config_value}

        super().__init__(message, details)
        self.config_field = config_field
        self.config_value = config_value


class TLSParsingError(DPIStrategyError):
    """
    Raised when TLS packet parsing fails.

    This occurs when:
    - TLS packet structure is invalid
    - TLS version is unsupported
    - Extensions parsing fails
    """

    def __init__(self, packet_size: int, tls_version: str = None, message: str = None):
        """
        Initialize the exception.

        Args:
            packet_size: Size of the TLS packet
            tls_version: TLS version if detected
            message: Optional custom message
        """
        if message is None:
            version_info = f" (version: {tls_version})" if tls_version else ""
            message = f"Failed to parse TLS packet of size {packet_size}{version_info}"

        details = {"packet_size": packet_size, "tls_version": tls_version}

        super().__init__(message, details)
        self.packet_size = packet_size
        self.tls_version = tls_version
