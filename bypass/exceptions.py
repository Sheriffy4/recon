# recon/core/bypass/exceptions.py

"""Exception classes for bypass system."""


class BypassError(Exception):
    """Base exception for bypass system."""

    pass


class EngineError(BypassError):
    """Engine-related errors."""

    pass


class EngineNotRunningError(EngineError):
    """Engine is not running."""

    pass


class EngineAlreadyRunningError(EngineError):
    """Engine is already running."""

    pass


class EngineConfigError(EngineError):
    """Engine configuration error."""

    pass


class StrategyError(BypassError):
    """Strategy-related errors."""

    pass


class InvalidStrategyError(StrategyError):
    """Invalid strategy configuration."""

    pass


class StrategyExecutionError(StrategyError):
    """Strategy execution failed."""

    pass


class TechniqueNotFoundError(StrategyError):
    """Technique not found in registry."""

    pass


class PacketError(BypassError):
    """Packet-related errors."""

    pass


class InvalidPacketError(PacketError):
    """Invalid packet data."""

    pass


class PacketProcessingError(PacketError):
    """Packet processing failed."""

    pass


class PacketSendError(PacketError):
    """Failed to send packet."""

    pass


class PlatformError(BypassError):
    """Platform-specific errors."""

    pass


class WindowsRequiredError(PlatformError):
    """Operation requires Windows platform."""

    pass


class DriverNotFoundError(PlatformError):
    """Required driver not found."""

    pass


class InsufficientPrivilegesError(PlatformError):
    """Insufficient privileges for operation."""

    pass
