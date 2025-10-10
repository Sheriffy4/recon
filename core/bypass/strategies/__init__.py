"""
Bypass Strategy Management Package

This package contains the strategy pool management system for organizing
and applying bypass strategies across different domains and use cases.
It also includes the DPI strategy system for packet-level bypass operations.
"""

from core.bypass.strategies.pool_management import (
    StrategyPoolManager,
    StrategyPool,
    BypassStrategy,
    DomainRule,
    PoolPriority,
    analyze_domain_patterns,
    suggest_pool_strategies,
)

# DPI Strategy System
from core.bypass.strategies.interfaces import (
    IDPIStrategy,
    IPacketProcessor,
    IPositionResolver,
    ISNIDetector,
    IPacketModifier,
    IChecksumFooler,
)

from core.bypass.strategies.dpi_strategy_engine import (
    DPIStrategyEngine,
    BasePacketProcessor,
)

# DPI Strategy Components
from core.bypass.strategies.position_resolver import PositionResolver
from core.bypass.strategies.sni_detector import SNIDetector
from core.bypass.strategies.checksum_fooler import ChecksumFooler, ChecksumResult

from core.bypass.strategies.config_models import (
    DPIConfig,
    SplitConfig,
    FoolingConfig,
    PacketSplitResult,
    TLSPacketInfo,
    TCPPacketInfo,
    DesyncMode,
    FoolingMethod,
)

from core.bypass.strategies.exceptions import (
    DPIStrategyError,
    InvalidSplitPositionError,
    SNINotFoundError,
    PacketTooSmallError,
    ChecksumCalculationError,
    PacketProcessingError,
    ConfigurationError,
    TLSParsingError,
)

__all__ = [
    # Pool Management
    "StrategyPoolManager",
    "StrategyPool",
    "BypassStrategy",
    "DomainRule",
    "PoolPriority",
    "analyze_domain_patterns",
    "suggest_pool_strategies",
    
    # DPI Strategy Interfaces
    "IDPIStrategy",
    "IPacketProcessor",
    "IPositionResolver",
    "ISNIDetector",
    "IPacketModifier",
    "IChecksumFooler",
    
    # DPI Strategy Engine
    "DPIStrategyEngine",
    "BasePacketProcessor",
    
    # DPI Strategy Components
    "PositionResolver",
    "SNIDetector",
    "ChecksumFooler",
    "ChecksumResult",
    
    # Configuration Models
    "DPIConfig",
    "SplitConfig",
    "FoolingConfig",
    "PacketSplitResult",
    "TLSPacketInfo",
    "TCPPacketInfo",
    "DesyncMode",
    "FoolingMethod",
    
    # Exceptions
    "DPIStrategyError",
    "InvalidSplitPositionError",
    "SNINotFoundError",
    "PacketTooSmallError",
    "ChecksumCalculationError",
    "PacketProcessingError",
    "ConfigurationError",
    "TLSParsingError",
]
