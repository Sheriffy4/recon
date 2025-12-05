"""
Payload management module for fake payload generation and handling.

This module provides components for managing, validating, and capturing
fake payloads used in DPI bypass strategies.
"""

from .types import PayloadType, PayloadInfo
from .validator import PayloadValidator, ValidationResult
from .serializer import (
    PayloadSerializer,
    PayloadSerializerError,
    InvalidHexError,
    InvalidPlaceholderError,
)
from .manager import (
    PayloadManager,
    PayloadNotFoundError,
    PayloadCorruptedError,
    PayloadDirectoryError,
)
from .capturer import (
    PayloadCapturer,
    CaptureResult,
    CaptureError,
    CaptureTimeoutError,
    CaptureNetworkError,
    CaptureValidationError,
)
from .strategy_integration import (
    StrategyPayloadIntegration,
    create_payload_enhanced_strategies,
)
from .attack_integration import (
    AttackPayloadProvider,
    get_attack_payload,
    get_global_payload_manager,
    set_global_payload_manager,
    reset_global_payload_manager,
)

__all__ = [
    "PayloadType",
    "PayloadInfo",
    "PayloadValidator",
    "ValidationResult",
    "PayloadSerializer",
    "PayloadSerializerError",
    "InvalidHexError",
    "InvalidPlaceholderError",
    "PayloadManager",
    "PayloadNotFoundError",
    "PayloadCorruptedError",
    "PayloadDirectoryError",
    "PayloadCapturer",
    "CaptureResult",
    "CaptureError",
    "CaptureTimeoutError",
    "CaptureNetworkError",
    "CaptureValidationError",
    "StrategyPayloadIntegration",
    "create_payload_enhanced_strategies",
    # Attack integration
    "AttackPayloadProvider",
    "get_attack_payload",
    "get_global_payload_manager",
    "set_global_payload_manager",
    "reset_global_payload_manager",
]
