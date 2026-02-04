"""
Attack payload integration module.

This module integrates the payload system with attack classes:
- Provides PayloadManager access for attack classes
- Handles payload resolution from various sources (file, hex, placeholder)
- Ensures payload integrity during attack execution

Requirements: 6.1, 6.2, 6.3, 6.4
"""

import logging
from pathlib import Path
from typing import Optional, Union, Any

from .types import PayloadType
from .manager import PayloadManager, DEFAULT_PAYLOAD_SIZE
from .serializer import PayloadSerializer


logger = logging.getLogger(__name__)


# Global payload manager instance for attack classes
_global_payload_manager: Optional[PayloadManager] = None


def get_global_payload_manager() -> PayloadManager:
    """
    Get the global PayloadManager instance.

    Creates and initializes the manager on first access.

    Returns:
        Global PayloadManager instance

    Requirements: 6.1
    """
    global _global_payload_manager

    if _global_payload_manager is None:
        _global_payload_manager = PayloadManager()
        try:
            _global_payload_manager.load_all()
            logger.info(
                f"Initialized global PayloadManager with "
                f"{len(_global_payload_manager)} payloads"
            )
        except Exception as e:
            logger.warning(f"Failed to load payloads: {e}")

    return _global_payload_manager


def set_global_payload_manager(manager: PayloadManager) -> None:
    """
    Set the global PayloadManager instance.

    Allows injection of a custom manager for testing or configuration.

    Args:
        manager: PayloadManager instance to use globally
    """
    global _global_payload_manager
    _global_payload_manager = manager
    logger.debug("Global PayloadManager updated")


def reset_global_payload_manager() -> None:
    """Reset the global PayloadManager instance."""
    global _global_payload_manager
    _global_payload_manager = None
    logger.debug("Global PayloadManager reset")


class AttackPayloadProvider:
    """
    Provides payload resolution for attack classes.

    Handles:
    - Resolution of payload from various sources (bytes, file, hex, placeholder)
    - Fallback to default payload when resolution fails
    - Payload integrity verification

    Requirements: 6.1, 6.2, 6.3, 6.4
    """

    def __init__(
        self,
        payload_manager: Optional[PayloadManager] = None,
        default_payload_size: int = DEFAULT_PAYLOAD_SIZE,
    ):
        """
        Initialize AttackPayloadProvider.

        Args:
            payload_manager: PayloadManager instance (uses global if None)
            default_payload_size: Size of default fallback payload
        """
        self._manager = payload_manager
        self._serializer = PayloadSerializer()
        self._default_size = default_payload_size

    @property
    def manager(self) -> PayloadManager:
        """Get the PayloadManager instance."""
        if self._manager is not None:
            return self._manager
        return get_global_payload_manager()

    def resolve_payload(
        self,
        payload_param: Optional[Union[bytes, str, Path]] = None,
        payload_type: PayloadType = PayloadType.TLS,
        domain: Optional[str] = None,
        use_default_on_failure: bool = True,
    ) -> bytes:
        """
        Resolve payload from various sources.

        Resolution order:
        1. If payload_param is bytes, use directly
        2. If payload_param is hex string (0x...), decode it
        3. If payload_param is file path, load from file
        4. If payload_param is placeholder (PAYLOADTLS), resolve from manager
        5. If payload_param is None, get from manager by type/domain
        6. If all else fails and use_default_on_failure, return default payload

        Args:
            payload_param: Payload parameter (bytes, hex string, file path, or placeholder)
            payload_type: Type of payload for manager lookup
            domain: Target domain for domain-specific payload selection
            use_default_on_failure: If True, return default payload on failure

        Returns:
            Resolved payload bytes

        Raises:
            ValueError: If payload cannot be resolved and use_default_on_failure is False

        Requirements: 6.1, 6.2, 6.3
        """
        # Case 1: Direct bytes
        if isinstance(payload_param, bytes):
            logger.debug(f"Using direct bytes payload: {len(payload_param)} bytes")
            return payload_param

        # Case 2: String parameter (hex, file path, or placeholder)
        if isinstance(payload_param, str):
            resolved = self._resolve_string_payload(payload_param, payload_type, domain)
            if resolved is not None:
                return resolved

        # Case 3: Path object
        if isinstance(payload_param, Path):
            resolved = self._load_from_file(payload_param)
            if resolved is not None:
                return resolved

        # Case 4: No explicit payload - try manager
        if payload_param is None:
            resolved = self._get_from_manager(payload_type, domain)
            if resolved is not None:
                return resolved

        # Case 5: Fallback to default
        if use_default_on_failure:
            logger.debug(
                f"Using default {self._default_size}-byte payload "
                f"(type={payload_type.value}, domain={domain})"
            )
            return self.get_default_payload()

        raise ValueError(
            f"Could not resolve payload: param={payload_param}, "
            f"type={payload_type.value}, domain={domain}"
        )

    def _resolve_string_payload(
        self, payload_str: str, payload_type: PayloadType, domain: Optional[str] = None
    ) -> Optional[bytes]:
        """
        Resolve payload from string parameter.

        Args:
            payload_str: String payload parameter
            payload_type: Type of payload for placeholder resolution
            domain: Target domain for CDN-aware resolution

        Returns:
            Resolved bytes or None
        """
        # Check if hex string
        if self._serializer.is_hex_string(payload_str):
            try:
                payload = self._serializer.from_hex(payload_str)
                logger.debug(f"Resolved hex payload: {len(payload)} bytes")
                return payload
            except Exception as e:
                logger.warning(f"Failed to decode hex payload: {e}")
                return None

        # Check if placeholder
        if self._serializer.is_placeholder(payload_str):
            # Pass domain for CDN-aware resolution
            payload = self.manager.resolve_placeholder(payload_str, domain=domain)
            if payload:
                logger.debug(
                    f"Resolved placeholder '{payload_str}' for domain '{domain}': {len(payload)} bytes"
                )
                return payload
            logger.warning(f"Failed to resolve placeholder: {payload_str}")
            return None

        # Check if file path
        if self._serializer.is_file_path(payload_str):
            return self._load_from_file(Path(payload_str))

        # Unknown string format
        logger.warning(f"Unknown payload string format: {payload_str[:50]}...")
        return None

    def _load_from_file(self, file_path: Path) -> Optional[bytes]:
        """
        Load payload from file.

        Args:
            file_path: Path to payload file

        Returns:
            File contents or None on failure
        """
        try:
            if not file_path.exists():
                logger.warning(f"Payload file not found: {file_path}")
                return None

            payload = file_path.read_bytes()
            logger.debug(f"Loaded payload from {file_path}: {len(payload)} bytes")
            return payload

        except Exception as e:
            logger.error(f"Failed to load payload from {file_path}: {e}")
            return None

    def _get_from_manager(
        self, payload_type: PayloadType, domain: Optional[str]
    ) -> Optional[bytes]:
        """
        Get payload from PayloadManager.

        Args:
            payload_type: Type of payload
            domain: Target domain

        Returns:
            Payload bytes or None
        """
        # Try CDN-aware lookup first
        if domain:
            payload = self.manager.get_payload_for_cdn(domain)
            if payload:
                logger.debug(
                    f"Got payload from manager for domain {domain}: " f"{len(payload)} bytes"
                )
                return payload

        # Try type-based lookup
        payload = self.manager.get_payload(payload_type, domain)
        if payload:
            logger.debug(
                f"Got payload from manager (type={payload_type.value}): " f"{len(payload)} bytes"
            )
            return payload

        return None

    def get_default_payload(self) -> bytes:
        """
        Get default fallback payload.

        Returns:
            Default payload bytes (zeros)

        Requirements: 6.4
        """
        return bytes(self._default_size)

    def verify_payload_integrity(self, original: bytes, used: bytes) -> bool:
        """
        Verify that payload was not modified during attack execution.

        Args:
            original: Original payload bytes
            used: Payload bytes after use

        Returns:
            True if payloads are identical

        Requirements: 6.2
        """
        return original == used


# Convenience function for attack classes
def get_attack_payload(
    payload_param: Optional[Union[bytes, str, Path]] = None,
    payload_type: PayloadType = PayloadType.TLS,
    domain: Optional[str] = None,
) -> bytes:
    """
    Convenience function to get payload for attack execution.

    This is the primary interface for attack classes to obtain payloads.

    Args:
        payload_param: Explicit payload (bytes, hex, file path, or placeholder)
        payload_type: Type of payload for manager lookup
        domain: Target domain for domain-specific selection

    Returns:
        Resolved payload bytes (never None, falls back to default)

    Requirements: 6.1

    Example:
        # In attack class execute() method:
        fake_payload = get_attack_payload(
            payload_param=context.params.get('fake_payload'),
            payload_type=PayloadType.TLS,
            domain=context.domain
        )
    """
    provider = AttackPayloadProvider()
    return provider.resolve_payload(
        payload_param=payload_param,
        payload_type=payload_type,
        domain=domain,
        use_default_on_failure=True,
    )
