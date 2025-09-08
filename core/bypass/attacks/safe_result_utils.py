"""
Safe AttackResult creation utilities.

This module provides utilities for safely creating AttackResult objects
to avoid "cannot access local variable 'AttackStatus'" errors.
"""

import logging
from typing import Any, Dict, Optional

LOG = logging.getLogger("SafeResultUtils")


def safe_create_attack_result(
    status_name: str,
    error_message: str = "",
    technique_used: str = "",
    latency_ms: float = 0.0,
    packets_sent: int = 0,
    bytes_sent: int = 0,
    modified_payload: Optional[bytes] = None,
    metadata: Optional[Dict[str, Any]] = None,
    **kwargs,
):
    """
    Safely create AttackResult with proper error handling.

    Args:
        status_name: Name of the status (e.g., "SUCCESS", "ERROR", "FAILED")
        error_message: Error message if any
        technique_used: Name of the technique used
        latency_ms: Latency in milliseconds
        packets_sent: Number of packets sent
        bytes_sent: Number of bytes sent
        modified_payload: Modified payload if any
        metadata: Additional metadata
        **kwargs: Additional keyword arguments

    Returns:
        AttackResult object or None if creation fails
    """
    try:
        from core.bypass.attacks.base import AttackResult, AttackStatus

        status = getattr(AttackStatus, status_name)
        return AttackResult(
            status=status,
            error_message=error_message,
            technique_used=technique_used,
            latency_ms=latency_ms,
            packets_sent=packets_sent,
            bytes_sent=bytes_sent,
            modified_payload=modified_payload,
            metadata=metadata or {},
            **kwargs,
        )
    except (ImportError, NameError, AttributeError) as e:
        LOG.warning(f"Failed to create AttackResult with direct import: {e}")
        try:
            import importlib

            base_module = importlib.import_module("core.bypass.attacks.base")
            AttackResult = getattr(base_module, "AttackResult")
            AttackStatus = getattr(base_module, "AttackStatus")
            status = getattr(AttackStatus, status_name)
            return AttackResult(
                status=status,
                error_message=error_message,
                technique_used=technique_used,
                latency_ms=latency_ms,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                modified_payload=modified_payload,
                metadata=metadata or {},
                **kwargs,
            )
        except Exception as fallback_e:
            LOG.critical(f"Critical error creating AttackResult: {fallback_e}")
            return None


def safe_get_attack_status(status_name: str):
    """
    Safely get AttackStatus enum value.

    Args:
        status_name: Name of the status (e.g., "SUCCESS", "ERROR", "FAILED")

    Returns:
        AttackStatus enum value or None if not found
    """
    try:
        from core.bypass.attacks.base import AttackStatus

        return getattr(AttackStatus, status_name)
    except (ImportError, NameError, AttributeError) as e:
        LOG.warning(f"Failed to get AttackStatus with direct import: {e}")
        try:
            import importlib

            base_module = importlib.import_module("core.bypass.attacks.base")
            AttackStatus = getattr(base_module, "AttackStatus")
            return getattr(AttackStatus, status_name)
        except Exception as fallback_e:
            LOG.critical(f"Critical error getting AttackStatus: {fallback_e}")
            return None


def create_success_result(technique_used: str = "", latency_ms: float = 0.0, **kwargs):
    """Create a successful AttackResult."""
    return safe_create_attack_result(
        status_name="SUCCESS",
        technique_used=technique_used,
        latency_ms=latency_ms,
        **kwargs,
    )


def create_error_result(
    error_message: str, technique_used: str = "", latency_ms: float = 0.0, **kwargs
):
    """Create an error AttackResult."""
    return safe_create_attack_result(
        status_name="ERROR",
        error_message=error_message,
        technique_used=technique_used,
        latency_ms=latency_ms,
        **kwargs,
    )


def create_failed_result(
    error_message: str, technique_used: str = "", latency_ms: float = 0.0, **kwargs
):
    """Create a failed AttackResult."""
    return safe_create_attack_result(
        status_name="FAILED",
        error_message=error_message,
        technique_used=technique_used,
        latency_ms=latency_ms,
        **kwargs,
    )


def create_timeout_result(
    error_message: str = "Attack timed out",
    technique_used: str = "",
    latency_ms: float = 0.0,
    **kwargs,
):
    """Create a timeout AttackResult."""
    return safe_create_attack_result(
        status_name="TIMEOUT",
        error_message=error_message,
        technique_used=technique_used,
        latency_ms=latency_ms,
        **kwargs,
    )


def create_invalid_params_result(
    error_message: str, technique_used: str = "", **kwargs
):
    """Create an invalid parameters AttackResult."""
    return safe_create_attack_result(
        status_name="INVALID_PARAMS",
        error_message=error_message,
        technique_used=technique_used,
        **kwargs,
    )
