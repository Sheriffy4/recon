"""
Dispatcher telemetry and logging.

Utilities for logging recipe execution and recording metrics.
"""

import logging
from typing import Any, Dict, List, Optional

from .attack_constants import AttackConstants
from .packet_segment import PacketSegment

logger = logging.getLogger(__name__)


def validate_payload(payload: bytes) -> None:
    """Optional payload validation."""
    if not payload:
        raise ValueError("Empty payload")

    if len(payload) < AttackConstants.MIN_PAYLOAD_SIZE:
        raise ValueError(
            f"Payload too small: {len(payload)} bytes "
            f"(minimum: {AttackConstants.MIN_PAYLOAD_SIZE})"
        )

    if len(payload) > AttackConstants.MAX_PAYLOAD_SIZE:
        raise ValueError(
            f"Payload too large: {len(payload)} bytes "
            f"(maximum: {AttackConstants.MAX_PAYLOAD_SIZE})"
        )


def log_recipe_start(
    recipe, payload: bytes, packet_info: Dict[str, Any], detailed_logging: bool
) -> None:
    """Log recipe execution start."""
    if not detailed_logging:
        return

    mode = packet_info.get("mode", "UNKNOWN")
    domain = packet_info.get("domain", "unknown")

    logger.info("=" * 80)
    logger.info("🎯 STRATEGY APPLICATION START")
    logger.info(f"   Domain: {domain}")
    logger.info(f"   Mode: {mode}")
    logger.info(f"   Attacks: {recipe.attacks}")
    logger.info(f"   Steps: {len(recipe.steps)}")
    logger.info(f"   Payload size: {len(payload)} bytes")

    if recipe.params:
        logger.info("   Parameters:")
        for key, value in sorted(recipe.params.items()):
            logger.info(f"      {key}: {value}")

    logger.info("=" * 80)


def log_recipe_complete(
    segments: List[PacketSegment], original_payload: bytes, detailed_logging: bool
) -> None:
    """Log recipe execution completion."""
    if not detailed_logging:
        return

    fake_count = sum(1 for s in segments if s.is_fake)
    real_count = len(segments) - fake_count

    logger.info("=" * 80)
    logger.info("✅ STRATEGY APPLICATION COMPLETE")
    logger.info(f"   Total segments: {len(segments)}")
    logger.info(f"   Fake segments: {fake_count}")
    logger.info(f"   Real segments: {real_count}")
    logger.info(f"   Original size: {len(original_payload)} bytes")

    if segments:
        total_size = sum(s.size for s in segments)
        logger.info(f"   Total modified size: {total_size} bytes")

    logger.info("=" * 80)


def record_metrics(
    recipe,
    packet_info: Dict[str, Any],
    success: bool,
    error_message: Optional[str],
    exec_time: float,
    metrics_breaker,
    metrics_available: bool,
    get_metrics_collector_func,
) -> None:
    """Record metrics with circuit breaker protection."""
    if not metrics_available:
        return

    def record():
        collector = get_metrics_collector_func()
        domain = packet_info.get("domain", "unknown")
        strategy_id = f"recipe_{hash(tuple(recipe.attacks))}"

        collector.record_strategy_application(
            domain=domain,
            strategy_id=strategy_id,
            attacks=recipe.attacks,
            success=success,
            error_message=error_message,
            application_time_ms=exec_time,
            mode=packet_info.get("mode", "production"),
        )

    metrics_breaker.execute(record)
