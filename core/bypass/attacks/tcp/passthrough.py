"""
Passthrough Attack - No modification

This is a special "attack" that doesn't modify packets at all.
It's used as a fallback when no other strategy works.
"""

from typing import List, Tuple, Optional, Dict, Any
import logging

logger = logging.getLogger(__name__)


class PassthroughAttack:
    """
    Passthrough attack - sends packet as-is without modification.

    This is not really an "attack" but a fallback strategy that
    allows packets to pass through without any DPI bypass attempts.
    """

    def __init__(self, **params):
        """Initialize passthrough attack (no parameters needed)."""
        self.params = params
        logger.debug("PassthroughAttack initialized (no-op)")

    def apply(
        self, payload: bytes, packet_info: Optional[Dict[str, Any]] = None
    ) -> List[Tuple[bytes, int, bool, Dict[str, Any]]]:
        """
        Apply passthrough "attack" - return payload unchanged.

        Args:
            payload: Original packet payload
            packet_info: Optional packet information

        Returns:
            List with single segment: [(payload, 0, False, {})]
            - payload: unchanged
            - offset: 0
            - is_fake: False
            - metadata: empty dict
        """
        logger.debug(f"Passthrough: sending {len(payload)} bytes unchanged")

        # Return single segment with original payload
        return [(payload, 0, False, {})]


def register_attack(registry):
    """Register passthrough attack with registry."""
    from core.bypass.attacks.attack_registry import AttackPriority

    registry.register_attack(
        name="passthrough",
        attack_class=PassthroughAttack,
        priority=AttackPriority.LOW,
        description="No modification - send packet as-is (fallback)",
        default_params={},
    )

    logger.info("Registered 'passthrough' attack (fallback/no-op)")
