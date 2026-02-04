"""Strategy generation and validation helpers for monitoring system."""

import logging
import uuid
from typing import List

try:
    from core.bypass.strategies.pool_management import BypassStrategy

    BYPASS_STRATEGY_AVAILABLE = True
except ImportError:
    BYPASS_STRATEGY_AVAILABLE = False
    BypassStrategy = None


logger = logging.getLogger(__name__)


def generate_registry_recovery_strategies(
    attack_registry, registry_attacks: List[str]
) -> List[str]:
    """Generate recovery strategies from registry attacks.

    Args:
        attack_registry: AttackRegistry instance
        registry_attacks: List of attack IDs from registry

    Returns:
        List of strategy strings
    """
    strategies = []
    for attack_id in registry_attacks[:3]:
        if not attack_registry:
            break
        definition = attack_registry.get_attack_definition(attack_id)
        if not definition:
            continue
        if definition.category.value == "tcp_fragmentation":
            strategies.append("--dpi-desync=fake --dpi-desync-ttl=2 --dpi-desync-fooling=badsum")
        elif definition.category.value == "http_manipulation":
            strategies.append(
                "--dpi-desync=fake --dpi-desync-split-pos=midsld --dpi-desync-fooling=badsum"
            )
        elif definition.category.value == "tls_evasion":
            strategies.append(
                "--dpi-desync=disorder --dpi-desync-split-pos=3 --dpi-desync-fooling=badseq"
            )
    return strategies


async def validate_recovery_strategies(
    reliability_validator, health, strategies: List[str]
) -> List[str]:
    """Validate recovery strategies using reliability validator.

    Fixed SR7: Using UUID instead of hash() to avoid collisions.

    Args:
        reliability_validator: ReliabilityValidator instance
        health: ConnectionHealth instance
        strategies: List of strategy strings to validate

    Returns:
        List of validated strategy strings
    """
    if not reliability_validator:
        return strategies

    if not BYPASS_STRATEGY_AVAILABLE:
        logger.warning("BypassStrategy not available, skipping validation")
        return strategies

    validated_strategies = []
    for strategy_str in strategies:
        try:
            # SR7 FIX: Use UUID instead of hash() for unique IDs
            strategy_id = f"recovery_{uuid.uuid4().hex[:8]}"

            strategy = BypassStrategy(
                id=strategy_id,
                name=f"Recovery strategy for {health.domain}",
                attacks=["tcp_fragmentation"],
                parameters={},
            )
            validation_result = await reliability_validator.validate_strategy(
                health.domain, strategy
            )
            if validation_result and validation_result.reliability_score > 0.5:
                validated_strategies.append(strategy_str)
        except Exception as e:
            logger.debug(f"Strategy validation failed: {e}")
            validated_strategies.append(strategy_str)
    return validated_strategies if validated_strategies else strategies
