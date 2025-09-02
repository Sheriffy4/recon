"""
Baseline Attack - No modifications applied.
Used to establish a baseline for bypass effectiveness testing.
"""

import time
from typing import List, Optional, Dict, Any
from core.bypass.attacks.base import (
    BaseAttack,
    AttackContext,
    AttackResult,
    AttackStatus,
)
from core.bypass.attacks.registry import register_attack


@register_attack
class BaselineAttack(BaseAttack):
    """
    A special attack that applies no modifications. It sends the payload as-is
    to measure the baseline connectivity and latency without any bypass techniques.
    """

    @property
    def name(self) -> str:
        return "baseline"

    @property
    def category(self) -> str:
        return "combo"

    @property
    def description(self) -> str:
        return "Sends the payload without modifications to establish a baseline."

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp", "udp", "icmp"]

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute the baseline test."""
        start_time = time.time()
        try:
            segments = [(context.payload, 0)]
            await asyncio.sleep(0)
            latency = (time.time() - start_time) * 1000
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=1,
                bytes_sent=len(context.payload),
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "segments": segments if context.engine_type != "local" else None,
                    "info": "Payload sent without modification.",
                },
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def to_zapret_command(self, params: Optional[Dict[str, Any]] = None) -> str:
        """Baseline has no equivalent zapret command."""
        return "# Baseline test: no bypass applied."
