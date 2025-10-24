"""
Pacing and Timing Attack to mimic slow or unstable connections.
"""

import time
import random
import logging
from typing import List
from core.bypass.attacks.base import AttackContext, AttackResult, AttackStatus
from core.bypass.attacks.base import BaseAttack
from core.bypass.attacks.metadata import AttackMetadata, AttackCategories
from core.bypass.attacks.attack_registry import register_attack

LOG = logging.getLogger(__name__)


class PacingAttack(BaseAttack):
    """
    Slows down data transmission by splitting the payload into small chunks
    and sending them with variable delays (jitter) to mimic an unstable
    connection and evade simple DPIs that timeout or have resource limits.
    """

    @property
    def name(self) -> str:
        return "pacing_attack"

    @property
    def category(self) -> str:
        return AttackCategories.TIMING

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> dict:
        return {"chunk_size": 10, "base_delay_ms": 50, "jitter_ms": 20}

    def execute(self, context: AttackContext) -> AttackResult:
        start_time = time.time()
        try:
            payload = context.payload
            if not payload:
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message="Payload is empty.",
                )
            params = context.params
            chunk_size = params.get("chunk_size", 10)
            base_delay_ms = params.get("base_delay_ms", 50)
            jitter_ms = params.get("jitter_ms", 20)
            if chunk_size <= 0:
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message="Chunk size must be positive.",
                )
            segments = []
            offset = 0
            is_first_segment = True
            while offset < len(payload):
                chunk = payload[offset : offset + chunk_size]
                options = {}
                if not is_first_segment:
                    delay = base_delay_ms + random.uniform(-jitter_ms, jitter_ms)
                    if delay > 0:
                        options["delay_ms"] = delay
                segments.append((chunk, offset, options))
                offset += len(chunk)
                is_first_segment = False
            result = AttackResult(
                status=AttackStatus.SUCCESS,
                technique_used=self.name,
                packets_sent=len(segments),
                bytes_sent=len(payload),
                processing_time_ms=(time.time() - start_time) * 1000,
            )
            result.segments = segments
            result.update_metadata(
                {
                    "attack_type": "pacing_with_jitter",
                    "chunk_size": chunk_size,
                    "base_delay_ms": base_delay_ms,
                    "jitter_ms": jitter_ms,
                    "segment_count": len(segments),
                }
            )
            return result
        except Exception as e:
            LOG.error(f"Pacing attack failed: {e}", exc_info=context.debug)
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                technique_used=self.name,
            )


# Note: Attack registration is handled by the @register_attack decorator
# These classes can be imported and used directly or registered via decorator
