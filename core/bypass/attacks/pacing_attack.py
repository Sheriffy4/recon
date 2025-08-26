"""
Pacing and Timing Attack to mimic slow or unstable connections.
"""
import time
import random
import logging
from typing import List
from core.bypass.attacks.base import AttackContext, AttackResult, AttackStatus
from core.bypass.attacks.advanced_base import AdvancedAttack, AdvancedAttackConfig
from core.integration.advanced_attack_registry import get_advanced_attack_registry
LOG = logging.getLogger(__name__)

class PacingAttack(AdvancedAttack):
    """
    Slows down data transmission by splitting the payload into small chunks
    and sending them with variable delays (jitter) to mimic an unstable
    connection and evade simple DPIs that timeout or have resource limits.
    """

    async def execute(self, context: AttackContext) -> AttackResult:
        start_time = time.time()
        try:
            payload = context.payload
            if not payload:
                return AttackResult(status=AttackStatus.INVALID_PARAMS, error_message='Payload is empty.')
            params = {**self.config.default_params, **context.params}
            chunk_size = params.get('chunk_size', 10)
            base_delay_ms = params.get('base_delay_ms', 50)
            jitter_ms = params.get('jitter_ms', 20)
            if chunk_size <= 0:
                return AttackResult(status=AttackStatus.INVALID_PARAMS, error_message='Chunk size must be positive.')
            segments = []
            offset = 0
            is_first_segment = True
            while offset < len(payload):
                chunk = payload[offset:offset + chunk_size]
                options = {}
                if not is_first_segment:
                    delay = base_delay_ms + random.uniform(-jitter_ms, jitter_ms)
                    if delay > 0:
                        options['delay_ms'] = delay
                segments.append((chunk, offset, options))
                offset += len(chunk)
                is_first_segment = False
            result = AttackResult(status=AttackStatus.SUCCESS, technique_used=self.name, packets_sent=len(segments), bytes_sent=len(payload), processing_time_ms=(time.time() - start_time) * 1000)
            result.segments = segments
            result.update_metadata({'attack_type': 'pacing_with_jitter', 'chunk_size': chunk_size, 'base_delay_ms': base_delay_ms, 'jitter_ms': jitter_ms, 'segment_count': len(segments)})
            return result
        except Exception as e:
            LOG.error(f'Pacing attack failed: {e}', exc_info=context.debug)
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), technique_used=self.name)
pacing_attack_config = AdvancedAttackConfig(name='pacing_attack', priority=40, complexity='Medium', target_protocols=['tcp', 'tls'], dpi_signatures=['resource_limited_dpi', 'stateful_timeout_dpi', 'generic_stateful_inspector'], description='Slows down data transmission with variable delays (jitter) to mimic an unstable connection.', default_params={'chunk_size': 10, 'base_delay_ms': 50, 'jitter_ms': 20}, learning_enabled=True)
try:
    registry = get_advanced_attack_registry()
    registry.register_attack(PacingAttack, pacing_attack_config)
    LOG.info('Successfully registered PacingAttack with AdvancedAttackRegistry.')
except Exception as e:
    LOG.error(f'Failed to register PacingAttack with AdvancedAttackRegistry: {e}')