import time
import random
import logging
from typing import List
from core.bypass.attacks.base import AttackContext, AttackResult, AttackStatus
from core.bypass.attacks.advanced_base import AdvancedAttack, AdvancedAttackConfig
from core.integration.advanced_attack_registry import get_advanced_attack_registry
LOG = logging.getLogger(__name__)

class StatefulFragmentationAttack(AdvancedAttack):
    """
    Sends a fragmented payload with a garbage packet in the middle to confuse stateful DPIs.
    Example sequence for a ClientHello:
    1. TCP Segment 1: ClientHello[0:10] (valid)
    2. TCP Segment 2: "garbage_data" (invalid checksum, will be dropped by host)
    3. TCP Segment 3: ClientHello[10:] (valid)
    The host's TCP stack should ignore the garbage packet and reassemble the valid fragments.
    A less sophisticated DPI might see the garbage and fail to reassemble the stream correctly.
    """

    async def execute(self, context: AttackContext) -> AttackResult:
        start_time = time.time()
        try:
            payload = context.payload
            if not payload or len(payload) < 20:
                return AttackResult(status=AttackStatus.INVALID_PARAMS, error_message='Payload too small for stateful fragmentation.')
            params = {**self.config.default_params, **context.params}
            split_pos = params.get('split_pos', 10)
            garbage_data_param = params.get('garbage_data', b'GARBAGE_PACKET')
            garbage_data = garbage_data_param.encode() if isinstance(garbage_data_param, str) else garbage_data_param
            part1 = payload[:split_pos]
            segment1_options = {}
            segment1 = (part1, 0, segment1_options)
            garbage_options = {'bad_checksum': True}
            garbage_seq_offset = len(part1)
            segment2 = (garbage_data, garbage_seq_offset, garbage_options)
            part2 = payload[split_pos:]
            segment3_options = {}
            part2_seq_offset = len(part1)
            segment3 = (part2, part2_seq_offset, segment3_options)
            segments = [segment1, segment2, segment3]
            result = AttackResult(status=AttackStatus.SUCCESS, technique_used=self.name, packets_sent=len(segments), bytes_sent=sum((len(s[0]) for s in segments)), processing_time_ms=(time.time() - start_time) * 1000)
            result.segments = segments
            result.set_metadata({'fragmentation_type': 'stateful_garbage_injection', 'split_position': split_pos, 'garbage_size': len(garbage_data)})
            return result
        except Exception as e:
            LOG.error(f'Stateful fragmentation attack failed: {e}', exc_info=context.debug)
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), technique_used=self.name)

class AdvancedOverlapAttack(AdvancedAttack):
    """
    Sends overlapping TCP segments with different data.
    - Segment 1 (for DPI): Contains `dpi_payload`
    - Segment 2 (for host): Overlaps segment 1 and contains `real_payload`
    A compliant TCP stack will favor the later data, accepting `real_payload`.
    A simple DPI might inspect the `dpi_payload` and miss the real data.
    """

    async def execute(self, context: AttackContext) -> AttackResult:
        start_time = time.time()
        try:
            real_payload = context.payload
            if not real_payload:
                return AttackResult(status=AttackStatus.INVALID_PARAMS, error_message='Payload is empty.')
            params = {**self.config.default_params, **context.params}
            dpi_payload_param = params.get('dpi_payload', b'GET / HTTP/1.1\\r\\n\\r\\n')
            dpi_payload = dpi_payload_param.encode() if isinstance(dpi_payload_param, str) else dpi_payload_param
            segment1_options = {}
            segment1 = (dpi_payload, 0, segment1_options)
            segment2_options = {}
            segment2 = (real_payload, 0, segment2_options)
            segments = [segment1, segment2]
            result = AttackResult(status=AttackStatus.SUCCESS, technique_used=self.name, packets_sent=len(segments), bytes_sent=sum((len(s[0]) for s in segments)), processing_time_ms=(time.time() - start_time) * 1000)
            result.segments = segments
            result.set_metadata({'fragmentation_type': 'advanced_overlap', 'dpi_payload_size': len(dpi_payload), 'real_payload_size': len(real_payload)})
            return result
        except Exception as e:
            LOG.error(f'Advanced overlap attack failed: {e}', exc_info=context.debug)
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), technique_used=self.name)
stateful_fragment_config = AdvancedAttackConfig(name='stateful_fragment', priority=20, complexity='High', target_protocols=['tcp', 'tls'], dpi_signatures=['stateful_dpi', 'ROSKOMNADZOR_TSPU', 'generic_stateful_inspector'], description='Injects a garbage packet between two valid fragments to confuse stateful DPI.', default_params={'split_pos': 10, 'garbage_data': b'GARBAGE_PACKET_CONTENT'}, learning_enabled=True)
advanced_overlap_config = AdvancedAttackConfig(name='advanced_overlap', priority=15, complexity='High', target_protocols=['tcp', 'tls'], dpi_signatures=['signature_matching_dpi', 'generic_proxy'], description='Uses overlapping segments with different data for DPI and host to cause desync.', default_params={'dpi_payload': b'GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n'}, learning_enabled=True)
try:
    registry = get_advanced_attack_registry()
    registry.register_attack(StatefulFragmentationAttack, stateful_fragment_config)
    registry.register_attack(AdvancedOverlapAttack, advanced_overlap_config)
    LOG.info('Successfully registered stateful and overlap attacks with AdvancedAttackRegistry.')
except Exception as e:
    LOG.error(f'Failed to register stateful/overlap attacks with AdvancedAttackRegistry: {e}')