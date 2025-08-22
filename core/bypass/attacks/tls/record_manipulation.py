"""
TLS Record Manipulation Attacks

Migrated and unified from:
- TlsRecSplitTechnique (core/fast_bypass/techniques/tcp_techniques.py)
- apply_tlsrec_split (core/fast_bypass.py)
"""
import time
import struct
from typing import List
from recon.core.bypass.attacks.base import BaseAttack, AttackContext, AttackResult, AttackStatus
from recon.core.bypass.attacks.registry import register_attack

def _safe_create_result(status_name: str, **kwargs):
    """Safely create AttackResult to prevent AttackStatus errors."""
    try:
        from recon.core.bypass.attacks.safe_result_utils import safe_create_attack_result
        return safe_create_attack_result(status_name, **kwargs)
    except Exception:
        try:
            from recon.core.bypass.attacks.base import AttackResult, AttackStatus
            status = getattr(AttackStatus, status_name)
            return AttackResult(status=status, **kwargs)
        except Exception:
            return None

@register_attack
class TLSRecordSplitAttack(BaseAttack):
    """
    TLS Record Split Attack - splits one TLS record into two.

    Migrated from:
    - TlsRecSplitTechnique (fast_bypass/techniques/tcp_techniques.py)
    - apply_tlsrec_split (fast_bypass.py)
    """

    @property
    def name(self) -> str:
        return 'tlsrec_split'

    @property
    def category(self) -> str:
        return 'tls'

    @property
    def description(self) -> str:
        return 'Splits one TLS record into two separate records'

    @property
    def supported_protocols(self) -> List[str]:
        return ['tcp']

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute TLS record split attack."""
        start_time = time.time()
        try:
            payload = context.payload
            split_pos = context.params.get('split_pos', 5)
            if not (payload.startswith(b'\x16\x03\x01') and len(payload) > 5 + split_pos):
                return AttackResult(status=AttackStatus.INVALID_PARAMS, error_message='Not a splittable TLS record')
            tls_data = payload[5:]
            part1 = tls_data[:split_pos]
            part2 = tls_data[split_pos:]
            record1 = b'\x16\x03\x01' + len(part1).to_bytes(2, 'big') + part1
            record2 = b'\x16\x03\x01' + len(part2).to_bytes(2, 'big') + part2
            modified_payload = record1 + record2
            segments = [(modified_payload, 0)]
            packets_sent = 1
            bytes_sent = len(modified_payload)
            latency = (time.time() - start_time) * 1000
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=latency, packets_sent=packets_sent, bytes_sent=bytes_sent, connection_established=True, data_transmitted=True, metadata={'split_pos': split_pos, 'original_size': len(payload), 'modified_size': len(modified_payload), 'record1_size': len(record1), 'record2_size': len(record2), 'segments': segments if context.engine_type != 'local' else None})
        except Exception as e:
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=(time.time() - start_time) * 1000)

@register_attack
class TLSRecordPaddingAttack(BaseAttack):
    """
    TLS Record Padding Attack - adds padding to TLS records.
    """

    @property
    def name(self) -> str:
        return 'tls_record_padding'

    @property
    def category(self) -> str:
        return 'tls'

    @property
    def description(self) -> str:
        return 'Adds padding to TLS records to change their size'

    @property
    def supported_protocols(self) -> List[str]:
        return ['tcp']

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute TLS record padding attack."""
        start_time = time.time()
        try:
            payload = context.payload
            padding_size = context.params.get('padding_size', 16)
            if not payload.startswith(b'\x16\x03'):
                return AttackResult(status=AttackStatus.INVALID_PARAMS, error_message='Not a TLS record')
            padding = b'\x00' * padding_size
            modified_payload = payload + padding
            if len(payload) >= 5:
                original_length = struct.unpack('!H', payload[3:5])[0]
                new_length = original_length + padding_size
                modified_payload = payload[:3] + struct.pack('!H', new_length) + payload[5:] + padding
            segments = [(modified_payload, 0)]
            packets_sent = 1
            bytes_sent = len(modified_payload)
            latency = (time.time() - start_time) * 1000
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=latency, packets_sent=packets_sent, bytes_sent=bytes_sent, connection_established=True, data_transmitted=True, metadata={'padding_size': padding_size, 'original_size': len(payload), 'modified_size': len(modified_payload), 'segments': segments if context.engine_type != 'local' else None})
        except Exception as e:
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=(time.time() - start_time) * 1000)

class TLSRecordFragmentationAttack(BaseAttack):
    """
    TLS Record Fragmentation Attack - fragments TLS records across multiple TCP segments.
    """

    @property
    def name(self) -> str:
        return 'tls_record_fragmentation'

    @property
    def category(self) -> str:
        return 'tls'

    @property
    def description(self) -> str:
        return 'Fragments TLS records across multiple TCP segments'

    @property
    def supported_protocols(self) -> List[str]:
        return ['tcp']

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute TLS record fragmentation attack."""
        start_time = time.time()
        try:
            payload = context.payload
            fragment_size = context.params.get('fragment_size', 8)
            if not payload.startswith(b'\x16\x03'):
                return AttackResult(status=AttackStatus.INVALID_PARAMS, error_message='Not a TLS record')
            segments = []
            offset = 0
            while offset < len(payload):
                chunk_size = min(fragment_size, len(payload) - offset)
                chunk = payload[offset:offset + chunk_size]
                segments.append((chunk, offset))
                offset += chunk_size
            packets_sent = len(segments)
            bytes_sent = len(payload)
            latency = (time.time() - start_time) * 1000
            return AttackResult(status=AttackStatus.SUCCESS, latency_ms=latency, packets_sent=packets_sent, bytes_sent=bytes_sent, connection_established=True, data_transmitted=True, metadata={'fragment_size': fragment_size, 'fragments_count': len(segments), 'segments': segments if context.engine_type != 'local' else None})
        except Exception as e:
            return AttackResult(status=AttackStatus.ERROR, error_message=str(e), latency_ms=(time.time() - start_time) * 1000)