import time
import logging
from typing import List, Dict, Any
from core.bypass.attacks.base import AttackContext, AttackResult, AttackStatus
from core.bypass.attacks.base import BaseAttack
from core.bypass.attacks.metadata import AttackCategories
from core.bypass.attacks.attack_registry import register_attack

LOG = logging.getLogger(__name__)


class StatefulFragmentationAttack(BaseAttack):
    """
    Sends a fragmented payload with a garbage packet in the middle to confuse stateful DPIs.
    Example sequence for a ClientHello:
    1. TCP Segment 1: ClientHello[0:10] (valid)
    2. TCP Segment 2: "garbage_data" (invalid checksum, will be dropped by host)
    3. TCP Segment 3: ClientHello[10:] (valid)
    The host's TCP stack should ignore the garbage packet and reassemble the valid fragments.
    A less sophisticated DPI might see the garbage and fail to reassemble the stream correctly.
    """

    @property
    def name(self) -> str:
        return "stateful_fragmentation"

    @property
    def category(self) -> str:
        return AttackCategories.TCP

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> dict:
        return {"split_pos": 10, "garbage_data": b"GARBAGE_PACKET"}

    def execute(self, context: AttackContext) -> AttackResult:
        start_time = time.time()
        try:
            payload = context.payload
            if not payload or len(payload) < 20:
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message="Payload too small for stateful fragmentation.",
                )
            params = context.params
            split_pos = params.get("split_pos", 10)
            garbage_data_param = params.get("garbage_data", b"GARBAGE_PACKET")
            garbage_data = (
                garbage_data_param.encode()
                if isinstance(garbage_data_param, str)
                else garbage_data_param
            )
            part1 = payload[:split_pos]
            segment1_options = {}
            segment1 = (part1, 0, segment1_options)
            garbage_options = {"bad_checksum": True}
            garbage_seq_offset = len(part1)
            segment2 = (garbage_data, garbage_seq_offset, garbage_options)
            part2 = payload[split_pos:]
            segment3_options = {}
            part2_seq_offset = len(part1)
            segment3 = (part2, part2_seq_offset, segment3_options)
            segments = [segment1, segment2, segment3]
            result = AttackResult(
                status=AttackStatus.SUCCESS,
                technique_used=self.name,
                packets_sent=len(segments),
                bytes_sent=sum((len(s[0]) for s in segments)),
                processing_time_ms=(time.time() - start_time) * 1000,
            )
            result.segments = segments
            result.update_metadata(
                {
                    "fragmentation_type": "stateful_garbage_injection",
                    "split_position": split_pos,
                    "garbage_size": len(garbage_data),
                }
            )
            return result
        except Exception as e:
            LOG.error(
                f"Stateful fragmentation attack failed: {e}", exc_info=context.debug
            )
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                technique_used=self.name,
            )


class AdvancedOverlapAttack(BaseAttack):
    """
    Sends overlapping TCP segments with different data.
    - Segment 1 (for DPI): Contains `dpi_payload`
    - Segment 2 (for host): Overlaps segment 1 and contains `real_payload`
    A compliant TCP stack will favor the later data, accepting `real_payload`.
    A simple DPI might inspect the `dpi_payload` and miss the real data.
    """

    @property
    def name(self) -> str:
        return "advanced_overlap"

    @property
    def category(self) -> str:
        return AttackCategories.TCP

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> dict:
        return {"dpi_payload": b"GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n"}

    def execute(self, context: AttackContext) -> AttackResult:
        start_time = time.time()
        try:
            real_payload = context.payload
            if not real_payload:
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message="Payload is empty.",
                )
            params = context.params
            dpi_payload_param = params.get("dpi_payload", b"GET / HTTP/1.1\\r\\n\\r\\n")
            dpi_payload = (
                dpi_payload_param.encode()
                if isinstance(dpi_payload_param, str)
                else dpi_payload_param
            )
            segment1_options = {}
            segment1 = (dpi_payload, 0, segment1_options)
            segment2_options = {}
            segment2 = (real_payload, 0, segment2_options)
            segments = [segment1, segment2]
            result = AttackResult(
                status=AttackStatus.SUCCESS,
                technique_used=self.name,
                packets_sent=len(segments),
                bytes_sent=sum((len(s[0]) for s in segments)),
                processing_time_ms=(time.time() - start_time) * 1000,
            )
            result.segments = segments
            result.update_metadata(
                {
                    "fragmentation_type": "advanced_overlap",
                    "dpi_payload_size": len(dpi_payload),
                    "real_payload_size": len(real_payload),
                }
            )
            return result
        except Exception as e:
            LOG.error(f"Advanced overlap attack failed: {e}", exc_info=context.debug)
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                technique_used=self.name,
            )


# Note: Attack registration is handled by the @register_attack decorator
# These classes can be imported and used directly or registered via decorator
