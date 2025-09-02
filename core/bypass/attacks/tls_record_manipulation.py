"""
TLS Record Manipulation Attacks
"""

import time
import struct
import logging
from typing import List
from core.bypass.attacks.base import AttackContext, AttackResult, AttackStatus
from core.bypass.attacks.advanced_base import AdvancedAttack, AdvancedAttackConfig
from core.integration.advanced_attack_registry import get_advanced_attack_registry

LOG = logging.getLogger(__name__)


class ClientHelloSplitAttack(AdvancedAttack):
    """
    Splits a TLS ClientHello message into two separate TLS records within a single TCP packet.
    This is a valid RFC behavior that can break simple DPI parsers.
    """

    async def execute(self, context: AttackContext) -> AttackResult:
        start_time = time.time()
        try:
            payload = context.payload
            params = {**self.config.default_params, **context.params}
            split_pos = params.get("split_pos", 15)
            if not (
                len(payload) > 9 and payload.startswith(b"\x16") and (payload[5] == 1)
            ):
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message="Payload is not a valid ClientHello record.",
                )
            tls_record_content = payload[5:]
            if len(tls_record_content) <= split_pos:
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message=f"Payload too small to split at position {split_pos}.",
                )
            part1 = tls_record_content[:split_pos]
            part2 = tls_record_content[split_pos:]
            version_bytes = payload[1:3]
            record1 = b"\x16" + version_bytes + len(part1).to_bytes(2, "big") + part1
            record2 = b"\x16" + version_bytes + len(part2).to_bytes(2, "big") + part2
            modified_payload = record1 + record2
            result = AttackResult(
                status=AttackStatus.SUCCESS,
                technique_used=self.name,
                packets_sent=1,
                bytes_sent=len(modified_payload),
                processing_time_ms=(time.time() - start_time) * 1000,
            )
            result.segments = [(modified_payload, 0, {})]
            result.update_metadata(
                {
                    "split_pos": split_pos,
                    "original_size": len(payload),
                    "modified_size": len(modified_payload),
                    "record1_size": len(record1),
                    "record2_size": len(record2),
                }
            )
            return result
        except Exception as e:
            LOG.error(f"ClientHello split attack failed: {e}", exc_info=context.debug)
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                technique_used=self.name,
            )


class TLSRecordPaddingAttack(AdvancedAttack):
    """
    TLS Record Padding Attack - adds padding to a TLS record to change its size signature.
    """

    async def execute(self, context: AttackContext) -> AttackResult:
        start_time = time.time()
        try:
            payload = context.payload
            params = {**self.config.default_params, **context.params}
            padding_size = params.get("padding_size", 16)
            if not payload.startswith(b"\x16\x03"):
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS, error_message="Not a TLS record"
                )
            padding = b"\x00" * padding_size
            modified_payload = payload + padding
            if len(payload) >= 5:
                original_length = struct.unpack("!H", payload[3:5])[0]
                new_length = original_length + padding_size
                modified_payload = (
                    payload[:3] + struct.pack("!H", new_length) + payload[5:] + padding
                )
            result = AttackResult(
                status=AttackStatus.SUCCESS,
                technique_used=self.name,
                packets_sent=1,
                bytes_sent=len(modified_payload),
                processing_time_ms=(time.time() - start_time) * 1000,
            )
            result.segments = [(modified_payload, 0, {})]
            result.update_metadata(
                {
                    "padding_size": padding_size,
                    "original_size": len(payload),
                    "modified_size": len(modified_payload),
                }
            )
            return result
        except Exception as e:
            LOG.error(f"TLS record padding attack failed: {e}", exc_info=context.debug)
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                technique_used=self.name,
            )


ch_split_config = AdvancedAttackConfig(
    name="client_hello_split",
    priority=10,
    complexity="Medium",
    target_protocols=["tls"],
    dpi_signatures=["tls_aware_dpi", "bad_tls_parser_dpi", "generic_proxy"],
    description="Splits a ClientHello into two TLS records within one TCP packet to break weak DPI parsers.",
    default_params={"split_pos": 15},
    learning_enabled=True,
)
tls_padding_config = AdvancedAttackConfig(
    name="tls_record_padding",
    priority=50,
    complexity="Low",
    target_protocols=["tls"],
    dpi_signatures=["signature_matching_dpi"],
    description="Adds padding to TLS records to alter their size signature.",
    default_params={"padding_size": 32},
    learning_enabled=True,
)
try:
    registry = get_advanced_attack_registry()
    registry.register_attack(ClientHelloSplitAttack, ch_split_config)
    registry.register_attack(TLSRecordPaddingAttack, tls_padding_config)
    LOG.info("Successfully registered TLS record manipulation attacks.")
except Exception as e:
    LOG.error(f"Failed to register TLS record manipulation attacks: {e}")
