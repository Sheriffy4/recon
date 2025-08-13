# recon/core/packet_modification_validator.py

from dataclasses import dataclass
from typing import Optional, Dict, Any


@dataclass
class ModificationReport:
    success: bool
    reason: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class PacketModificationValidator:
    """Проверяет, что модификации действительно применены: payload изменён, seq/flags соответствуют ожиданиям."""

    def validate_segment(self, original_payload: bytes, new_payload: bytes, expected_seq: Optional[int] = None, new_seq: Optional[int] = None, is_last: bool = True) -> ModificationReport:
        try:
            if not isinstance(original_payload, (bytes, bytearray)):
                original_payload = bytes(original_payload)
            if not isinstance(new_payload, (bytes, bytearray)):
                new_payload = bytes(new_payload)
        except Exception:
            return ModificationReport(success=False, reason="payload_cast_error")

        if new_payload == original_payload:
            return ModificationReport(success=False, reason="payload_not_changed")

        if expected_seq is not None and new_seq is not None and ((new_seq - expected_seq) & 0xFFFFFFFF) != 0:
            # если явно не совпадает ожидаемая последовательность
            return ModificationReport(success=False, reason="seq_mismatch", details={"expected_seq": expected_seq, "new_seq": new_seq})

        return ModificationReport(success=True) 