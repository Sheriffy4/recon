"""
TLS Record Manipulation Attacks

Migrated and unified from:
- TlsRecSplitTechnique (core/fast_bypass/techniques/tcp_techniques.py)
- apply_tlsrec_split (core/fast_bypass.py)
"""

import logging
import random
import time
import struct
from typing import List, Dict, Any
from core.bypass.attacks.base import (
    BaseAttack,
    AttackContext,
    AttackResult,
    AttackStatus,
)
from core.bypass.attacks.attack_registry import register_attack, RegistrationPriority
from core.bypass.attacks.metadata import AttackCategories
from core.bypass.attacks.tls.tls_helpers import (
    clamp_int,
    coalesce,
    ensure_bytes,
    is_tls_record,
    normalize_segments_to_segment_tuples,
)

LOG = logging.getLogger(__name__)


def _read_tls_record_len(payload: bytes) -> int | None:
    """Return TLS record length from header, or None if header is missing."""
    if len(payload) < 5:
        return None
    return struct.unpack("!H", payload[3:5])[0]


@register_attack(
    name="tlsrec_split",
    category=AttackCategories.TLS,
    priority=RegistrationPriority.NORMAL,
    required_params=[],
    optional_params={"split_pos": 5},
    aliases=["tlsrec"],
    description="Splits one TLS record into two separate records",
)
class TLSRecordSplitAttack(BaseAttack):
    """
    TLS Record Split Attack - splits one TLS record into two.

    Migrated from:
    - TlsRecSplitTechnique (fast_bypass/techniques/tcp_techniques.py)
    - apply_tlsrec_split (fast_bypass.py)
    """

    @property
    def name(self) -> str:
        return "tlsrec_split"

    @property
    def category(self) -> str:
        return "tls"

    @property
    def description(self) -> str:
        return "Splits one TLS record into two separate records"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    @property
    def required_params(self) -> List[str]:
        """List of required parameter names."""
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        """Dictionary of optional parameters with default values."""
        return {"split_pos": 5}

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute TLS record split attack."""
        start_time = time.perf_counter()
        try:
            payload = ensure_bytes(context.payload)
            if payload is None:
                return AttackResult(
                    status=AttackStatus.ERROR, error_message="Payload must be bytes"
                )

            params = context.params or {}
            split_pos = clamp_int(params.get("split_pos", 5), 5, min_value=1, max_value=16_384)

            # Must be a Handshake TLS record (content_type=22, version major=3)
            rec_len = _read_tls_record_len(payload)
            if (
                rec_len is None
                or payload[0] != 22
                or payload[1] != 3
                or len(payload) < 5 + rec_len
            ):
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS, error_message="Not a valid TLS handshake record"
                )

            if split_pos >= rec_len:
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS, error_message="split_pos exceeds TLS record size"
                )

            header_prefix = payload[:3]  # content_type + version (preserve original)
            record_body = payload[5 : 5 + rec_len]
            trailing = payload[5 + rec_len :]  # keep any subsequent records untouched

            part1 = record_body[:split_pos]
            part2 = record_body[split_pos:]

            record1 = header_prefix + len(part1).to_bytes(2, "big") + part1
            record2 = header_prefix + len(part2).to_bytes(2, "big") + part2
            modified_payload = record1 + record2 + trailing

            # One TCP send (record-level split)
            segments = [(modified_payload, 0)]
            norm_segments = normalize_segments_to_segment_tuples(segments)

            latency = (time.perf_counter() - start_time) * 1000
            result = AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=len(norm_segments),
                bytes_sent=len(modified_payload),
                connection_established=True,
                data_transmitted=True,
                modified_payload=modified_payload,
                metadata={
                    "split_pos": split_pos,
                    "original_size": len(payload),
                    "modified_size": len(modified_payload),
                    "record1_size": len(record1),
                    "record2_size": len(record2),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )
            if context.engine_type != "local":
                result.segments = norm_segments
            return result
        except Exception as e:
            LOG.debug("TLSRecordSplitAttack.execute failed", exc_info=True)
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.perf_counter() - start_time) * 1000,
            )


@register_attack(
    name="tls_record_padding",
    category=AttackCategories.TLS,
    priority=RegistrationPriority.HIGH,
    required_params=[],
    optional_params={"padding_size": 16},
    aliases=["tlsrec_padding", "tls_padding"],
    description="Adds padding to TLS records to change their size",
)
class TLSRecordPaddingAttack(BaseAttack):
    """
    TLS Record Padding Attack - adds padding to TLS records.
    """

    @property
    def name(self) -> str:
        return "tls_record_padding"

    @property
    def category(self) -> str:
        return "tls"

    @property
    def description(self) -> str:
        return "Adds padding to TLS records to change their size"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    @property
    def required_params(self) -> List[str]:
        """List of required parameter names."""
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        """Dictionary of optional parameters with default values."""
        return {"padding_size": 16}

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute TLS record padding attack."""
        start_time = time.perf_counter()
        try:
            payload = ensure_bytes(context.payload)
            if payload is None:
                return AttackResult(
                    status=AttackStatus.ERROR, error_message="Payload must be bytes"
                )

            params = context.params or {}
            padding_size = clamp_int(params.get("padding_size", 16), 16, min_value=0, max_value=65_535)

            if not is_tls_record(payload):
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS, error_message="Not a TLS record"
                )

            rec_len = _read_tls_record_len(payload)
            if rec_len is None or len(payload) < 5 + rec_len:
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS, error_message="Malformed TLS record"
                )

            header_prefix = payload[:3]
            record_body = payload[5 : 5 + rec_len]
            trailing = payload[5 + rec_len :]

            if rec_len + padding_size > 0xFFFF:
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS, error_message="Resulting TLS record length overflow"
                )

            padding = b"\x00" * padding_size
            new_len = rec_len + padding_size
            record_padded = header_prefix + struct.pack("!H", new_len) + record_body + padding
            modified_payload = record_padded + trailing

            segments = [(modified_payload, 0)]
            norm_segments = normalize_segments_to_segment_tuples(segments)
            latency = (time.perf_counter() - start_time) * 1000
            result = AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=len(norm_segments),
                bytes_sent=len(modified_payload),
                connection_established=True,
                data_transmitted=True,
                modified_payload=modified_payload,
                metadata={
                    "padding_size": padding_size,
                    "original_size": len(payload),
                    "modified_size": len(modified_payload),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )
            if context.engine_type != "local":
                result.segments = norm_segments
            return result
        except Exception as e:
            LOG.debug("TLSRecordPaddingAttack.execute failed", exc_info=True)
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.perf_counter() - start_time) * 1000,
            )


@register_attack(
    name="tls_record_fragmentation",
    category=AttackCategories.TLS,
    priority=RegistrationPriority.HIGH,
    required_params=[],
    optional_params={"fragment_size": 8},
    aliases=["tlsrec_fragment", "tls_fragment"],
    description="Fragments TLS records across multiple TCP segments",
)
class TLSRecordFragmentationAttack(BaseAttack):
    """
    TLS Record Fragmentation Attack - fragments TLS records across multiple TCP segments.
    """

    @property
    def name(self) -> str:
        return "tls_record_fragmentation"

    @property
    def category(self) -> str:
        return "tls"

    @property
    def description(self) -> str:
        return "Fragments TLS records across multiple TCP segments"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    @property
    def required_params(self) -> List[str]:
        """List of required parameter names."""
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        """Dictionary of optional parameters with default values."""
        # Backward compatible defaults (old behavior: fixed TCP segmentation by fragment_size=8)
        return {
            "fragment_size": 8,
            "fragmentation_method": "tcp_segments",  # tcp_segments | tls_record | mixed | adaptive
            "max_fragments": 8,
            "randomize_sizes": False,
        }

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute TLS record fragmentation attack."""
        start_time = time.perf_counter()
        try:
            payload = ensure_bytes(context.payload)
            if payload is None:
                return AttackResult(
                    status=AttackStatus.ERROR, error_message="Payload must be bytes"
                )

            params = context.params or {}
            fragment_size = clamp_int(params.get("fragment_size", 8), 8, min_value=1, max_value=16_384)
            max_fragments = clamp_int(params.get("max_fragments", 8), 8, min_value=1, max_value=256)
            randomize_sizes = bool(coalesce(params, "randomize_sizes", default=False))
            fragmentation_method = coalesce(
                params, "fragmentation_method", "fragmentation_type", default="tcp_segments"
            )

            if not is_tls_record(payload):
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS, error_message="Not a TLS record"
                )

            method = str(fragmentation_method).lower()
            if method in ("tcp", "tcp_segment", "tcp_segments"):
                modified_payload, segments = self._fragment_tcp_segments(payload, fragment_size, randomize_sizes)
            elif method in ("tls_record", "record", "tls_records"):
                modified_payload, segments = self._fragment_tls_records(payload, fragment_size)
            elif method == "mixed":
                modified_payload, segments = self._mixed_fragmentation(payload, fragment_size)
            elif method == "adaptive":
                modified_payload, segments = self._adaptive_fragmentation(payload, max_fragments)
            else:
                modified_payload, segments = self._fragment_tcp_segments(payload, fragment_size, randomize_sizes)

            norm_segments = normalize_segments_to_segment_tuples(segments)
            bytes_sent = sum(len(s[0]) for s in norm_segments)
            latency = (time.perf_counter() - start_time) * 1000

            result = AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=len(norm_segments),
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                modified_payload=modified_payload,
                metadata={
                    "fragment_size": fragment_size,
                    "fragmentation_method": method,
                    "max_fragments": max_fragments,
                    "randomize_sizes": randomize_sizes,
                    "fragments_count": len(norm_segments),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )
            if context.engine_type != "local":
                result.segments = norm_segments
            return result
        except Exception as e:
            LOG.debug("TLSRecordFragmentationAttack.execute failed", exc_info=True)
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.perf_counter() - start_time) * 1000,
            )

    def _fragment_tcp_segments(
        self, payload: bytes, fragment_size: int, randomize_sizes: bool
    ) -> tuple[bytes, list[tuple[bytes, int]]]:
        """Fragment payload across TCP segments."""
        segments: list[tuple[bytes, int]] = []
        offset = 0
        while offset < len(payload):
            if randomize_sizes:
                min_rand = max(1, fragment_size // 2)
                max_rand = min(len(payload) - offset, fragment_size * 2)
                current = max_rand if min_rand >= max_rand else random.randint(min_rand, max_rand)
            else:
                current = min(fragment_size, len(payload) - offset)
            if current <= 0:
                break
            segments.append((payload[offset : offset + current], offset))
            offset += current
        return payload, segments

    def _fragment_tls_records(
        self, payload: bytes, fragment_size: int
    ) -> tuple[bytes, list[tuple[bytes, int]]]:
        """Fragment by splitting TLS records into smaller records (single TCP send)."""
        try:
            new_records: list[bytes] = []
            offset = 0
            while offset < len(payload):
                if offset + 5 > len(payload):
                    new_records.append(payload[offset:])
                    break
                content_type = payload[offset]
                version = payload[offset + 1 : offset + 3]
                record_length = struct.unpack("!H", payload[offset + 3 : offset + 5])[0]
                if offset + 5 + record_length > len(payload):
                    new_records.append(payload[offset:])
                    break
                record_data = payload[offset + 5 : offset + 5 + record_length]
                if record_length > fragment_size:
                    data_offset = 0
                    while data_offset < len(record_data):
                        chunk_size = min(fragment_size, len(record_data) - data_offset)
                        chunk_data = record_data[data_offset : data_offset + chunk_size]
                        new_records.append(
                            bytes([content_type]) + version + struct.pack("!H", len(chunk_data)) + chunk_data
                        )
                        data_offset += chunk_size
                else:
                    new_records.append(payload[offset : offset + 5 + record_length])
                offset += 5 + record_length
            combined = b"".join(new_records)
            return combined, [(combined, 0)]
        except Exception:
            LOG.debug("TLSRecordFragmentationAttack._fragment_tls_records failed", exc_info=True)
            return payload, [(payload, 0)]

    def _mixed_fragmentation(
        self, payload: bytes, fragment_size: int
    ) -> tuple[bytes, list[tuple[bytes, int]]]:
        """Apply mixed fragmentation (TLS record level + TCP level)."""
        record_fragmented, _ = self._fragment_tls_records(payload, fragment_size * 2)
        return self._fragment_tcp_segments(record_fragmented, fragment_size, True)

    def _adaptive_fragmentation(
        self, payload: bytes, max_fragments: int
    ) -> tuple[bytes, list[tuple[bytes, int]]]:
        """Adaptive TCP fragmentation based on payload size."""
        payload_size = len(payload)
        if payload_size <= 100:
            fragment_size = max(20, payload_size // 2)
        elif payload_size <= 500:
            fragment_size = payload_size // min(max_fragments, 5)
        else:
            fragment_size = payload_size // max_fragments
        fragment_size = max(16, fragment_size)
        return self._fragment_tcp_segments(payload, fragment_size, True)
