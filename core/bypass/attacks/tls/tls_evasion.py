from __future__ import annotations

import time
import random
import struct
import os
import logging
from typing import List, Tuple, Dict, Any, Optional

from core.bypass.attacks.base import (
    BaseAttack,
    AttackContext,
    AttackResult,
    AttackStatus,
)
from core.bypass.attacks.attack_registry import register_attack
from core.bypass.attacks.tls.tls_helpers import (
    clamp_int,
    coalesce,
    ensure_bytes,
    normalize_segments_to_segment_tuples,
    is_tls_handshake_payload,
    is_tls_record,
    client_hello_body_offset,
    SegmentTuple,
)
from core.bypass.attacks.tls.tls_parser import (
    find_extensions_offset_client_hello,
    recalculate_tls_handshake_lengths,
    normalize_tls_version_key,
)
from core.bypass.attacks.tls.tls_extension_utils import (
    randomize_extension_order as randomize_extensions,
    insert_extensions as insert_extensions_util,
    rebuild_extensions as rebuild_extensions_util,
)
from core.bypass.attacks.tls.tls_fake_generators import (
    create_fake_certificate_message,
    create_fake_server_hello,
    add_fake_handshake_messages,
)

"""
Comprehensive TLS Evasion Attacks Implementation

This module implements the core TLS evasion attacks required by task 7:
- TLS handshake manipulation techniques
- TLS version downgrade attacks
- TLS extension manipulation
- TLS record fragmentation attacks

These attacks are designed to evade DPI systems that analyze TLS traffic patterns.
"""

LOG = logging.getLogger(__name__)

# Backward compatibility aliases (deprecated, use tls_helpers/tls_parser directly)
_clamp_int = clamp_int
_coalesce = coalesce
_ensure_bytes = ensure_bytes
_normalize_segments_to_segment_tuples = normalize_segments_to_segment_tuples
_is_tls_handshake_payload = is_tls_handshake_payload
_is_tls_record = is_tls_record
_client_hello_body_offset = client_hello_body_offset
_find_extensions_offset_client_hello = find_extensions_offset_client_hello
_recalculate_tls_handshake_lengths = recalculate_tls_handshake_lengths
_normalize_tls_version_key = normalize_tls_version_key


@register_attack
class TLSHandshakeManipulationAttack(BaseAttack):
    """
    TLS Handshake Manipulation Attack - modifies TLS handshake structure and timing.

    This attack manipulates various aspects of the TLS handshake to evade DPI detection:
    - Handshake message ordering
    - Message fragmentation
    - Timing manipulation
    - Fake handshake messages
    """

    @property
    def name(self) -> str:
        return "tls_handshake_manipulation"

    @property
    def category(self) -> str:
        return "tls"

    @property
    def description(self) -> str:
        return "Manipulates TLS handshake structure and timing to evade DPI"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {
            # Keep legacy values/keys while documenting the canonical ones.
            "manipulation_type": "fragment_hello",
            "fragment_size": 64,
            "timing_delay_ms": 10,
            "include_fake_messages": False,
            # legacy/alternate keys:
            "add_fake_messages": False,
            "randomize_timing": False,
        }

    def _validate_and_prepare_params(
        self, context: AttackContext
    ) -> tuple[bytes, Dict[str, Any], Optional[AttackResult]]:
        """
        Validate payload and prepare parameters for manipulation.

        Returns:
            Tuple of (payload, prepared_params, error_result)
            If error_result is not None, execution should stop and return it.
        """
        payload = _ensure_bytes(context.payload)
        if payload is None:
            error = AttackResult(status=AttackStatus.ERROR, error_message="Payload must be bytes")
            return (b"", {}, error)

        if not _is_tls_handshake_payload(payload):
            error = AttackResult(
                status=AttackStatus.INVALID_PARAMS,
                error_message="Payload is not a valid TLS handshake",
            )
            return (b"", {}, error)

        params = context.params or {}

        # Extract and normalize manipulation_type
        manipulation_type = _coalesce(params, "manipulation_type", default="fragment_hello")
        if manipulation_type in ("fragmentation", "fragment"):
            manipulation_type = "fragment_hello"

        # Extract and validate numeric parameters
        fragment_size = _clamp_int(
            params.get("fragment_size", 64), 64, min_value=1, max_value=16_384
        )
        timing_delay_ms = _clamp_int(
            _coalesce(params, "timing_delay_ms", default=10), 10, min_value=0, max_value=60_000
        )

        # Extract boolean flags
        add_fake_messages = bool(
            _coalesce(params, "include_fake_messages", "add_fake_messages", default=False)
        )
        randomize_timing = bool(_coalesce(params, "randomize_timing", default=False))

        prepared_params = {
            "manipulation_type": manipulation_type,
            "fragment_size": fragment_size,
            "timing_delay_ms": timing_delay_ms,
            "add_fake_messages": add_fake_messages,
            "randomize_timing": randomize_timing,
        }

        return (payload, prepared_params, None)

    def _apply_manipulation(self, payload: bytes, params: Dict[str, Any]) -> tuple[Any, List[Any]]:
        """
        Apply the primary manipulation based on manipulation_type.

        Args:
            payload: Original TLS handshake payload
            params: Prepared parameters from _validate_and_prepare_params

        Returns:
            Tuple of (modified_payload, segments)
        """
        manipulation_type = params["manipulation_type"]
        fragment_size = params["fragment_size"]
        timing_delay_ms = params["timing_delay_ms"]

        if manipulation_type == "fragment_hello":
            return self._fragment_client_hello(payload, fragment_size)
        elif manipulation_type == "reorder_extensions":
            return self._reorder_extensions(payload)
        elif manipulation_type == "split_handshake":
            return self._split_handshake_messages(payload)
        elif manipulation_type == "fake_messages":
            return self._add_fake_handshake_messages(payload)
        elif manipulation_type == "timing_manipulation":
            return self._apply_timing_manipulation(payload, base_delay_ms=timing_delay_ms)
        else:
            # Default fallback
            return self._fragment_client_hello(payload, fragment_size)

    def _apply_optional_manipulations(
        self,
        payload: bytes,
        modified_payload: Any,
        segments: List[Any],
        params: Dict[str, Any],
        context: AttackContext,
    ) -> tuple[Any, List[Any], Optional[List[SegmentTuple]]]:
        """
        Apply optional additional manipulations (fake messages, timing).

        Args:
            payload: Original payload
            modified_payload: Payload after primary manipulation
            segments: Segments after primary manipulation
            params: Prepared parameters
            context: Attack context

        Returns:
            Tuple of (final_modified_payload, final_segments, timing_segments)
        """
        manipulation_type = params["manipulation_type"]
        add_fake_messages = params["add_fake_messages"]
        randomize_timing = params["randomize_timing"]
        timing_delay_ms = params["timing_delay_ms"]
        timing_segments: Optional[List[SegmentTuple]] = None

        # Optional additional fake messages
        if add_fake_messages and manipulation_type not in ("fake_messages",):
            payload_for_fake = (
                modified_payload if isinstance(modified_payload, (bytes, bytearray)) else payload
            )
            modified_payload, segments = self._add_fake_handshake_messages(payload_for_fake)

        # Optional timing randomization (metadata only)
        if randomize_timing and manipulation_type not in ("timing_manipulation",):
            payload_for_timing = (
                modified_payload if isinstance(modified_payload, (bytes, bytearray)) else payload
            )
            _, timing_segments_raw = self._apply_timing_manipulation(  # type: ignore[assignment]
                payload_for_timing, base_delay_ms=timing_delay_ms
            )
            timing_segments = _normalize_segments_to_segment_tuples(timing_segments_raw)

        return (modified_payload, segments, timing_segments)

    def _build_result(
        self,
        payload: bytes,
        modified_payload: Any,
        segments: List[Any],
        params: Dict[str, Any],
        timing_segments: Optional[List[SegmentTuple]],
        context: AttackContext,
        start_time: float,
    ) -> AttackResult:
        """
        Build the final AttackResult with all metadata.

        Args:
            payload: Original payload
            modified_payload: Final modified payload
            segments: Final segments
            params: Prepared parameters
            timing_segments: Optional timing segments
            context: Attack context
            start_time: Execution start time

        Returns:
            Complete AttackResult
        """
        # Normalize segments for orchestration engines
        norm_segments = _normalize_segments_to_segment_tuples(segments)
        packets_sent = len(norm_segments)
        bytes_sent = sum(len(seg[0]) for seg in norm_segments)

        # Ensure payload is bytes
        modified_payload_bytes = (
            bytes(modified_payload) if isinstance(modified_payload, (bytes, bytearray)) else payload
        )

        latency = (time.perf_counter() - start_time) * 1000

        result = AttackResult(
            status=AttackStatus.SUCCESS,
            latency_ms=latency,
            packets_sent=packets_sent,
            bytes_sent=bytes_sent,
            connection_established=True,
            data_transmitted=True,
            modified_payload=modified_payload_bytes,
            metadata={
                "manipulation_type": params["manipulation_type"],
                "fragment_size": params["fragment_size"],
                "segments_count": len(norm_segments),
                "add_fake_messages": params["add_fake_messages"],
                "randomize_timing": params["randomize_timing"],
                "timing_delay_ms": params["timing_delay_ms"],
                "original_size": len(payload),
                "modified_size": len(modified_payload_bytes),
                "timing_segments": (
                    timing_segments
                    if (params["randomize_timing"] and context.engine_type != "local")
                    else None
                ),
            },
        )

        # Store segments for orchestration engines
        if context.engine_type != "local":
            result.segments = norm_segments

        return result

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute TLS handshake manipulation attack."""
        start_time = time.perf_counter()
        try:
            # Step 1: Validate and prepare parameters
            payload, params, error = self._validate_and_prepare_params(context)
            if error is not None:
                return error

            # Step 2: Apply primary manipulation
            modified_payload, segments = self._apply_manipulation(payload, params)

            # Step 3: Apply optional manipulations
            modified_payload, segments, timing_segments = self._apply_optional_manipulations(
                payload, modified_payload, segments, params, context
            )

            # Step 4: Build and return result
            return self._build_result(
                payload, modified_payload, segments, params, timing_segments, context, start_time
            )
        except Exception as e:
            LOG.debug("TLSHandshakeManipulationAttack.execute failed", exc_info=True)
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.perf_counter() - start_time) * 1000,
            )

    def _fragment_client_hello(
        self, payload: bytes, fragment_size: int
    ) -> Tuple[bytes, List[Tuple[bytes, int]]]:
        """Fragment ClientHello across multiple TCP segments."""
        segments = []
        offset = 0
        while offset < len(payload):
            chunk_size = min(fragment_size, len(payload) - offset)
            chunk = payload[offset : offset + chunk_size]
            segments.append((chunk, offset))
            offset += chunk_size
        return (payload, segments)

    def _reorder_extensions(self, payload: bytes) -> Tuple[bytes, List[Tuple[bytes, int]]]:
        """Reorder TLS extensions to confuse DPI."""
        try:
            extensions_start = find_extensions_offset_client_hello(payload)
            if extensions_start == -1:
                return (payload, [(payload, 0)])
            modified_payload = self._randomize_extension_order(payload, extensions_start)
            return (modified_payload, [(modified_payload, 0)])
        except Exception:
            LOG.debug("TLSHandshakeManipulationAttack._reorder_extensions failed", exc_info=True)
            return (payload, [(payload, 0)])

    def _split_handshake_messages(self, payload: bytes) -> Tuple[bytes, List[Tuple[bytes, int]]]:
        """Split handshake into multiple messages."""
        segments = []
        offset = 0
        while offset < len(payload):
            if offset + 5 > len(payload):
                segments.append((payload[offset:], offset))
                break
            record_length = struct.unpack("!H", payload[offset + 3 : offset + 5])[0]
            total_record_size = 5 + record_length
            if offset + total_record_size > len(payload):
                segments.append((payload[offset:], offset))
                break
            record = payload[offset : offset + total_record_size]
            segments.append((record, offset))
            offset += total_record_size
        return (payload, segments)

    def _add_fake_handshake_messages(self, payload: bytes) -> Tuple[bytes, List[Tuple[bytes, int]]]:
        """Add fake handshake messages to confuse DPI."""
        combined_payload = add_fake_handshake_messages(payload)
        return (combined_payload, [(combined_payload, 0)])

    def _apply_timing_manipulation(
        self, payload: bytes, *, base_delay_ms: int = 10
    ) -> Tuple[bytes, List[Tuple[bytes, int, Dict[str, int]]]]:
        """Apply timing-based manipulation."""
        segments = []
        fragment_size = 32
        for i in range(0, len(payload), fragment_size):
            chunk = payload[i : i + fragment_size]
            # base_delay_ms == 0 means "no intentional delay", still allow tiny jitter for evasion
            low = max(0, base_delay_ms // 2)
            high = max(low, base_delay_ms * 2) if base_delay_ms else 5
            delay_ms = random.randint(low, high)
            segments.append((chunk, i, {"delay_ms": delay_ms}))
        return (payload, segments)

    def _randomize_extension_order(self, payload: bytes, extensions_start: int) -> bytes:
        """Randomize the order of TLS extensions."""
        return randomize_extensions(payload, extensions_start, keep_sni_first=True)


@register_attack
class TLSVersionDowngradeAttack(BaseAttack):
    """
    TLS Version Downgrade Attack - forces downgrade to older TLS versions.

    This attack manipulates TLS version fields to force downgrade to less secure
    versions that may be easier to bypass or have known vulnerabilities.
    """

    @property
    def name(self) -> str:
        return "tls_version_downgrade"

    @property
    def category(self) -> str:
        return "tls"

    @property
    def description(self) -> str:
        return "Forces TLS version downgrade to evade modern DPI detection"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {
            "target_version": "tls12",
            "downgrade_method": "record_version",
            "include_fallback_scsv": True,
            # legacy:
            "add_fallback_scsv": False,
        }

    def _validate_and_prepare_params(
        self, context: AttackContext
    ) -> tuple[bytes, Dict[str, Any], Optional[AttackResult]]:
        """
        Validate payload and prepare parameters for version downgrade.

        Returns:
            Tuple of (payload, prepared_params, error_result)
            If error_result is not None, execution should stop and return it.
        """
        payload = _ensure_bytes(context.payload)
        if payload is None:
            error = AttackResult(status=AttackStatus.ERROR, error_message="Payload must be bytes")
            return (b"", {}, error)

        if not _is_tls_handshake_payload(payload):
            error = AttackResult(
                status=AttackStatus.INVALID_PARAMS,
                error_message="Payload is not a valid TLS handshake",
            )
            return (b"", {}, error)

        params = context.params or {}

        # Normalize target version
        target_version = _normalize_tls_version_key(params.get("target_version", "tls12"))

        # Extract downgrade method
        downgrade_method = _coalesce(params, "downgrade_method", default="record_version")

        # Extract boolean flags
        modify_supported_versions = bool(
            _coalesce(params, "modify_supported_versions", default=True)
        )
        add_fallback_scsv = bool(
            _coalesce(params, "include_fallback_scsv", "add_fallback_scsv", default=False)
        )

        # Map version string to bytes
        version_map = {
            "ssl30": b"\x03\x00",
            "tls10": b"\x03\x01",
            "tls11": b"\x03\x02",
            "tls12": b"\x03\x03",
            "tls13": b"\x03\x04",
        }
        target_version_bytes = version_map.get(target_version, b"\x03\x03")

        prepared_params = {
            "target_version": target_version,
            "target_version_bytes": target_version_bytes,
            "downgrade_method": downgrade_method,
            "modify_supported_versions": modify_supported_versions,
            "add_fallback_scsv": add_fallback_scsv,
        }

        return (payload, prepared_params, None)

    def _apply_downgrade(self, payload: bytes, params: Dict[str, Any]) -> bytes:
        """
        Apply version downgrade to the payload.

        Args:
            payload: Original TLS handshake payload
            params: Prepared parameters from _validate_and_prepare_params

        Returns:
            Modified payload with version downgrade applied
        """
        return self._apply_version_downgrade(
            payload,
            params["target_version_bytes"],
            params["modify_supported_versions"],
            params["add_fallback_scsv"],
            downgrade_method=params["downgrade_method"],
        )

    def _build_result(
        self,
        payload: bytes,
        modified_payload: bytes,
        params: Dict[str, Any],
        context: AttackContext,
        start_time: float,
    ) -> AttackResult:
        """
        Build the final AttackResult with all metadata.

        Args:
            payload: Original payload
            modified_payload: Modified payload after downgrade
            params: Prepared parameters
            context: Attack context
            start_time: Execution start time

        Returns:
            Complete AttackResult
        """
        bytes_sent = len(modified_payload)
        latency = (time.perf_counter() - start_time) * 1000

        result = AttackResult(
            status=AttackStatus.SUCCESS,
            latency_ms=latency,
            packets_sent=1,
            bytes_sent=bytes_sent,
            connection_established=True,
            data_transmitted=True,
            modified_payload=modified_payload,
            metadata={
                "target_version": params["target_version"],
                "target_version_bytes": params["target_version_bytes"].hex(),
                "downgrade_method": params["downgrade_method"],
                "modify_supported_versions": params["modify_supported_versions"],
                "add_fallback_scsv": params["add_fallback_scsv"],
                "original_size": len(payload),
                "modified_size": len(modified_payload),
            },
        )

        # Store segments for orchestration engines
        if context.engine_type != "local":
            result.segments = [(modified_payload, 0, {})]

        return result

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute TLS version downgrade attack."""
        start_time = time.perf_counter()
        try:
            # Step 1: Validate and prepare parameters
            payload, params, error = self._validate_and_prepare_params(context)
            if error is not None:
                return error

            # Step 2: Apply version downgrade
            modified_payload = self._apply_downgrade(payload, params)

            # Step 3: Build and return result
            return self._build_result(payload, modified_payload, params, context, start_time)
        except Exception as e:
            LOG.debug("TLSVersionDowngradeAttack.execute failed", exc_info=True)
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.perf_counter() - start_time) * 1000,
            )

    def _apply_version_downgrade(
        self,
        payload: bytes,
        target_version: bytes,
        modify_supported_versions: bool,
        add_fallback_scsv: bool,
        downgrade_method: str = "record_version",
    ) -> bytes:
        """Apply TLS version downgrade to the payload."""
        try:
            modified_payload = bytearray(payload)
            # record_version: TLSPlaintext.version
            if downgrade_method in ("record_version", "both", "all"):
                modified_payload[1:3] = target_version
            # client_hello_version: ClientHello.client_version
            if downgrade_method in ("client_hello_version", "both", "all"):
                if len(modified_payload) > 10:
                    modified_payload[9:11] = target_version
            if modify_supported_versions:
                modified_payload = self._modify_supported_versions_extension(
                    bytes(modified_payload), target_version
                )
            if add_fallback_scsv:
                modified_payload = self._add_fallback_scsv(bytes(modified_payload))
            return _recalculate_tls_handshake_lengths(bytes(modified_payload))
        except Exception:
            return payload

    def _modify_supported_versions_extension(self, payload: bytes, target_version: bytes) -> bytes:
        """Modify the supported_versions extension to only include target version."""
        try:
            extensions_start = find_extensions_offset_client_hello(payload)
            if extensions_start == -1:
                return payload
            extensions_len = struct.unpack("!H", payload[extensions_start : extensions_start + 2])[
                0
            ]
            extensions_end = extensions_start + 2 + extensions_len
            offset = extensions_start + 2
            new_extensions_data = b""
            while offset < extensions_end:
                if offset + 4 > len(payload):
                    break
                ext_type = struct.unpack("!H", payload[offset : offset + 2])[0]
                ext_len = struct.unpack("!H", payload[offset + 2 : offset + 4])[0]
                if offset + 4 + ext_len > len(payload):
                    break
                if ext_type == 43:
                    new_ext_data = b"\x02" + target_version
                    new_extensions_data += struct.pack("!H", ext_type)
                    new_extensions_data += struct.pack("!H", len(new_ext_data))
                    new_extensions_data += new_ext_data
                else:
                    ext_data = payload[offset + 4 : offset + 4 + ext_len]
                    new_extensions_data += struct.pack("!H", ext_type)
                    new_extensions_data += struct.pack("!H", ext_len)
                    new_extensions_data += ext_data
                offset += 4 + ext_len
            new_payload = payload[:extensions_start]
            new_payload += struct.pack("!H", len(new_extensions_data))
            new_payload += new_extensions_data
            new_payload += payload[extensions_end:]
            return _recalculate_tls_handshake_lengths(new_payload)
        except Exception:
            LOG.debug(
                "TLSVersionDowngradeAttack._modify_supported_versions_extension failed",
                exc_info=True,
            )
            return payload

    def _add_fallback_scsv(self, payload: bytes) -> bytes:
        """Add TLS_FALLBACK_SCSV to cipher suites."""
        try:
            body = _client_hello_body_offset(payload)
            if body is None:
                return payload
            offset = body + 2 + 32  # version + random
            if offset >= len(payload):
                return payload
            session_id_len = payload[offset]
            offset += 1 + session_id_len
            if offset + 2 > len(payload):
                return payload
            cipher_suites_len = struct.unpack("!H", payload[offset : offset + 2])[0]
            cipher_suites_data = payload[offset + 2 : offset + 2 + cipher_suites_len]
            fallback_scsv = b"V\x00"
            if fallback_scsv not in cipher_suites_data:
                new_cipher_suites = cipher_suites_data + fallback_scsv
                new_cipher_suites_len = len(new_cipher_suites)
                new_payload = payload[:offset]
                new_payload += struct.pack("!H", new_cipher_suites_len)
                new_payload += new_cipher_suites
                new_payload += payload[offset + 2 + cipher_suites_len :]
                return _recalculate_tls_handshake_lengths(new_payload)
            return payload
        except Exception:
            LOG.debug("TLSVersionDowngradeAttack._add_fallback_scsv failed", exc_info=True)
            return payload


@register_attack
class TLSExtensionManipulationAttack(BaseAttack):
    """
    TLS Extension Manipulation Attack - manipulates TLS extensions to evade DPI.

    This attack modifies, reorders, or injects TLS extensions to confuse DPI systems
    that rely on extension patterns for detection.
    """

    @property
    def name(self) -> str:
        return "tls_extension_manipulation"

    @property
    def category(self) -> str:
        return "tls"

    @property
    def description(self) -> str:
        return "Manipulates TLS extensions to evade DPI pattern detection"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {
            "manipulation_type": "inject_fake",
            "extension_count": 3,
            "randomize_order": True,
            "include_grease": True,
        }

    def _validate_and_prepare_params(
        self, context: AttackContext
    ) -> tuple[bytes, Dict[str, Any], Optional[AttackResult]]:
        """
        Validate payload and prepare parameters for extension manipulation.

        Returns:
            Tuple of (payload, prepared_params, error_result)
            If error_result is not None, execution should stop and return it.
        """
        payload = _ensure_bytes(context.payload)
        if payload is None:
            error = AttackResult(status=AttackStatus.ERROR, error_message="Payload must be bytes")
            return (b"", {}, error)

        if not _is_tls_handshake_payload(payload):
            error = AttackResult(
                status=AttackStatus.INVALID_PARAMS,
                error_message="Payload is not a valid TLS handshake",
            )
            return (b"", {}, error)

        params = context.params or {}

        # Extract manipulation type
        manipulation_type = _coalesce(params, "manipulation_type", default="inject_fake")

        # Extract numeric parameters
        fake_extension_count = _clamp_int(
            _coalesce(params, "fake_extension_count", "extension_count", default=3),
            3,
            min_value=0,
            max_value=64,
        )

        # Extract boolean flags
        randomize_order = bool(_coalesce(params, "randomize_order", default=True))
        add_grease = bool(_coalesce(params, "add_grease", "include_grease", default=True))

        prepared_params = {
            "manipulation_type": manipulation_type,
            "fake_extension_count": fake_extension_count,
            "randomize_order": randomize_order,
            "add_grease": add_grease,
        }

        return (payload, prepared_params, None)

    def _apply_manipulation(self, payload: bytes, params: Dict[str, Any]) -> bytes:
        """
        Apply extension manipulation based on manipulation_type.

        Args:
            payload: Original TLS handshake payload
            params: Prepared parameters from _validate_and_prepare_params

        Returns:
            Modified payload with extension manipulation applied
        """
        manipulation_type = params["manipulation_type"]
        fake_extension_count = params["fake_extension_count"]

        if manipulation_type == "inject_fake":
            modified_payload = self._inject_fake_extensions(payload, fake_extension_count)
        elif manipulation_type == "randomize_order":
            modified_payload = self._randomize_extension_order(payload)
        elif manipulation_type == "add_grease":
            modified_payload = self._add_grease_extensions(payload)
        elif manipulation_type == "duplicate_extensions":
            modified_payload = self._duplicate_extensions(payload)
        elif manipulation_type == "malformed_extensions":
            modified_payload = self._add_malformed_extensions(payload)
        else:
            # Default fallback
            modified_payload = self._inject_fake_extensions(payload, fake_extension_count)

        # Recalculate lengths after modification
        return _recalculate_tls_handshake_lengths(modified_payload)

    def _build_result(
        self,
        payload: bytes,
        modified_payload: bytes,
        params: Dict[str, Any],
        context: AttackContext,
        start_time: float,
    ) -> AttackResult:
        """
        Build the final AttackResult with all metadata.

        Args:
            payload: Original payload
            modified_payload: Modified payload after manipulation
            params: Prepared parameters
            context: Attack context
            start_time: Execution start time

        Returns:
            Complete AttackResult
        """
        bytes_sent = len(modified_payload)
        latency = (time.perf_counter() - start_time) * 1000

        result = AttackResult(
            status=AttackStatus.SUCCESS,
            latency_ms=latency,
            packets_sent=1,
            bytes_sent=bytes_sent,
            connection_established=True,
            data_transmitted=True,
            modified_payload=modified_payload,
            metadata={
                "manipulation_type": params["manipulation_type"],
                "fake_extension_count": params["fake_extension_count"],
                "randomize_order": params["randomize_order"],
                "add_grease": params["add_grease"],
                "original_size": len(payload),
                "modified_size": len(modified_payload),
            },
        )

        # Store segments for orchestration engines
        if context.engine_type != "local":
            result.segments = [(modified_payload, 0, {})]

        return result

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute TLS extension manipulation attack."""
        start_time = time.perf_counter()
        try:
            # Step 1: Validate and prepare parameters
            payload, params, error = self._validate_and_prepare_params(context)
            if error is not None:
                return error

            # Step 2: Apply extension manipulation
            modified_payload = self._apply_manipulation(payload, params)

            # Step 3: Build and return result
            return self._build_result(payload, modified_payload, params, context, start_time)
        except Exception as e:
            LOG.debug("TLSExtensionManipulationAttack.execute failed", exc_info=True)
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.perf_counter() - start_time) * 1000,
            )

    def _inject_fake_extensions(self, payload: bytes, count: int) -> bytes:
        """Inject fake extensions into the ClientHello."""
        try:
            extensions_start = find_extensions_offset_client_hello(payload)
            if extensions_start == -1:
                return payload
            fake_extensions = []
            for i in range(count):
                ext_type = 4096 + i
                ext_data = os.urandom(random.randint(4, 32))
                fake_extensions.append((ext_type, ext_data))
            return self._insert_extensions(payload, extensions_start, fake_extensions)
        except Exception:
            return payload

    def _randomize_extension_order(self, payload: bytes) -> bytes:
        """Randomize the order of TLS extensions."""
        extensions_start = find_extensions_offset_client_hello(payload)
        if extensions_start == -1:
            return payload
        return randomize_extensions(payload, extensions_start, keep_sni_first=True)

    def _add_grease_extensions(self, payload: bytes) -> bytes:
        """Add GREASE extensions to confuse DPI."""
        try:
            extensions_start = find_extensions_offset_client_hello(payload)
            if extensions_start == -1:
                return payload
            grease_types = [2570, 6682, 10794, 14906, 19018]
            grease_extensions = []
            for grease_type in grease_types[:3]:
                grease_data = os.urandom(random.randint(0, 16))
                grease_extensions.append((grease_type, grease_data))
            return self._insert_extensions(payload, extensions_start, grease_extensions)
        except Exception:
            return payload

    def _duplicate_extensions(self, payload: bytes) -> bytes:
        """Duplicate some extensions to confuse DPI."""
        try:
            extensions_start = find_extensions_offset_client_hello(payload)
            if extensions_start == -1:
                return payload
            extensions_len = struct.unpack("!H", payload[extensions_start : extensions_start + 2])[
                0
            ]
            extensions_data = payload[extensions_start + 2 : extensions_start + 2 + extensions_len]
            extensions = []
            offset = 0
            while offset < len(extensions_data):
                if offset + 4 > len(extensions_data):
                    break
                ext_type = struct.unpack("!H", extensions_data[offset : offset + 2])[0]
                ext_len = struct.unpack("!H", extensions_data[offset + 2 : offset + 4])[0]
                if offset + 4 + ext_len > len(extensions_data):
                    break
                ext_data = extensions_data[offset + 4 : offset + 4 + ext_len]
                extensions.append((ext_type, ext_data))
                if ext_type != 0 and random.random() < 0.3:
                    extensions.append((ext_type, ext_data))
                offset += 4 + ext_len
            return self._rebuild_extensions(payload, extensions_start, extensions)
        except Exception:
            return payload

    def _add_malformed_extensions(self, payload: bytes) -> bytes:
        """Add malformed extensions to test DPI robustness."""
        try:
            extensions_start = find_extensions_offset_client_hello(payload)
            if extensions_start == -1:
                return payload
            malformed_extensions = [
                (65535, b""),
                (16, b"\xff" * 100),
                (35, b"\x00" * 50),
            ]
            return self._insert_extensions(payload, extensions_start, malformed_extensions)
        except Exception:
            return payload

    def _insert_extensions(
        self,
        payload: bytes,
        extensions_start: int,
        new_extensions: List[Tuple[int, bytes]],
    ) -> bytes:
        """Insert new extensions at the beginning of the extensions list."""
        return insert_extensions_util(payload, extensions_start, new_extensions, position=0)

    def _rebuild_extensions(
        self, payload: bytes, extensions_start: int, extensions: List[Tuple[int, bytes]]
    ) -> bytes:
        """Rebuild the extensions section with new extension list."""
        return rebuild_extensions_util(payload, extensions_start, extensions)


class TLSRecordFragmentationAttack(BaseAttack):
    """
    Backward-compatibility wrapper (import path).

    NOTE:
      The canonical registered implementation of "tls_record_fragmentation"
      lives in core.bypass.attacks.tls.record_manipulation.TLSRecordFragmentationAttack
      to avoid duplicate registry entries and import-order dependent behavior.
    """

    @property
    def name(self) -> str:
        return "tls_record_fragmentation"

    @property
    def category(self) -> str:
        return "tls"

    @property
    def description(self) -> str:
        return "Fragments TLS records to evade DPI record-level analysis"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        # Delegate to canonical implementation defaults
        from core.bypass.attacks.tls.record_manipulation import (
            TLSRecordFragmentationAttack as _Impl,
        )

        return _Impl().optional_params

    def execute(self, context: AttackContext) -> AttackResult:
        """Delegate to canonical implementation."""
        from core.bypass.attacks.tls.record_manipulation import (
            TLSRecordFragmentationAttack as _Impl,
        )

        return _Impl().execute(context)
