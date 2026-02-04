"""
HTTP/2 Protocol Attacks

Attacks that manipulate HTTP/2 frames and HPACK compression to evade DPI detection.
"""

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
from core.bypass.attacks.http.http2_utils import (
    HTTP2Frame,
    HPACKEncoder,
    is_http2_traffic,
    looks_like_http2_frame,
    convert_http1_to_http2,
    parse_http2_frames,
    split_headers_frame,
    split_data_frames,
    split_mixed_frames,
    force_literal_headers,
    disable_huffman_encoding,
    add_header_padding,
    manipulate_hpack,
    create_hpack_bomb,
    wrap_hpack_bomb_in_frames,
    wrap_hpack_bomb_in_frames_split,
    create_priority_payload,
    create_h2c_prior_knowledge_connection,
    create_h2c_upgrade_request,
)
from core.bypass.attacks.http.hpack_frame_builders import (
    create_table_poisoning_frames,
    create_index_overflow_frames,
    create_dynamic_eviction_frames,
    create_multiplexed_streams,
)
from core.bypass.attacks.http.smuggling_builders import (
    create_h2c_smuggling,
    create_frame_confusion_smuggling,
    create_header_injection_smuggling,
    create_post_upgrade_frames,
    create_smuggled_h2c_request,
    create_h2_frames_from_payload,
    create_cl_smuggled_request,
    create_te_smuggled_request,
    create_double_cl_smuggled_request,
    create_simple_h2c_upgrade,
)


def _handle_attack_exception(e: Exception, start_time: float) -> AttackResult:
    """
    Handle exceptions in attack execution with specific error categorization.

    Args:
        e: The exception that was raised
        start_time: Attack start time for latency calculation

    Returns:
        AttackResult with appropriate error status and message
    """
    latency = (time.time() - start_time) * 1000

    if isinstance(e, (ValueError, struct.error, IndexError)):
        # Frame parsing/manipulation errors
        error_msg = f"Frame processing error: {str(e)}"
    elif isinstance(e, (AttributeError, KeyError)):
        # Context/parameter access errors
        error_msg = f"Configuration error: {str(e)}"
    elif isinstance(e, (TypeError,)):
        # Type conversion errors
        error_msg = f"Type error: {str(e)}"
    else:
        # Unexpected errors - include exception type for debugging
        error_msg = f"Unexpected error ({type(e).__name__}): {str(e)}"

    return AttackResult(
        status=AttackStatus.ERROR,
        error_message=error_msg,
        latency_ms=latency,
    )


def _serialize_frames_or_raise(frames: List[HTTP2Frame], what: str = "frames") -> bytes:
    """
    Serialize a list of HTTP2Frame objects with better diagnostics than a raw exception.

    This is intentionally a lightweight self-check:
    - It does not validate RFC correctness.
    - It ensures frame.to_bytes() succeeds and provides frame index/type/stream context if not.
    """
    if frames is None:
        raise ValueError(f"{what} is None")
    if not isinstance(frames, list):
        raise TypeError(f"{what} must be a list, got: {type(frames).__name__}")
    if len(frames) == 0:
        raise ValueError(f"{what} is empty")

    out: List[bytes] = []
    for i, frame in enumerate(frames):
        if not isinstance(frame, HTTP2Frame):
            raise TypeError(f"{what}[{i}] is not HTTP2Frame, got: {type(frame).__name__}")
        try:
            out.append(frame.to_bytes())
        except Exception as e:
            # Provide frame metadata for debugging/observability.
            raise ValueError(
                f"Failed to serialize {what}[{i}] "
                f"(type={getattr(frame, 'frame_type', None)}, "
                f"flags={getattr(frame, 'flags', None)}, "
                f"stream_id={getattr(frame, 'stream_id', None)}, "
                f"payload_len={len(getattr(frame, 'payload', b''))}): {e}"
            ) from e
    return b"".join(out)


@register_attack(
    name="h2_frame_splitting",
    category=AttackCategories.HTTP,
    priority=RegistrationPriority.NORMAL,
    required_params=[],
    optional_params={"split_strategy": "headers", "max_frame_size": 16384},
    aliases=["http2_frame_split", "h2_split"],
    description="Splits HTTP/2 frames to evade DPI detection",
)
class H2FrameSplittingAttack(BaseAttack):
    """
    HTTP/2 Frame Splitting Attack - splits HTTP/2 frames to evade DPI detection.
    """

    @property
    def name(self) -> str:
        return "h2_frame_splitting"

    @property
    def category(self) -> str:
        return AttackCategories.HTTP

    @property
    def description(self) -> str:
        return "Splits HTTP/2 frames to evade DPI detection"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {"split_strategy": "headers", "max_frame_size": 16384}

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP/2 frame splitting attack."""
        start_time = time.time()
        try:
            payload = context.payload
            split_strategy = context.params.get("split_strategy", "headers")
            max_frame_size = context.params.get("max_frame_size", 16384)
            if not isinstance(payload, (bytes, bytearray)):
                raise TypeError(f"context.payload must be bytes, got: {type(payload).__name__}")
            if not isinstance(max_frame_size, int) or max_frame_size <= 0:
                raise ValueError("max_frame_size must be a positive integer")

            if not self._is_http2_traffic(payload):
                http2_frames = self._convert_http1_to_http2(payload)
            else:
                http2_frames = self._parse_http2_frames(payload)
            if not http2_frames:
                raise ValueError("No HTTP/2 frames produced/parsed from payload")

            if split_strategy == "headers":
                modified_frames = self._split_headers_frame(http2_frames, max_frame_size)
            elif split_strategy == "data":
                modified_frames = self._split_data_frames(http2_frames, max_frame_size)
            elif split_strategy == "mixed":
                modified_frames = self._split_mixed_frames(http2_frames, max_frame_size)
            else:
                modified_frames = http2_frames
            modified_payload = _serialize_frames_or_raise(modified_frames, what="modified_frames")
            segments = [(modified_payload, 0, {})]
            packets_sent = 1
            bytes_sent = len(modified_payload)
            latency = (time.time() - start_time) * 1000

            result = AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used=self.name,
                metadata={
                    "split_strategy": split_strategy,
                    "original_frames": len(http2_frames),
                    "modified_frames": len(modified_frames),
                    "original_size": len(payload),
                    "modified_size": len(modified_payload),
                },
            )
            result.segments = segments
            return result
        except Exception as e:
            return _handle_attack_exception(e, start_time)

    def _is_http2_traffic(self, payload: bytes) -> bool:
        """Check if payload contains HTTP/2 traffic."""
        return is_http2_traffic(payload)

    def _convert_http1_to_http2(self, payload: bytes) -> List[HTTP2Frame]:
        """Convert HTTP/1.1 request to HTTP/2 frames."""
        return convert_http1_to_http2(payload)

    def _parse_http2_frames(self, payload: bytes) -> List[HTTP2Frame]:
        """Parse HTTP/2 frames from payload."""
        return parse_http2_frames(payload)

    def _split_headers_frame(self, frames: List[HTTP2Frame], max_size: int) -> List[HTTP2Frame]:
        """Split HEADERS frames into smaller frames."""
        return split_headers_frame(frames, max_size)

    def _split_data_frames(self, frames: List[HTTP2Frame], max_size: int) -> List[HTTP2Frame]:
        """Split DATA frames into smaller frames."""
        return split_data_frames(frames, max_size)

    def _split_mixed_frames(self, frames: List[HTTP2Frame], max_size: int) -> List[HTTP2Frame]:
        """Split both HEADERS and DATA frames."""
        return split_mixed_frames(frames, max_size)


@register_attack(
    name="h2_hpack_manipulation",
    category=AttackCategories.HTTP,
    priority=RegistrationPriority.NORMAL,
    required_params=[],
    optional_params={"manipulation_type": "literal_headers"},
    aliases=["hpack_manipulation", "h2_hpack"],
    description="Manipulates HPACK header compression to evade DPI",
)
class H2HPACKManipulationAttack(BaseAttack):
    """
    HTTP/2 HPACK Header Compression Manipulation Attack.
    """

    @property
    def name(self) -> str:
        return "h2_hpack_manipulation"

    @property
    def category(self) -> str:
        return AttackCategories.HTTP

    @property
    def description(self) -> str:
        return "Manipulates HPACK header compression to evade DPI"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {"manipulation_type": "literal_headers"}

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute HPACK manipulation attack."""
        start_time = time.time()
        try:
            payload = context.payload
            manipulation_type = context.params.get("manipulation_type", "literal_headers")
            if not isinstance(payload, (bytes, bytearray)):
                raise TypeError(f"context.payload must be bytes, got: {type(payload).__name__}")

            if not self._is_http2_traffic(payload):
                http2_frames = self._convert_http1_to_http2(payload)
            else:
                http2_frames = self._parse_http2_frames(payload)
            if not http2_frames:
                raise ValueError("No HTTP/2 frames produced/parsed from payload")

            modified_frames = []
            for frame in http2_frames:
                if frame.frame_type == 1:
                    modified_payload = self._manipulate_hpack(frame.payload, manipulation_type)
                    modified_frame = HTTP2Frame(
                        frame.frame_type, frame.flags, frame.stream_id, modified_payload
                    )
                    modified_frames.append(modified_frame)
                else:
                    modified_frames.append(frame)
            modified_payload = _serialize_frames_or_raise(modified_frames, what="modified_frames")
            segments = [(modified_payload, 0, {})]
            packets_sent = 1
            bytes_sent = len(modified_payload)
            latency = (time.time() - start_time) * 1000

            result = AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used=self.name,
                metadata={
                    "manipulation_type": manipulation_type,
                    "original_size": len(payload),
                    "modified_size": len(modified_payload),
                },
            )
            result.segments = segments
            return result
        except Exception as e:
            return _handle_attack_exception(e, start_time)

    def _is_http2_traffic(self, payload: bytes) -> bool:
        """Check if payload contains HTTP/2 traffic."""
        return is_http2_traffic(payload)

    def _looks_like_http2_frame(self, payload: bytes) -> bool:
        """Check if payload looks like HTTP/2 frame."""
        return looks_like_http2_frame(payload)

    def _convert_http1_to_http2(self, payload: bytes) -> List[HTTP2Frame]:
        """Convert HTTP/1.1 to HTTP/2 frames."""
        return convert_http1_to_http2(payload)

    def _parse_http2_frames(self, payload: bytes) -> List[HTTP2Frame]:
        """Parse HTTP/2 frames."""
        return parse_http2_frames(payload)

    def _manipulate_hpack(self, hpack_payload: bytes, manipulation_type: str) -> bytes:
        """Manipulate HPACK encoded headers."""
        return manipulate_hpack(hpack_payload, manipulation_type)

    def _force_literal_headers(self, payload: bytes) -> bytes:
        """Force headers to use literal encoding instead of indexing."""
        return force_literal_headers(payload)

    def _disable_huffman_encoding(self, payload: bytes) -> bytes:
        """Disable Huffman encoding in HPACK."""
        return disable_huffman_encoding(payload)

    def _add_header_padding(self, payload: bytes) -> bytes:
        """Add padding to HPACK headers."""
        return add_header_padding(payload)


@register_attack(
    name="h2_priority_manipulation",
    category=AttackCategories.HTTP,
    priority=RegistrationPriority.NORMAL,
    required_params=[],
    optional_params={"priority_strategy": "random"},
    aliases=["h2_priority", "http2_priority"],
    description="Manipulates HTTP/2 stream priorities to evade DPI",
)
class H2PriorityManipulationAttack(BaseAttack):
    """
    HTTP/2 Priority Manipulation Attack - manipulates stream priorities.
    """

    @property
    def name(self) -> str:
        return "h2_priority_manipulation"

    @property
    def category(self) -> str:
        return AttackCategories.HTTP

    @property
    def description(self) -> str:
        return "Manipulates HTTP/2 stream priorities to evade DPI"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {"priority_strategy": "random"}

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP/2 priority manipulation attack."""
        start_time = time.time()
        try:
            payload = context.payload
            priority_strategy = context.params.get("priority_strategy", "random")
            if not isinstance(payload, (bytes, bytearray)):
                raise TypeError(f"context.payload must be bytes, got: {type(payload).__name__}")

            if not self._is_http2_traffic(payload):
                http2_frames = self._convert_http1_to_http2(payload)
            else:
                http2_frames = self._parse_http2_frames(payload)
            if not http2_frames:
                raise ValueError("No HTTP/2 frames produced/parsed from payload")

            modified_frames = []
            for frame in http2_frames:
                if frame.frame_type == 1:
                    priority_payload = self._create_priority_payload(
                        frame.stream_id, priority_strategy
                    )
                    priority_frame = HTTP2Frame(2, 0, frame.stream_id, priority_payload)
                    modified_frames.append(priority_frame)
                modified_frames.append(frame)
            modified_payload = _serialize_frames_or_raise(modified_frames, what="modified_frames")
            segments = [(modified_payload, 0, {})]
            packets_sent = 1
            bytes_sent = len(modified_payload)
            latency = (time.time() - start_time) * 1000
            result = AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used=self.name,
                metadata={
                    "priority_strategy": priority_strategy,
                    "original_frames": len(http2_frames),
                    "modified_frames": len(modified_frames),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )
            result.segments = segments
            return result
        except Exception as e:
            return _handle_attack_exception(e, start_time)

    def _is_http2_traffic(self, payload: bytes) -> bool:
        """Check if payload contains HTTP/2 traffic."""
        return is_http2_traffic(payload)

    def _looks_like_http2_frame(self, payload: bytes) -> bool:
        """Check if payload looks like HTTP/2 frame."""
        return looks_like_http2_frame(payload)

    def _convert_http1_to_http2(self, payload: bytes) -> List[HTTP2Frame]:
        """Convert HTTP/1.1 to HTTP/2 frames."""
        return convert_http1_to_http2(payload)

    def _parse_http2_frames(self, payload: bytes) -> List[HTTP2Frame]:
        """Parse HTTP/2 frames."""
        return parse_http2_frames(payload)

    def _create_priority_payload(self, stream_id: int, strategy: str) -> bytes:
        """Create priority frame payload."""
        return create_priority_payload(stream_id, strategy)


@register_attack(
    name="h2c_upgrade",
    category=AttackCategories.HTTP,
    priority=RegistrationPriority.NORMAL,
    required_params=[],
    optional_params={"upgrade_method": "prior_knowledge"},
    aliases=["h2c", "http2_cleartext"],
    description="Uses HTTP/2 clear text upgrade to bypass HTTPS inspection",
)
class H2ClearTextUpgradeAttack(BaseAttack):
    """
    HTTP/2 Clear Text (h2c) Upgrade Attack - uses h2c upgrade to bypass HTTPS inspection.
    """

    @property
    def name(self) -> str:
        return "h2c_upgrade"

    @property
    def category(self) -> str:
        return "http"

    @property
    def description(self) -> str:
        return "Uses HTTP/2 clear text upgrade to bypass HTTPS inspection"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> dict:
        return {"upgrade_method": "prior_knowledge"}

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute h2c upgrade attack."""
        start_time = time.time()
        try:
            payload = context.payload
            upgrade_method = context.params.get("upgrade_method", "prior_knowledge")
            if not isinstance(payload, (bytes, bytearray)):
                raise TypeError(f"context.payload must be bytes, got: {type(payload).__name__}")

            if upgrade_method == "prior_knowledge":
                h2c_payload = self._create_h2c_prior_knowledge_connection(payload, context)
            else:
                h2c_payload = self._create_h2c_upgrade_request(payload, context)
            if not isinstance(h2c_payload, (bytes, bytearray)) or len(h2c_payload) == 0:
                raise ValueError("h2c payload is empty or not bytes")
            segments = [(h2c_payload, 0, {})]
            packets_sent = 1
            bytes_sent = len(h2c_payload)
            latency = (time.time() - start_time) * 1000
            result = AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used=self.name,
                metadata={
                    "upgrade_method": upgrade_method,
                    "original_size": len(payload),
                    "h2c_size": len(h2c_payload),
                    "bypass_technique": "h2c_cleartext",
                    "segments": segments if context.engine_type != "local" else None,
                },
            )
            result.segments = segments
            return result
        except Exception as e:
            return _handle_attack_exception(e, start_time)

    def _create_h2c_prior_knowledge_connection(
        self, payload: bytes, context: AttackContext
    ) -> bytes:
        """Create h2c connection with prior knowledge."""
        domain = context.domain or context.dst_ip
        return create_h2c_prior_knowledge_connection(payload, domain, path="/api/data")

    def _create_h2c_upgrade_request(self, payload: bytes, context: AttackContext) -> bytes:
        """Create HTTP/1.1 to h2c upgrade request."""
        domain = context.domain or context.dst_ip
        return create_h2c_upgrade_request(payload, domain)


@register_attack(
    name="h2_hpack_bomb",
    category=AttackCategories.HTTP,
    priority=RegistrationPriority.NORMAL,
    required_params=[],
    optional_params={"compression_ratio": 10, "header_count": 100},
    aliases=["hpack_bomb", "h2_compression_bomb"],
    description="Uses HPACK compression bomb to hide payload in HTTP/2 headers",
)
class H2HPACKBombAttack(BaseAttack):
    """
    HTTP/2 HPACK Bomb Attack - uses HPACK compression to hide payload in headers.
    """

    @property
    def name(self) -> str:
        return "h2_hpack_bomb"

    @property
    def category(self) -> str:
        return "http"

    @property
    def description(self) -> str:
        return "Uses HPACK compression bomb to hide payload in HTTP/2 headers"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> dict:
        return {"compression_ratio": 10, "header_count": 100}

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute HPACK bomb attack."""
        start_time = time.time()
        try:
            payload = context.payload
            compression_ratio = context.params.get("compression_ratio", 10)
            header_count = context.params.get("header_count", 100)
            if not isinstance(payload, (bytes, bytearray)):
                raise TypeError(f"context.payload must be bytes, got: {type(payload).__name__}")

            hpack_bomb = self._create_hpack_bomb(payload, compression_ratio, header_count)
            h2_payload = self._wrap_hpack_bomb_in_frames(hpack_bomb, context)
            if not isinstance(h2_payload, (bytes, bytearray)) or len(h2_payload) == 0:
                raise ValueError("Wrapped HPACK bomb payload is empty or not bytes")
            segments = [(h2_payload, 0, {})]
            packets_sent = 1
            bytes_sent = len(h2_payload)
            latency = (time.time() - start_time) * 1000
            result = AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used=self.name,
                metadata={
                    "compression_ratio": compression_ratio,
                    "header_count": header_count,
                    "original_size": len(payload),
                    "bomb_size": len(h2_payload),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )
            result.segments = segments
            return result
        except Exception as e:
            return _handle_attack_exception(e, start_time)

    def _create_hpack_bomb(
        self, payload: bytes, compression_ratio: int, header_count: int
    ) -> bytes:
        """
        Create HPACK compression bomb.

        Args:
            payload: Original payload (intentionally unused - see note below)
            compression_ratio: Number of duplicate headers to create
            header_count: Number of unique header patterns

        Returns:
            HPACK encoded bomb data

        Note:
            The payload parameter is intentionally unused in this implementation.
            The HPACK bomb is created from repeated patterns (base_pattern and
            base_value) rather than from the actual payload data. This design
            allows the bomb to achieve maximum compression ratios by using
            highly repetitive data that compresses well with HPACK's dynamic
            table indexing. The actual payload is transmitted separately in
            DATA frames after the HPACK bomb headers.

            This parameter is maintained for API consistency with other attack
            methods and may be used in future versions to embed payload fragments
            within the bomb headers.
        """
        # Note: payload parameter is intentionally unused here as the bomb
        # is created from repeated patterns, not from the actual payload
        return create_hpack_bomb(
            compression_ratio=compression_ratio,
            header_count=header_count,
            base_pattern=b"x-custom-header-",
            base_value=b"repeated-value-pattern-",
        )

    def _wrap_hpack_bomb_in_frames(self, hpack_bomb: bytes, context: AttackContext) -> bytes:
        """
        Wrap HPACK bomb in HTTP/2 frames.

        Args:
            hpack_bomb: HPACK encoded bomb data
            context: Attack context (intentionally unused - see note below)

        Returns:
            Complete HTTP/2 frames containing the bomb

        Note:
            The context parameter is intentionally unused in this simplified
            implementation. The function uses a fixed max_frame_size (16384 bytes)
            instead of extracting it from context. This design choice simplifies
            the implementation while maintaining API compatibility.

            Future versions may use context to:
            - Extract custom max_frame_size from context.params
            - Add domain-specific frame flags
            - Adjust frame splitting strategy based on context.engine_type
        """
        return wrap_hpack_bomb_in_frames(hpack_bomb, context.payload)


@register_attack(
    name="h2_hpack_index_manipulation",
    category=AttackCategories.HTTP,
    priority=RegistrationPriority.NORMAL,
    required_params=[],
    optional_params={"manipulation_type": "table_poisoning", "index_confusion": True},
    aliases=["hpack_index", "h2_index_manipulation"],
    description="Manipulates HPACK dynamic table indexing to evade DPI",
)
class H2HPACKIndexManipulationAttack(BaseAttack):
    """
    HTTP/2 HPACK Index Manipulation Attack - manipulates HPACK dynamic table indexing.
    """

    @property
    def name(self) -> str:
        return "h2_hpack_index_manipulation"

    @property
    def category(self) -> str:
        return "http"

    @property
    def description(self) -> str:
        return "Manipulates HPACK dynamic table indexing to evade DPI"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> dict:
        return {"manipulation_type": "table_poisoning", "index_confusion": True}

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute HPACK index manipulation attack."""
        start_time = time.time()
        try:
            payload = context.payload
            manipulation_type = context.params.get("manipulation_type", "table_poisoning")
            index_confusion = context.params.get("index_confusion", True)
            manipulated_payload = self._create_hpack_index_manipulation(
                payload, manipulation_type, index_confusion, context
            )
            segments = [(manipulated_payload, 0, {})]
            packets_sent = 1
            bytes_sent = len(manipulated_payload)
            latency = (time.time() - start_time) * 1000
            result = AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used=self.name,
                metadata={
                    "manipulation_type": manipulation_type,
                    "index_confusion": index_confusion,
                    "original_size": len(payload),
                    "manipulated_size": len(manipulated_payload),
                    "bypass_technique": "hpack_index_manipulation",
                    "segments": segments if context.engine_type != "local" else None,
                },
            )
            result.segments = segments
            return result
        except Exception as e:
            return _handle_attack_exception(e, start_time)

    def _create_hpack_index_manipulation(
        self,
        payload: bytes,
        manipulation_type: str,
        index_confusion: bool,
        context: AttackContext,
    ) -> bytes:
        """Create HPACK index manipulation payload."""
        domain = context.domain or context.dst_ip
        preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        settings_payload = struct.pack(">HI", 1, 8192)
        settings_frame = HTTP2Frame(4, 0, 0, settings_payload)

        # Use extracted frame builders
        if manipulation_type == "table_poisoning":
            headers_frames = create_table_poisoning_frames(domain, payload, index_confusion)
        elif manipulation_type == "index_overflow":
            headers_frames = create_index_overflow_frames(domain, payload, index_confusion)
        elif manipulation_type == "dynamic_eviction":
            headers_frames = create_dynamic_eviction_frames(domain, payload, index_confusion)
        else:
            headers_frames = create_table_poisoning_frames(domain, payload, index_confusion)

        # Self-check: ensure all frames are serializable; provide better errors on failure.
        serialized = _serialize_frames_or_raise(
            [settings_frame] + headers_frames, what="index_manipulation_frames"
        )
        return preface + serialized

    def _create_hpack_bomb(
        self, payload: bytes, compression_ratio: int, header_count: int
    ) -> bytes:
        """
        Create HPACK compression bomb.

        Args:
            payload: Original payload (intentionally unused - see note below)
            compression_ratio: Number of duplicate headers to create
            header_count: Number of unique header patterns

        Returns:
            HPACK encoded bomb data

        Note:
            The payload parameter is intentionally unused in this implementation.
            The HPACK bomb is created from repeated patterns (base_pattern="x-bomb-"
            and base_value="x"*100) rather than from the actual payload data.
            This allows the bomb to achieve maximum compression with HPACK's
            dynamic table indexing.

            This parameter is maintained for API consistency with other attack
            methods and may be used in future versions to embed payload data.
        """
        # Note: payload parameter is intentionally unused here
        return create_hpack_bomb(
            compression_ratio=compression_ratio,
            header_count=header_count,
            base_pattern=b"x-bomb-",
            base_value=b"x" * 100,
        )

    def _wrap_hpack_bomb_in_frames(self, hpack_bomb: bytes, context: AttackContext) -> bytes:
        """
        Wrap HPACK bomb in HTTP/2 frames.

        Args:
            hpack_bomb: HPACK encoded bomb data
            context: Attack context (intentionally unused - see note below)

        Returns:
            Complete HTTP/2 frames containing the bomb

        Note:
            The context parameter is intentionally unused in this simplified version.
            The function uses a fixed max_frame_size (16384 bytes) for frame splitting.
            This design simplifies the implementation while maintaining API compatibility
            with other wrapper methods that may use context.

            Future versions may extract max_frame_size from context.params or use
            context.engine_type to adjust frame splitting behavior.
        """
        # Note: context parameter is intentionally unused in this simplified version
        return wrap_hpack_bomb_in_frames_split(hpack_bomb, max_frame_size=16384)


@register_attack(
    name="h2_smuggling",
    category=AttackCategories.HTTP,
    priority=RegistrationPriority.NORMAL,
    required_params=[],
    optional_params={
        "smuggling_type": "h2c_upgrade",
        "hidden_request": b"GET /admin HTTP/1.1\r\nHost: internal\r\n\r\n",
    },
    aliases=["http2_smuggling", "h2_request_smuggling"],
    description="Exploits HTTP/2 request smuggling via h2c upgrade and frame parsing",
)
class H2SmugglingAttack(BaseAttack):
    """
    HTTP/2 Request Smuggling Attack - exploits h2c upgrade and frame parsing differences.
    """

    @property
    def name(self) -> str:
        return "h2_smuggling"

    @property
    def category(self) -> str:
        return "http"

    @property
    def description(self) -> str:
        return "Exploits HTTP/2 request smuggling via h2c upgrade and frame parsing"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> dict:
        return {
            "smuggling_type": "h2c_upgrade",
            "hidden_request": b"GET /admin HTTP/1.1\r\nHost: internal\r\n\r\n",
        }

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP/2 smuggling attack."""
        start_time = time.time()
        try:
            payload = context.payload
            smuggling_type = context.params.get("smuggling_type", "h2c_upgrade")
            hidden_request = context.params.get(
                "hidden_request", b"GET /admin HTTP/1.1\r\nHost: internal\r\n\r\n"
            )
            if not isinstance(payload, (bytes, bytearray)):
                raise TypeError(f"context.payload must be bytes, got: {type(payload).__name__}")
            if not isinstance(hidden_request, (bytes, bytearray)):
                raise TypeError("hidden_request must be bytes")

            if smuggling_type == "h2c_upgrade":
                smuggled_payload = self._create_h2c_smuggling(payload, hidden_request, context)
            elif smuggling_type == "frame_confusion":
                smuggled_payload = self._create_frame_confusion_smuggling(payload, hidden_request)
            elif smuggling_type == "header_injection":
                smuggled_payload = self._create_header_injection_smuggling(
                    payload, hidden_request, context
                )
            else:
                smuggled_payload = payload
            if not isinstance(smuggled_payload, (bytes, bytearray)) or len(smuggled_payload) == 0:
                raise ValueError("Smuggled payload is empty or not bytes")
            segments = [(smuggled_payload, 0, {})]
            packets_sent = 1
            bytes_sent = len(smuggled_payload)
            latency = (time.time() - start_time) * 1000
            result = AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used=self.name,
                metadata={
                    "smuggling_type": smuggling_type,
                    "hidden_request_size": len(hidden_request),
                    "original_size": len(payload),
                    "smuggled_size": len(smuggled_payload),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )
            result.segments = segments
            return result
        except Exception as e:
            return _handle_attack_exception(e, start_time)

    def _create_h2c_smuggling(
        self, payload: bytes, hidden_request: bytes, context: AttackContext
    ) -> bytes:
        """Create h2c upgrade smuggling attack."""
        domain = context.domain or context.dst_ip
        return create_h2c_smuggling(payload, hidden_request, domain)

    def _create_frame_confusion_smuggling(self, payload: bytes, hidden_request: bytes) -> bytes:
        """Create frame confusion smuggling attack."""
        return create_frame_confusion_smuggling(payload, hidden_request)

    def _create_header_injection_smuggling(
        self, payload: bytes, hidden_request: bytes, context: AttackContext
    ) -> bytes:
        """Create header injection smuggling attack."""
        domain = context.domain or context.dst_ip
        return create_header_injection_smuggling(payload, hidden_request, domain)

    def _create_post_upgrade_frames(self, payload: bytes, context: AttackContext) -> bytes:
        """Create HTTP/2 frames after h2c upgrade."""
        domain = context.domain or context.dst_ip
        return create_post_upgrade_frames(payload, domain)


@register_attack(
    name="h2_stream_multiplexing",
    category=AttackCategories.HTTP,
    priority=RegistrationPriority.NORMAL,
    required_params=[],
    optional_params={"stream_count": 5, "interleave_frames": True, "use_priorities": True},
    aliases=["h2_multiplexing", "http2_streams"],
    description="Uses HTTP/2 stream multiplexing to distribute payload across streams",
)
class H2StreamMultiplexingAttack(BaseAttack):
    """
    HTTP/2 Stream Multiplexing Attack - uses multiple concurrent streams to evade detection.
    """

    @property
    def name(self) -> str:
        return "h2_stream_multiplexing"

    @property
    def category(self) -> str:
        return "http"

    @property
    def description(self) -> str:
        return "Uses HTTP/2 stream multiplexing to distribute payload across streams"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> dict:
        return {"stream_count": 5, "interleave_frames": True, "use_priorities": True}

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP/2 stream multiplexing attack."""
        start_time = time.time()
        try:
            payload = context.payload
            stream_count = context.params.get("stream_count", 5)
            interleave_frames = context.params.get("interleave_frames", True)
            use_priorities = context.params.get("use_priorities", True)
            if not isinstance(payload, (bytes, bytearray)):
                raise TypeError(f"context.payload must be bytes, got: {type(payload).__name__}")
            if not isinstance(stream_count, int):
                raise TypeError("stream_count must be int")

            multiplexed_payload = self._create_multiplexed_streams(
                payload, stream_count, interleave_frames, use_priorities, context
            )
            if (
                not isinstance(multiplexed_payload, (bytes, bytearray))
                or len(multiplexed_payload) == 0
            ):
                raise ValueError("Multiplexed payload is empty or not bytes")
            segments = [(multiplexed_payload, 0, {})]
            packets_sent = 1
            bytes_sent = len(multiplexed_payload)
            latency = (time.time() - start_time) * 1000
            result = AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used=self.name,
                metadata={
                    "stream_count": stream_count,
                    "interleave_frames": interleave_frames,
                    "use_priorities": use_priorities,
                    "original_size": len(payload),
                    "multiplexed_size": len(multiplexed_payload),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )
            result.segments = segments
            return result
        except Exception as e:
            return _handle_attack_exception(e, start_time)

    def _create_multiplexed_streams(
        self,
        payload: bytes,
        stream_count: int,
        interleave: bool,
        use_priorities: bool,
        context: AttackContext,
    ) -> bytes:
        """Create multiple HTTP/2 streams with payload distribution."""
        domain = context.domain or context.dst_ip
        return create_multiplexed_streams(payload, stream_count, interleave, use_priorities, domain)

    def _create_hpack_bomb(
        self, payload: bytes, compression_ratio: int, header_count: int
    ) -> bytes:
        """
        Create HPACK compression bomb with payload embedded in headers.

        Args:
            payload: Actual payload data to embed in headers
            compression_ratio: Number of duplicate headers to create
            header_count: Number of header chunks to split payload into

        Returns:
            HPACK encoded data with payload embedded

        Note:
            Unlike other _create_hpack_bomb implementations, this version DOES use
            the payload parameter. It splits the payload into chunks and embeds them
            in custom headers (x-data-NNNN), then base64-encodes them. This allows
            the payload to be transmitted within HPACK headers rather than in
            separate DATA frames.

            This approach is useful for evading DPI systems that only inspect
            DATA frames and ignore header content.
        """
        import base64

        chunk_size = max(1, len(payload) // header_count)
        chunks = [payload[i : i + chunk_size] for i in range(0, len(payload), chunk_size)]

        headers = []
        headers.extend(
            [
                (b":method", b"POST"),
                (b":path", b"/api/upload"),
                (b":scheme", b"https"),
                (b":authority", b"example.com"),
            ]
        )

        # Embed payload chunks in headers
        for i, chunk in enumerate(chunks):
            header_name = f"x-data-{i:04d}".encode()
            header_value = base64.b64encode(chunk)
            headers.append((header_name, header_value))

        # Add duplicate headers for compression
        for i in range(compression_ratio):
            headers.append((b"x-duplicate", f"value-{i}".encode()))

        hpack_encoder = HPACKEncoder()
        return hpack_encoder.encode_headers(headers)

    def _wrap_hpack_bomb_in_frames(self, hpack_bomb: bytes, context: AttackContext) -> bytes:
        """
        Wrap HPACK bomb in HTTP/2 frames.

        Args:
            hpack_bomb: HPACK encoded bomb data
            context: Attack context (intentionally unused - see note below)

        Returns:
            Complete HTTP/2 frames containing the bomb

        Note:
            The context parameter is intentionally unused here. The function uses
            a fixed max_frame_size (16384 bytes) for frame splitting instead of
            extracting it from context. This simplifies the implementation while
            maintaining API compatibility with other wrapper methods.

            Future versions may use context to extract custom frame size limits
            or adjust splitting behavior based on context.engine_type.
        """
        # Note: context parameter is intentionally unused here
        return wrap_hpack_bomb_in_frames_split(hpack_bomb, max_frame_size=16384)


@register_attack(
    name="h2c_smuggling",
    category=AttackCategories.HTTP,
    priority=RegistrationPriority.NORMAL,
    required_params=[],
    optional_params={
        "smuggling_method": "content_length",
        "use_chunked": False,
        "add_te_header": True,
    },
    aliases=["h2c_request_smuggling", "cleartext_smuggling"],
    description="Uses HTTP/2 clear text smuggling to bypass DPI inspection",
)
class H2CSmugglingAttack(BaseAttack):
    """
    HTTP/2 Clear Text Smuggling Attack - uses h2c to smuggle HTTP/2 requests
    through HTTP/1.1 proxies and bypass DPI inspection.
    """

    @property
    def name(self) -> str:
        return "h2c_smuggling"

    @property
    def category(self) -> str:
        return "http"

    @property
    def description(self) -> str:
        return "Uses HTTP/2 clear text smuggling to bypass DPI inspection"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> dict:
        return {"smuggling_method": "content_length", "use_chunked": False, "add_te_header": True}

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute h2c smuggling attack."""
        start_time = time.time()
        try:
            payload = context.payload
            smuggling_method = context.params.get("smuggling_method", "content_length")
            use_chunked = context.params.get("use_chunked", False)
            add_te_header = context.params.get("add_te_header", True)
            if not isinstance(payload, (bytes, bytearray)):
                raise TypeError(f"context.payload must be bytes, got: {type(payload).__name__}")

            smuggled_payload = self._create_smuggled_h2c_request(
                payload, context, smuggling_method, use_chunked, add_te_header
            )
            if not isinstance(smuggled_payload, (bytes, bytearray)) or len(smuggled_payload) == 0:
                raise ValueError("Smuggled h2c payload is empty or not bytes")
            segments = [(smuggled_payload, 0, {})]
            packets_sent = 1
            bytes_sent = len(smuggled_payload)
            latency = (time.time() - start_time) * 1000
            result = AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used=self.name,
                metadata={
                    "smuggling_method": smuggling_method,
                    "use_chunked": use_chunked,
                    "add_te_header": add_te_header,
                    "original_size": len(payload),
                    "smuggled_size": len(smuggled_payload),
                    "bypass_technique": "h2c_smuggling",
                    "segments": segments if context.engine_type != "local" else None,
                },
            )
            result.segments = segments
            return result
        except Exception as e:
            return _handle_attack_exception(e, start_time)

    def _create_smuggled_h2c_request(
        self,
        payload: bytes,
        context: AttackContext,
        method: str,
        use_chunked: bool,
        add_te: bool,
    ) -> bytes:
        """Create smuggled h2c request."""
        domain = context.domain or context.dst_ip
        return create_smuggled_h2c_request(payload, domain, method, use_chunked, add_te)

    def _create_h2_frames_from_payload(
        self, payload: bytes, context: AttackContext
    ) -> List[HTTP2Frame]:
        """Create HTTP/2 frames from payload."""
        domain = context.domain or context.dst_ip
        return create_h2_frames_from_payload(payload, domain)

    def _create_cl_smuggled_request(
        self, domain: str, h2_data: bytes, use_chunked: bool, add_te: bool
    ) -> bytes:
        """Create Content-Length based smuggled request."""
        return create_cl_smuggled_request(domain, h2_data, use_chunked, add_te)

    def _create_te_smuggled_request(self, domain: str, h2_data: bytes, add_te: bool) -> bytes:
        """Create Transfer-Encoding based smuggled request."""
        return create_te_smuggled_request(domain, h2_data, add_te)

    def _create_double_cl_smuggled_request(self, domain: str, h2_data: bytes) -> bytes:
        """Create double Content-Length smuggled request."""
        return create_double_cl_smuggled_request(domain, h2_data)

    def _create_simple_h2c_upgrade(self, domain: str, h2_data: bytes) -> bytes:
        """Create simple h2c upgrade request."""
        return create_simple_h2c_upgrade(domain, h2_data)


@register_attack(
    name="h2_hpack_advanced",
    category=AttackCategories.HTTP,
    priority=RegistrationPriority.NORMAL,
    required_params=[],
    optional_params={
        "technique": "dynamic_table",
        "compression_level": "high",
        "use_huffman": True,
        "table_size_update": True,
    },
    aliases=["hpack_advanced", "h2_advanced_compression"],
    description="Uses advanced HPACK compression techniques to evade DPI",
)
class H2HPACKAdvancedManipulationAttack(BaseAttack):
    """
    Advanced HTTP/2 HPACK Manipulation Attack - uses sophisticated HPACK
    compression techniques to hide payloads and evade DPI detection.
    """

    @property
    def name(self) -> str:
        return "h2_hpack_advanced"

    @property
    def category(self) -> str:
        return "http"

    @property
    def description(self) -> str:
        return "Uses advanced HPACK compression techniques to evade DPI"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> dict:
        return {
            "technique": "dynamic_table",
            "compression_level": "high",
            "use_huffman": True,
            "table_size_update": True,
        }

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute advanced HPACK manipulation attack."""
        start_time = time.time()
        try:
            payload = context.payload
            manipulation_technique = context.params.get("technique", "dynamic_table")
            compression_level = context.params.get("compression_level", "high")
            use_huffman = context.params.get("use_huffman", True)
            table_size_update = context.params.get("table_size_update", True)
            if not isinstance(payload, (bytes, bytearray)):
                raise TypeError(f"context.payload must be bytes, got: {type(payload).__name__}")

            manipulated_payload = self._create_advanced_hpack_payload(
                payload,
                context,
                manipulation_technique,
                compression_level,
                use_huffman,
                table_size_update,
            )
            if (
                not isinstance(manipulated_payload, (bytes, bytearray))
                or len(manipulated_payload) == 0
            ):
                raise ValueError("Advanced HPACK payload is empty or not bytes")
            segments = [(manipulated_payload, 0, {})]
            packets_sent = 1
            bytes_sent = len(manipulated_payload)
            latency = (time.time() - start_time) * 1000
            result = AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used=self.name,
                metadata={
                    "manipulation_technique": manipulation_technique,
                    "compression_level": compression_level,
                    "use_huffman": use_huffman,
                    "table_size_update": table_size_update,
                    "original_size": len(payload),
                    "manipulated_size": len(manipulated_payload),
                    "compression_ratio": (
                        len(payload) / len(manipulated_payload) if manipulated_payload else 1
                    ),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )
            result.segments = segments
            return result
        except Exception as e:
            return _handle_attack_exception(e, start_time)

    def _create_advanced_hpack_payload(
        self,
        payload: bytes,
        context: AttackContext,
        technique: str,
        compression_level: str,
        use_huffman: bool,
        table_size_update: bool,
    ) -> bytes:
        """
        Create advanced HPACK manipulated payload.

        Args:
            payload: Actual data payload
            context: Attack context with domain and parameters
            technique: HPACK manipulation technique to use
            compression_level: Compression level (intentionally unused - see note below)
            use_huffman: Whether to use Huffman encoding
            table_size_update: Whether to send table size update in SETTINGS

        Returns:
            Complete HTTP/2 connection bytes with HPACK manipulation

        Note:
            The compression_level parameter is intentionally unused in the current
            implementation. All techniques use their own optimized compression
            strategies that are hardcoded for maximum effectiveness:
            - "dynamic_table": Uses table index references
            - "literal_never_indexed": Uses literal encoding with never-indexed flag
            - "header_splitting": Splits payload across multiple headers
            - "context_update": Uses context updates to manipulate table state

            This parameter is maintained for API consistency and may be used in
            future versions to control compression aggressiveness (e.g., "low"
            might use more literal encoding, "high" might use more table references).
        """
        preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        frames = []
        if table_size_update:
            settings_payload = struct.pack(">HI", 1, 8192)
            settings_payload += struct.pack(">HI", 2, 0)
            settings_frame = HTTP2Frame(4, 0, 0, settings_payload)
            frames.append(settings_frame)
        if technique == "dynamic_table":
            hpack_data = self._create_dynamic_table_manipulation(payload, context, use_huffman)
        elif technique == "literal_never_indexed":
            hpack_data = self._create_literal_never_indexed(payload, context, use_huffman)
        elif technique == "header_splitting":
            hpack_data = self._create_header_splitting(payload, context, use_huffman)
        elif technique == "context_update":
            hpack_data = self._create_context_update_manipulation(payload, context, use_huffman)
        else:
            hpack_data = self._create_basic_hpack_manipulation(payload, context, use_huffman)
        headers_frame = HTTP2Frame(1, 5, 1, hpack_data)
        frames.append(headers_frame)
        # Self-check: frames must serialize; provides better error context than raw exception.
        return preface + _serialize_frames_or_raise(frames, what="advanced_hpack_frames")

    def _create_dynamic_table_manipulation(
        self, payload: bytes, context: AttackContext, use_huffman: bool
    ) -> bytes:
        """
        Create HPACK data using dynamic table manipulation.

        Args:
            payload: Original payload (intentionally unused - see note below)
            context: Attack context with domain information
            use_huffman: Whether to use Huffman encoding for strings

        Returns:
            HPACK encoded data with dynamic table manipulation

        Note:
            The payload parameter is intentionally unused in this implementation.
            This technique focuses on manipulating the HPACK dynamic table state
            through custom headers (x-bypass-method, x-payload-encoding, x-dpi-evasion)
            and table index references, rather than embedding the actual payload data.

            The payload is typically transmitted separately in DATA frames after
            the HEADERS frame containing this HPACK data. This separation allows
            the dynamic table manipulation to confuse DPI systems before the
            actual payload arrives.

            Future versions may embed payload fragments in the custom header values
            to further obfuscate the data transmission.
        """
        hpack_data = b""
        hpack_data += b"?\xe1\x1f"
        custom_headers = [
            (b"x-bypass-method", b"hpack-dynamic"),
            (b"x-payload-encoding", b"base64"),
            (b"x-dpi-evasion", b"active"),
        ]
        for name, value in custom_headers:
            hpack_data += b"@"
            hpack_data += self._encode_string(name, use_huffman)
            hpack_data += self._encode_string(value, use_huffman)
        hpack_data += b"\xbe"
        hpack_data += b"\xbf"
        hpack_data += b"\xc0"
        hpack_data += b"\x82"
        hpack_data += b"\x84"
        hpack_data += b"\x87"
        hpack_data += b"A"
        domain = (context.domain or context.dst_ip).encode()
        hpack_data += self._encode_string(domain, use_huffman)
        return hpack_data

    def _create_literal_never_indexed(
        self, payload: bytes, context: AttackContext, use_huffman: bool
    ) -> bytes:
        """Create HPACK data using literal never indexed headers."""
        hpack_data = b""
        sensitive_headers = [
            (b":method", b"POST"),
            (b":path", b"/api/sensitive"),
            (b":scheme", b"https"),
            (b":authority", (context.domain or context.dst_ip).encode()),
            (b"authorization", b"Bearer " + payload[:50]),
            (b"x-api-key", payload[50:100] if len(payload) > 50 else payload),
        ]
        for name, value in sensitive_headers:
            hpack_data += b"\x10"
            hpack_data += self._encode_string(name, use_huffman)
            hpack_data += self._encode_string(value, use_huffman)
        return hpack_data

    def _create_header_splitting(
        self, payload: bytes, context: AttackContext, use_huffman: bool
    ) -> bytes:
        """Create HPACK data using header splitting technique."""
        hpack_data = b""
        chunk_size = 64
        chunks = [payload[i : i + chunk_size] for i in range(0, len(payload), chunk_size)]
        hpack_data += b"\x83"
        hpack_data += b"\x84"
        hpack_data += b"\x87"
        hpack_data += b"A"
        domain = (context.domain or context.dst_ip).encode()
        hpack_data += self._encode_string(domain, use_huffman)
        for i, chunk in enumerate(chunks):
            header_name = f"x-data-chunk-{i:02d}".encode()
            hpack_data += b"@"
            hpack_data += self._encode_string(header_name, use_huffman)
            hpack_data += self._encode_string(chunk, use_huffman)
        metadata = f"chunks={len(chunks)};size={len(payload)}".encode()
        hpack_data += b"@"
        hpack_data += self._encode_string(b"x-payload-metadata", use_huffman)
        hpack_data += self._encode_string(metadata, use_huffman)
        return hpack_data

    def _create_context_update_manipulation(
        self, payload: bytes, context: AttackContext, use_huffman: bool
    ) -> bytes:
        """Create HPACK data using context update manipulation."""
        hpack_data = b""
        hpack_data += b" "
        hpack_data += b"?\xe1\x1f"
        hpack_data += b"?\x81\x1f"
        temp_headers = [
            (b"x-temp-1", b"value1"),
            (b"x-temp-2", b"value2"),
            (b"x-temp-3", b"value3"),
        ]
        for name, value in temp_headers:
            hpack_data += b"@"
            hpack_data += self._encode_string(name, use_huffman)
            hpack_data += self._encode_string(value, use_huffman)
        hpack_data += b"?a"
        real_headers = [
            (b":method", b"POST"),
            (b":path", b"/api/data"),
            (b":scheme", b"https"),
            (b":authority", (context.domain or context.dst_ip).encode()),
            (b"content-type", b"application/octet-stream"),
            (b"x-payload-data", payload[:100]),
        ]
        for name, value in real_headers:
            hpack_data += b"@"
            hpack_data += self._encode_string(name, use_huffman)
            hpack_data += self._encode_string(value, use_huffman)
        return hpack_data

    def _create_basic_hpack_manipulation(
        self, payload: bytes, context: AttackContext, use_huffman: bool
    ) -> bytes:
        """Create basic HPACK manipulated data."""
        hpack_data = b""
        hpack_data += b"\x83"
        hpack_data += b"\x84"
        hpack_data += b"\x87"
        hpack_data += b"A"
        domain = (context.domain or context.dst_ip).encode()
        hpack_data += self._encode_string(domain, use_huffman)
        hpack_data += b"@"
        hpack_data += self._encode_string(b"content-type", use_huffman)
        hpack_data += self._encode_string(b"application/octet-stream", use_huffman)
        hpack_data += b"@"
        hpack_data += self._encode_string(b"x-embedded-payload", use_huffman)
        hpack_data += self._encode_string(payload, use_huffman)
        return hpack_data

    def _encode_string(self, data: bytes, use_huffman: bool) -> bytes:
        """
        Encode string for HPACK.

        HPACK strings use a 7-bit prefixed integer length (RFC 7541, 5.2).
        NOTE: When use_huffman=True we set the Huffman bit, but this implementation
        does not perform real Huffman encoding; it keeps raw bytes intentionally.
        This preserves the original "manipulation" behavior while avoiding crashes
        on len(data) > 255.
        """
        # HPACK strings use a 7-bit prefixed integer length (RFC 7541, 5.2).
        huffman_bit = 0x80 if use_huffman else 0x00
        return self._encode_hpack_int(len(data), prefix_bits=7, first_byte_mask=huffman_bit) + data

    def _encode_hpack_int(self, value: int, prefix_bits: int, first_byte_mask: int = 0) -> bytes:
        """
        Encode an integer using HPACK integer representation (RFC 7541, 5.1).
        Kept as an instance method to avoid changing external interfaces.
        """
        if prefix_bits <= 0 or prefix_bits > 8:
            raise ValueError(f"Invalid prefix_bits={prefix_bits}")

        max_prefix = (1 << prefix_bits) - 1
        if value < max_prefix:
            return bytes([first_byte_mask | value])

        out = bytearray()
        out.append(first_byte_mask | max_prefix)
        value -= max_prefix

        while value >= 128:
            out.append((value & 0x7F) | 0x80)
            value >>= 7
        out.append(value & 0x7F)
        return bytes(out)
