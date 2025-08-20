# recon/core/bypass/attacks/http/http2_attacks.py
"""
HTTP/2 Protocol Attacks

Attacks that manipulate HTTP/2 frames and HPACK compression to evade DPI detection.
"""

import time
import struct
import random
from typing import List, Tuple
from ..base import BaseAttack, AttackContext, AttackResult, AttackStatus
from ..registry import register_attack


class HTTP2Frame:
    """HTTP/2 frame structure."""

    def __init__(self, frame_type: int, flags: int, stream_id: int, payload: bytes):
        self.frame_type = frame_type
        self.flags = flags
        self.stream_id = stream_id
        self.payload = payload
        self.length = len(payload)

    def to_bytes(self) -> bytes:
        """Convert frame to bytes."""
        # Frame format: Length(24) + Type(8) + Flags(8) + R(1) + Stream ID(31)
        # Length is 24 bits, so we need to pack it properly
        length_bytes = struct.pack(">I", self.length)[
            1:
        ]  # Take last 3 bytes for 24-bit length
        header = length_bytes
        header += struct.pack(">B", self.frame_type)  # Type (8 bits)
        header += struct.pack(">B", self.flags)  # Flags (8 bits)
        header += struct.pack(">I", self.stream_id & 0x7FFFFFFF)  # Stream ID (31 bits)
        return header + self.payload

    @classmethod
    def from_bytes(cls, data: bytes) -> "HTTP2Frame":
        """Parse frame from bytes."""
        if len(data) < 9:
            raise ValueError("Invalid frame: too short")

        # Parse header
        length = struct.unpack(">I", b"\x00" + data[:3])[0]
        frame_type = data[3]
        flags = data[4]
        stream_id = struct.unpack(">I", data[5:9])[0] & 0x7FFFFFFF

        payload = data[9 : 9 + length]
        return cls(frame_type, flags, stream_id, payload)


class HPACKEncoder:
    """Simple HPACK encoder for header compression."""

    # Static table (simplified)
    STATIC_TABLE = {
        b":authority": 1,
        b":method": 2,
        b":method GET": 2,
        b":method POST": 3,
        b":path": 4,
        b":path /": 4,
        b":scheme": 6,
        b":scheme http": 6,
        b":scheme https": 7,
        b":status": 8,
        b":status 200": 8,
        b"accept": 19,
        b"accept-encoding": 16,
        b"accept-language": 17,
        b"cache-control": 24,
        b"content-length": 28,
        b"content-type": 31,
        b"cookie": 32,
        b"date": 33,
        b"host": 38,
        b"user-agent": 58,
    }

    def encode_header(self, name: bytes, value: bytes) -> bytes:
        """Encode a single header using HPACK."""
        # Simplified HPACK encoding - literal header with incremental indexing
        name_lower = name.lower()

        if name_lower in self.STATIC_TABLE:
            # Indexed header name
            index = self.STATIC_TABLE[name_lower]
            result = struct.pack(
                ">B", 0x40 | index
            )  # Literal with incremental indexing
        else:
            # Literal header name
            result = struct.pack(">B", 0x40)  # Literal with incremental indexing
            result += struct.pack(">B", len(name)) + name

        # Add value
        result += struct.pack(">B", len(value)) + value
        return result

    def encode_headers(self, headers: List[Tuple[bytes, bytes]]) -> bytes:
        """Encode multiple headers."""
        result = b""
        for name, value in headers:
            result += self.encode_header(name, value)
        return result


@register_attack
class H2FrameSplittingAttack(BaseAttack):
    """
    HTTP/2 Frame Splitting Attack - splits HTTP/2 frames to evade DPI detection.
    """

    @property
    def name(self) -> str:
        return "h2_frame_splitting"

    @property
    def category(self) -> str:
        return "http"

    @property
    def description(self) -> str:
        return "Splits HTTP/2 frames to evade DPI detection"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP/2 frame splitting attack."""
        start_time = time.time()

        try:
            payload = context.payload
            split_strategy = context.params.get("split_strategy", "headers")
            max_frame_size = context.params.get("max_frame_size", 16384)

            # Check if this is HTTP/2 traffic (starts with connection preface or frame)
            if not self._is_http2_traffic(payload):
                # Convert HTTP/1.1 to HTTP/2 if needed
                http2_frames = self._convert_http1_to_http2(payload)
            else:
                # Parse existing HTTP/2 frames
                http2_frames = self._parse_http2_frames(payload)

            # Apply frame splitting based on strategy
            if split_strategy == "headers":
                modified_frames = self._split_headers_frame(
                    http2_frames, max_frame_size
                )
            elif split_strategy == "data":
                modified_frames = self._split_data_frames(http2_frames, max_frame_size)
            elif split_strategy == "mixed":
                modified_frames = self._split_mixed_frames(http2_frames, max_frame_size)
            else:
                modified_frames = http2_frames

            # Convert frames back to bytes
            modified_payload = b""
            for frame in modified_frames:
                modified_payload += frame.to_bytes()

            segments = [(modified_payload, 0)]
            packets_sent = 1
            bytes_sent = len(modified_payload)

            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "split_strategy": split_strategy,
                    "original_frames": len(http2_frames),
                    "modified_frames": len(modified_frames),
                    "original_size": len(payload),
                    "modified_size": len(modified_payload),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _is_http2_traffic(self, payload: bytes) -> bool:
        """Check if payload contains HTTP/2 traffic."""
        # HTTP/2 connection preface
        if payload.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"):
            return True

        # Check for HTTP/2 frame structure
        if len(payload) >= 9:
            try:
                frame = HTTP2Frame.from_bytes(payload)
                return True
            except:
                pass

        return False

    def _convert_http1_to_http2(self, payload: bytes) -> List[HTTP2Frame]:
        """Convert HTTP/1.1 request to HTTP/2 frames."""
        frames = []

        # Add connection preface (SETTINGS frame)
        settings_payload = b""  # Empty settings
        settings_frame = HTTP2Frame(0x04, 0x00, 0, settings_payload)  # SETTINGS frame
        frames.append(settings_frame)

        # Parse HTTP/1.1 request
        if not (payload.startswith(b"GET ") or payload.startswith(b"POST ")):
            return frames

        lines = payload.split(b"\r\n")
        request_line = lines[0]

        # Parse request line
        parts = request_line.split(b" ")
        if len(parts) >= 3:
            method = parts[0]
            path = parts[1]

            # Create pseudo-headers
            headers = [
                (b":method", method),
                (b":path", path),
                (b":scheme", b"https"),
            ]

            # Add regular headers
            for line in lines[1:]:
                if b":" in line and line != b"":
                    name, value = line.split(b":", 1)
                    name = name.strip().lower()
                    value = value.strip()

                    if name == b"host":
                        headers.insert(
                            -1, (b":authority", value)
                        )  # Insert before :scheme
                    else:
                        headers.append((name, value))

            # Encode headers using HPACK
            encoder = HPACKEncoder()
            headers_payload = encoder.encode_headers(headers)

            # Create HEADERS frame
            headers_frame = HTTP2Frame(
                0x01, 0x05, 1, headers_payload
            )  # HEADERS frame with END_HEADERS and END_STREAM flags
            frames.append(headers_frame)

        return frames

    def _parse_http2_frames(self, payload: bytes) -> List[HTTP2Frame]:
        """Parse HTTP/2 frames from payload."""
        frames = []
        offset = 0

        while offset < len(payload):
            if offset + 9 > len(payload):
                break

            try:
                frame = HTTP2Frame.from_bytes(payload[offset:])
                frames.append(frame)
                offset += 9 + frame.length
            except:
                break

        return frames

    def _split_headers_frame(
        self, frames: List[HTTP2Frame], max_size: int
    ) -> List[HTTP2Frame]:
        """Split HEADERS frames into smaller frames."""
        modified_frames = []

        for frame in frames:
            if (
                frame.frame_type == 0x01 and len(frame.payload) > max_size
            ):  # HEADERS frame
                # Split headers payload
                payload_chunks = []
                offset = 0

                while offset < len(frame.payload):
                    chunk_size = min(max_size, len(frame.payload) - offset)
                    payload_chunks.append(frame.payload[offset : offset + chunk_size])
                    offset += chunk_size

                # Create multiple frames
                for i, chunk in enumerate(payload_chunks):
                    flags = 0x00  # No flags by default

                    if i == len(payload_chunks) - 1:
                        # Last frame gets the original flags
                        flags = frame.flags

                    new_frame = HTTP2Frame(
                        0x09, flags, frame.stream_id, chunk
                    )  # CONTINUATION frame
                    modified_frames.append(new_frame)
            else:
                modified_frames.append(frame)

        return modified_frames

    def _split_data_frames(
        self, frames: List[HTTP2Frame], max_size: int
    ) -> List[HTTP2Frame]:
        """Split DATA frames into smaller frames."""
        modified_frames = []

        for frame in frames:
            if frame.frame_type == 0x00 and len(frame.payload) > max_size:  # DATA frame
                # Split data payload
                payload_chunks = []
                offset = 0

                while offset < len(frame.payload):
                    chunk_size = min(max_size, len(frame.payload) - offset)
                    payload_chunks.append(frame.payload[offset : offset + chunk_size])
                    offset += chunk_size

                # Create multiple DATA frames
                for i, chunk in enumerate(payload_chunks):
                    flags = 0x00  # No flags by default

                    if i == len(payload_chunks) - 1:
                        # Last frame gets the original flags
                        flags = frame.flags

                    new_frame = HTTP2Frame(
                        0x00, flags, frame.stream_id, chunk
                    )  # DATA frame
                    modified_frames.append(new_frame)
            else:
                modified_frames.append(frame)

        return modified_frames

    def _split_mixed_frames(
        self, frames: List[HTTP2Frame], max_size: int
    ) -> List[HTTP2Frame]:
        """Split both HEADERS and DATA frames."""
        frames = self._split_headers_frame(frames, max_size)
        frames = self._split_data_frames(frames, max_size)
        return frames


@register_attack
class H2HPACKManipulationAttack(BaseAttack):
    """
    HTTP/2 HPACK Header Compression Manipulation Attack.
    """

    @property
    def name(self) -> str:
        return "h2_hpack_manipulation"

    @property
    def category(self) -> str:
        return "http"

    @property
    def description(self) -> str:
        return "Manipulates HPACK header compression to evade DPI"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute HPACK manipulation attack."""
        start_time = time.time()

        try:
            payload = context.payload
            manipulation_type = context.params.get(
                "manipulation_type", "literal_headers"
            )

            # Convert to HTTP/2 if needed
            if not self._is_http2_traffic(payload):
                http2_frames = self._convert_http1_to_http2(payload)
            else:
                http2_frames = self._parse_http2_frames(payload)

            # Apply HPACK manipulation
            modified_frames = []
            for frame in http2_frames:
                if frame.frame_type == 0x01:  # HEADERS frame
                    modified_payload = self._manipulate_hpack(
                        frame.payload, manipulation_type
                    )
                    modified_frame = HTTP2Frame(
                        frame.frame_type, frame.flags, frame.stream_id, modified_payload
                    )
                    modified_frames.append(modified_frame)
                else:
                    modified_frames.append(frame)

            # Convert back to bytes
            modified_payload = b""
            for frame in modified_frames:
                modified_payload += frame.to_bytes()

            segments = [(modified_payload, 0)]
            packets_sent = 1
            bytes_sent = len(modified_payload)

            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "manipulation_type": manipulation_type,
                    "original_size": len(payload),
                    "modified_size": len(modified_payload),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _is_http2_traffic(self, payload: bytes) -> bool:
        """Check if payload contains HTTP/2 traffic."""
        return payload.startswith(b"PRI * HTTP/2.0") or (
            len(payload) >= 9 and self._looks_like_http2_frame(payload)
        )

    def _looks_like_http2_frame(self, payload: bytes) -> bool:
        """Check if payload looks like HTTP/2 frame."""
        try:
            HTTP2Frame.from_bytes(payload)
            return True
        except:
            return False

    def _convert_http1_to_http2(self, payload: bytes) -> List[HTTP2Frame]:
        """Convert HTTP/1.1 to HTTP/2 frames."""
        # Simplified conversion - reuse from H2FrameSplittingAttack
        attack = H2FrameSplittingAttack()
        return attack._convert_http1_to_http2(payload)

    def _parse_http2_frames(self, payload: bytes) -> List[HTTP2Frame]:
        """Parse HTTP/2 frames."""
        # Reuse from H2FrameSplittingAttack
        attack = H2FrameSplittingAttack()
        return attack._parse_http2_frames(payload)

    def _manipulate_hpack(self, hpack_payload: bytes, manipulation_type: str) -> bytes:
        """Manipulate HPACK encoded headers."""
        if manipulation_type == "literal_headers":
            # Force all headers to be literal (not indexed)
            return self._force_literal_headers(hpack_payload)
        elif manipulation_type == "huffman_disable":
            # Disable Huffman encoding
            return self._disable_huffman_encoding(hpack_payload)
        elif manipulation_type == "padding":
            # Add padding to headers
            return self._add_header_padding(hpack_payload)
        else:
            return hpack_payload

    def _force_literal_headers(self, payload: bytes) -> bytes:
        """Force headers to use literal encoding instead of indexing."""
        # This is a simplified implementation
        # In practice, you'd need to fully decode and re-encode HPACK
        modified = bytearray(payload)

        # Replace indexed header patterns with literal patterns
        for i in range(len(modified)):
            if modified[i] & 0x80:  # Indexed header field
                modified[i] = (
                    modified[i] & 0x7F
                ) | 0x40  # Convert to literal with incremental indexing

        return bytes(modified)

    def _disable_huffman_encoding(self, payload: bytes) -> bytes:
        """Disable Huffman encoding in HPACK."""
        # Simplified - clear Huffman bit in string literals
        modified = bytearray(payload)

        for i in range(len(modified)):
            if modified[i] & 0x80:  # String literal with Huffman encoding
                modified[i] &= 0x7F  # Clear Huffman bit

        return bytes(modified)

    def _add_header_padding(self, payload: bytes) -> bytes:
        """Add padding to HPACK headers."""
        # Add some dummy headers for padding
        padding_headers = [
            b"\x40\x0ax-padding-1\x05dummy",
            b"\x40\x0ax-padding-2\x05value",
        ]

        result = payload
        for padding in padding_headers:
            result += padding

        return result


@register_attack
class H2PriorityManipulationAttack(BaseAttack):
    """
    HTTP/2 Priority Manipulation Attack - manipulates stream priorities.
    """

    @property
    def name(self) -> str:
        return "h2_priority_manipulation"

    @property
    def category(self) -> str:
        return "http"

    @property
    def description(self) -> str:
        return "Manipulates HTTP/2 stream priorities to evade DPI"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP/2 priority manipulation attack."""
        start_time = time.time()

        try:
            payload = context.payload
            priority_strategy = context.params.get("priority_strategy", "random")

            # Convert to HTTP/2 if needed
            if not self._is_http2_traffic(payload):
                http2_frames = self._convert_http1_to_http2(payload)
            else:
                http2_frames = self._parse_http2_frames(payload)

            # Add priority frames
            modified_frames = []

            # Add PRIORITY frames before HEADERS frames
            for frame in http2_frames:
                if frame.frame_type == 0x01:  # HEADERS frame
                    # Add PRIORITY frame before HEADERS
                    priority_payload = self._create_priority_payload(
                        frame.stream_id, priority_strategy
                    )
                    priority_frame = HTTP2Frame(
                        0x02, 0x00, frame.stream_id, priority_payload
                    )  # PRIORITY frame
                    modified_frames.append(priority_frame)

                modified_frames.append(frame)

            # Convert back to bytes
            modified_payload = b""
            for frame in modified_frames:
                modified_payload += frame.to_bytes()

            segments = [(modified_payload, 0)]
            packets_sent = 1
            bytes_sent = len(modified_payload)

            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "priority_strategy": priority_strategy,
                    "original_frames": len(http2_frames),
                    "modified_frames": len(modified_frames),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _is_http2_traffic(self, payload: bytes) -> bool:
        """Check if payload contains HTTP/2 traffic."""
        return payload.startswith(b"PRI * HTTP/2.0") or (
            len(payload) >= 9 and self._looks_like_http2_frame(payload)
        )

    def _looks_like_http2_frame(self, payload: bytes) -> bool:
        """Check if payload looks like HTTP/2 frame."""
        try:
            HTTP2Frame.from_bytes(payload)
            return True
        except:
            return False

    def _convert_http1_to_http2(self, payload: bytes) -> List[HTTP2Frame]:
        """Convert HTTP/1.1 to HTTP/2 frames."""
        attack = H2FrameSplittingAttack()
        return attack._convert_http1_to_http2(payload)

    def _parse_http2_frames(self, payload: bytes) -> List[HTTP2Frame]:
        """Parse HTTP/2 frames."""
        attack = H2FrameSplittingAttack()
        return attack._parse_http2_frames(payload)

    def _create_priority_payload(self, stream_id: int, strategy: str) -> bytes:
        """Create priority frame payload."""
        if strategy == "random":
            # Random priority values
            exclusive = random.choice([0, 1])
            stream_dependency = random.randint(0, stream_id - 1) if stream_id > 1 else 0
            weight = random.randint(1, 256)
        elif strategy == "high":
            # High priority
            exclusive = 1
            stream_dependency = 0
            weight = 256
        elif strategy == "low":
            # Low priority
            exclusive = 0
            stream_dependency = 0
            weight = 1
        else:
            # Default priority
            exclusive = 0
            stream_dependency = 0
            weight = 16

        # Priority payload format: E(1) + Stream Dependency(31) + Weight(8)
        dependency_field = (exclusive << 31) | (stream_dependency & 0x7FFFFFFF)
        return struct.pack(
            ">IB", dependency_field, weight - 1
        )  # Weight is 0-255 in wire format


# Advanced HTTP/2 Attacks


@register_attack
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

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute h2c upgrade attack."""
        start_time = time.time()

        try:
            payload = context.payload
            upgrade_method = context.params.get("upgrade_method", "prior_knowledge")

            if upgrade_method == "prior_knowledge":
                # Direct h2c connection with prior knowledge
                h2c_payload = self._create_h2c_prior_knowledge_connection(
                    payload, context
                )
            else:
                # HTTP/1.1 upgrade to h2c
                h2c_payload = self._create_h2c_upgrade_request(payload, context)

            segments = [(h2c_payload, 0)]
            packets_sent = 1
            bytes_sent = len(h2c_payload)
            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "upgrade_method": upgrade_method,
                    "original_size": len(payload),
                    "h2c_size": len(h2c_payload),
                    "bypass_technique": "h2c_cleartext",
                    "segments": segments if context.engine_type != "local" else None,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _create_h2c_prior_knowledge_connection(
        self, payload: bytes, context: AttackContext
    ) -> bytes:
        """Create h2c connection with prior knowledge."""
        # HTTP/2 connection preface
        preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

        # SETTINGS frame
        settings_payload = struct.pack(">HI", 0x2, 0)  # ENABLE_PUSH = 0
        settings_payload += struct.pack(
            ">HI", 0x3, 1000
        )  # MAX_CONCURRENT_STREAMS = 1000
        settings_payload += struct.pack(
            ">HI", 0x4, 65535
        )  # INITIAL_WINDOW_SIZE = 65535

        settings_frame = HTTP2Frame(0x4, 0x0, 0, settings_payload)  # SETTINGS frame

        # HEADERS frame with payload
        headers = [
            (b":method", b"POST"),
            (b":path", b"/api/data"),
            (b":scheme", b"http"),
            (b":authority", (context.domain or context.dst_ip).encode()),
            (b"content-type", b"application/octet-stream"),
            (b"content-length", str(len(payload)).encode()),
        ]

        hpack_encoder = HPACKEncoder()
        headers_payload = hpack_encoder.encode_headers(headers)
        headers_frame = HTTP2Frame(
            0x1, 0x4, 1, headers_payload
        )  # HEADERS frame, END_HEADERS

        # DATA frame with actual payload
        data_frame = HTTP2Frame(0x0, 0x1, 1, payload)  # DATA frame, END_STREAM

        return (
            preface
            + settings_frame.to_bytes()
            + headers_frame.to_bytes()
            + data_frame.to_bytes()
        )

    def _create_h2c_upgrade_request(
        self, payload: bytes, context: AttackContext
    ) -> bytes:
        """Create HTTP/1.1 to h2c upgrade request."""
        domain = context.domain or context.dst_ip

        # HTTP/1.1 upgrade request
        upgrade_request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {domain}\r\n"
            f"Connection: Upgrade, HTTP2-Settings\r\n"
            f"Upgrade: h2c\r\n"
            f"HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n"  # Base64 encoded settings
            f"\r\n"
        ).encode()

        # After upgrade, send HTTP/2 frames
        h2c_frames = self._create_h2c_prior_knowledge_connection(payload, context)

        return upgrade_request + h2c_frames


@register_attack
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

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute HPACK bomb attack."""
        start_time = time.time()

        try:
            payload = context.payload
            compression_ratio = context.params.get("compression_ratio", 10)
            header_count = context.params.get("header_count", 100)

            # Create HPACK bomb
            hpack_bomb = self._create_hpack_bomb(
                payload, compression_ratio, header_count
            )

            # Wrap in HTTP/2 frames
            h2_payload = self._wrap_hpack_bomb_in_frames(hpack_bomb, context)

            segments = [(h2_payload, 0)]
            packets_sent = 1
            bytes_sent = len(h2_payload)
            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "compression_ratio": compression_ratio,
                    "header_count": header_count,
                    "original_size": len(payload),
                    "bomb_size": len(h2_payload),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _create_hpack_bomb(
        self, payload: bytes, compression_ratio: int, header_count: int
    ) -> bytes:
        """Create HPACK compression bomb."""
        # Create many headers with repeated patterns for compression
        headers = []

        # Add standard headers
        headers.extend(
            [
                (b":method", b"POST"),
                (b":path", b"/api/data"),
                (b":scheme", b"https"),
                (b":authority", b"example.com"),
            ]
        )

        # Add many similar headers for compression bomb
        base_pattern = b"x-custom-header-"
        base_value = b"repeated-value-pattern-" * compression_ratio

        for i in range(header_count):
            header_name = base_pattern + str(i).encode()
            header_value = base_value + str(i % 10).encode()  # Some variation
            headers.append((header_name, header_value))

        # Encode with HPACK
        encoder = HPACKEncoder()
        return encoder.encode_headers(headers)

    def _wrap_hpack_bomb_in_frames(
        self, hpack_bomb: bytes, context: AttackContext
    ) -> bytes:
        """Wrap HPACK bomb in HTTP/2 frames."""
        frames = []

        # Connection preface
        preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

        # SETTINGS frame
        settings_payload = struct.pack(">HI", 0x1, 4096)  # HEADER_TABLE_SIZE
        settings_payload += struct.pack(">HI", 0x4, 65535)  # INITIAL_WINDOW_SIZE
        settings_frame = HTTP2Frame(0x4, 0x0, 0, settings_payload)

        # HEADERS frame with HPACK bomb
        headers_frame = HTTP2Frame(0x1, 0x5, 1, hpack_bomb)  # END_HEADERS + END_STREAM

        # DATA frame with actual payload
        data_frame = HTTP2Frame(0x0, 0x1, 1, context.payload)  # END_STREAM

        result = preface
        result += settings_frame.to_bytes()
        result += headers_frame.to_bytes()
        result += data_frame.to_bytes()

        return result


@register_attack
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

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute HPACK index manipulation attack."""
        start_time = time.time()

        try:
            payload = context.payload
            manipulation_type = context.params.get(
                "manipulation_type", "table_poisoning"
            )
            index_confusion = context.params.get("index_confusion", True)

            # Create manipulated HPACK payload
            manipulated_payload = self._create_hpack_index_manipulation(
                payload, manipulation_type, index_confusion, context
            )

            segments = [(manipulated_payload, 0)]
            packets_sent = 1
            bytes_sent = len(manipulated_payload)
            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "manipulation_type": manipulation_type,
                    "index_confusion": index_confusion,
                    "original_size": len(payload),
                    "manipulated_size": len(manipulated_payload),
                    "bypass_technique": "hpack_index_manipulation",
                    "segments": segments if context.engine_type != "local" else None,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _create_hpack_index_manipulation(
        self,
        payload: bytes,
        manipulation_type: str,
        index_confusion: bool,
        context: AttackContext,
    ) -> bytes:
        """Create HPACK index manipulation payload."""
        domain = context.domain or context.dst_ip

        # HTTP/2 connection preface
        preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

        # SETTINGS frame with custom HPACK table size
        settings_payload = struct.pack(">HI", 0x1, 8192)  # HEADER_TABLE_SIZE = 8192
        settings_frame = HTTP2Frame(0x4, 0x0, 0, settings_payload)

        # Create manipulated HEADERS frames
        if manipulation_type == "table_poisoning":
            headers_frames = self._create_table_poisoning_frames(
                domain, payload, index_confusion
            )
        elif manipulation_type == "index_overflow":
            headers_frames = self._create_index_overflow_frames(
                domain, payload, index_confusion
            )
        elif manipulation_type == "dynamic_eviction":
            headers_frames = self._create_dynamic_eviction_frames(
                domain, payload, index_confusion
            )
        else:
            headers_frames = self._create_table_poisoning_frames(
                domain, payload, index_confusion
            )

        # Combine all frames
        result = preface + settings_frame.to_bytes()
        for frame in headers_frames:
            result += frame.to_bytes()

        return result

    def _create_table_poisoning_frames(
        self, domain: str, payload: bytes, index_confusion: bool
    ) -> List[HTTP2Frame]:
        """Create frames that poison the HPACK dynamic table."""
        frames = []

        # First, populate dynamic table with decoy entries
        for i in range(10):
            decoy_headers = [
                (b":method", b"GET"),
                (b":path", f"/decoy{i}".encode()),
                (b":scheme", b"https"),
                (b":authority", domain.encode()),
                (f"x-decoy-{i}".encode(), f"decoy-value-{i}".encode()),
            ]

            # Use literal with incremental indexing to populate table
            hpack_payload = b""
            for name, value in decoy_headers:
                # Literal with incremental indexing (0x40)
                hpack_payload += b"\x40"
                hpack_payload += struct.pack(">B", len(name)) + name
                hpack_payload += struct.pack(">B", len(value)) + value

            frame = HTTP2Frame(0x1, 0x4, i * 2 + 1, hpack_payload)  # END_HEADERS
            frames.append(frame)

        # Now send real request using indexed headers (references to dynamic table)
        real_headers = [
            (b":method", b"POST"),
            (b":path", b"/api/data"),
            (b":scheme", b"https"),
            (b":authority", domain.encode()),
            (b"content-type", b"application/octet-stream"),
        ]

        # Mix indexed and literal headers
        real_hpack_payload = b""
        for i, (name, value) in enumerate(real_headers):
            if index_confusion and i % 2 == 0:
                # Use indexed header field (0x80 + index)
                # Reference to dynamic table entry (index > 61)
                table_index = 62 + (i % 10)  # Dynamic table starts at 62
                real_hpack_payload += struct.pack(">B", 0x80 | table_index)
            else:
                # Use literal header
                real_hpack_payload += b"\x40"
                real_hpack_payload += struct.pack(">B", len(name)) + name
                real_hpack_payload += struct.pack(">B", len(value)) + value

        real_headers_frame = HTTP2Frame(0x1, 0x4, 21, real_hpack_payload)  # END_HEADERS
        real_data_frame = HTTP2Frame(0x0, 0x1, 21, payload)  # END_STREAM

        frames.extend([real_headers_frame, real_data_frame])
        return frames

    def _create_index_overflow_frames(
        self, domain: str, payload: bytes, index_confusion: bool
    ) -> List[HTTP2Frame]:
        """Create frames that cause HPACK index overflow."""
        frames = []

        # Create headers with very high index references
        headers_payload = b""

        # Try to reference non-existent high indices
        for i in range(5):
            # Invalid high index (should be ignored or cause error)
            invalid_index = 200 + i
            headers_payload += struct.pack(">B", 0x80 | (invalid_index & 0x7F))
            if invalid_index > 127:
                # Multi-byte index encoding
                headers_payload = headers_payload[:-1]  # Remove last byte
                headers_payload += struct.pack(">BB", 0x80 | 0x7F, invalid_index - 127)

        # Add valid headers after invalid ones
        valid_headers = [
            (b":method", b"POST"),
            (b":path", b"/api"),
            (b":scheme", b"https"),
            (b":authority", domain.encode()),
        ]

        for name, value in valid_headers:
            headers_payload += b"\x40"  # Literal with incremental indexing
            headers_payload += struct.pack(">B", len(name)) + name
            headers_payload += struct.pack(">B", len(value)) + value

        headers_frame = HTTP2Frame(0x1, 0x4, 1, headers_payload)  # END_HEADERS
        data_frame = HTTP2Frame(0x0, 0x1, 1, payload)  # END_STREAM

        frames.extend([headers_frame, data_frame])
        return frames

    def _create_dynamic_eviction_frames(
        self, domain: str, payload: bytes, index_confusion: bool
    ) -> List[HTTP2Frame]:
        """Create frames that cause dynamic table eviction confusion."""
        frames = []

        # Fill dynamic table to capacity, then cause evictions
        for i in range(20):  # More than typical table size
            large_header_value = b"x" * 1000  # Large value to fill table quickly

            headers = [
                (b":method", b"GET"),
                (b":path", f"/fill{i}".encode()),
                (b":scheme", b"https"),
                (b":authority", domain.encode()),
                (f"x-large-{i}".encode(), large_header_value),
            ]

            hpack_payload = b""
            for name, value in headers:
                hpack_payload += b"\x40"  # Literal with incremental indexing
                hpack_payload += struct.pack(">B", len(name)) + name
                hpack_payload += struct.pack(">B", len(value)) + value

            frame = HTTP2Frame(0x1, 0x4, i * 2 + 1, hpack_payload)  # END_HEADERS
            frames.append(frame)

        # Now reference evicted entries (should cause confusion)
        confused_payload = b""
        for i in range(10):
            # Reference entries that should have been evicted
            evicted_index = 62 + i  # Early dynamic table entries
            confused_payload += struct.pack(">B", 0x80 | evicted_index)

        # Add real headers
        real_headers = [
            (b":method", b"POST"),
            (b":path", b"/real"),
            (b":authority", domain.encode()),
        ]

        for name, value in real_headers:
            confused_payload += b"\x40"
            confused_payload += struct.pack(">B", len(name)) + name
            confused_payload += struct.pack(">B", len(value)) + value

        real_frame = HTTP2Frame(0x1, 0x4, 41, confused_payload)  # END_HEADERS
        data_frame = HTTP2Frame(0x0, 0x1, 41, payload)  # END_STREAM

        frames.extend([real_frame, data_frame])
        return frames

    def _create_hpack_bomb(
        self, payload: bytes, compression_ratio: int, header_count: int
    ) -> bytes:
        """Create HPACK compression bomb."""
        # Create many headers with repetitive patterns that compress well
        headers = []

        # Add standard headers
        headers.extend(
            [
                (b":method", b"POST"),
                (b":path", b"/api/upload"),
                (b":scheme", b"https"),
                (b":authority", b"example.com"),
            ]
        )

        # Add many repetitive headers for compression bomb
        base_pattern = b"x" * 100  # Base pattern that will be repeated

        for i in range(header_count):
            header_name = f"x-bomb-{i:04d}".encode()
            # Use repetitive pattern that compresses well
            header_value = base_pattern * (compression_ratio // 10 + 1)
            headers.append((header_name, header_value))

        # Encode with HPACK
        encoder = HPACKEncoder()
        return encoder.encode_headers(headers)

    def _wrap_hpack_bomb_in_frames(
        self, hpack_bomb: bytes, context: AttackContext
    ) -> bytes:
        """Wrap HPACK bomb in HTTP/2 frames."""
        frames = []

        # Connection preface
        preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

        # SETTINGS frame
        settings_payload = struct.pack(">HI", 0x1, 4096)  # HEADER_TABLE_SIZE
        settings_payload += struct.pack(">HI", 0x4, 65535)  # INITIAL_WINDOW_SIZE
        settings_frame = HTTP2Frame(0x4, 0x0, 0, settings_payload)

        # HEADERS frame with HPACK bomb
        headers_frame = HTTP2Frame(0x1, 0x5, 1, hpack_bomb)  # END_HEADERS | END_STREAM

        return preface + settings_frame.to_bytes() + headers_frame.to_bytes()


@register_attack
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

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP/2 smuggling attack."""
        start_time = time.time()

        try:
            payload = context.payload
            smuggling_type = context.params.get("smuggling_type", "h2c_upgrade")
            hidden_request = context.params.get(
                "hidden_request", b"GET /admin HTTP/1.1\r\nHost: internal\r\n\r\n"
            )

            if smuggling_type == "h2c_upgrade":
                smuggled_payload = self._create_h2c_smuggling(
                    payload, hidden_request, context
                )
            elif smuggling_type == "frame_confusion":
                smuggled_payload = self._create_frame_confusion_smuggling(
                    payload, hidden_request
                )
            elif smuggling_type == "header_injection":
                smuggled_payload = self._create_header_injection_smuggling(
                    payload, hidden_request, context
                )
            else:
                smuggled_payload = payload

            segments = [(smuggled_payload, 0)]
            packets_sent = 1
            bytes_sent = len(smuggled_payload)
            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "smuggling_type": smuggling_type,
                    "hidden_request_size": len(hidden_request),
                    "original_size": len(payload),
                    "smuggled_size": len(smuggled_payload),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _create_h2c_smuggling(
        self, payload: bytes, hidden_request: bytes, context: AttackContext
    ) -> bytes:
        """Create h2c upgrade smuggling attack."""
        domain = context.domain or context.dst_ip

        # HTTP/1.1 request with h2c upgrade that contains smuggled request
        upgrade_request = (
            f"POST /api HTTP/1.1\r\n"
            f"Host: {domain}\r\n"
            f"Connection: Upgrade, HTTP2-Settings\r\n"
            f"Upgrade: h2c\r\n"
            f"HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n"
            f"Content-Length: {len(hidden_request)}\r\n"
            f"\r\n"
        ).encode()

        # Add hidden request in the body
        upgrade_request += hidden_request

        # After upgrade, send HTTP/2 frames with original payload
        h2_frames = self._create_post_upgrade_frames(payload, context)

        return upgrade_request + h2_frames

    def _create_frame_confusion_smuggling(
        self, payload: bytes, hidden_request: bytes
    ) -> bytes:
        """Create frame confusion smuggling attack."""
        # Create malformed frames that might be parsed differently
        connection_id = secrets.token_bytes(8)

        # Create a DATA frame that looks like HTTP/1.1 request
        fake_data_frame = HTTP2Frame(0x0, 0x0, 1, hidden_request)

        # Create normal HEADERS frame with payload
        headers = [
            (b":method", b"POST"),
            (b":path", b"/api"),
            (b":scheme", b"https"),
            (b":authority", b"example.com"),
        ]

        encoder = HPACKEncoder()
        headers_payload = encoder.encode_headers(headers)
        headers_frame = HTTP2Frame(0x1, 0x4, 1, headers_payload)  # END_HEADERS

        # Real data frame
        data_frame = HTTP2Frame(0x0, 0x1, 1, payload)  # END_STREAM

        # Connection preface
        preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

        return (
            preface
            + fake_data_frame.to_bytes()
            + headers_frame.to_bytes()
            + data_frame.to_bytes()
        )

    def _create_header_injection_smuggling(
        self, payload: bytes, hidden_request: bytes, context: AttackContext
    ) -> bytes:
        """Create header injection smuggling attack."""
        # Inject hidden request in header values
        headers = [
            (b":method", b"POST"),
            (b":path", b"/api"),
            (b":scheme", b"https"),
            (b":authority", (context.domain or context.dst_ip).encode()),
            # Inject hidden request in a custom header
            (b"x-forwarded-for", hidden_request.replace(b"\r\n", b"; ")),
            (b"content-type", b"application/octet-stream"),
        ]

        encoder = HPACKEncoder()
        headers_payload = encoder.encode_headers(headers)
        headers_frame = HTTP2Frame(0x1, 0x4, 1, headers_payload)  # END_HEADERS

        # Data frame with original payload
        data_frame = HTTP2Frame(0x0, 0x1, 1, payload)  # END_STREAM

        # Connection preface and settings
        preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        settings_frame = HTTP2Frame(0x4, 0x0, 0, b"")  # Empty SETTINGS

        return (
            preface
            + settings_frame.to_bytes()
            + headers_frame.to_bytes()
            + data_frame.to_bytes()
        )

    def _create_post_upgrade_frames(
        self, payload: bytes, context: AttackContext
    ) -> bytes:
        """Create HTTP/2 frames after h2c upgrade."""
        # SETTINGS frame
        settings_frame = HTTP2Frame(0x4, 0x0, 0, b"")

        # HEADERS frame
        headers = [
            (b":method", b"POST"),
            (b":path", b"/upload"),
            (b":scheme", b"http"),  # h2c uses http
            (b":authority", (context.domain or context.dst_ip).encode()),
        ]

        encoder = HPACKEncoder()
        headers_payload = encoder.encode_headers(headers)
        headers_frame = HTTP2Frame(
            0x1, 0x4, 3, headers_payload
        )  # Stream 3, END_HEADERS

        # DATA frame
        data_frame = HTTP2Frame(0x0, 0x1, 3, payload)  # Stream 3, END_STREAM

        return (
            settings_frame.to_bytes() + headers_frame.to_bytes() + data_frame.to_bytes()
        )


@register_attack
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

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP/2 stream multiplexing attack."""
        start_time = time.time()

        try:
            payload = context.payload
            stream_count = context.params.get("stream_count", 5)
            interleave_frames = context.params.get("interleave_frames", True)
            use_priorities = context.params.get("use_priorities", True)

            # Split payload across multiple streams
            multiplexed_payload = self._create_multiplexed_streams(
                payload, stream_count, interleave_frames, use_priorities, context
            )

            segments = [(multiplexed_payload, 0)]
            packets_sent = 1
            bytes_sent = len(multiplexed_payload)
            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "stream_count": stream_count,
                    "interleave_frames": interleave_frames,
                    "use_priorities": use_priorities,
                    "original_size": len(payload),
                    "multiplexed_size": len(multiplexed_payload),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _create_multiplexed_streams(
        self,
        payload: bytes,
        stream_count: int,
        interleave: bool,
        use_priorities: bool,
        context: AttackContext,
    ) -> bytes:
        """Create multiple HTTP/2 streams with payload distribution."""
        frames = []

        # Connection preface
        preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

        # SETTINGS frame
        settings_payload = struct.pack(
            ">HI", 0x3, stream_count * 2
        )  # MAX_CONCURRENT_STREAMS
        settings_frame = HTTP2Frame(0x4, 0x0, 0, settings_payload)
        frames.append(settings_frame)

        # Split payload into chunks
        chunk_size = len(payload) // stream_count
        payload_chunks = []
        for i in range(stream_count):
            start = i * chunk_size
            if i == stream_count - 1:
                end = len(payload)
            else:
                end = start + chunk_size
            payload_chunks.append(payload[start:end])

        # Create frames for each stream
        stream_frames = []
        encoder = HPACKEncoder()

        for i, chunk in enumerate(payload_chunks):
            stream_id = (i * 2) + 1  # Odd stream IDs for client-initiated streams

            # Priority frame if requested
            if use_priorities:
                priority_payload = struct.pack(">IB", 0, 16 + i)  # Different weights
                priority_frame = HTTP2Frame(0x2, 0x0, stream_id, priority_payload)
                stream_frames.append((i, priority_frame))

            # Headers frame
            headers = [
                (b":method", b"POST"),
                (b":path", f"/api/stream/{i}".encode()),
                (b":scheme", b"https"),
                (b":authority", (context.domain or context.dst_ip).encode()),
                (b"content-length", str(len(chunk)).encode()),
            ]

            headers_payload = encoder.encode_headers(headers)
            headers_frame = HTTP2Frame(
                0x1, 0x4, stream_id, headers_payload
            )  # END_HEADERS
            stream_frames.append((i, headers_frame))

            # Data frame
            data_frame = HTTP2Frame(0x0, 0x1, stream_id, chunk)  # END_STREAM
            stream_frames.append((i, data_frame))

        # Interleave frames if requested
        if interleave:
            # Sort by frame type to interleave (priorities first, then headers, then data)
            stream_frames.sort(key=lambda x: (x[1].frame_type, x[0]))

        # Build final payload
        result = preface + settings_frame.to_bytes()
        for _, frame in stream_frames:
            result += frame.to_bytes()

        return result

    def _create_hpack_bomb(
        self, payload: bytes, compression_ratio: int, header_count: int
    ) -> bytes:
        """Create HPACK compression bomb."""
        # Split payload into chunks for headers
        chunk_size = max(1, len(payload) // header_count)
        chunks = [
            payload[i : i + chunk_size] for i in range(0, len(payload), chunk_size)
        ]

        # Create headers with compressed payload chunks
        headers = []
        hpack_encoder = HPACKEncoder()

        # Add standard headers
        headers.extend(
            [
                (b":method", b"POST"),
                (b":path", b"/api/upload"),
                (b":scheme", b"https"),
                (b":authority", b"example.com"),
            ]
        )

        # Add payload chunks as custom headers
        for i, chunk in enumerate(chunks):
            # Use custom header names that compress well
            header_name = f"x-data-{i:04d}".encode()
            # Base64 encode chunk to make it header-safe
            import base64

            header_value = base64.b64encode(chunk)
            headers.append((header_name, header_value))

        # Add many duplicate headers for compression
        for i in range(compression_ratio):
            headers.append((b"x-duplicate", f"value-{i}".encode()))

        return hpack_encoder.encode_headers(headers)

    def _wrap_hpack_bomb_in_frames(
        self, hpack_bomb: bytes, context: AttackContext
    ) -> bytes:
        """Wrap HPACK bomb in HTTP/2 frames."""
        # Connection preface
        preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

        # SETTINGS frame
        settings_frame = HTTP2Frame(0x4, 0x0, 0, b"")

        # Split HPACK bomb into multiple HEADERS frames if too large
        max_frame_size = 16384
        frames = []

        if len(hpack_bomb) <= max_frame_size:
            # Single HEADERS frame
            headers_frame = HTTP2Frame(
                0x1, 0x5, 1, hpack_bomb
            )  # HEADERS, END_HEADERS, END_STREAM
            frames.append(headers_frame)
        else:
            # Multiple HEADERS and CONTINUATION frames
            chunks = [
                hpack_bomb[i : i + max_frame_size]
                for i in range(0, len(hpack_bomb), max_frame_size)
            ]

            # First HEADERS frame
            first_frame = HTTP2Frame(0x1, 0x1, 1, chunks[0])  # HEADERS, END_STREAM
            frames.append(first_frame)

            # CONTINUATION frames
            for i, chunk in enumerate(chunks[1:], 1):
                flags = (
                    0x4 if i == len(chunks) - 1 else 0x0
                )  # END_HEADERS on last frame
                cont_frame = HTTP2Frame(0x9, flags, 1, chunk)  # CONTINUATION
                frames.append(cont_frame)

        # Combine all frames
        result = preface + settings_frame.to_bytes()
        for frame in frames:
            result += frame.to_bytes()

        return result


@register_attack
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

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute h2c smuggling attack."""
        start_time = time.time()

        try:
            payload = context.payload
            smuggling_method = context.params.get("smuggling_method", "content_length")
            use_chunked = context.params.get("use_chunked", False)
            add_te_header = context.params.get("add_te_header", True)

            # Create smuggled h2c request
            smuggled_payload = self._create_smuggled_h2c_request(
                payload, context, smuggling_method, use_chunked, add_te_header
            )

            segments = [(smuggled_payload, 0)]
            packets_sent = 1
            bytes_sent = len(smuggled_payload)
            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
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

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

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

        # Create HTTP/2 frames for the actual payload
        h2_frames = self._create_h2_frames_from_payload(payload, context)
        h2_data = b"".join(frame.to_bytes() for frame in h2_frames)

        # HTTP/2 connection preface
        h2_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        full_h2_data = h2_preface + h2_data

        if method == "content_length":
            # Content-Length based smuggling
            smuggled_request = self._create_cl_smuggled_request(
                domain, full_h2_data, use_chunked, add_te
            )
        elif method == "transfer_encoding":
            # Transfer-Encoding based smuggling
            smuggled_request = self._create_te_smuggled_request(
                domain, full_h2_data, add_te
            )
        elif method == "double_content_length":
            # Double Content-Length smuggling
            smuggled_request = self._create_double_cl_smuggled_request(
                domain, full_h2_data
            )
        else:
            # Default to simple h2c upgrade
            smuggled_request = self._create_simple_h2c_upgrade(domain, full_h2_data)

        return smuggled_request

    def _create_h2_frames_from_payload(
        self, payload: bytes, context: AttackContext
    ) -> List[HTTP2Frame]:
        """Create HTTP/2 frames from payload."""
        frames = []

        # SETTINGS frame
        settings_payload = struct.pack(">HI", 0x2, 0)  # ENABLE_PUSH = 0
        settings_frame = HTTP2Frame(0x4, 0x0, 0, settings_payload)
        frames.append(settings_frame)

        # HEADERS frame
        headers = [
            (b":method", b"POST"),
            (b":path", b"/api/bypass"),
            (b":scheme", b"http"),
            (b":authority", (context.domain or context.dst_ip).encode()),
            (b"content-type", b"application/octet-stream"),
            (b"content-length", str(len(payload)).encode()),
        ]

        hpack_encoder = HPACKEncoder()
        headers_payload = hpack_encoder.encode_headers(headers)
        headers_frame = HTTP2Frame(0x1, 0x4, 1, headers_payload)  # END_HEADERS
        frames.append(headers_frame)

        # DATA frame
        data_frame = HTTP2Frame(0x0, 0x1, 1, payload)  # END_STREAM
        frames.append(data_frame)

        return frames

    def _create_cl_smuggled_request(
        self, domain: str, h2_data: bytes, use_chunked: bool, add_te: bool
    ) -> bytes:
        """Create Content-Length based smuggled request."""
        # First request (seen by proxy)
        first_request = (
            f"POST /api/proxy HTTP/1.1\r\n"
            f"Host: {domain}\r\n"
            f"Content-Length: {len(h2_data)}\r\n"
        )

        if add_te:
            first_request += "Transfer-Encoding: chunked\r\n"

        first_request += "Connection: upgrade\r\n" "Upgrade: h2c\r\n" "\r\n"

        # Second request (smuggled, seen by backend)
        if use_chunked:
            # Chunked encoding for h2c data
            chunk_size = hex(len(h2_data))[2:].upper()
            smuggled_data = f"{chunk_size}\r\n".encode() + h2_data + b"\r\n0\r\n\r\n"
        else:
            smuggled_data = h2_data

        return first_request.encode() + smuggled_data

    def _create_te_smuggled_request(
        self, domain: str, h2_data: bytes, add_te: bool
    ) -> bytes:
        """Create Transfer-Encoding based smuggled request."""
        # Use Transfer-Encoding header manipulation
        request = (
            f"POST /api/bypass HTTP/1.1\r\n"
            f"Host: {domain}\r\n"
            f"Transfer-Encoding: chunked\r\n"
        )

        if add_te:
            # Add conflicting TE header
            request += "Transfer-Encoding: identity\r\n"

        request += "Connection: upgrade\r\n" "Upgrade: h2c\r\n" "\r\n"

        # Chunked h2c data
        chunk_size = hex(len(h2_data))[2:].upper()
        chunked_data = f"{chunk_size}\r\n".encode() + h2_data + b"\r\n0\r\n\r\n"

        return request.encode() + chunked_data

    def _create_double_cl_smuggled_request(self, domain: str, h2_data: bytes) -> bytes:
        """Create double Content-Length smuggled request."""
        # Use conflicting Content-Length headers
        fake_length = len(h2_data) // 2  # Shorter length to confuse proxy

        request = (
            f"POST /api/bypass HTTP/1.1\r\n"
            f"Host: {domain}\r\n"
            f"Content-Length: {fake_length}\r\n"
            f"Content-Length: {len(h2_data)}\r\n"
            f"Connection: upgrade\r\n"
            f"Upgrade: h2c\r\n"
            f"\r\n"
        )

        return request.encode() + h2_data

    def _create_simple_h2c_upgrade(self, domain: str, h2_data: bytes) -> bytes:
        """Create simple h2c upgrade request."""
        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {domain}\r\n"
            f"Connection: Upgrade, HTTP2-Settings\r\n"
            f"Upgrade: h2c\r\n"
            f"HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n"
            f"\r\n"
        )

        return request.encode() + h2_data


@register_attack
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

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute advanced HPACK manipulation attack."""
        start_time = time.time()

        try:
            payload = context.payload
            manipulation_technique = context.params.get("technique", "dynamic_table")
            compression_level = context.params.get("compression_level", "high")
            use_huffman = context.params.get("use_huffman", True)
            table_size_update = context.params.get("table_size_update", True)

            # Create advanced HPACK manipulated payload
            manipulated_payload = self._create_advanced_hpack_payload(
                payload,
                context,
                manipulation_technique,
                compression_level,
                use_huffman,
                table_size_update,
            )

            segments = [(manipulated_payload, 0)]
            packets_sent = 1
            bytes_sent = len(manipulated_payload)
            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "manipulation_technique": manipulation_technique,
                    "compression_level": compression_level,
                    "use_huffman": use_huffman,
                    "table_size_update": table_size_update,
                    "original_size": len(payload),
                    "manipulated_size": len(manipulated_payload),
                    "compression_ratio": (
                        len(payload) / len(manipulated_payload)
                        if manipulated_payload
                        else 1
                    ),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _create_advanced_hpack_payload(
        self,
        payload: bytes,
        context: AttackContext,
        technique: str,
        compression_level: str,
        use_huffman: bool,
        table_size_update: bool,
    ) -> bytes:
        """Create advanced HPACK manipulated payload."""
        # HTTP/2 connection preface
        preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

        frames = []

        # SETTINGS frame with table size update
        if table_size_update:
            settings_payload = struct.pack(">HI", 0x1, 8192)  # HEADER_TABLE_SIZE = 8192
            settings_payload += struct.pack(">HI", 0x2, 0)  # ENABLE_PUSH = 0
            settings_frame = HTTP2Frame(0x4, 0x0, 0, settings_payload)
            frames.append(settings_frame)

        # Create HPACK manipulated headers
        if technique == "dynamic_table":
            hpack_data = self._create_dynamic_table_manipulation(
                payload, context, use_huffman
            )
        elif technique == "literal_never_indexed":
            hpack_data = self._create_literal_never_indexed(
                payload, context, use_huffman
            )
        elif technique == "header_splitting":
            hpack_data = self._create_header_splitting(payload, context, use_huffman)
        elif technique == "context_update":
            hpack_data = self._create_context_update_manipulation(
                payload, context, use_huffman
            )
        else:
            hpack_data = self._create_basic_hpack_manipulation(
                payload, context, use_huffman
            )

        # HEADERS frame with manipulated HPACK data
        headers_frame = HTTP2Frame(0x1, 0x5, 1, hpack_data)  # END_HEADERS | END_STREAM
        frames.append(headers_frame)

        # Convert frames to bytes
        result = preface
        for frame in frames:
            result += frame.to_bytes()

        return result

    def _create_dynamic_table_manipulation(
        self, payload: bytes, context: AttackContext, use_huffman: bool
    ) -> bytes:
        """Create HPACK data using dynamic table manipulation."""
        hpack_data = b""

        # Dynamic table size update
        hpack_data += b"\x3f\xe1\x1f"  # Dynamic table size update to 4096

        # Add headers to dynamic table first
        custom_headers = [
            (b"x-bypass-method", b"hpack-dynamic"),
            (b"x-payload-encoding", b"base64"),
            (b"x-dpi-evasion", b"active"),
        ]

        for name, value in custom_headers:
            # Literal header with incremental indexing (adds to dynamic table)
            hpack_data += b"\x40"  # Literal with incremental indexing
            hpack_data += self._encode_string(name, use_huffman)
            hpack_data += self._encode_string(value, use_huffman)

        # Now use indexed headers from dynamic table
        hpack_data += b"\xbe"  # Index 62 (first dynamic table entry)
        hpack_data += b"\xbf"  # Index 63 (second dynamic table entry)
        hpack_data += b"\xc0"  # Index 64 (third dynamic table entry)

        # Standard pseudo-headers
        hpack_data += b"\x82"  # :method GET (index 2)
        hpack_data += b"\x84"  # :path / (index 4)
        hpack_data += b"\x87"  # :scheme https (index 7)

        # Authority header with domain
        hpack_data += b"\x41"  # Literal with incremental indexing for :authority
        domain = (context.domain or context.dst_ip).encode()
        hpack_data += self._encode_string(domain, use_huffman)

        return hpack_data

    def _create_literal_never_indexed(
        self, payload: bytes, context: AttackContext, use_huffman: bool
    ) -> bytes:
        """Create HPACK data using literal never indexed headers."""
        hpack_data = b""

        # Use literal never indexed for sensitive headers
        sensitive_headers = [
            (b":method", b"POST"),
            (b":path", b"/api/sensitive"),
            (b":scheme", b"https"),
            (b":authority", (context.domain or context.dst_ip).encode()),
            (b"authorization", b"Bearer " + payload[:50]),  # Embed part of payload
            (b"x-api-key", payload[50:100] if len(payload) > 50 else payload),
        ]

        for name, value in sensitive_headers:
            # Literal never indexed (0x10 pattern)
            hpack_data += b"\x10"
            hpack_data += self._encode_string(name, use_huffman)
            hpack_data += self._encode_string(value, use_huffman)

        return hpack_data

    def _create_header_splitting(
        self, payload: bytes, context: AttackContext, use_huffman: bool
    ) -> bytes:
        """Create HPACK data using header splitting technique."""
        hpack_data = b""

        # Split payload across multiple custom headers
        chunk_size = 64
        chunks = [
            payload[i : i + chunk_size] for i in range(0, len(payload), chunk_size)
        ]

        # Standard headers first
        hpack_data += b"\x83"  # :method POST (index 3)
        hpack_data += b"\x84"  # :path / (index 4)
        hpack_data += b"\x87"  # :scheme https (index 7)

        # Authority
        hpack_data += b"\x41"
        domain = (context.domain or context.dst_ip).encode()
        hpack_data += self._encode_string(domain, use_huffman)

        # Split payload across custom headers
        for i, chunk in enumerate(chunks):
            header_name = f"x-data-chunk-{i:02d}".encode()
            # Literal with incremental indexing
            hpack_data += b"\x40"
            hpack_data += self._encode_string(header_name, use_huffman)
            hpack_data += self._encode_string(chunk, use_huffman)

        # Add metadata header
        metadata = f"chunks={len(chunks)};size={len(payload)}".encode()
        hpack_data += b"\x40"
        hpack_data += self._encode_string(b"x-payload-metadata", use_huffman)
        hpack_data += self._encode_string(metadata, use_huffman)

        return hpack_data

    def _create_context_update_manipulation(
        self, payload: bytes, context: AttackContext, use_huffman: bool
    ) -> bytes:
        """Create HPACK data using context update manipulation."""
        hpack_data = b""

        # Multiple dynamic table size updates to confuse parsers
        hpack_data += b"\x20"  # Dynamic table size update to 0
        hpack_data += b"\x3f\xe1\x1f"  # Dynamic table size update to 4096
        hpack_data += b"\x3f\x81\x1f"  # Dynamic table size update to 2048

        # Add and immediately evict headers to manipulate table state
        temp_headers = [
            (b"x-temp-1", b"value1"),
            (b"x-temp-2", b"value2"),
            (b"x-temp-3", b"value3"),
        ]

        for name, value in temp_headers:
            hpack_data += b"\x40"  # Add to dynamic table
            hpack_data += self._encode_string(name, use_huffman)
            hpack_data += self._encode_string(value, use_huffman)

        # Force table eviction with size update
        hpack_data += b"\x3f\x61"  # Dynamic table size update to 512

        # Now add real headers
        real_headers = [
            (b":method", b"POST"),
            (b":path", b"/api/data"),
            (b":scheme", b"https"),
            (b":authority", (context.domain or context.dst_ip).encode()),
            (b"content-type", b"application/octet-stream"),
            (b"x-payload-data", payload[:100]),  # Embed payload
        ]

        for name, value in real_headers:
            hpack_data += b"\x40"
            hpack_data += self._encode_string(name, use_huffman)
            hpack_data += self._encode_string(value, use_huffman)

        return hpack_data

    def _create_basic_hpack_manipulation(
        self, payload: bytes, context: AttackContext, use_huffman: bool
    ) -> bytes:
        """Create basic HPACK manipulated data."""
        hpack_data = b""

        # Standard pseudo-headers
        hpack_data += b"\x83"  # :method POST
        hpack_data += b"\x84"  # :path /
        hpack_data += b"\x87"  # :scheme https

        # Authority with domain
        hpack_data += b"\x41"
        domain = (context.domain or context.dst_ip).encode()
        hpack_data += self._encode_string(domain, use_huffman)

        # Content-type
        hpack_data += b"\x40"
        hpack_data += self._encode_string(b"content-type", use_huffman)
        hpack_data += self._encode_string(b"application/octet-stream", use_huffman)

        # Embed payload in custom header
        hpack_data += b"\x40"
        hpack_data += self._encode_string(b"x-embedded-payload", use_huffman)
        hpack_data += self._encode_string(payload, use_huffman)

        return hpack_data

    def _encode_string(self, data: bytes, use_huffman: bool) -> bytes:
        """Encode string for HPACK."""
        if use_huffman:
            # Simplified Huffman encoding (just set the bit, don't actually encode)
            return bytes([0x80 | len(data)]) + data
        else:
            return bytes([len(data)]) + data
