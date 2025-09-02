"""
Multi-Layer Combo Attacks

Attacks that combine multiple bypass techniques in layers.
"""

import asyncio
import time
import random
from typing import List, Dict, Any, Optional
from core.bypass.attacks.base import (
    BaseAttack,
    AttackContext,
    AttackResult,
    AttackStatus,
)
from core.bypass.attacks.registry import register_attack


@register_attack
class TCPHTTPComboAttack(BaseAttack):
    """
    TCP + HTTP Combo Attack - combines TCP segmentation with HTTP obfuscation.
    """

    @property
    def name(self) -> str:
        return "tcp_http_combo"

    @property
    def category(self) -> str:
        return "combo"

    @property
    def description(self) -> str:
        return "Combines TCP segmentation with HTTP header manipulation"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute TCP + HTTP combo attack."""
        start_time = time.time()
        try:
            payload = context.payload
            segment_size = context.params.get("segment_size", 32)
            header_case = context.params.get("header_case", "random")
            http_modified = self._apply_http_manipulation(payload, header_case)
            segments = self._apply_tcp_segmentation(http_modified, segment_size)
            timed_segments = await self._add_timing_delays(segments)
            total_bytes = sum((len(seg[0]) for seg in timed_segments))
            packets_sent = len(timed_segments)
            latency = (time.time() - start_time) * 1000
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=total_bytes,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "layers_applied": [
                        "http_manipulation",
                        "tcp_segmentation",
                        "timing_delays",
                    ],
                    "segment_count": len(timed_segments),
                    "header_case": header_case,
                    "segment_size": segment_size,
                    "original_size": len(payload),
                    "final_size": total_bytes,
                    "segments": (
                        timed_segments if context.engine_type != "local" else None
                    ),
                },
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _apply_http_manipulation(self, payload: bytes, case_strategy: str) -> bytes:
        """Apply HTTP header case manipulation."""
        try:
            text = payload.decode("utf-8", errors="ignore")
            lines = text.split("\\r\\n")
            modified_lines = []
            for i, line in enumerate(lines):
                if i == 0 and any(
                    (
                        line.startswith(method)
                        for method in ["GET ", "POST ", "PUT ", "DELETE "]
                    )
                ):
                    parts = line.split(" ", 2)
                    if len(parts) >= 1:
                        method = parts[0]
                        if case_strategy == "lower":
                            method = method.lower()
                        elif case_strategy == "upper":
                            method = method.upper()
                        elif case_strategy == "random":
                            method = self._randomize_case(method)
                        parts[0] = method
                        line = " ".join(parts)
                elif ":" in line:
                    header, value = line.split(":", 1)
                    if case_strategy == "lower":
                        header = header.lower()
                    elif case_strategy == "upper":
                        header = header.upper()
                    elif case_strategy == "random":
                        header = self._randomize_case(header)
                    line = f"{header}:{value}"
                modified_lines.append(line)
            return "\\r\\n".join(modified_lines).encode("utf-8")
        except:
            return payload

    def _randomize_case(self, text: str) -> str:
        """Randomly change case of characters."""
        result = []
        for char in text:
            if char.isalpha():
                result.append(char.upper() if random.random() > 0.5 else char.lower())
            else:
                result.append(char)
        return "".join(result)

    def _apply_tcp_segmentation(self, payload: bytes, segment_size: int) -> List[tuple]:
        """Apply TCP segmentation."""
        segments = []
        for i in range(0, len(payload), segment_size):
            segment = payload[i : i + segment_size]
            segments.append((segment, 0))
        return segments

    def to_zapret_command(self, params: Optional[Dict[str, Any]] = None) -> str:
        params = params or {}
        tcp_size = params.get("segment_size", 3)
        header_case = params.get("header_case", "random") != "none"
        command_parts = [f"--dpi-desync=disorder --dpi-desync-split-pos={tcp_size}"]
        if header_case:
            command_parts.append("--hostcase")
        return " ".join(command_parts)

    async def _add_timing_delays(self, segments: List[tuple]) -> List[tuple]:
        """Add timing delays between segments."""
        timed_segments = []
        for i, (segment, _) in enumerate(segments):
            delay = random.randint(10, 100) if i > 0 else 0
            if delay > 0:
                await asyncio.sleep(delay / 1000.0)
            timed_segments.append((segment, delay))
        return timed_segments


@register_attack
class TLSFragmentationComboAttack(BaseAttack):
    """
    TLS + Fragmentation Combo Attack - combines TLS manipulation with IP fragmentation.
    """

    @property
    def name(self) -> str:
        return "tls_fragmentation_combo"

    @property
    def category(self) -> str:
        return "combo"

    @property
    def description(self) -> str:
        return "Combines TLS record manipulation with IP fragmentation"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute TLS + Fragmentation combo attack."""
        start_time = time.time()
        try:
            payload = context.payload
            fragment_size = context.params.get("fragment_size", 64)
            tls_record_split = context.params.get("tls_record_split", True)
            tls_modified = self._apply_tls_manipulation(payload, tls_record_split)
            fragments = self._apply_ip_fragmentation(tls_modified, fragment_size)
            randomized_fragments = self._randomize_fragment_order(fragments)
            total_bytes = sum((len(frag[0]) for frag in randomized_fragments))
            packets_sent = len(randomized_fragments)
            await asyncio.sleep(0)
            latency = (time.time() - start_time) * 1000
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=total_bytes,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "layers_applied": [
                        "tls_manipulation",
                        "ip_fragmentation",
                        "order_randomization",
                    ],
                    "fragment_count": len(randomized_fragments),
                    "fragment_size": fragment_size,
                    "tls_record_split": tls_record_split,
                    "original_size": len(payload),
                    "final_size": total_bytes,
                    "segments": (
                        randomized_fragments if context.engine_type != "local" else None
                    ),
                },
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _apply_tls_manipulation(self, payload: bytes, split_records: bool) -> bytes:
        """Apply TLS record manipulation."""
        if not split_records or len(payload) < 10:
            return payload
        if len(payload) >= 5 and payload[0] in [22, 23, 20, 21]:
            header = payload[:5]
            data = payload[5:]
            if len(data) > 32:
                mid_point = len(data) // 2
                first_data = data[:mid_point]
                second_data = data[mid_point:]
                first_record = (
                    header[:1]
                    + header[1:3]
                    + len(first_data).to_bytes(2, "big")
                    + first_data
                )
                second_record = (
                    header[:1]
                    + header[1:3]
                    + len(second_data).to_bytes(2, "big")
                    + second_data
                )
                return first_record + second_record
        return payload

    def _apply_ip_fragmentation(
        self, payload: bytes, fragment_size: int
    ) -> List[tuple]:
        """Apply IP fragmentation."""
        fragments = []
        fragment_id = random.randint(0, 65535)
        for i in range(0, len(payload), fragment_size):
            fragment_data = payload[i : i + fragment_size]
            fragment_offset = i // 8
            more_fragments = 1 if i + fragment_size < len(payload) else 0
            ip_header = self._create_ip_fragment_header(
                fragment_id, fragment_offset, more_fragments
            )
            fragment = ip_header + fragment_data
            fragments.append((fragment, 0))
        return fragments

    def _create_ip_fragment_header(
        self, fragment_id: int, offset: int, more_fragments: int
    ) -> bytes:
        """Create IP header with fragmentation info."""
        version_ihl = 69
        tos = 0
        total_length = 0
        identification = fragment_id
        flags_fragment = more_fragments << 13 | offset
        ttl = 64
        protocol = 6
        checksum = 0
        src_ip = b"\\x7f\\x00\\x00\\x01"
        dst_ip = b"\\x7f\\x00\\x00\\x01"
        import struct

        return struct.pack(
            "!BBHHHBBH4s4s",
            version_ihl,
            tos,
            total_length,
            identification,
            flags_fragment,
            ttl,
            protocol,
            checksum,
            src_ip,
            dst_ip,
        )

    def _randomize_fragment_order(self, fragments: List[tuple]) -> List[tuple]:
        """Randomize fragment order (except first and last)."""
        if len(fragments) <= 2:
            return fragments
        first = fragments[0]
        last = fragments[-1]
        middle = fragments[1:-1]
        random.shuffle(middle)
        return [first] + middle + [last]


@register_attack
class PayloadTunnelingComboAttack(BaseAttack):
    """
    Payload + Tunneling Combo Attack - combines payload obfuscation with protocol tunneling.
    """

    @property
    def name(self) -> str:
        return "payload_tunneling_combo"

    @property
    def category(self) -> str:
        return "combo"

    @property
    def description(self) -> str:
        return "Combines payload obfuscation with protocol tunneling"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp", "udp"]

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute Payload + Tunneling combo attack."""
        start_time = time.time()
        try:
            payload = context.payload
            obfuscation_type = context.params.get("obfuscation_type", "xor")
            tunnel_protocol = context.params.get("tunnel_protocol", "dns")
            encryption_key = context.params.get("encryption_key", b"default_key_123")
            obfuscated_payload = self._apply_payload_obfuscation(
                payload, obfuscation_type, encryption_key
            )
            tunneled_payload = self._apply_protocol_tunneling(
                obfuscated_payload, tunnel_protocol
            )
            final_payload = self._add_noise_padding(tunneled_payload)
            segments = [(final_payload, 0)]
            packets_sent = 1
            bytes_sent = len(final_payload)
            await asyncio.sleep(0)
            latency = (time.time() - start_time) * 1000
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "layers_applied": [
                        "payload_obfuscation",
                        "protocol_tunneling",
                        "noise_padding",
                    ],
                    "obfuscation_type": obfuscation_type,
                    "tunnel_protocol": tunnel_protocol,
                    "original_size": len(payload),
                    "obfuscated_size": len(obfuscated_payload),
                    "tunneled_size": len(tunneled_payload),
                    "final_size": len(final_payload),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _apply_payload_obfuscation(
        self, payload: bytes, obfuscation_type: str, key: bytes
    ) -> bytes:
        """Apply payload obfuscation."""
        if obfuscation_type == "xor":
            return self._xor_encrypt(payload, key)
        elif obfuscation_type == "base64":
            import base64

            return base64.b64encode(payload)
        elif obfuscation_type == "reverse":
            return payload[::-1]
        elif obfuscation_type == "caesar":
            return self._caesar_cipher(payload, 13)
        else:
            return payload

    def _xor_encrypt(self, data: bytes, key: bytes) -> bytes:
        """XOR encryption."""
        result = bytearray()
        for i, byte in enumerate(data):
            result.append(byte ^ key[i % len(key)])
        return bytes(result)

    def _caesar_cipher(self, data: bytes, shift: int) -> bytes:
        """Caesar cipher."""
        result = bytearray()
        for byte in data:
            result.append((byte + shift) % 256)
        return bytes(result)

    def _apply_protocol_tunneling(self, payload: bytes, tunnel_protocol: str) -> bytes:
        """Apply protocol tunneling."""
        if tunnel_protocol == "dns":
            return self._create_dns_tunnel(payload)
        elif tunnel_protocol == "http":
            return self._create_http_tunnel(payload)
        elif tunnel_protocol == "icmp":
            return self._create_icmp_tunnel(payload)
        else:
            return payload

    def _create_dns_tunnel(self, payload: bytes) -> bytes:
        """Create DNS tunnel packet."""
        import base64

        encoded = base64.b32encode(payload).decode("ascii").lower().rstrip("=")
        query_id = random.randint(0, 65535).to_bytes(2, "big")
        flags = b"\\x01\\x00"
        questions = b"\\x00\\x01"
        answers = b"\\x00\\x00"
        authority = b"\\x00\\x00"
        additional = b"\\x00\\x00"
        domain = f"{encoded}.example.com"
        encoded_domain = b""
        for part in domain.split("."):
            encoded_domain += len(part).to_bytes(1, "big") + part.encode("ascii")
        encoded_domain += b"\\x00"
        query_type = b"\\x00\\x01"
        query_class = b"\\x00\\x01"
        return (
            query_id
            + flags
            + questions
            + answers
            + authority
            + additional
            + encoded_domain
            + query_type
            + query_class
        )

    def _create_http_tunnel(self, payload: bytes) -> bytes:
        """Create HTTP tunnel packet."""
        import base64

        encoded = base64.b64encode(payload).decode("ascii")
        request = f"POST /tunnel HTTP/1.1\\r\nHost: example.com\\r\nContent-Type: application/x-www-form-urlencoded\\r\nContent-Length: {len(encoded) + 5}\\r\n\\r\ndata={encoded}"
        return request.encode("utf-8")

    def _create_icmp_tunnel(self, payload: bytes) -> bytes:
        """Create ICMP tunnel packet."""
        import struct

        icmp_type = 8
        icmp_code = 0
        icmp_id = random.randint(0, 65535)
        icmp_seq = random.randint(0, 65535)
        header = struct.pack("!BBHHH", icmp_type, icmp_code, 0, icmp_id, icmp_seq)
        packet = header + payload
        checksum = self._calculate_icmp_checksum(packet)
        header = struct.pack(
            "!BBHHH", icmp_type, icmp_code, checksum, icmp_id, icmp_seq
        )
        return header + payload

    def _calculate_icmp_checksum(self, data: bytes) -> int:
        """Calculate ICMP checksum."""
        if len(data) % 2:
            data += b"\\x00"
        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i + 1]
            checksum += word
        checksum = (checksum >> 16) + (checksum & 65535)
        checksum += checksum >> 16
        return ~checksum & 65535

    def _add_noise_padding(self, payload: bytes) -> bytes:
        """Add noise padding to payload."""
        noise_size = random.randint(16, 64)
        noise = random.randbytes(noise_size)
        position = random.randint(0, len(payload))
        return payload[:position] + noise + payload[position:]


@register_attack
class AdaptiveMultiLayerAttack(BaseAttack):
    """
    Adaptive Multi-Layer Attack - dynamically combines multiple techniques.
    """

    @property
    def name(self) -> str:
        return "adaptive_multi_layer"

    @property
    def category(self) -> str:
        return "combo"

    @property
    def description(self) -> str:
        return (
            "Dynamically combines multiple bypass techniques based on payload analysis"
        )

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp", "udp"]

    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute adaptive multi-layer attack."""
        start_time = time.time()
        try:
            payload = context.payload
            adaptation_level = context.params.get("adaptation_level", "medium")
            analysis = self._analyze_payload(payload)
            techniques = self._select_techniques(analysis, adaptation_level)
            modified_payload = payload
            applied_techniques = []
            for technique in techniques:
                modified_payload = self._apply_technique(modified_payload, technique)
                applied_techniques.append(technique["name"])
            segments = self._create_adaptive_segments(modified_payload, analysis)
            total_bytes = sum((len(seg[0]) for seg in segments))
            packets_sent = len(segments)
            await asyncio.sleep(0)
            latency = (time.time() - start_time) * 1000
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=total_bytes,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "adaptation_level": adaptation_level,
                    "payload_analysis": analysis,
                    "applied_techniques": applied_techniques,
                    "technique_count": len(applied_techniques),
                    "original_size": len(payload),
                    "final_size": total_bytes,
                    "segments": segments if context.engine_type != "local" else None,
                },
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _analyze_payload(self, payload: bytes) -> Dict[str, Any]:
        """Analyze payload characteristics."""
        analysis = {
            "size": len(payload),
            "entropy": self._calculate_entropy(payload),
            "has_http": b"HTTP/" in payload
            or any(
                (
                    payload.startswith(method.encode())
                    for method in ["GET ", "POST ", "PUT "]
                )
            ),
            "has_tls": len(payload) > 5 and payload[0] in [22, 23, 20, 21],
            "has_dns": len(payload) > 12
            and payload[2:4] in [b"\\x01\\x00", b"\\x81\\x80"],
            "printable_ratio": (
                sum((1 for b in payload if 32 <= b <= 126)) / len(payload)
                if payload
                else 0
            ),
        }
        return analysis

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        import math

        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        return entropy

    def _select_techniques(
        self, analysis: Dict[str, Any], level: str
    ) -> List[Dict[str, Any]]:
        """Select techniques based on payload analysis."""
        techniques = []
        if analysis["size"] > 64:
            techniques.append({"name": "segmentation", "params": {"size": 32}})
        if level in ["medium", "high"]:
            if analysis["has_http"]:
                techniques.append(
                    {"name": "http_manipulation", "params": {"case": "random"}}
                )
            if analysis["entropy"] < 6.0:
                techniques.append(
                    {"name": "payload_obfuscation", "params": {"type": "xor"}}
                )
        if level == "high":
            techniques.append(
                {"name": "timing_variation", "params": {"max_delay": 200}}
            )
            if not analysis["has_tls"]:
                techniques.append(
                    {"name": "protocol_tunneling", "params": {"protocol": "dns"}}
                )
        return techniques

    def _apply_technique(self, payload: bytes, technique: Dict[str, Any]) -> bytes:
        """Apply a specific technique to payload."""
        name = technique["name"]
        params = technique.get("params", {})
        if name == "segmentation":
            return payload
        elif name == "http_manipulation":
            return self._apply_http_case_change(payload, params.get("case", "random"))
        elif name == "payload_obfuscation":
            return self._apply_xor_obfuscation(payload)
        elif name == "protocol_tunneling":
            return self._apply_simple_tunneling(payload, params.get("protocol", "dns"))
        else:
            return payload

    def _apply_http_case_change(self, payload: bytes, case_type: str) -> bytes:
        """Apply HTTP case manipulation."""
        try:
            text = payload.decode("utf-8", errors="ignore")
            if case_type == "random":
                result = "".join(
                    (
                        (
                            c.upper()
                            if random.random() > 0.5
                            else c.lower() if c.isalpha() else c
                        )
                        for c in text
                    )
                )
                return result.encode("utf-8")
        except:
            pass
        return payload

    def _apply_xor_obfuscation(self, payload: bytes) -> bytes:
        """Apply XOR obfuscation."""
        key = b"adaptive_key"
        result = bytearray()
        for i, byte in enumerate(payload):
            result.append(byte ^ key[i % len(key)])
        return bytes(result)

    def _apply_simple_tunneling(self, payload: bytes, protocol: str) -> bytes:
        """Apply simple protocol tunneling."""
        if protocol == "dns":
            prefix = b"\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00"
            suffix = b"\\x00\\x00\\x01\\x00\\x01"
            return prefix + payload + suffix
        return payload

    def _create_adaptive_segments(
        self, payload: bytes, analysis: Dict[str, Any]
    ) -> List[tuple]:
        """Create segments with adaptive timing."""
        segment_size = 64 if analysis["size"] > 128 else 32
        segments = []
        for i in range(0, len(payload), segment_size):
            segment = payload[i : i + segment_size]
            delay = (
                random.randint(10, 50)
                if analysis["entropy"] > 6.0
                else random.randint(50, 150)
            )
            segments.append((segment, delay if i > 0 else 0))
        return segments
