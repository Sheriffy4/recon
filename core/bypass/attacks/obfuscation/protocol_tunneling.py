"""
Protocol Tunneling Obfuscation Attacks

Advanced protocol tunneling techniques that hide traffic within legitimate protocols
to evade DPI detection. These attacks restore and enhance tunneling capabilities
from the legacy system.
"""

import time
import random
import base64
import hashlib

from typing import List, Dict, Any, Callable, Optional
from core.bypass.attacks.attack_registry import register_attack
from core.bypass.attacks.base import (
    BaseAttack,
    AttackContext,
    AttackResult,
    AttackStatus,
)
from core.bypass.attacks.obfuscation import tunneling_utils
from core.bypass.attacks.obfuscation.segment_schema import make_segment, next_seq_offset


def _build_sequential_segments(
    packets: List[bytes],
    delay_ms_fn: Optional[Callable[[int], int]] = None,
) -> List[tuple]:
    """
    Build SegmentTuple list in the engine-compatible format:
      (payload_bytes, seq_offset:int, options:dict)

    delay, if any, is encoded in options["delay_ms"] (NOT in seq_offset).
    """
    segments: List[tuple] = []
    seq_offset = 0
    for i, packet in enumerate(packets):
        options: Dict[str, Any] = {}
        if delay_ms_fn is not None:
            delay_ms = int(delay_ms_fn(i) or 0)
            if delay_ms > 0:
                options["delay_ms"] = delay_ms
        segments.append(
            make_segment(
                packet,
                seq_offset,
                delay_ms=options.get("delay_ms", 0),
                protocol="tcp",
                segment_index=i,
                segment_kind="data",
                direction="c2s",
                **options,
            )
        )
        seq_offset = next_seq_offset(seq_offset, len(packet))
    return segments


def _has_delays(segments: List[tuple]) -> bool:
    for seg in segments:
        if isinstance(seg, tuple) and len(seg) == 3 and isinstance(seg[2], dict):
            if seg[2].get("delay_ms"):
                return True
    return False


@register_attack
class HTTPTunnelingObfuscationAttack(BaseAttack):
    """
    Advanced HTTP Tunneling Attack with multiple obfuscation layers.

    Tunnels data through HTTP requests with various encoding and obfuscation
    techniques to make traffic appear as legitimate web browsing.
    """

    @property
    def name(self) -> str:
        return "http_tunneling_obfuscation"

    @property
    def category(self) -> str:
        return "tunneling"

    @property
    def description(self) -> str:
        return "Advanced HTTP tunneling with multiple obfuscation layers"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP tunneling obfuscation attack."""
        start_time = time.time()
        try:
            # Extract parameters
            params = tunneling_utils.extract_http_tunneling_params(context)
            if context.debug:
                self.logger.debug(
                    "HTTP tunneling params=%s payload_len=%d", params, len(context.payload)
                )

            # Build obfuscated HTTP request
            obfuscated_payload = self._apply_obfuscation_layers(
                context.payload, params["encoding"], params["obfuscation_level"]
            )
            http_request = self._build_http_request(
                obfuscated_payload,
                params["method"],
                params["host_header"],
                params["user_agent"],
                params["obfuscation_level"],
            )

            # Build result
            segments = [
                make_segment(
                    http_request,
                    0,
                    delay_ms=0,
                    protocol="tcp",
                    attack=self.name,
                    segment_index=0,
                    segment_kind="data",
                    direction="c2s",
                )
            ]
            latency = (time.time() - start_time) * 1000

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=1,
                bytes_sent=len(http_request),
                connection_established=True,
                data_transmitted=True,
                technique_used="http_tunneling_obfuscation",
                metadata={
                    "method": params["method"],
                    "encoding": params["encoding"],
                    "obfuscation_level": params["obfuscation_level"],
                    "original_size": len(context.payload),
                    "obfuscated_size": len(obfuscated_payload),
                    "total_size": len(http_request),
                    "segments": segments,
                    "segment_count": len(segments),
                    "plan_total_bytes": sum(len(s[0]) for s in segments),
                    "has_delays": _has_delays(segments),
                    "payload_digest8": hashlib.sha256(context.payload).hexdigest()[:8],
                },
            )
        except (UnicodeDecodeError, UnicodeEncodeError) as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"Encoding error: {str(e)}",
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="http_tunneling_obfuscation",
            )
        except (KeyError, ValueError, TypeError) as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"Parameter error: {str(e)}",
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="http_tunneling_obfuscation",
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"Unexpected error: {str(e)}",
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="http_tunneling_obfuscation",
            )

    def _build_http_request(
        self, obfuscated_payload: str, method: str, host: str, user_agent: str, level: str
    ) -> bytes:
        """Build HTTP request based on method."""
        method_upper = method.upper()
        if method_upper == "POST":
            return self._create_obfuscated_post_request(obfuscated_payload, host, user_agent, level)
        elif method_upper == "GET":
            return self._create_obfuscated_get_request(obfuscated_payload, host, user_agent, level)
        elif method_upper == "PUT":
            return self._create_obfuscated_put_request(obfuscated_payload, host, user_agent, level)
        else:
            return self._create_obfuscated_post_request(obfuscated_payload, host, user_agent, level)

    def _apply_obfuscation_layers(self, payload: bytes, encoding: str, level: str) -> str:
        """Apply multiple layers of obfuscation to payload."""
        if encoding == "base64":
            encoded = base64.b64encode(payload).decode("ascii")
        elif encoding == "hex":
            encoded = payload.hex()
        elif encoding == "url":
            encoded = self._url_encode(payload)
        else:
            encoded = payload.decode("utf-8", errors="ignore")
        # Prevent accidental CRLF injection into HTTP headers/URL contexts
        if encoded:
            encoded = encoded.replace("\r", "").replace("\n", "")
        if level == "low":
            return encoded
        elif level == "medium":
            return self._apply_medium_obfuscation(encoded)
        elif level == "high":
            return self._apply_high_obfuscation(encoded)
        else:
            return encoded

    def _apply_medium_obfuscation(self, data: str) -> str:
        """Apply medium-level obfuscation."""
        return tunneling_utils.apply_medium_obfuscation(data)

    def _apply_high_obfuscation(self, data: str) -> str:
        """Apply high-level obfuscation with JSON structure."""
        return tunneling_utils.apply_high_obfuscation(data)

    def _create_obfuscated_post_request(
        self, data: str, host: str, user_agent: str, level: str
    ) -> bytes:
        """Create obfuscated POST request."""
        return tunneling_utils.create_http_post_request(data, host, user_agent, level)

    def _create_obfuscated_get_request(
        self, data: str, host: str, user_agent: str, level: str
    ) -> bytes:
        """Create obfuscated GET request."""
        return tunneling_utils.create_http_get_request(data, host, user_agent, level)

    def _create_obfuscated_put_request(
        self, data: str, host: str, user_agent: str, level: str
    ) -> bytes:
        """Create obfuscated PUT request."""
        return tunneling_utils.create_http_put_request(data, host, user_agent, level)

    def _url_encode(self, data: bytes) -> str:
        """URL encode binary data."""
        return tunneling_utils.url_encode(data)


@register_attack
class DNSOverHTTPSTunnelingAttack(BaseAttack):
    """
    DNS over HTTPS (DoH) Tunneling Attack.

    Tunnels data through DNS over HTTPS requests to evade DPI detection
    by appearing as legitimate DNS queries.
    """

    @property
    def name(self) -> str:
        return "dns_over_https_tunneling"

    @property
    def category(self) -> str:
        return "tunneling"

    @property
    def description(self) -> str:
        return "Tunnels data through DNS over HTTPS requests"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute DNS over HTTPS tunneling attack."""
        start_time = time.time()
        try:
            payload = context.payload
            doh_server = context.params.get("doh_server", "cloudflare-dns.com")
            encoding_method = context.params.get("encoding_method", "base32")
            max_label_length = context.params.get("max_label_length", 63)
            if context.debug:
                self.logger.debug(
                    "DoH tunneling params=%s payload_len=%d",
                    {
                        "doh_server": doh_server,
                        "encoding_method": encoding_method,
                        "max_label_length": max_label_length,
                    },
                    len(payload),
                )
            encoded_payload = self._encode_payload_for_dns(payload, encoding_method)
            dns_queries = self._create_dns_queries(encoded_payload, max_label_length)
            doh_requests = []
            for query in dns_queries:
                doh_request = self._create_doh_request(query, doh_server)
                doh_requests.append(doh_request)
            segments = _build_sequential_segments(doh_requests, delay_ms_fn=lambda i: i * 100)
            # Ensure attack label is present on every segment.
            for seg in segments:
                if isinstance(seg, tuple) and len(seg) == 3 and isinstance(seg[2], dict):
                    seg[2].setdefault("attack", self.name)
            packets_sent = len(doh_requests)
            bytes_sent = sum(len(p) for p in doh_requests)
            latency = (time.time() - start_time) * 1000
            if context.debug:
                self.logger.debug(
                    "DoH plan query_count=%d packets=%d bytes=%d",
                    len(dns_queries),
                    packets_sent,
                    bytes_sent,
                )
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used="dns_over_https_tunneling",
                metadata={
                    "doh_server": doh_server,
                    "encoding_method": encoding_method,
                    "query_count": len(dns_queries),
                    "original_size": len(payload),
                    "encoded_size": len(encoded_payload),
                    "total_size": bytes_sent,
                    "segments": segments,
                    "segment_count": len(segments),
                    "plan_total_bytes": sum(len(s[0]) for s in segments),
                    "has_delays": _has_delays(segments),
                    "payload_digest8": hashlib.sha256(payload).hexdigest()[:8],
                },
            )
        except (UnicodeDecodeError, UnicodeEncodeError) as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"DNS encoding error: {str(e)}",
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="dns_over_https_tunneling",
            )
        except (KeyError, ValueError, TypeError) as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"DNS parameter error: {str(e)}",
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="dns_over_https_tunneling",
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"Unexpected DNS error: {str(e)}",
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="dns_over_https_tunneling",
            )

    def _encode_payload_for_dns(self, payload: bytes, method: str) -> str:
        """Encode payload for DNS tunneling."""
        return tunneling_utils.encode_payload_for_dns(payload, method)

    def _create_dns_queries(self, encoded_data: str, max_label_length: int) -> List[str]:
        """Create DNS queries from encoded data."""
        return tunneling_utils.create_dns_queries(encoded_data, max_label_length)

    def _create_doh_request(self, query_domain: str, doh_server: str) -> bytes:
        """Create DNS over HTTPS request."""
        dns_query = self._create_dns_query_packet(query_domain)
        dns_query_b64 = base64.urlsafe_b64encode(dns_query).decode("ascii").rstrip("=")
        headers = [
            f"GET /dns-query?dns={dns_query_b64} HTTP/1.1",
            f"Host: {doh_server}",
            "Accept: application/dns-message",
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Connection: keep-alive",
        ]
        request = "\r\n".join(headers) + "\r\n\r\n"
        return request.encode("utf-8")

    def _create_dns_query_packet(self, domain: str) -> bytes:
        """Create DNS query packet."""
        return tunneling_utils.create_dns_query_packet(domain)


@register_attack
class WebSocketTunnelingObfuscationAttack(BaseAttack):
    """
    Advanced WebSocket Tunneling Attack with obfuscation.

    Tunnels data through WebSocket connections with various obfuscation
    techniques to evade DPI detection.
    """

    @property
    def name(self) -> str:
        return "websocket_tunneling_obfuscation"

    @property
    def category(self) -> str:
        return "tunneling"

    @property
    def description(self) -> str:
        return "Advanced WebSocket tunneling with obfuscation layers"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute WebSocket tunneling obfuscation attack."""
        start_time = time.time()
        try:
            payload = context.payload
            host_header = context.params.get("host_header", context.domain or "example.com")
            path = context.params.get("path", "/ws")
            subprotocol = context.params.get("subprotocol", "chat")
            obfuscation_method = context.params.get("obfuscation_method", "fragmentation")
            ws_key = base64.b64encode(tunneling_utils.randbytes(16)).decode("ascii")
            if context.debug:
                self.logger.debug(
                    "WS tunneling params=%s payload_len=%d",
                    {
                        "host_header": host_header,
                        "path": path,
                        "subprotocol": subprotocol,
                        "obfuscation_method": obfuscation_method,
                    },
                    len(payload),
                )
            handshake = self._create_obfuscated_ws_handshake(host_header, path, ws_key, subprotocol)
            ws_frames = self._create_obfuscated_ws_frames(payload, obfuscation_method)
            all_packets = [handshake] + ws_frames
            combined_payload = b"".join(all_packets)
            segments = _build_sequential_segments(all_packets, delay_ms_fn=lambda i: i * 50)
            for seg in segments:
                if isinstance(seg, tuple) and len(seg) == 3 and isinstance(seg[2], dict):
                    seg[2].setdefault("attack", self.name)
            packets_sent = len(all_packets)
            bytes_sent = len(combined_payload)
            latency = (time.time() - start_time) * 1000
            if context.debug:
                self.logger.debug(
                    "WS plan frames=%d packets=%d bytes=%d",
                    len(ws_frames),
                    packets_sent,
                    bytes_sent,
                )
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used="websocket_tunneling_obfuscation",
                metadata={
                    "host_header": host_header,
                    "path": path,
                    "subprotocol": subprotocol,
                    "obfuscation_method": obfuscation_method,
                    "frame_count": len(ws_frames),
                    "original_size": len(payload),
                    "total_size": len(combined_payload),
                    "segments": segments,
                    "segment_count": len(segments),
                    "plan_total_bytes": sum(len(s[0]) for s in segments),
                    "has_delays": _has_delays(segments),
                    "payload_digest8": hashlib.sha256(payload).hexdigest()[:8],
                },
            )
        except (UnicodeDecodeError, UnicodeEncodeError) as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"WebSocket encoding error: {str(e)}",
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="websocket_tunneling_obfuscation",
            )
        except (KeyError, ValueError, TypeError) as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"WebSocket parameter error: {str(e)}",
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="websocket_tunneling_obfuscation",
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"Unexpected WebSocket error: {str(e)}",
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="websocket_tunneling_obfuscation",
            )

    def _create_obfuscated_ws_handshake(
        self, host: str, path: str, ws_key: str, subprotocol: str
    ) -> bytes:
        """Create obfuscated WebSocket handshake."""
        return tunneling_utils.create_obfuscated_ws_handshake(host, path, ws_key, subprotocol)

    def _create_obfuscated_ws_frames(self, payload: bytes, method: str) -> List[bytes]:
        """Create obfuscated WebSocket frames."""
        return tunneling_utils.create_obfuscated_ws_frames(payload, method)


@register_attack
class SSHTunnelingObfuscationAttack(BaseAttack):
    """
    Advanced SSH Tunneling Attack with obfuscation.

    Simulates SSH protocol with advanced obfuscation techniques
    to tunnel data while evading DPI detection.
    """

    @property
    def name(self) -> str:
        return "ssh_tunneling_obfuscation"

    @property
    def category(self) -> str:
        return "tunneling"

    @property
    def description(self) -> str:
        return "Advanced SSH protocol simulation with obfuscation"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute SSH tunneling obfuscation attack."""
        start_time = time.time()
        try:
            payload = context.payload
            ssh_version = context.params.get("ssh_version", "SSH-2.0-OpenSSH_8.9")
            encryption_method = context.params.get("encryption_method", "aes256-ctr")
            obfuscation_level = context.params.get("obfuscation_level", "high")
            if context.debug:
                self.logger.debug(
                    "SSH tunneling params=%s payload_len=%d",
                    {
                        "ssh_version": ssh_version,
                        "encryption_method": encryption_method,
                        "obfuscation_level": obfuscation_level,
                    },
                    len(payload),
                )
            ssh_packets = []
            ssh_ident = self._create_ssh_identification(ssh_version)
            ssh_packets.append(ssh_ident)
            kex_packet = self._create_obfuscated_kex_packet(obfuscation_level)
            ssh_packets.append(kex_packet)
            encrypted_packets = self._create_encrypted_data_packets(
                payload, encryption_method, obfuscation_level
            )
            ssh_packets.extend(encrypted_packets)
            combined_payload = b"".join(ssh_packets)
            segments = _build_sequential_segments(ssh_packets, delay_ms_fn=lambda i: i * 75)
            for seg in segments:
                if isinstance(seg, tuple) and len(seg) == 3 and isinstance(seg[2], dict):
                    seg[2].setdefault("attack", self.name)
            packets_sent = len(ssh_packets)
            bytes_sent = len(combined_payload)
            latency = (time.time() - start_time) * 1000
            if context.debug:
                self.logger.debug("SSH plan packets=%d bytes=%d", packets_sent, bytes_sent)
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used="ssh_tunneling_obfuscation",
                metadata={
                    "ssh_version": ssh_version,
                    "encryption_method": encryption_method,
                    "obfuscation_level": obfuscation_level,
                    "packet_count": len(ssh_packets),
                    "original_size": len(payload),
                    "total_size": len(combined_payload),
                    "segments": segments,
                    "segment_count": len(segments),
                    "plan_total_bytes": sum(len(s[0]) for s in segments),
                    "has_delays": _has_delays(segments),
                    "payload_digest8": hashlib.sha256(payload).hexdigest()[:8],
                },
            )
        except (UnicodeDecodeError, UnicodeEncodeError) as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"SSH encoding error: {str(e)}",
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="ssh_tunneling_obfuscation",
            )
        except (KeyError, ValueError, TypeError) as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"SSH parameter error: {str(e)}",
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="ssh_tunneling_obfuscation",
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"Unexpected SSH error: {str(e)}",
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="ssh_tunneling_obfuscation",
            )

    def _create_ssh_identification(self, version: str) -> bytes:
        """Create SSH identification string."""
        return tunneling_utils.create_ssh_identification(version)

    def _create_obfuscated_kex_packet(self, obfuscation_level: str) -> bytes:
        """Create obfuscated key exchange packet."""
        return tunneling_utils.create_obfuscated_ssh_kex_packet(obfuscation_level)

    def _create_encrypted_data_packets(
        self, payload: bytes, encryption_method: str, obfuscation_level: str
    ) -> List[bytes]:
        """Create encrypted data packets."""
        packets = []
        chunk_size = random.randint(100, 500)
        for i in range(0, len(payload), chunk_size):
            chunk = payload[i : i + chunk_size]
            encrypted_chunk = self._simulate_encryption(chunk, encryption_method)
            ssh_packet = self._create_ssh_data_packet(encrypted_chunk, obfuscation_level)
            packets.append(ssh_packet)
        return packets

    def _simulate_encryption(self, data: bytes, method: str) -> bytes:
        """Simulate encryption of data."""
        return tunneling_utils.simulate_ssh_encryption(data, method)

    def _create_ssh_data_packet(self, encrypted_data: bytes, obfuscation_level: str) -> bytes:
        """Create SSH data packet."""
        return tunneling_utils.create_ssh_data_packet(encrypted_data, obfuscation_level)


@register_attack
class VPNTunnelingObfuscationAttack(BaseAttack):
    """
    Advanced VPN Tunneling Attack with multiple VPN protocol simulation.

    Simulates various VPN protocols (OpenVPN, WireGuard, IPSec) with
    obfuscation techniques to tunnel data while evading DPI detection.
    """

    @property
    def name(self) -> str:
        return "vpn_tunneling_obfuscation"

    @property
    def category(self) -> str:
        return "tunneling"

    @property
    def description(self) -> str:
        return "Advanced VPN protocol simulation with obfuscation"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp", "udp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute VPN tunneling obfuscation attack."""
        start_time = time.time()
        try:
            # Extract and validate parameters
            params = tunneling_utils.extract_vpn_tunneling_params(context)
            if context.debug:
                self.logger.debug(
                    "VPN tunneling params=%s payload_len=%d",
                    params,
                    len(context.payload),
                )

            # Generate VPN packets
            vpn_packets = self._generate_vpn_packets_by_type(
                context.payload,
                params["vpn_type"],
                params["obfuscation_level"],
                params["use_compression"],
            )

            # Build segments with delays
            segments = _build_sequential_segments(
                vpn_packets,
                delay_ms_fn=lambda i: self._calculate_vpn_delay(i, params["vpn_type"]),
            )
            for seg in segments:
                if isinstance(seg, tuple) and len(seg) == 3 and isinstance(seg[2], dict):
                    seg[2].setdefault("attack", self.name)

            # Create result
            packets_sent = len(vpn_packets)
            bytes_sent = sum((len(packet) for packet in vpn_packets))
            latency = (time.time() - start_time) * 1000
            if context.debug:
                self.logger.debug("VPN plan packets=%d bytes=%d", packets_sent, bytes_sent)

            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used="vpn_tunneling_obfuscation",
                metadata={
                    "vpn_type": params["vpn_type"],
                    "obfuscation_level": params["obfuscation_level"],
                    "use_compression": params["use_compression"],
                    "original_size": len(context.payload),
                    "total_size": bytes_sent,
                    "segments": segments,
                    "segment_count": len(segments),
                    "plan_total_bytes": sum(len(s[0]) for s in segments),
                    "has_delays": _has_delays(segments),
                    "payload_digest8": hashlib.sha256(context.payload).hexdigest()[:8],
                },
            )
        except (UnicodeDecodeError, UnicodeEncodeError) as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"VPN encoding error: {str(e)}",
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="vpn_tunneling_obfuscation",
            )
        except (KeyError, ValueError, TypeError) as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"VPN parameter error: {str(e)}",
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="vpn_tunneling_obfuscation",
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=f"Unexpected VPN error: {str(e)}",
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="vpn_tunneling_obfuscation",
            )

    def _generate_vpn_packets_by_type(
        self, payload: bytes, vpn_type: str, obfuscation_level: str, use_compression: bool
    ) -> List[bytes]:
        """Generate VPN packets based on protocol type."""
        if vpn_type == "openvpn":
            return self._generate_openvpn_packets(payload, obfuscation_level, use_compression)
        elif vpn_type == "wireguard":
            return self._generate_wireguard_packets(payload, obfuscation_level)
        elif vpn_type == "ipsec":
            return self._generate_ipsec_packets(payload, obfuscation_level)
        else:
            raise ValueError(f"Unsupported VPN type: {vpn_type}")

    def _generate_openvpn_packets(
        self, payload: bytes, obfuscation_level: str, use_compression: bool
    ) -> List[bytes]:
        """Generate OpenVPN packets."""
        return tunneling_utils.generate_openvpn_packets(payload, obfuscation_level, use_compression)

    def _generate_wireguard_packets(self, payload: bytes, obfuscation_level: str) -> List[bytes]:
        """Generate WireGuard packets."""
        return tunneling_utils.generate_wireguard_packets(payload, obfuscation_level)

    def _generate_ipsec_packets(self, payload: bytes, obfuscation_level: str) -> List[bytes]:
        """Generate IPSec packets."""
        return tunneling_utils.generate_ipsec_packets(payload, obfuscation_level)

    def _calculate_vpn_delay(self, packet_index: int, vpn_type: str) -> int:
        """Calculate realistic VPN delay."""
        base_delays = {"openvpn": 20, "wireguard": 10, "ipsec": 30}
        base_delay = base_delays.get(vpn_type, 20)
        delay = 0
        if packet_index < 2:
            delay = base_delay + random.randint(50, 150)
        else:
            delay = base_delay + random.randint(5, 25)
        return delay

    def _get_vpn_packet_type(self, packet_index: int, vpn_type: str) -> str:
        """Get VPN packet type description."""
        if vpn_type == "openvpn":
            if packet_index == 0:
                return "client_hello"
            elif packet_index == 1:
                return "server_hello"
            else:
                return "data"
        elif vpn_type == "wireguard":
            if packet_index == 0:
                return "handshake_initiation"
            elif packet_index == 1:
                return "handshake_response"
            else:
                return "transport_data"
        elif vpn_type == "ipsec":
            if packet_index == 0:
                return "ike_init"
            elif packet_index == 1:
                return "ike_auth"
            else:
                return "esp_data"
        else:
            return "unknown"
