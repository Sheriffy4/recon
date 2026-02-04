"""
Protocol Tunneling Attacks

Attacks that tunnel protocols within other protocols to evade DPI.
"""

import time
import struct
import random
import base64
from typing import List, Dict, Any
from core.bypass.attacks.base import (
    BaseAttack,
    AttackContext,
    AttackResult,
    AttackStatus,
)
from core.bypass.attacks.attack_registry import register_attack


def _safe_create_result(status_name: str, **kwargs):
    """Safely create AttackResult to prevent AttackStatus errors."""
    try:
        from core.bypass.attacks.safe_result_utils import safe_create_attack_result

        return safe_create_attack_result(status_name, **kwargs)
    except Exception:
        try:
            from core.bypass.attacks.base import AttackResult, AttackStatus

            status = getattr(AttackStatus, status_name)
            return AttackResult(status=status, **kwargs)
        except Exception:
            return None


@register_attack
class HTTPTunnelingAttack(BaseAttack):
    """
    HTTP Tunneling Attack - tunnels data through HTTP requests.
    """

    @property
    def name(self) -> str:
        return "http_tunneling"

    @property
    def category(self) -> str:
        return "tunneling"

    @property
    def description(self) -> str:
        return "Tunnels data through HTTP requests and responses"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {"method": "POST", "path": "/", "headers": {}}

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP tunneling attack."""
        start_time = time.time()
        try:
            payload = context.payload
            tunnel_method = context.params.get("tunnel_method", "POST")
            tunnel_path = context.params.get("tunnel_path", "/tunnel")
            host_header = context.params.get("host_header", "example.com")
            encoding = context.params.get("encoding", "base64")
            if encoding == "base64":
                encoded_payload = base64.b64encode(payload).decode("ascii")
            elif encoding == "url":
                encoded_payload = self._url_encode(payload)
            else:
                encoded_payload = payload.decode("utf-8", errors="ignore")
            if tunnel_method == "POST":
                http_request = self._create_post_tunnel(tunnel_path, host_header, encoded_payload)
            elif tunnel_method == "GET":
                http_request = self._create_get_tunnel(tunnel_path, host_header, encoded_payload)
            elif tunnel_method == "PUT":
                http_request = self._create_put_tunnel(tunnel_path, host_header, encoded_payload)
            else:
                http_request = self._create_post_tunnel(tunnel_path, host_header, encoded_payload)
            segments = [(http_request, 0)]
            packets_sent = 1
            bytes_sent = len(http_request)
            latency = (time.time() - start_time) * 1000
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "tunnel_method": tunnel_method,
                    "tunnel_path": tunnel_path,
                    "encoding": encoding,
                    "original_size": len(payload),
                    "tunneled_size": len(http_request),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _create_post_tunnel(self, path: str, host: str, data: str) -> bytes:
        """Create HTTP POST tunnel request."""
        content_length = len(data)
        request = f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {content_length}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nConnection: close\r\n\r\ndata={data}"
        return request.encode("utf-8")

    def _create_get_tunnel(self, path: str, host: str, data: str) -> bytes:
        """Create HTTP GET tunnel request."""
        if len(data) > 2000:
            data = data[:2000]
        request = f"GET {path}?data={data} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nConnection: close\r\n\r\n"
        return request.encode("utf-8")

    def _create_put_tunnel(self, path: str, host: str, data: str) -> bytes:
        """Create HTTP PUT tunnel request."""
        content_length = len(data)
        request = f"PUT {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: text/plain\r\nContent-Length: {content_length}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nConnection: close\r\n\r\n{data}"
        return request.encode("utf-8")

    def _url_encode(self, data: bytes) -> str:
        """Simple URL encoding."""
        result = ""
        for byte in data:
            if 32 <= byte <= 126 and byte not in [37, 38, 43, 61]:
                result += chr(byte)
            else:
                result += f"%{byte:02X}"
        return result


@register_attack
class WebSocketTunnelingAttack(BaseAttack):
    """
    WebSocket Tunneling Attack - tunnels data through WebSocket connections.
    """

    @property
    def name(self) -> str:
        return "websocket_tunneling"

    @property
    def category(self) -> str:
        return "tunneling"

    @property
    def description(self) -> str:
        return "Tunnels data through WebSocket protocol"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {"path": "/ws", "protocol": "chat"}

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute WebSocket tunneling attack."""
        start_time = time.time()
        try:
            payload = context.payload
            host_header = context.params.get("host_header", "example.com")
            path = context.params.get("path", "/ws")
            ws_key = base64.b64encode(random.randbytes(16)).decode("ascii")
            handshake = self._create_ws_handshake(host_header, path, ws_key)
            ws_frame = self._create_ws_frame(payload)
            combined_payload = handshake + ws_frame
            segments = [(handshake, 0), (ws_frame, 100)]
            packets_sent = 2
            bytes_sent = len(combined_payload)
            latency = (time.time() - start_time) * 1000
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "host_header": host_header,
                    "path": path,
                    "ws_key": ws_key,
                    "original_size": len(payload),
                    "tunneled_size": len(combined_payload),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _create_ws_handshake(self, host: str, path: str, ws_key: str) -> bytes:
        """Create WebSocket handshake request."""
        handshake = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {ws_key}\r\nSec-WebSocket-Version: 13\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n\r\n"
        return handshake.encode("utf-8")

    def _create_ws_frame(self, payload: bytes) -> bytes:
        """Create WebSocket frame."""
        fin = 1
        opcode = 2
        mask = 1
        payload_len = len(payload)
        first_byte = fin << 7 | opcode
        if payload_len < 126:
            second_byte = mask << 7 | payload_len
            length_bytes = b""
        elif payload_len < 65536:
            second_byte = mask << 7 | 126
            length_bytes = struct.pack("!H", payload_len)
        else:
            second_byte = mask << 7 | 127
            length_bytes = struct.pack("!Q", payload_len)
        masking_key = random.randbytes(4)
        masked_payload = bytearray()
        for i, byte in enumerate(payload):
            masked_payload.append(byte ^ masking_key[i % 4])
        return bytes([first_byte, second_byte]) + length_bytes + masking_key + bytes(masked_payload)


@register_attack
class SSHTunnelingAttack(BaseAttack):
    """
    SSH Tunneling Attack - simulates SSH tunneling for data transmission.
    """

    @property
    def name(self) -> str:
        return "ssh_tunneling"

    @property
    def category(self) -> str:
        return "tunneling"

    @property
    def description(self) -> str:
        return "Simulates SSH tunneling for data transmission"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {"port": 22, "username": "user"}

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute SSH tunneling attack."""
        start_time = time.time()
        try:
            payload = context.payload
            ssh_version = context.params.get("ssh_version", "SSH-2.0-OpenSSH_8.0")
            ssh_ident = f"{ssh_version}\r\n".encode("utf-8")
            ssh_kex = self._create_ssh_kex()
            encrypted_payload = self._create_encrypted_payload(payload)
            combined_payload = ssh_ident + ssh_kex + encrypted_payload
            segments = [(ssh_ident, 0), (ssh_kex, 100), (encrypted_payload, 200)]
            packets_sent = 3
            bytes_sent = len(combined_payload)
            latency = (time.time() - start_time) * 1000
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "ssh_version": ssh_version,
                    "original_size": len(payload),
                    "tunneled_size": len(combined_payload),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _create_ssh_kex(self) -> bytes:
        """Create fake SSH key exchange packet."""
        kex_payload = b"\\x14" + random.randbytes(32)
        padding_length = 8 - (len(kex_payload) + 1) % 8
        padding = random.randbytes(padding_length)
        packet_length = len(kex_payload) + 1 + padding_length
        return struct.pack("!I", packet_length) + bytes([padding_length]) + kex_payload + padding

    def _create_encrypted_payload(self, payload: bytes) -> bytes:
        """Create encrypted-looking payload."""
        key = random.randbytes(32)
        encrypted = bytearray()
        for i, byte in enumerate(payload):
            encrypted.append(byte ^ key[i % len(key)])
        padding_length = 8 - (len(encrypted) + 1) % 8
        padding = random.randbytes(padding_length)
        packet_length = len(encrypted) + 1 + padding_length
        return (
            struct.pack("!I", packet_length) + bytes([padding_length]) + bytes(encrypted) + padding
        )


@register_attack
class VPNTunnelingAttack(BaseAttack):
    """
    VPN Tunneling Attack - simulates VPN tunneling protocols.
    """

    @property
    def name(self) -> str:
        return "vpn_tunneling"

    @property
    def category(self) -> str:
        return "tunneling"

    @property
    def description(self) -> str:
        return "Simulates VPN tunneling protocols for data transmission"

    @property
    def supported_protocols(self) -> List[str]:
        return ["udp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {"protocol": "openvpn", "port": 1194}

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute VPN tunneling attack."""
        start_time = time.time()
        try:
            payload = context.payload
            vpn_type = context.params.get("vpn_type", "openvpn")
            if vpn_type == "openvpn":
                tunneled_payload = self._create_openvpn_packet(payload)
            elif vpn_type == "wireguard":
                tunneled_payload = self._create_wireguard_packet(payload)
            elif vpn_type == "ipsec":
                tunneled_payload = self._create_ipsec_packet(payload)
            else:
                tunneled_payload = self._create_openvpn_packet(payload)
            segments = [(tunneled_payload, 0)]
            packets_sent = 1
            bytes_sent = len(tunneled_payload)
            latency = (time.time() - start_time) * 1000
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                metadata={
                    "vpn_type": vpn_type,
                    "original_size": len(payload),
                    "tunneled_size": len(tunneled_payload),
                    "segments": segments if context.engine_type != "local" else None,
                },
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _create_openvpn_packet(self, payload: bytes) -> bytes:
        """Create OpenVPN-like packet."""
        opcode = 56
        session_id = random.randbytes(8)
        packet_id = random.randint(0, 4294967295).to_bytes(4, "big")
        return bytes([opcode]) + session_id + packet_id + payload

    def _create_wireguard_packet(self, payload: bytes) -> bytes:
        """Create WireGuard-like packet."""
        packet_type = 4
        reserved = b"\\x00\\x00\\x00"
        receiver = random.randbytes(4)
        counter = random.randint(0, 18446744073709551615).to_bytes(8, "little")
        encrypted_payload = bytes((b ^ 170 for b in payload))
        return bytes([packet_type]) + reserved + receiver + counter + encrypted_payload

    def _create_ipsec_packet(self, payload: bytes) -> bytes:
        """Create IPSec ESP-like packet."""
        spi = random.randbytes(4)
        sequence = random.randint(0, 4294967295).to_bytes(4, "big")
        pad_length = 16 - (len(payload) + 2) % 16
        padding = b"\\x00" * pad_length
        next_header = b"\\x04"
        encrypted_data = bytes(
            (b ^ 85 for b in payload + padding + bytes([pad_length]) + next_header)
        )
        icv = random.randbytes(12)
        return spi + sequence + encrypted_data + icv
