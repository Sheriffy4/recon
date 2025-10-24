"""
Protocol Mimicry Obfuscation Attacks

Advanced protocol mimicry techniques that disguise traffic as legitimate
protocols to evade DPI detection through protocol impersonation.
"""

import asyncio
import time
import random
import base64
import struct
import hashlib
from typing import List, Dict, Any
from core.bypass.attacks.attack_registry import register_attack
from core.bypass.attacks.base import (
    BaseAttack,
    AttackContext,
    AttackResult,
    AttackStatus,
)


@register_attack
class HTTPProtocolMimicryAttack(BaseAttack):
    """
    HTTP Protocol Mimicry Attack.

    Disguises arbitrary traffic as legitimate HTTP requests and responses
    with realistic headers, timing, and content patterns.
    """

    @property
    def name(self) -> str:
        return "http_protocol_mimicry"

    @property
    def category(self) -> str:
        return "tunneling"

    @property
    def description(self) -> str:
        return "Disguises traffic as legitimate HTTP requests and responses"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {}


    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute HTTP protocol mimicry attack."""
        start_time = time.time()
        try:
            payload = context.payload
            mimicry_type = context.params.get("mimicry_type", "web_browsing")
            include_response = context.params.get("include_response", True)
            user_agent_type = context.params.get("user_agent_type", "chrome")
            content_type = context.params.get("content_type", "auto")
            http_request = self._generate_http_request(
                payload, mimicry_type, user_agent_type, content_type, context
            )
            packets = [http_request]
            if include_response:
                http_response = self._generate_http_response(
                    payload, mimicry_type, content_type
                )
                packets.append(http_response)
            segments = []
            for i, packet in enumerate(packets):
                delay = self._calculate_realistic_delay(i, mimicry_type)
                await asyncio.sleep(delay / 1000.0)
                segments.append(
                    (
                        packet,
                        delay,
                        {
                            "mimicry_type": mimicry_type,
                            "packet_type": "request" if i == 0 else "response",
                            "realistic_timing": True,
                        },
                    )
                )
            packets_sent = len(packets)
            bytes_sent = sum((len(packet) for packet in packets))
            latency = (time.time() - start_time) * 1000
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used="http_protocol_mimicry",
                metadata={
                    "mimicry_type": mimicry_type,
                    "include_response": include_response,
                    "user_agent_type": user_agent_type,
                    "content_type": content_type,
                    "original_size": len(payload),
                    "total_size": bytes_sent,
                    "segments": segments,
                },
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="http_protocol_mimicry",
            )

    def _generate_http_request(
        self,
        payload: bytes,
        mimicry_type: str,
        user_agent_type: str,
        content_type: str,
        context: AttackContext,
    ) -> bytes:
        """Generate realistic HTTP request."""
        if mimicry_type == "web_browsing":
            return self._generate_browsing_request(payload, user_agent_type, context)
        elif mimicry_type == "api_call":
            return self._generate_api_request(
                payload, user_agent_type, content_type, context
            )
        elif mimicry_type == "file_download":
            return self._generate_download_request(payload, user_agent_type, context)
        elif mimicry_type == "form_submission":
            return self._generate_form_request(payload, user_agent_type, context)
        else:
            return self._generate_browsing_request(payload, user_agent_type, context)

    def _generate_browsing_request(
        self, payload: bytes, user_agent_type: str, context: AttackContext
    ) -> bytes:
        """Generate web browsing request."""
        user_agent = self._get_user_agent(user_agent_type)
        host = context.domain or "example.com"
        encoded_payload = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
        paths = ["/search", "/page", "/content", "/view", "/article"]
        path = random.choice(paths)
        params = [
            f"q={encoded_payload[:100]}",
            f"t={int(time.time())}",
            f"r={random.randint(1000, 9999)}",
            "lang=en",
            "format=html",
        ]
        if len(encoded_payload) > 100:
            remaining = encoded_payload[100:]
            for i in range(0, len(remaining), 50):
                chunk = remaining[i : i + 50]
                params.append(f"p{i // 50}={chunk}")
        query_string = "&".join(params)
        headers = [
            f"GET {path}?{query_string} HTTP/1.1",
            f"Host: {host}",
            f"User-Agent: {user_agent}",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language: en-US,en;q=0.5",
            "Accept-Encoding: gzip, deflate",
            "DNT: 1",
            "Connection: keep-alive",
            "Upgrade-Insecure-Requests: 1",
            "Sec-Fetch-Dest: document",
            "Sec-Fetch-Mode: navigate",
            "Sec-Fetch-Site: none",
            "Cache-Control: max-age=0",
        ]
        request = "\r\n".join(headers) + "\r\n\r\n"
        return request.encode("utf-8")

    def _generate_api_request(
        self,
        payload: bytes,
        user_agent_type: str,
        content_type: str,
        context: AttackContext,
    ) -> bytes:
        """Generate API request."""
        user_agent = self._get_user_agent(user_agent_type)
        host = context.domain or "api.example.com"
        if content_type == "auto":
            content_type = "application/json"
        if content_type == "application/json":
            import json

            encoded_payload = json.dumps(
                {
                    "data": base64.b64encode(payload).decode("ascii"),
                    "timestamp": int(time.time()),
                    "version": "1.0",
                    "client_id": self._generate_client_id(),
                }
            )
        else:
            encoded_payload = base64.b64encode(payload).decode("ascii")
        headers = [
            "POST /api/v1/data HTTP/1.1",
            f"Host: {host}",
            f"User-Agent: {user_agent}",
            "Accept: application/json, text/plain, */*",
            "Accept-Language: en-US,en;q=0.9",
            f"Content-Type: {content_type}",
            f"Content-Length: {len(encoded_payload)}",
            f"Authorization: Bearer {self._generate_bearer_token()}",
            "X-Requested-With: XMLHttpRequest",
            f"Origin: https://{host}",
            f"Referer: https://{host}/dashboard",
            "Connection: keep-alive",
        ]
        request = "\r\n".join(headers) + "\r\n\r\n" + encoded_payload
        return request.encode("utf-8")

    def _generate_download_request(
        self, payload: bytes, user_agent_type: str, context: AttackContext
    ) -> bytes:
        """Generate file download request."""
        user_agent = self._get_user_agent(user_agent_type)
        host = context.domain or "cdn.example.com"
        filename_hash = hashlib.md5(payload).hexdigest()[:8]
        file_extensions = [".pdf", ".zip", ".exe", ".dmg", ".tar.gz"]
        extension = random.choice(file_extensions)
        filename = f"file_{filename_hash}{extension}"
        headers = [
            f"GET /downloads/{filename} HTTP/1.1",
            f"Host: {host}",
            f"User-Agent: {user_agent}",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language: en-US,en;q=0.5",
            "Accept-Encoding: gzip, deflate",
            f"Referer: https://{host}/files",
            "Connection: keep-alive",
            "Upgrade-Insecure-Requests: 1",
        ]
        request = "\r\n".join(headers) + "\r\n\r\n"
        return request.encode("utf-8")

    def _generate_form_request(
        self, payload: bytes, user_agent_type: str, context: AttackContext
    ) -> bytes:
        """Generate form submission request."""
        user_agent = self._get_user_agent(user_agent_type)
        host = context.domain or "forms.example.com"
        form_data = [
            f"name=user_{random.randint(1000, 9999)}",
            "email=user@example.com",
            f"message={base64.b64encode(payload).decode('ascii')}",
            f"csrf_token={self._generate_csrf_token()}",
            f"timestamp={int(time.time())}",
        ]
        form_body = "&".join(form_data)
        headers = [
            "POST /submit HTTP/1.1",
            f"Host: {host}",
            f"User-Agent: {user_agent}",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language: en-US,en;q=0.5",
            "Accept-Encoding: gzip, deflate",
            "Content-Type: application/x-www-form-urlencoded",
            f"Content-Length: {len(form_body)}",
            f"Origin: https://{host}",
            f"Referer: https://{host}/form",
            "Connection: keep-alive",
            "Upgrade-Insecure-Requests: 1",
        ]
        request = "\r\n".join(headers) + "\r\n\r\n" + form_body
        return request.encode("utf-8")

    def _generate_http_response(
        self, payload: bytes, mimicry_type: str, content_type: str
    ) -> bytes:
        """Generate realistic HTTP response."""
        if mimicry_type == "web_browsing":
            return self._generate_html_response(payload)
        elif mimicry_type == "api_call":
            return self._generate_json_response(payload)
        elif mimicry_type == "file_download":
            return self._generate_file_response(payload)
        else:
            return self._generate_html_response(payload)

    def _generate_html_response(self, payload: bytes) -> bytes:
        """Generate HTML response."""
        encoded_payload = base64.b64encode(payload).decode("ascii")
        html_content = f'<!DOCTYPE html>\n<html>\n<head>\n    <title>Example Page</title>\n    <meta charset="UTF-8">\n    <!-- {encoded_payload[:100]} -->\n</head>\n<body>\n    <h1>Welcome</h1>\n    <p>This is a sample page.</p>\n    <form style="display:none;">\n        <input type="hidden" name="data" value="{encoded_payload[100:]}">\n    </form>\n    <script>\n        // Analytics data: {encoded_payload[-50:]}\n        console.log("Page loaded");\n    </script>\n</body>\n</html>'
        headers = [
            "HTTP/1.1 200 OK",
            "Content-Type: text/html; charset=UTF-8",
            f"Content-Length: {len(html_content)}",
            "Server: Apache/2.4.41 (Ubuntu)",
            "Cache-Control: public, max-age=3600",
            'ETag: "' + hashlib.md5(html_content.encode()).hexdigest()[:16] + '"',
            "Connection: keep-alive",
        ]
        response = "\r\n".join(headers) + "\r\n\r\n" + html_content
        return response.encode("utf-8")

    def _generate_json_response(self, payload: bytes) -> bytes:
        """Generate JSON API response."""
        import json

        response_data = {
            "status": "success",
            "data": {
                "result": base64.b64encode(payload).decode("ascii"),
                "timestamp": int(time.time()),
                "metadata": {
                    "size": len(payload),
                    "hash": hashlib.sha256(payload).hexdigest()[:16],
                },
            },
            "version": "1.0",
        }
        json_content = json.dumps(response_data, indent=2)
        headers = [
            "HTTP/1.1 200 OK",
            "Content-Type: application/json",
            f"Content-Length: {len(json_content)}",
            "Server: nginx/1.18.0",
            "Access-Control-Allow-Origin: *",
            "Cache-Control: no-cache",
            "Connection: keep-alive",
        ]
        response = "\r\n".join(headers) + "\r\n\r\n" + json_content
        return response.encode("utf-8")

    def _generate_file_response(self, payload: bytes) -> bytes:
        """Generate file download response."""
        file_header = b"PK\x03\x04"
        fake_file_content = file_header + payload + b"\x00" * 100
        headers = [
            "HTTP/1.1 200 OK",
            "Content-Type: application/octet-stream",
            f"Content-Length: {len(fake_file_content)}",
            'Content-Disposition: attachment; filename="download.zip"',
            "Server: nginx/1.18.0",
            "Cache-Control: no-cache",
            "Connection: keep-alive",
        ]
        response = "\r\n".join(headers) + "\r\n\r\n"
        return response.encode("utf-8") + fake_file_content

    def _get_user_agent(self, user_agent_type: str) -> str:
        """Get realistic user agent string."""
        user_agents = {
            "chrome": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "firefox": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
            "safari": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
            "edge": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        }
        return user_agents.get(user_agent_type, user_agents["chrome"])

    def _generate_client_id(self) -> str:
        """Generate realistic client ID."""
        return hashlib.md5(str(random.random()).encode()).hexdigest()[:16]

    def _generate_bearer_token(self) -> str:
        """Generate realistic bearer token."""
        return base64.b64encode(random.randbytes(24)).decode("ascii")

    def _generate_csrf_token(self) -> str:
        """Generate CSRF token."""
        return hashlib.sha256(str(random.random()).encode()).hexdigest()[:32]

    def _calculate_realistic_delay(self, packet_index: int, mimicry_type: str) -> int:
        """Calculate realistic delay between packets."""
        if mimicry_type == "web_browsing":
            return (
                random.randint(50, 200)
                if packet_index == 0
                else random.randint(100, 500)
            )
        elif mimicry_type == "api_call":
            return (
                random.randint(10, 50) if packet_index == 0 else random.randint(20, 100)
            )
        else:
            return random.randint(25, 150)


@register_attack
class TLSProtocolMimicryAttack(BaseAttack):
    """
    TLS Protocol Mimicry Attack.

    Disguises traffic as TLS handshake and encrypted data to evade
    DPI detection through TLS protocol impersonation.
    """

    @property
    def name(self) -> str:
        return "tls_protocol_mimicry"

    @property
    def category(self) -> str:
        return "tunneling"

    @property
    def description(self) -> str:
        return "Disguises traffic as TLS handshake and encrypted data"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {}


    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute TLS protocol mimicry attack."""
        start_time = time.time()
        try:
            payload = context.payload
            tls_version = context.params.get("tls_version", "1.3")
            cipher_suite = context.params.get("cipher_suite", "TLS_AES_256_GCM_SHA384")
            include_handshake = context.params.get("include_handshake", True)
            server_name = context.params.get(
                "server_name", context.domain or "example.com"
            )
            packets = []
            if include_handshake:
                client_hello = self._generate_client_hello(
                    tls_version, cipher_suite, server_name
                )
                server_hello = self._generate_server_hello(tls_version, cipher_suite)
                certificate = self._generate_certificate(server_name)
                finished = self._generate_finished()
                packets.extend([client_hello, server_hello, certificate, finished])
            encrypted_data = self._generate_encrypted_application_data(
                payload, tls_version
            )
            packets.append(encrypted_data)
            segments = []
            for i, packet in enumerate(packets):
                delay = await self._calculate_tls_delay(i, include_handshake)
                packet_type = self._get_packet_type(i, include_handshake)
                segments.append(
                    (
                        packet,
                        delay,
                        {
                            "tls_version": tls_version,
                            "packet_type": packet_type,
                            "cipher_suite": cipher_suite,
                        },
                    )
                )
            packets_sent = len(packets)
            bytes_sent = sum((len(packet) for packet in packets))
            latency = (time.time() - start_time) * 1000
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used="tls_protocol_mimicry",
                metadata={
                    "tls_version": tls_version,
                    "cipher_suite": cipher_suite,
                    "include_handshake": include_handshake,
                    "server_name": server_name,
                    "original_size": len(payload),
                    "total_size": bytes_sent,
                    "segments": segments,
                },
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="tls_protocol_mimicry",
            )

    def _generate_client_hello(
        self, tls_version: str, cipher_suite: str, server_name: str
    ) -> bytes:
        """Generate TLS Client Hello message."""
        record_type = 22
        version = self._get_tls_version_bytes(tls_version)
        handshake_type = 1
        client_version = version
        random_bytes = random.randbytes(32)
        session_id_length = 0
        session_id = b""
        cipher_suites = self._get_cipher_suites(cipher_suite)
        cipher_suites_length = len(cipher_suites)
        compression_methods = b"\x01\x00"
        extensions = self._generate_client_hello_extensions(server_name)
        extensions_length = len(extensions)
        handshake_content = (
            client_version
            + random_bytes
            + bytes([session_id_length])
            + session_id
            + struct.pack("!H", cipher_suites_length)
            + cipher_suites
            + compression_methods
            + struct.pack("!H", extensions_length)
            + extensions
        )
        handshake_length = len(handshake_content)
        handshake_header = (
            bytes([handshake_type]) + struct.pack("!I", handshake_length)[1:]
        )
        handshake_message = handshake_header + handshake_content
        record_length = len(handshake_message)
        record_header = (
            bytes([record_type]) + version + struct.pack("!H", record_length)
        )
        return record_header + handshake_message

    def _generate_server_hello(self, tls_version: str, cipher_suite: str) -> bytes:
        """Generate TLS Server Hello message."""
        record_type = 22
        version = self._get_tls_version_bytes(tls_version)
        handshake_type = 2
        server_version = version
        random_bytes = random.randbytes(32)
        session_id_length = 32
        session_id = random.randbytes(32)
        selected_cipher = self._get_cipher_suite_bytes(cipher_suite)
        compression_method = b"\x00"
        extensions = self._generate_server_hello_extensions()
        extensions_length = len(extensions)
        handshake_content = (
            server_version
            + random_bytes
            + bytes([session_id_length])
            + session_id
            + selected_cipher
            + compression_method
            + struct.pack("!H", extensions_length)
            + extensions
        )
        handshake_length = len(handshake_content)
        handshake_header = (
            bytes([handshake_type]) + struct.pack("!I", handshake_length)[1:]
        )
        handshake_message = handshake_header + handshake_content
        record_length = len(handshake_message)
        record_header = (
            bytes([record_type]) + version + struct.pack("!H", record_length)
        )
        return record_header + handshake_message

    def _generate_certificate(self, server_name: str) -> bytes:
        """Generate TLS Certificate message."""
        record_type = 22
        version = b"\x03\x03"
        handshake_type = 11
        fake_cert = self._generate_fake_certificate(server_name)
        cert_length = len(fake_cert)
        cert_list = struct.pack("!I", cert_length)[1:] + fake_cert
        cert_list_length = len(cert_list)
        handshake_content = struct.pack("!I", cert_list_length)[1:] + cert_list
        handshake_length = len(handshake_content)
        handshake_header = (
            bytes([handshake_type]) + struct.pack("!I", handshake_length)[1:]
        )
        handshake_message = handshake_header + handshake_content
        record_length = len(handshake_message)
        record_header = (
            bytes([record_type]) + version + struct.pack("!H", record_length)
        )
        return record_header + handshake_message

    def _generate_finished(self) -> bytes:
        """Generate TLS Finished message."""
        record_type = 22
        version = b"\x03\x03"
        handshake_type = 20
        verify_data = random.randbytes(12)
        handshake_content = verify_data
        handshake_length = len(handshake_content)
        handshake_header = (
            bytes([handshake_type]) + struct.pack("!I", handshake_length)[1:]
        )
        handshake_message = handshake_header + handshake_content
        record_length = len(handshake_message)
        record_header = (
            bytes([record_type]) + version + struct.pack("!H", record_length)
        )
        return record_header + handshake_message

    def _generate_encrypted_application_data(
        self, payload: bytes, tls_version: str
    ) -> bytes:
        """Generate encrypted application data record."""
        record_type = 23
        version = self._get_tls_version_bytes(tls_version)
        encryption_key = random.randbytes(32)
        encrypted_payload = bytearray()
        for i, byte in enumerate(payload):
            encrypted_payload.append(byte ^ encryption_key[i % len(encryption_key)])
        padding_length = random.randint(1, 16)
        padding = random.randbytes(padding_length)
        encrypted_data = bytes(encrypted_payload) + padding
        record_length = len(encrypted_data)
        record_header = (
            bytes([record_type]) + version + struct.pack("!H", record_length)
        )
        return record_header + encrypted_data

    def _get_tls_version_bytes(self, version: str) -> bytes:
        """Get TLS version bytes."""
        versions = {
            "1.0": b"\x03\x01",
            "1.1": b"\x03\x02",
            "1.2": b"\x03\x03",
            "1.3": b"\x03\x04",
        }
        return versions.get(version, b"\x03\x03")

    def _get_cipher_suites(self, cipher_suite: str) -> bytes:
        """Get cipher suites bytes."""
        suites = [b"\x13\x01", b"\x13\x02", b"\x13\x03", b"\xc0+", b"\xc0/"]
        return b"".join(suites)

    def _get_cipher_suite_bytes(self, cipher_suite: str) -> bytes:
        """Get selected cipher suite bytes."""
        suites = {
            "TLS_AES_128_GCM_SHA256": b"\x13\x01",
            "TLS_AES_256_GCM_SHA384": b"\x13\x02",
            "TLS_CHACHA20_POLY1305_SHA256": b"\x13\x03",
        }
        return suites.get(cipher_suite, b"\x13\x02")

    def _generate_client_hello_extensions(self, server_name: str) -> bytes:
        """Generate Client Hello extensions."""
        extensions = b""
        sni_data = server_name.encode("utf-8")
        sni_length = len(sni_data)
        sni_ext = (
            b"\x00\x00"
            + struct.pack("!H", sni_length + 5)
            + struct.pack("!H", sni_length + 3)
            + b"\x00"
            + struct.pack("!H", sni_length)
            + sni_data
        )
        extensions += sni_ext
        groups_ext = (
            b"\x00\n"
            + b"\x00\x08"
            + b"\x00\x06"
            + b"\x00\x17"
            + b"\x00\x18"
            + b"\x00\x19"
        )
        extensions += groups_ext
        return extensions

    def _generate_server_hello_extensions(self) -> bytes:
        """Generate Server Hello extensions."""
        key_share_ext = (
            b"\x003" + b"\x00$" + b"\x00\x17" + b"\x00 " + random.randbytes(32)
        )
        return key_share_ext

    def _generate_fake_certificate(self, server_name: str) -> bytes:
        """Generate fake X.509 certificate."""
        cert_header = b"0\x82\x03\x00"
        cert_body = (
            b"0\x82\x02\x00"
            + b"\xa0\x03\x02\x01\x02"
            + b"\x02\x08"
            + random.randbytes(8)
            + b"0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x0b\x05\x00"
            + b"0\x101\x0e0\x0c\x06\x03U\x04\x03\x0c\x05"
            + b"TestCA"
            + b"0\x1e\x17\r"
            + b"231201000000Z"
            + b"\x17\r"
            + b"241201000000Z"
            + b"0 1\x1e0\x1c\x06\x03U\x04\x03\x0c\x15"
            + server_name.encode("utf-8")[:21]
            + b'0\x82\x01"'
            + random.randbytes(290)
        )
        return cert_header + cert_body

    async def _calculate_tls_delay(
        self, packet_index: int, include_handshake: bool
    ) -> int:
        """Calculate realistic TLS timing delays."""
        delay = 0
        if include_handshake:
            if packet_index == 0:
                delay = 0
            elif packet_index == 1:
                delay = random.randint(20, 80)
            elif packet_index == 2:
                delay = random.randint(5, 20)
            elif packet_index == 3:
                delay = random.randint(10, 30)
            else:
                delay = random.randint(50, 200)
        else:
            delay = random.randint(10, 50)

        if delay > 0:
            await asyncio.sleep(delay / 1000.0)
        return delay

    def _get_packet_type(self, packet_index: int, include_handshake: bool) -> str:
        """Get packet type description."""
        if include_handshake:
            types = [
                "client_hello",
                "server_hello",
                "certificate",
                "finished",
                "application_data",
            ]
            return types[min(packet_index, len(types) - 1)]
        else:
            return "application_data"


@register_attack
class SMTPProtocolMimicryAttack(BaseAttack):
    """
    SMTP Protocol Mimicry Attack.

    Disguises traffic as SMTP email communication to evade DPI detection
    through email protocol impersonation.
    """

    @property
    def name(self) -> str:
        return "smtp_protocol_mimicry"

    @property
    def category(self) -> str:
        return "tunneling"

    @property
    def description(self) -> str:
        return "Disguises traffic as SMTP email communication"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {}


    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute SMTP protocol mimicry attack."""
        start_time = time.time()
        try:
            payload = context.payload
            smtp_server = context.params.get("smtp_server", "mail.example.com")
            sender_email = context.params.get("sender_email", "user@example.com")
            recipient_email = context.params.get(
                "recipient_email", "recipient@example.com"
            )
            use_tls = context.params.get("use_tls", True)
            smtp_packets = self._generate_smtp_conversation(
                payload, smtp_server, sender_email, recipient_email, use_tls
            )
            segments = []
            for i, packet in enumerate(smtp_packets):
                delay = await self._calculate_smtp_delay(i)
                packet_type = self._get_smtp_packet_type(i, len(smtp_packets))
                segments.append(
                    (
                        packet,
                        delay,
                        {
                            "smtp_server": smtp_server,
                            "packet_type": packet_type,
                            "use_tls": use_tls,
                        },
                    )
                )
            packets_sent = len(smtp_packets)
            bytes_sent = sum((len(packet) for packet in smtp_packets))
            latency = (time.time() - start_time) * 1000
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used="smtp_protocol_mimicry",
                metadata={
                    "smtp_server": smtp_server,
                    "sender_email": sender_email,
                    "recipient_email": recipient_email,
                    "use_tls": use_tls,
                    "original_size": len(payload),
                    "total_size": bytes_sent,
                    "segments": segments,
                },
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="smtp_protocol_mimicry",
            )

    def _generate_smtp_conversation(
        self, payload: bytes, server: str, sender: str, recipient: str, use_tls: bool
    ) -> List[bytes]:
        """Generate complete SMTP conversation."""
        packets = []
        packets.append(f"220 {server} ESMTP Ready\r\n".encode("utf-8"))
        packets.append("EHLO client.example.com\r\n".encode("utf-8"))
        capabilities = [
            f"250-{server} Hello client.example.com",
            "250-SIZE 52428800",
            "250-8BITMIME",
            "250-PIPELINING",
            "250-AUTH PLAIN LOGIN",
            "250-STARTTLS" if use_tls else "",
            "250 HELP",
        ]
        capabilities = [cap for cap in capabilities if cap]
        packets.append("\r\n".join(capabilities).encode("utf-8") + b"\r\n")
        if use_tls:
            packets.append(b"STARTTLS\r\n")
            packets.append(b"220 2.0.0 Ready to start TLS\r\n")
            packets.append(b"TLS_HANDSHAKE_SIMULATION")
        auth_string = base64.b64encode(f"\x00{sender}\x00password123".encode()).decode(
            "ascii"
        )
        packets.append(f"AUTH PLAIN {auth_string}\r\n".encode("utf-8"))
        packets.append(b"235 2.7.0 Authentication successful\r\n")
        packets.append(f"MAIL FROM:<{sender}>\r\n".encode("utf-8"))
        packets.append(b"250 2.1.0 OK\r\n")
        packets.append(f"RCPT TO:<{recipient}>\r\n".encode("utf-8"))
        packets.append(b"250 2.1.5 OK\r\n")
        packets.append(b"DATA\r\n")
        packets.append(b"354 End data with <CR><LF>.<CR><LF>\r\n")
        email_content = self._generate_email_content(payload, sender, recipient)
        packets.append(email_content)
        packets.append(b".\r\n")
        packets.append(b"250 2.0.0 OK: queued\r\n")
        packets.append(b"QUIT\r\n")
        packets.append(b"221 2.0.0 Bye\r\n")
        return packets

    def _generate_email_content(
        self, payload: bytes, sender: str, recipient: str
    ) -> bytes:
        """Generate email content with embedded payload."""
        encoded_payload = base64.b64encode(payload).decode("ascii")
        encoded_lines = []
        for i in range(0, len(encoded_payload), 76):
            encoded_lines.append(encoded_payload[i : i + 76])
        boundary = f"boundary_{random.randint(100000, 999999)}"
        email_content = f"""From: {sender}\nTo: {recipient}\nSubject: Document Attachment\nDate: {time.strftime('%a, %d %b %Y %H:%M:%S %z')}\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary="{boundary}"\n\n--{boundary}\nContent-Type: text/plain; charset=UTF-8\nContent-Transfer-Encoding: 7bit\n\nPlease find the attached document.\n\nBest regards,\nUser\n\n--{boundary}\nContent-Type: application/octet-stream\nContent-Transfer-Encoding: base64\nContent-Disposition: attachment; filename="document.dat"\n\n{chr(10).join(encoded_lines)}\n\n--{boundary}--\n"""
        return email_content.encode("utf-8") + b"\r\n"

    async def _calculate_smtp_delay(self, packet_index: int) -> int:
        """Calculate realistic SMTP timing delays."""
        delay = 0
        if packet_index == 0:
            delay = 0
        elif packet_index < 5:
            delay = random.randint(10, 50)
        else:
            delay = random.randint(20, 100)

        if delay > 0:
            await asyncio.sleep(delay / 1000.0)
        return delay

    def _get_smtp_packet_type(self, packet_index: int, total_packets: int) -> str:
        """Get SMTP packet type description."""
        if packet_index == 0:
            return "server_greeting"
        elif packet_index < total_packets // 2:
            return "handshake"
        elif packet_index < total_packets - 2:
            return "data_transfer"
        else:
            return "connection_close"


@register_attack
class FTPProtocolMimicryAttack(BaseAttack):
    """
    FTP Protocol Mimicry Attack.

    Disguises traffic as FTP file transfer to evade DPI detection
    through FTP protocol impersonation.
    """

    @property
    def name(self) -> str:
        return "ftp_protocol_mimicry"

    @property
    def category(self) -> str:
        return "tunneling"

    @property
    def description(self) -> str:
        return "Disguises traffic as FTP file transfer protocol"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    @property
    def required_params(self) -> List[str]:
        return []

    @property
    def optional_params(self) -> Dict[str, Any]:
        return {}


    async def execute(self, context: AttackContext) -> AttackResult:
        """Execute FTP protocol mimicry attack."""
        start_time = time.time()
        try:
            payload = context.payload
            ftp_server = context.params.get("ftp_server", "ftp.example.com")
            username = context.params.get("username", "anonymous")
            password = context.params.get("password", "user@example.com")
            transfer_mode = context.params.get("transfer_mode", "binary")
            ftp_packets = self._generate_ftp_conversation(
                payload, ftp_server, username, password, transfer_mode
            )
            segments = []
            for i, packet in enumerate(ftp_packets):
                delay = await self._calculate_ftp_delay(i, len(ftp_packets))
                packet_type = self._get_ftp_packet_type(i, len(ftp_packets))
                segments.append(
                    (
                        packet,
                        delay,
                        {
                            "ftp_server": ftp_server,
                            "packet_type": packet_type,
                            "transfer_mode": transfer_mode,
                        },
                    )
                )
            packets_sent = len(ftp_packets)
            bytes_sent = sum((len(packet) for packet in ftp_packets))
            latency = (time.time() - start_time) * 1000
            return AttackResult(
                status=AttackStatus.SUCCESS,
                latency_ms=latency,
                packets_sent=packets_sent,
                bytes_sent=bytes_sent,
                connection_established=True,
                data_transmitted=True,
                technique_used="ftp_protocol_mimicry",
                metadata={
                    "ftp_server": ftp_server,
                    "username": username,
                    "transfer_mode": transfer_mode,
                    "original_size": len(payload),
                    "total_size": bytes_sent,
                    "segments": segments,
                },
            )
        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
                technique_used="ftp_protocol_mimicry",
            )

    def _generate_ftp_conversation(
        self, payload: bytes, server: str, username: str, password: str, mode: str
    ) -> List[bytes]:
        """Generate complete FTP conversation."""
        packets = []
        packets.append(f"220 {server} FTP server ready\r\n".encode("utf-8"))
        packets.append(f"USER {username}\r\n".encode("utf-8"))
        if username == "anonymous":
            packets.append(b"331 Please specify the password\r\n")
        else:
            packets.append(b"331 Password required\r\n")
        packets.append(f"PASS {password}\r\n".encode("utf-8"))
        packets.append(b"230 Login successful\r\n")
        if mode == "binary":
            packets.append(b"TYPE I\r\n")
            packets.append(b"200 Switching to Binary mode\r\n")
        else:
            packets.append(b"TYPE A\r\n")
            packets.append(b"200 Switching to ASCII mode\r\n")
        packets.append(b"PASV\r\n")
        data_port = random.randint(20000, 30000)
        ip_parts = "192,168,1,100"
        port_high = data_port // 256
        port_low = data_port % 256
        packets.append(
            f"227 Entering Passive Mode ({ip_parts},{port_high},{port_low})\r\n".encode(
                "utf-8"
            )
        )
        filename = f"data_{hashlib.md5(payload).hexdigest()[:8]}.bin"
        packets.append(f"STOR {filename}\r\n".encode("utf-8"))
        packets.append(b"150 Ok to send data\r\n")
        packets.append(b"DATA_CONNECTION_ESTABLISHED\r\n")
        packets.append(payload)
        packets.append(b"DATA_CONNECTION_CLOSED\r\n")
        packets.append(b"226 Transfer complete\r\n")
        packets.append(b"QUIT\r\n")
        packets.append(b"221 Goodbye\r\n")
        return packets

    async def _calculate_ftp_delay(self, packet_index: int, total_packets: int) -> int:
        """Calculate realistic FTP timing delays."""
        delay = 0
        if packet_index == 0:
            delay = 0
        elif packet_index < 6:
            delay = random.randint(20, 100)
        elif packet_index < total_packets - 3:
            delay = random.randint(50, 200)
        else:
            delay = random.randint(10, 50)

        if delay > 0:
            await asyncio.sleep(delay / 1000.0)
        return delay

    def _get_ftp_packet_type(self, packet_index: int, total_packets: int) -> str:
        """Get FTP packet type description."""
        if packet_index == 0:
            return "server_welcome"
        elif packet_index < 6:
            return "authentication"
        elif packet_index < total_packets - 2:
            return "data_transfer"
        else:
            return "connection_close"
