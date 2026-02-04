# path: core/bypass/techniques/payload_generators.py
"""
Fake payload generators for DPI bypass attacks.

This module provides various fake payload generation methods used in
fakeddisorder and other DPI bypass attacks. Fake payloads are sent with
low TTL to confuse DPI systems while not reaching the destination server.

Supported payload types:
    - TLS: Enhanced TLS ClientHello with proper structure
    - HTTP: HTTP requests with randomization
    - QUIC: QUIC Initial packets
    - WireGuard: WireGuard handshake packets
    - DHT: BitTorrent DHT packets
"""

import random
import logging
from typing import Optional


class PayloadGeneratorFactory:
    """
    Factory for generating fake payloads of various protocol types.

    This class provides static methods for generating realistic-looking
    fake payloads that can be used in DPI bypass attacks.
    """

    @staticmethod
    def generate(
        payload_type: str,
        original_payload: Optional[bytes] = None,
        custom_payload: Optional[bytes] = None,
        **kwargs,
    ) -> bytes:
        """
        Generate fake payload based on type specification.

        Args:
            payload_type: Type of payload to generate
                ("TLS", "HTTP", "QUIC", "WIREGUARD", "DHT", "AUTO")
            original_payload: Original payload for auto-detection
            custom_payload: Custom payload to use instead of generating
            **kwargs: Additional parameters for specific generators

        Returns:
            Generated fake payload bytes

        Examples:
            >>> # Generate TLS payload
            >>> payload = PayloadGeneratorFactory.generate("TLS")

            >>> # Auto-detect from original
            >>> payload = PayloadGeneratorFactory.generate("AUTO", original_payload=data)

            >>> # Use custom payload
            >>> payload = PayloadGeneratorFactory.generate("TLS", custom_payload=b"custom")
        """
        logger = logging.getLogger("PayloadGeneratorFactory")

        # Use custom payload if provided
        if custom_payload:
            logger.debug("Using custom fake payload")
            return custom_payload

        payload_type = payload_type.upper()

        # Generate based on type
        if payload_type in ("PAYLOADTLS", "TLS"):
            return PayloadGeneratorFactory.generate_enhanced_tls_payload()
        elif payload_type == "HTTP":
            return PayloadGeneratorFactory.generate_enhanced_http_payload()
        elif payload_type == "QUIC":
            return PayloadGeneratorFactory.generate_quic_payload()
        elif payload_type == "WIREGUARD":
            return PayloadGeneratorFactory.generate_wireguard_payload()
        elif payload_type == "DHT":
            return PayloadGeneratorFactory.generate_dht_payload()
        elif payload_type == "AUTO":
            # Auto-detect from original payload
            if original_payload:
                if PayloadGeneratorFactory.detect_tls(original_payload):
                    return PayloadGeneratorFactory.generate_enhanced_tls_payload()
                elif PayloadGeneratorFactory.detect_http(original_payload):
                    return PayloadGeneratorFactory.generate_enhanced_http_payload()
            # Default to TLS if can't detect
            return PayloadGeneratorFactory.generate_enhanced_tls_payload()
        else:
            logger.warning(f"Unknown payload type '{payload_type}', defaulting to TLS")
            return PayloadGeneratorFactory.generate_enhanced_tls_payload()

    @staticmethod
    def generate_enhanced_tls_payload() -> bytes:
        """
        Generate enhanced TLS ClientHello with proper structure.

        Creates a realistic TLS 1.2 ClientHello packet with:
        - Proper TLS record and handshake headers
        - Modern cipher suites
        - Essential extensions (SNI, supported groups, EC point formats)
        - Random elements for uniqueness

        Returns:
            Complete TLS ClientHello packet bytes
        """
        # Enhanced TLS ClientHello with proper structure
        tls_version = b"\x03\x03"  # TLS 1.2
        random_bytes = bytes([random.randint(0, 255) for _ in range(32)])
        session_id_len = b"\x00"  # No session ID

        # Cipher suites (zapret-compatible)
        cipher_suites = b"\x00\x2c"  # Length
        cipher_suites += b"\x13\x01"  # TLS_AES_128_GCM_SHA256
        cipher_suites += b"\x13\x02"  # TLS_AES_256_GCM_SHA384
        cipher_suites += b"\xc0\x2f"  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        cipher_suites += b"\xc0\x30"  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        cipher_suites += b"\x00\x9e"  # TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
        cipher_suites += b"\x00\x9f"  # TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
        cipher_suites += b"\xc0\x13"  # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        cipher_suites += b"\xc0\x14"  # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        cipher_suites += b"\x00\x33"  # TLS_DHE_RSA_WITH_AES_128_CBC_SHA
        cipher_suites += b"\x00\x39"  # TLS_DHE_RSA_WITH_AES_256_CBC_SHA
        cipher_suites += b"\x00\x2f"  # TLS_RSA_WITH_AES_128_CBC_SHA
        cipher_suites += b"\x00\x35"  # TLS_RSA_WITH_AES_256_CBC_SHA

        compression_methods = b"\x01\x00"  # No compression

        # Extensions (critical for DPI bypass)
        extensions = b""

        # SNI extension
        sni_ext = b"\x00\x00"  # Extension type: server_name
        sni_data = b"\x00\x0e"  # Extension length
        sni_data += b"\x00\x0c"  # Server name list length
        sni_data += b"\x00"  # Name type: host_name
        sni_data += b"\x00\x09"  # Name length
        sni_data += b"google.com"  # Fake hostname
        extensions += sni_ext + sni_data

        # Supported Groups
        groups_ext = b"\x00\x0a"  # Extension type
        groups_data = b"\x00\x08"  # Extension length
        groups_data += b"\x00\x06"  # Groups length
        groups_data += b"\x00\x17"  # secp256r1
        groups_data += b"\x00\x18"  # secp384r1
        groups_data += b"\x00\x19"  # secp521r1
        extensions += groups_ext + groups_data

        # EC Point Formats
        ec_ext = b"\x00\x0b"  # Extension type
        ec_data = b"\x00\x02"  # Extension length
        ec_data += b"\x01\x00"  # Uncompressed format
        extensions += ec_ext + ec_data

        extensions_len = len(extensions).to_bytes(2, "big")

        # Assemble ClientHello
        client_hello = (
            tls_version
            + random_bytes
            + session_id_len
            + cipher_suites
            + compression_methods
            + extensions_len
            + extensions
        )

        # Handshake header
        handshake_type = b"\x01"  # ClientHello
        handshake_len = len(client_hello).to_bytes(3, "big")
        handshake = handshake_type + handshake_len + client_hello

        # TLS Record header
        record_type = b"\x16"  # Handshake
        record_version = b"\x03\x01"  # TLS 1.0
        record_len = len(handshake).to_bytes(2, "big")

        return record_type + record_version + record_len + handshake

    @staticmethod
    def generate_enhanced_http_payload() -> bytes:
        """
        Generate enhanced HTTP payload with randomization.

        Creates a realistic HTTP request with:
        - Random HTTP method (GET, POST, HEAD)
        - Random path
        - Random host
        - Standard headers

        Returns:
            Complete HTTP request bytes
        """
        methods = ["GET", "POST", "HEAD"]
        paths = ["/", "/index.html", "/favicon.ico", "/robots.txt"]

        method = random.choice(methods)
        path = random.choice(paths)

        http_request = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: example{random.randint(1, 999)}.com\r\n"
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            "Accept-Language: en-US,en;q=0.5\r\n"
            "Accept-Encoding: gzip, deflate\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
        )
        return http_request.encode("utf-8")

    @staticmethod
    def generate_quic_payload() -> bytes:
        """
        Generate QUIC Initial packet payload.

        Creates a QUIC v1 Initial packet with:
        - Long header format
        - Random connection IDs
        - Random payload

        Returns:
            Complete QUIC Initial packet bytes
        """
        quic_packet = bytearray()

        # Header Form + Fixed Bit + Packet Type + Reserved + Packet Number Length
        header_byte = 0b11000000  # Long header, Initial packet
        quic_packet.append(header_byte)

        # Version - QUIC v1
        quic_packet.extend(b"\x00\x00\x00\x01")

        # Connection IDs
        dcid_len = 8
        quic_packet.append(dcid_len)
        quic_packet.extend(bytes([random.randint(0, 255) for _ in range(dcid_len)]))

        scid_len = 8
        quic_packet.append(scid_len)
        quic_packet.extend(bytes([random.randint(0, 255) for _ in range(scid_len)]))

        # Token Length and Length
        quic_packet.append(0)  # No token
        quic_packet.extend(b"\x40\x40")  # Length ~64

        # Packet Number and Payload
        quic_packet.append(0x01)
        payload = bytes([random.randint(0, 255) for _ in range(63)])
        quic_packet.extend(payload)

        return bytes(quic_packet)

    @staticmethod
    def generate_wireguard_payload() -> bytes:
        """
        Generate WireGuard handshake payload.

        Creates a WireGuard Handshake Initiation message with:
        - Message type and reserved bytes
        - Random sender index
        - Random ephemeral, static, and timestamp fields
        - Random MAC values

        Returns:
            Complete WireGuard handshake packet bytes
        """
        wg_packet = bytearray()

        # Message Type - Handshake Initiation
        wg_packet.append(1)
        wg_packet.extend(b"\x00\x00\x00")  # Reserved

        # Sender Index
        sender_index = random.randint(0, 0xFFFFFFFF)
        wg_packet.extend(sender_index.to_bytes(4, "little"))

        # Ephemeral, Static, Timestamp (with random data)
        wg_packet.extend(bytes([random.randint(0, 255) for _ in range(32)]))  # Ephemeral
        wg_packet.extend(bytes([random.randint(0, 255) for _ in range(48)]))  # Static
        wg_packet.extend(bytes([random.randint(0, 255) for _ in range(28)]))  # Timestamp

        # MAC1 and MAC2
        wg_packet.extend(bytes([random.randint(0, 255) for _ in range(16)]))  # MAC1
        wg_packet.extend(bytes([random.randint(0, 255) for _ in range(16)]))  # MAC2

        return bytes(wg_packet)

    @staticmethod
    def generate_dht_payload() -> bytes:
        """
        Generate BitTorrent DHT payload.

        Creates a DHT ping query with:
        - Random transaction ID
        - Bencode-encoded DHT ping query
        - Random node ID

        Returns:
            Complete DHT packet bytes
        """
        dht_packet = bytearray()

        # Transaction ID
        transaction_id = random.randint(0, 0xFFFF)
        dht_packet.extend(transaction_id.to_bytes(2, "big"))

        # Bencode DHT ping query
        node_id = bytes([random.randint(0, 255) for _ in range(20)])
        # Avoid f-string/encoding pitfalls: build bytes directly.
        dht_packet.extend(b"d1:ad2:id20:" + node_id + b"e1:q4:ping1:t2:aa1:y1:qe")

        return bytes(dht_packet)

    @staticmethod
    def detect_tls(payload: bytes) -> bool:
        """
        Detect if payload is TLS.

        Args:
            payload: Payload bytes to check

        Returns:
            True if payload appears to be TLS, False otherwise
        """
        return len(payload) > 5 and payload[0] == 0x16 and payload[1] == 0x03

    @staticmethod
    def detect_http(payload: bytes) -> bool:
        """
        Detect if payload is HTTP.

        Args:
            payload: Payload bytes to check

        Returns:
            True if payload appears to be HTTP, False otherwise
        """
        return payload.startswith(b"GET ") or payload.startswith(b"POST ")
