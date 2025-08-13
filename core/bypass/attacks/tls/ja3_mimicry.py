# recon/core/bypass/attacks/tls/ja3_mimicry.py

import time
import random
import struct
import hashlib
from typing import List, Dict, Optional, Tuple
from ..base import BaseAttack, AttackContext, AttackResult, AttackStatus
from ..registry import register_attack
from ....protocols.tls import TLSParser, TLSExtensionType


class BrowserProfile:
    """Browser TLS fingerprint profile for JA3/JA4 mimicry"""

    def __init__(
        self,
        name: str,
        version: bytes,
        cipher_suites: List[int],
        extensions: List[int],
        elliptic_curves: List[int],
        signature_algorithms: List[int],
        alpn_protocols: List[str],
    ):
        self.name = name
        self.version = version
        self.cipher_suites = cipher_suites
        self.extensions = extensions
        self.elliptic_curves = elliptic_curves
        self.signature_algorithms = signature_algorithms
        self.alpn_protocols = alpn_protocols

    def calculate_ja3(self, random_bytes: bytes = None) -> str:
        """Calculate JA3 fingerprint for this profile"""
        if random_bytes is None:
            random_bytes = bytes([random.randint(0, 255) for _ in range(32)])

        # JA3 format: Version,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
        version_str = str(int.from_bytes(self.version, "big"))
        ciphers_str = "-".join(str(c) for c in self.cipher_suites)
        extensions_str = "-".join(str(e) for e in self.extensions)
        curves_str = "-".join(str(c) for c in self.elliptic_curves)
        point_formats_str = "0"  # Usually just uncompressed (0)

        ja3_string = f"{version_str},{ciphers_str},{extensions_str},{curves_str},{point_formats_str}"
        return hashlib.md5(ja3_string.encode()).hexdigest()


class BrowserProfiles:
    """Collection of popular browser TLS profiles"""

    @staticmethod
    def get_chrome_profile() -> BrowserProfile:
        """Chrome 120+ TLS profile"""
        return BrowserProfile(
            name="Chrome 120",
            version=b"\x03\x03",  # TLS 1.2
            cipher_suites=[
                0x1301,  # TLS_AES_128_GCM_SHA256
                0x1302,  # TLS_AES_256_GCM_SHA384
                0x1303,  # TLS_CHACHA20_POLY1305_SHA256
                0xC02B,  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                0xC02F,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                0xC02C,  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                0xC030,  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                0xCCA9,  # TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                0xCCA8,  # TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
                0xC013,  # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
                0xC014,  # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
                0x009C,  # TLS_RSA_WITH_AES_128_GCM_SHA256
                0x009D,  # TLS_RSA_WITH_AES_256_GCM_SHA384
                0x002F,  # TLS_RSA_WITH_AES_128_CBC_SHA
                0x0035,  # TLS_RSA_WITH_AES_256_CBC_SHA
            ],
            extensions=[
                0x0000,  # server_name
                0x0017,  # extended_master_secret
                0xFF01,  # renegotiation_info
                0x000A,  # supported_groups
                0x000B,  # ec_point_formats
                0x0023,  # session_ticket
                0x0010,  # application_layer_protocol_negotiation
                0x0005,  # status_request
                0x0012,  # signed_certificate_timestamp
                0x0033,  # key_share
                0x002B,  # supported_versions
                0x000D,  # signature_algorithms
                0x002D,  # psk_key_exchange_modes
                0x0029,  # pre_shared_key
            ],
            elliptic_curves=[
                0x001D,  # x25519
                0x0017,  # secp256r1
                0x0018,  # secp384r1
            ],
            signature_algorithms=[
                0x0403,  # ecdsa_secp256r1_sha256
                0x0804,  # rsa_pss_rsae_sha256
                0x0401,  # rsa_pkcs1_sha256
                0x0503,  # ecdsa_secp384r1_sha384
                0x0805,  # rsa_pss_rsae_sha384
                0x0501,  # rsa_pkcs1_sha384
                0x0806,  # rsa_pss_rsae_sha512
                0x0601,  # rsa_pkcs1_sha512
            ],
            alpn_protocols=["h2", "http/1.1"],
        )

    @staticmethod
    def get_firefox_profile() -> BrowserProfile:
        """Firefox 121+ TLS profile"""
        return BrowserProfile(
            name="Firefox 121",
            version=b"\x03\x03",  # TLS 1.2
            cipher_suites=[
                0x1301,  # TLS_AES_128_GCM_SHA256
                0x1303,  # TLS_CHACHA20_POLY1305_SHA256
                0x1302,  # TLS_AES_256_GCM_SHA384
                0xC02B,  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                0xC02F,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                0xC02C,  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                0xC030,  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                0xCCA9,  # TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                0xCCA8,  # TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
                0xC009,  # TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
                0xC013,  # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
                0xC00A,  # TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
                0xC014,  # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
            ],
            extensions=[
                0x0000,  # server_name
                0x0017,  # extended_master_secret
                0xFF01,  # renegotiation_info
                0x000A,  # supported_groups
                0x000B,  # ec_point_formats
                0x0023,  # session_ticket
                0x0010,  # application_layer_protocol_negotiation
                0x0005,  # status_request
                0x0033,  # key_share
                0x002B,  # supported_versions
                0x000D,  # signature_algorithms
                0x002D,  # psk_key_exchange_modes
                0x0029,  # pre_shared_key
            ],
            elliptic_curves=[
                0x001D,  # x25519
                0x0017,  # secp256r1
                0x0018,  # secp384r1
                0x0019,  # secp521r1
            ],
            signature_algorithms=[
                0x0403,  # ecdsa_secp256r1_sha256
                0x0503,  # ecdsa_secp384r1_sha384
                0x0603,  # ecdsa_secp521r1_sha512
                0x0804,  # rsa_pss_rsae_sha256
                0x0805,  # rsa_pss_rsae_sha384
                0x0806,  # rsa_pss_rsae_sha512
                0x0401,  # rsa_pkcs1_sha256
                0x0501,  # rsa_pkcs1_sha384
                0x0601,  # rsa_pkcs1_sha512
            ],
            alpn_protocols=["h2", "http/1.1"],
        )

    @staticmethod
    def get_safari_profile() -> BrowserProfile:
        """Safari 17+ TLS profile"""
        return BrowserProfile(
            name="Safari 17",
            version=b"\x03\x03",  # TLS 1.2
            cipher_suites=[
                0x1301,  # TLS_AES_128_GCM_SHA256
                0x1302,  # TLS_AES_256_GCM_SHA384
                0x1303,  # TLS_CHACHA20_POLY1305_SHA256
                0xC02B,  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                0xC02F,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                0xC02C,  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                0xC030,  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                0xC009,  # TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
                0xC013,  # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
                0xC00A,  # TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
                0xC014,  # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
                0x009C,  # TLS_RSA_WITH_AES_128_GCM_SHA256
                0x009D,  # TLS_RSA_WITH_AES_256_GCM_SHA384
                0x002F,  # TLS_RSA_WITH_AES_128_CBC_SHA
                0x0035,  # TLS_RSA_WITH_AES_256_CBC_SHA
            ],
            extensions=[
                0x0000,  # server_name
                0x0017,  # extended_master_secret
                0xFF01,  # renegotiation_info
                0x000A,  # supported_groups
                0x000B,  # ec_point_formats
                0x0023,  # session_ticket
                0x0010,  # application_layer_protocol_negotiation
                0x0005,  # status_request
                0x0012,  # signed_certificate_timestamp
                0x0033,  # key_share
                0x002B,  # supported_versions
                0x000D,  # signature_algorithms
                0x002D,  # psk_key_exchange_modes
            ],
            elliptic_curves=[
                0x001D,  # x25519
                0x0017,  # secp256r1
                0x0018,  # secp384r1
            ],
            signature_algorithms=[
                0x0403,  # ecdsa_secp256r1_sha256
                0x0804,  # rsa_pss_rsae_sha256
                0x0401,  # rsa_pkcs1_sha256
                0x0503,  # ecdsa_secp384r1_sha384
                0x0805,  # rsa_pss_rsae_sha384
                0x0501,  # rsa_pkcs1_sha384
                0x0806,  # rsa_pss_rsae_sha512
                0x0601,  # rsa_pkcs1_sha512
            ],
            alpn_protocols=["h2", "http/1.1"],
        )

    @staticmethod
    def get_edge_profile() -> BrowserProfile:
        """Microsoft Edge TLS profile (similar to Chrome)"""
        return BrowserProfile(
            name="Edge 120",
            version=b"\x03\x03",  # TLS 1.2
            cipher_suites=[
                0x1301,  # TLS_AES_128_GCM_SHA256
                0x1302,  # TLS_AES_256_GCM_SHA384
                0x1303,  # TLS_CHACHA20_POLY1305_SHA256
                0xC02B,  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                0xC02F,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                0xC02C,  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                0xC030,  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                0xCCA9,  # TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
                0xCCA8,  # TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
                0xC013,  # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
                0xC014,  # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
            ],
            extensions=[
                0x0000,  # server_name
                0x0017,  # extended_master_secret
                0xFF01,  # renegotiation_info
                0x000A,  # supported_groups
                0x000B,  # ec_point_formats
                0x0023,  # session_ticket
                0x0010,  # application_layer_protocol_negotiation
                0x0005,  # status_request
                0x0012,  # signed_certificate_timestamp
                0x0033,  # key_share
                0x002B,  # supported_versions
                0x000D,  # signature_algorithms
                0x002D,  # psk_key_exchange_modes
                0x0029,  # pre_shared_key
            ],
            elliptic_curves=[
                0x001D,  # x25519
                0x0017,  # secp256r1
                0x0018,  # secp384r1
            ],
            signature_algorithms=[
                0x0403,  # ecdsa_secp256r1_sha256
                0x0804,  # rsa_pss_rsae_sha256
                0x0401,  # rsa_pkcs1_sha256
                0x0503,  # ecdsa_secp384r1_sha384
                0x0805,  # rsa_pss_rsae_sha384
                0x0501,  # rsa_pkcs1_sha384
                0x0806,  # rsa_pss_rsae_sha512
                0x0601,  # rsa_pkcs1_sha512
            ],
            alpn_protocols=["h2", "http/1.1"],
        )

    @staticmethod
    def get_all_profiles() -> Dict[str, BrowserProfile]:
        """Get all available browser profiles"""
        return {
            "chrome": BrowserProfiles.get_chrome_profile(),
            "firefox": BrowserProfiles.get_firefox_profile(),
            "safari": BrowserProfiles.get_safari_profile(),
            "edge": BrowserProfiles.get_edge_profile(),
        }


@register_attack
class JA3FingerprintMimicryAttack(BaseAttack):
    """
    JA3/JA4 Fingerprint Mimicry Attack - mimics popular browser TLS fingerprints
    to evade TLS-based DPI detection.
    """

    @property
    def name(self) -> str:
        return "ja3_fingerprint_mimicry"

    @property
    def category(self) -> str:
        return "tls"

    @property
    def description(self) -> str:
        return "Mimics popular browser TLS fingerprints to evade DPI detection"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute JA3 fingerprint mimicry attack."""
        start_time = time.time()

        try:
            payload = context.payload
            browser_type = context.params.get("browser_type", "chrome")
            randomize_order = context.params.get("randomize_order", False)
            add_grease = context.params.get("add_grease", True)

            # Get browser profile
            profiles = BrowserProfiles.get_all_profiles()
            if browser_type not in profiles:
                browser_type = "chrome"  # fallback

            profile = profiles[browser_type]

            # Parse original ClientHello to get domain and other info
            client_hello_info = TLSParser.parse_client_hello(payload)
            if not client_hello_info:
                return AttackResult(
                    status=AttackStatus.INVALID_PARAMS,
                    error_message="Invalid TLS ClientHello payload",
                )

            # Get domain from SNI
            domain = TLSParser.get_sni(payload)
            if not domain:
                domain = "example.com"  # fallback

            # Build new ClientHello with browser profile
            modified_payload = self._build_mimicked_client_hello(
                profile, domain, client_hello_info, randomize_order, add_grease
            )

            # Calculate JA3 fingerprints for comparison
            original_ja3 = self._calculate_ja3_from_payload(payload)
            mimicked_ja3 = profile.calculate_ja3()

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
                    "browser_type": browser_type,
                    "browser_profile": profile.name,
                    "original_ja3": original_ja3,
                    "mimicked_ja3": mimicked_ja3,
                    "domain": domain,
                    "randomize_order": randomize_order,
                    "add_grease": add_grease,
                    "segments": segments if context.engine_type != "local" else None,
                },
            )

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )

    def _build_mimicked_client_hello(
        self,
        profile: BrowserProfile,
        domain: str,
        original_info: "ClientHelloInfo",
        randomize_order: bool = False,
        add_grease: bool = True,
    ) -> bytes:
        """Build a ClientHello that mimics the specified browser profile"""

        # Start with TLS record header
        result = bytearray()

        # TLS Record Header (5 bytes)
        result.extend(b"\x16")  # Content Type: Handshake
        result.extend(profile.version)  # Version
        # Length will be filled later
        length_pos = len(result)
        result.extend(b"\x00\x00")  # Placeholder for length

        # Handshake Header (4 bytes)
        handshake_start = len(result)
        result.extend(b"\x01")  # Handshake Type: ClientHello
        # Length will be filled later
        handshake_length_pos = len(result)
        result.extend(b"\x00\x00\x00")  # Placeholder for length

        # ClientHello content
        result.extend(profile.version)  # Client Version

        # Random (32 bytes) - use original or generate new
        if original_info and len(original_info.random) == 32:
            result.extend(original_info.random)
        else:
            result.extend(bytes([random.randint(0, 255) for _ in range(32)]))

        # Session ID (use original if available)
        if original_info and original_info.session_id:
            result.extend(bytes([len(original_info.session_id)]))
            result.extend(original_info.session_id)
        else:
            result.extend(b"\x00")  # No session ID

        # Cipher Suites
        cipher_suites = profile.cipher_suites.copy()
        if randomize_order:
            random.shuffle(cipher_suites)

        # Add GREASE cipher suites if requested
        if add_grease:
            grease_ciphers = [0x0A0A, 0x1A1A, 0x2A2A]
            cipher_suites = [random.choice(grease_ciphers)] + cipher_suites

        result.extend(struct.pack("!H", len(cipher_suites) * 2))
        for cipher in cipher_suites:
            result.extend(struct.pack("!H", cipher))

        # Compression Methods (always just null compression)
        result.extend(b"\x01\x00")

        # Extensions
        extensions_start = len(result)
        result.extend(b"\x00\x00")  # Placeholder for extensions length

        extensions_data = self._build_extensions(
            profile, domain, add_grease, randomize_order
        )
        result.extend(extensions_data)

        # Update extensions length
        extensions_length = len(extensions_data)
        result[extensions_start : extensions_start + 2] = struct.pack(
            "!H", extensions_length
        )

        # Update handshake length
        handshake_length = len(result) - handshake_start - 4
        result[handshake_length_pos : handshake_length_pos + 3] = (
            handshake_length.to_bytes(3, "big")
        )

        # Update TLS record length
        record_length = len(result) - 5
        result[length_pos : length_pos + 2] = struct.pack("!H", record_length)

        return bytes(result)

    def _build_extensions(
        self,
        profile: BrowserProfile,
        domain: str,
        add_grease: bool = True,
        randomize_order: bool = False,
    ) -> bytes:
        """Build extensions section for the ClientHello"""
        extensions = bytearray()

        # Build extensions in order
        extension_builders = {
            0x0000: lambda: self._build_sni_extension(domain),
            0x0017: lambda: b"",  # extended_master_secret (empty)
            0xFF01: lambda: b"\x00",  # renegotiation_info
            0x000A: lambda: self._build_supported_groups_extension(
                profile.elliptic_curves
            ),
            0x000B: lambda: b"\x00",  # ec_point_formats (uncompressed)
            0x0023: lambda: b"",  # session_ticket (empty)
            0x0010: lambda: self._build_alpn_extension(profile.alpn_protocols),
            0x0005: lambda: b"\x01\x00\x00\x00\x00",  # status_request
            0x0012: lambda: b"",  # signed_certificate_timestamp (empty)
            0x0033: lambda: self._build_key_share_extension(profile.elliptic_curves),
            0x002B: lambda: b"\x02\x03\x04",  # supported_versions (TLS 1.3)
            0x000D: lambda: self._build_signature_algorithms_extension(
                profile.signature_algorithms
            ),
            0x002D: lambda: b"\x01\x01",  # psk_key_exchange_modes
        }

        # Add GREASE extensions first if requested
        if add_grease:
            grease_values = [0x0A0A, 0x1A1A, 0x2A2A]
            for grease_val in grease_values[:2]:  # Add 2 GREASE extensions
                grease_data = bytes(
                    [random.randint(0, 255) for _ in range(random.randint(0, 8))]
                )
                extensions.extend(struct.pack("!H", grease_val))
                extensions.extend(struct.pack("!H", len(grease_data)))
                extensions.extend(grease_data)

        # Build profile extensions
        extension_list = profile.extensions.copy()
        if randomize_order:
            # Keep SNI first, randomize others
            if 0x0000 in extension_list:
                extension_list.remove(0x0000)
                random.shuffle(extension_list)
                extension_list.insert(0, 0x0000)
            else:
                random.shuffle(extension_list)

        for ext_type in extension_list:
            if ext_type in extension_builders:
                ext_data = extension_builders[ext_type]()
                extensions.extend(struct.pack("!H", ext_type))
                extensions.extend(struct.pack("!H", len(ext_data)))
                extensions.extend(ext_data)

        return bytes(extensions)

    def _build_sni_extension(self, domain: str) -> bytes:
        """Build SNI extension data"""
        domain_bytes = domain.encode("utf-8")
        sni_data = (
            struct.pack("!H", len(domain_bytes) + 3)  # Server name list length
            + b"\x00"  # Name type (hostname)
            + struct.pack("!H", len(domain_bytes))  # Name length
            + domain_bytes
        )
        return sni_data

    def _build_supported_groups_extension(self, curves: List[int]) -> bytes:
        """Build supported groups (elliptic curves) extension"""
        data = struct.pack("!H", len(curves) * 2)
        for curve in curves:
            data += struct.pack("!H", curve)
        return data

    def _build_alpn_extension(self, protocols: List[str]) -> bytes:
        """Build ALPN extension data"""
        alpn_data = b""
        for protocol in protocols:
            proto_bytes = protocol.encode("utf-8")
            alpn_data += bytes([len(proto_bytes)]) + proto_bytes

        return struct.pack("!H", len(alpn_data)) + alpn_data

    def _build_signature_algorithms_extension(self, algorithms: List[int]) -> bytes:
        """Build signature algorithms extension"""
        data = struct.pack("!H", len(algorithms) * 2)
        for alg in algorithms:
            data += struct.pack("!H", alg)
        return data

    def _build_key_share_extension(self, curves: List[int]) -> bytes:
        """Build key share extension (simplified)"""
        # This is a simplified version - real implementation would generate actual key shares
        if not curves:
            return b""

        # Use first curve for key share
        curve = curves[0]
        if curve == 0x001D:  # x25519
            key_data = bytes([random.randint(0, 255) for _ in range(32)])
        else:  # secp256r1, secp384r1, etc.
            key_data = bytes(
                [random.randint(0, 255) for _ in range(65)]
            )  # Uncompressed point

        key_share_data = (
            struct.pack("!H", len(key_data) + 4)  # Key share list length
            + struct.pack("!H", curve)  # Named group
            + struct.pack("!H", len(key_data))  # Key exchange length
            + key_data
        )
        return key_share_data

    def _calculate_ja3_from_payload(self, payload: bytes) -> Optional[str]:
        """Calculate JA3 fingerprint from existing payload"""
        try:
            info = TLSParser.parse_client_hello(payload)
            if not info:
                return None

            # Extract JA3 components
            version = int.from_bytes(info.version, "big")
            ciphers = [int.from_bytes(cs, "big") for cs in info.cipher_suites]
            extensions = list(info.extensions.keys())

            # Simplified - would need to extract curves and point formats from extensions
            curves = []
            point_formats = [0]

            # Build JA3 string
            ja3_string = f"{version},{'-'.join(map(str, ciphers))},{'-'.join(map(str, extensions))},{'-'.join(map(str, curves))},{'-'.join(map(str, point_formats))}"
            return hashlib.md5(ja3_string.encode()).hexdigest()

        except Exception:
            return None


@register_attack
class JA4FingerprintMimicryAttack(BaseAttack):
    """
    JA4 Fingerprint Mimicry Attack - mimics JA4 fingerprints (newer version of JA3)
    """

    @property
    def name(self) -> str:
        return "ja4_fingerprint_mimicry"

    @property
    def category(self) -> str:
        return "tls"

    @property
    def description(self) -> str:
        return "Mimics JA4 TLS fingerprints to evade advanced DPI detection"

    @property
    def supported_protocols(self) -> List[str]:
        return ["tcp"]

    def execute(self, context: AttackContext) -> AttackResult:
        """Execute JA4 fingerprint mimicry attack."""
        start_time = time.time()

        try:
            # JA4 is more complex than JA3, includes additional fields
            # For now, delegate to JA3 attack with enhanced parameters
            ja3_attack = JA3FingerprintMimicryAttack()

            # Enhance context for JA4-style mimicry
            enhanced_context = AttackContext(
                domain=context.domain,
                port=context.port,
                payload=context.payload,
                params={
                    **context.params,
                    "add_grease": True,
                    "randomize_order": True,
                    "enhanced_extensions": True,
                },
                engine_type=context.engine_type,
            )

            result = ja3_attack.execute(enhanced_context)

            # Update metadata to indicate JA4 mimicry
            if result.metadata:
                result.metadata["attack_type"] = "ja4_mimicry"
                result.metadata["enhanced_features"] = [
                    "grease",
                    "randomized_order",
                    "extended_extensions",
                ]

            return result

        except Exception as e:
            return AttackResult(
                status=AttackStatus.ERROR,
                error_message=str(e),
                latency_ms=(time.time() - start_time) * 1000,
            )
