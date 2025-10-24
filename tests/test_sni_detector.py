"""
Unit tests for SNIDetector component.

Tests TLS packet parsing, SNI extension detection, and SNI value extraction
with different TLS packet formats and edge cases.
"""

import pytest
import struct


class TestSNIDetector:
    """Test suite for SNIDetector component."""

    def setup_method(self):
        """Set up test fixtures."""
        self.detector = SNIDetector()

    def test_init(self):
        """Test SNIDetector initialization."""
        detector = SNIDetector()
        assert detector is not None
        assert hasattr(detector, "logger")
        assert detector.TLS_HANDSHAKE_TYPE == 0x16
        assert detector.TLS_CLIENT_HELLO == 0x01
        assert detector.SNI_EXTENSION_TYPE == 0x0000

    def test_is_client_hello_valid_tls12(self):
        """Test Client Hello detection with valid TLS 1.2 packet."""
        # TLS 1.2 Client Hello with correct structure
        # TLS Record: content_type(1) + version(2) + length(2) = 5 bytes
        # Handshake: type(1) + length(3) + data = 4+ bytes
        packet = bytearray()
        packet.extend(struct.pack("!BHH", 0x16, 0x0303, 0x0020))  # TLS record header
        packet.extend(struct.pack("!B", 0x01))  # Handshake type: Client Hello
        packet.extend(struct.pack("!I", 0x001C)[1:])  # Handshake length (3 bytes)
        packet.extend(b"\x00" * 28)  # Client Hello data

        result = self.detector.is_client_hello(bytes(packet))

        assert result is True

    def test_is_client_hello_valid_tls13(self):
        """Test Client Hello detection with valid TLS 1.3 packet."""
        # TLS 1.3 Client Hello with correct structure
        packet = bytearray()
        packet.extend(struct.pack("!BHH", 0x16, 0x0304, 0x0020))  # TLS record header
        packet.extend(struct.pack("!B", 0x01))  # Handshake type: Client Hello
        packet.extend(struct.pack("!I", 0x001C)[1:])  # Handshake length (3 bytes)
        packet.extend(b"\x00" * 28)  # Client Hello data

        result = self.detector.is_client_hello(bytes(packet))

        assert result is True

    def test_is_client_hello_invalid_content_type(self):
        """Test Client Hello detection with invalid content type."""
        # Wrong content type (0x15 instead of 0x16)
        packet = struct.pack("!BHHBH", 0x15, 0x0303, 0x0020, 0x01, 0x001C)
        packet += b"\x00" * 28

        result = self.detector.is_client_hello(packet)

        assert result is False

    def test_is_client_hello_invalid_version(self):
        """Test Client Hello detection with unsupported TLS version."""
        # Unsupported version (0x0200)
        packet = struct.pack("!BHHBH", 0x16, 0x0200, 0x0020, 0x01, 0x001C)
        packet += b"\x00" * 28

        result = self.detector.is_client_hello(packet)

        assert result is False

    def test_is_client_hello_invalid_handshake_type(self):
        """Test Client Hello detection with wrong handshake type."""
        # Wrong handshake type (0x02 instead of 0x01)
        packet = struct.pack("!BHHBH", 0x16, 0x0303, 0x0020, 0x02, 0x001C)
        packet += b"\x00" * 28

        result = self.detector.is_client_hello(packet)

        assert result is False

    def test_is_client_hello_too_small(self):
        """Test Client Hello detection with packet too small."""
        small_packet = b"\x16\x03\x03"  # Only 3 bytes

        result = self.detector.is_client_hello(small_packet)

        assert result is False

    def test_is_client_hello_length_mismatch(self):
        """Test Client Hello detection with length mismatch."""
        # Record length says 0x0100 but packet is much smaller
        packet = struct.pack("!BHHBH", 0x16, 0x0303, 0x0100, 0x01, 0x001C)
        packet += b"\x00" * 10  # Only 10 bytes instead of 256

        result = self.detector.is_client_hello(packet)

        assert result is False

    def test_find_sni_position_valid(self):
        """Test finding SNI position in valid TLS Client Hello."""
        packet = self._create_client_hello_with_sni("example.com")

        result = self.detector.find_sni_position(packet)

        assert result is not None
        assert isinstance(result, int)
        assert result > 0

    def test_find_sni_position_no_sni(self):
        """Test finding SNI position in packet without SNI."""
        packet = self._create_client_hello_without_sni()

        result = self.detector.find_sni_position(packet)

        assert result is None

    def test_find_sni_position_not_client_hello(self):
        """Test finding SNI position in non-Client Hello packet."""
        # Create a different type of packet
        packet = b"HTTP/1.1 GET / HTTP/1.1\r\n\r\n"

        result = self.detector.find_sni_position(packet)

        assert result is None

    def test_find_sni_position_malformed_tls(self):
        """Test finding SNI position in malformed TLS packet."""
        # Create packet that looks like TLS but is malformed
        packet = struct.pack("!BHHB", 0x16, 0x0303, 0x0020, 0x01)
        packet += b"\xff" * 10  # Malformed data

        result = self.detector.find_sni_position(packet)

        assert result is None

    def test_parse_tls_extensions_with_sni(self):
        """Test parsing TLS extensions containing SNI."""
        packet = self._create_client_hello_with_sni("test.example.com")

        result = self.detector.parse_tls_extensions(packet)

        assert isinstance(result, dict)
        assert 0x0000 in result  # SNI extension type
        assert result[0x0000] > 0  # Position should be positive

    def test_parse_tls_extensions_multiple_extensions(self):
        """Test parsing TLS extensions with multiple extensions."""
        packet = self._create_client_hello_with_multiple_extensions()

        result = self.detector.parse_tls_extensions(packet)

        assert isinstance(result, dict)
        # Should have at least SNI extension, may have more depending on implementation
        assert len(result) >= 1  # Should have at least one extension
        assert 0x0000 in result  # SNI extension should be present

    def test_parse_tls_extensions_no_extensions(self):
        """Test parsing TLS packet without extensions."""
        packet = self._create_client_hello_without_extensions()

        result = self.detector.parse_tls_extensions(packet)

        assert isinstance(result, dict)
        assert len(result) == 0  # No extensions

    def test_parse_tls_extensions_not_client_hello(self):
        """Test parsing extensions on non-Client Hello packet."""
        packet = b"Not a TLS packet"

        result = self.detector.parse_tls_extensions(packet)

        assert isinstance(result, dict)
        assert len(result) == 0

    def test_extract_sni_value_valid(self):
        """Test extracting SNI value from valid packet."""
        hostname = "www.example.com"
        packet = self._create_client_hello_with_sni(hostname)

        result = self.detector.extract_sni_value(packet)

        assert result == hostname

    def test_extract_sni_value_with_position(self):
        """Test extracting SNI value with provided position."""
        hostname = "api.example.com"
        packet = self._create_client_hello_with_sni(hostname)
        sni_position = self.detector.find_sni_position(packet)

        result = self.detector.extract_sni_value(packet, sni_position)

        assert result == hostname

    def test_extract_sni_value_no_sni(self):
        """Test extracting SNI value from packet without SNI."""
        packet = self._create_client_hello_without_sni()

        result = self.detector.extract_sni_value(packet)

        assert result is None

    def test_extract_sni_value_invalid_position(self):
        """Test extracting SNI value with invalid position."""
        packet = self._create_client_hello_with_sni("example.com")

        result = self.detector.extract_sni_value(packet, 999)  # Invalid position

        assert result is None

    def test_is_valid_hostname_valid(self):
        """Test hostname validation with valid hostnames."""
        valid_hostnames = [
            "example.com",
            "www.example.com",
            "api.sub.example.com",
            "test-site.example.org",
            "123.example.net",
            "a.b.c.d.example.co.uk",
        ]

        for hostname in valid_hostnames:
            assert (
                self.detector._is_valid_hostname(hostname) is True
            ), f"Failed for {hostname}"

    def test_is_valid_hostname_invalid(self):
        """Test hostname validation with invalid hostnames."""
        invalid_hostnames = [
            "",  # Empty
            ".",  # Just dot
            ".example.com",  # Leading dot
            "example.com.",  # Trailing dot
            "exam..ple.com",  # Double dot
            "exam ple.com",  # Space
            "exam@ple.com",  # Invalid character
            "a" * 254,  # Too long
        ]

        for hostname in invalid_hostnames:
            assert (
                self.detector._is_valid_hostname(hostname) is False
            ), f"Should fail for {hostname}"

    def test_parse_sni_extension_valid(self):
        """Test parsing valid SNI extension structure."""
        hostname = "secure.example.com"
        packet = self._create_client_hello_with_sni(hostname)
        sni_position = self.detector.find_sni_position(packet)

        result = self.detector._parse_sni_extension(packet, sni_position)

        assert result == hostname

    def test_parse_sni_extension_wrong_type(self):
        """Test parsing SNI extension with wrong extension type."""
        packet = self._create_client_hello_with_sni("example.com")
        # Use wrong position that doesn't point to SNI extension
        wrong_position = 10

        result = self.detector._parse_sni_extension(packet, wrong_position)

        assert result is None

    def test_parse_sni_extension_malformed(self):
        """Test parsing malformed SNI extension."""
        # Create a packet with malformed SNI extension
        packet = self._create_malformed_sni_packet()
        sni_position = 50  # Arbitrary position in malformed data

        result = self.detector._parse_sni_extension(packet, sni_position)

        assert result is None

    def test_get_sni_info_complete(self):
        """Test getting complete SNI information."""
        hostname = "info.example.com"
        packet = self._create_client_hello_with_sni(hostname)

        result = self.detector.get_sni_info(packet)

        assert result["is_client_hello"] is True
        assert result["has_sni"] is True
        assert result["sni_position"] is not None
        assert result["sni_value"] == hostname
        assert result["packet_size"] == len(packet)

    def test_get_sni_info_no_sni(self):
        """Test getting SNI information from packet without SNI."""
        packet = self._create_client_hello_without_sni()

        result = self.detector.get_sni_info(packet)

        assert result["is_client_hello"] is True
        assert result["has_sni"] is False
        assert result["sni_position"] is None
        assert result["sni_value"] is None
        assert result["packet_size"] == len(packet)

    def test_get_sni_info_not_tls(self):
        """Test getting SNI information from non-TLS packet."""
        packet = b"HTTP/1.1 GET / HTTP/1.1\r\n\r\n"

        result = self.detector.get_sni_info(packet)

        assert result["is_client_hello"] is False
        assert result["has_sni"] is False
        assert result["sni_position"] is None
        assert result["sni_value"] is None
        assert result["packet_size"] == len(packet)

    def test_multiple_sni_extensions(self):
        """Test handling packet with multiple SNI extensions (should use first)."""
        packet = self._create_client_hello_with_multiple_sni()

        result = self.detector.find_sni_position(packet)

        # Should find the first SNI extension
        assert result is not None

        # Extract value should get the first SNI
        sni_value = self.detector.extract_sni_value(packet, result)
        assert sni_value == "first.example.com"  # First SNI in the packet

    def test_sni_with_international_domain(self):
        """Test SNI extraction with international domain names."""
        # Test with punycode domain
        hostname = "xn--e1afmkfd.xn--p1ai"  # пример.рф in punycode
        packet = self._create_client_hello_with_sni(hostname)

        result = self.detector.extract_sni_value(packet)

        assert result == hostname

    def test_edge_case_empty_sni(self):
        """Test handling empty SNI extension."""
        packet = self._create_client_hello_with_empty_sni()

        result = self.detector.extract_sni_value(packet)

        assert result is None

    def test_edge_case_oversized_sni(self):
        """Test handling oversized SNI value."""
        # Create SNI with very long hostname
        long_hostname = "a" * 300 + ".example.com"
        packet = self._create_client_hello_with_sni(long_hostname)

        result = self.detector.extract_sni_value(packet)

        # Should reject oversized hostname
        assert result is None

    def _create_client_hello_with_sni(self, hostname: str) -> bytes:
        """Create a TLS Client Hello packet with SNI extension."""
        # TLS Record Header
        record = bytearray()
        record.extend(b"\x16")  # Content Type: Handshake
        record.extend(b"\x03\x03")  # Version: TLS 1.2

        # Build handshake message
        handshake = bytearray()
        handshake.extend(b"\x01")  # Handshake Type: Client Hello

        # Build Client Hello
        client_hello = bytearray()
        client_hello.extend(b"\x03\x03")  # Version: TLS 1.2
        client_hello.extend(b"\x00" * 32)  # Random
        client_hello.extend(b"\x00")  # Session ID Length

        # Cipher Suites
        client_hello.extend(b"\x00\x02")  # Length
        client_hello.extend(b"\x00\x35")  # TLS_RSA_WITH_AES_256_CBC_SHA

        # Compression Methods
        client_hello.extend(b"\x01")  # Length
        client_hello.extend(b"\x00")  # null compression

        # Extensions
        extensions = bytearray()

        # SNI Extension
        sni_ext = bytearray()
        sni_ext.extend(b"\x00\x00")  # Extension Type: SNI

        # SNI Extension Data
        sni_data = bytearray()
        hostname_bytes = hostname.encode("utf-8")
        sni_list_length = 1 + 2 + len(hostname_bytes)  # type + length + hostname
        sni_data.extend(struct.pack("!H", sni_list_length))  # Server Name List Length
        sni_data.extend(b"\x00")  # Server Name Type: host_name
        sni_data.extend(struct.pack("!H", len(hostname_bytes)))  # Server Name Length
        sni_data.extend(hostname_bytes)  # Server Name

        sni_ext.extend(struct.pack("!H", len(sni_data)))  # Extension Length
        sni_ext.extend(sni_data)

        extensions.extend(sni_ext)

        # Add extensions to Client Hello
        client_hello.extend(struct.pack("!H", len(extensions)))  # Extensions Length
        client_hello.extend(extensions)

        # Add Client Hello to handshake
        handshake.extend(struct.pack("!I", len(client_hello))[1:])  # Length (3 bytes)
        handshake.extend(client_hello)

        # Add handshake to record
        record.extend(struct.pack("!H", len(handshake)))  # Record Length
        record.extend(handshake)

        return bytes(record)

    def _create_client_hello_without_sni(self) -> bytes:
        """Create a TLS Client Hello packet without SNI extension."""
        # TLS Record Header
        record = bytearray()
        record.extend(b"\x16")  # Content Type: Handshake
        record.extend(b"\x03\x03")  # Version: TLS 1.2

        # Build handshake message
        handshake = bytearray()
        handshake.extend(b"\x01")  # Handshake Type: Client Hello

        # Build Client Hello
        client_hello = bytearray()
        client_hello.extend(b"\x03\x03")  # Version: TLS 1.2
        client_hello.extend(b"\x00" * 32)  # Random
        client_hello.extend(b"\x00")  # Session ID Length

        # Cipher Suites
        client_hello.extend(b"\x00\x02")  # Length
        client_hello.extend(b"\x00\x35")  # TLS_RSA_WITH_AES_256_CBC_SHA

        # Compression Methods
        client_hello.extend(b"\x01")  # Length
        client_hello.extend(b"\x00")  # null compression

        # Extensions - add some other extension but not SNI
        extensions = bytearray()

        # Supported Groups Extension (example)
        supported_groups_ext = bytearray()
        supported_groups_ext.extend(b"\x00\x0a")  # Extension Type: supported_groups
        supported_groups_data = b"\x00\x04\x00\x17\x00\x18"  # secp256r1, secp384r1
        supported_groups_ext.extend(struct.pack("!H", len(supported_groups_data)))
        supported_groups_ext.extend(supported_groups_data)

        extensions.extend(supported_groups_ext)

        # Add extensions to Client Hello
        client_hello.extend(struct.pack("!H", len(extensions)))  # Extensions Length
        client_hello.extend(extensions)

        # Add Client Hello to handshake
        handshake.extend(struct.pack("!I", len(client_hello))[1:])  # Length (3 bytes)
        handshake.extend(client_hello)

        # Add handshake to record
        record.extend(struct.pack("!H", len(handshake)))  # Record Length
        record.extend(handshake)

        return bytes(record)

    def _create_client_hello_without_extensions(self) -> bytes:
        """Create a TLS Client Hello packet without any extensions."""
        # TLS Record Header
        record = bytearray()
        record.extend(b"\x16")  # Content Type: Handshake
        record.extend(b"\x03\x03")  # Version: TLS 1.2

        # Build handshake message
        handshake = bytearray()
        handshake.extend(b"\x01")  # Handshake Type: Client Hello

        # Build Client Hello
        client_hello = bytearray()
        client_hello.extend(b"\x03\x03")  # Version: TLS 1.2
        client_hello.extend(b"\x00" * 32)  # Random
        client_hello.extend(b"\x00")  # Session ID Length

        # Cipher Suites
        client_hello.extend(b"\x00\x02")  # Length
        client_hello.extend(b"\x00\x35")  # TLS_RSA_WITH_AES_256_CBC_SHA

        # Compression Methods
        client_hello.extend(b"\x01")  # Length
        client_hello.extend(b"\x00")  # null compression

        # No extensions - don't add extensions length field

        # Add Client Hello to handshake
        handshake.extend(struct.pack("!I", len(client_hello))[1:])  # Length (3 bytes)
        handshake.extend(client_hello)

        # Add handshake to record
        record.extend(struct.pack("!H", len(handshake)))  # Record Length
        record.extend(handshake)

        return bytes(record)

    def _create_client_hello_with_multiple_extensions(self) -> bytes:
        """Create a TLS Client Hello with multiple extensions including SNI."""
        # Start with SNI packet
        packet_data = bytearray(self._create_client_hello_with_sni("example.com"))

        # Find extensions section and add more extensions
        # This is a simplified approach - in practice would need proper parsing

        # Add another extension (Supported Groups)
        additional_ext = bytearray()
        additional_ext.extend(b"\x00\x0a")  # Extension Type: supported_groups
        ext_data = b"\x00\x04\x00\x17\x00\x18"  # secp256r1, secp384r1
        additional_ext.extend(struct.pack("!H", len(ext_data)))
        additional_ext.extend(ext_data)

        # For simplicity, just append to the packet
        # In real implementation, would properly insert into extensions section
        packet_data.extend(additional_ext)

        return bytes(packet_data)

    def _create_client_hello_with_multiple_sni(self) -> bytes:
        """Create a TLS Client Hello with multiple SNI extensions (invalid but for testing)."""
        # Create base packet with first SNI
        packet = self._create_client_hello_with_sni("first.example.com")

        # Add second SNI extension (this is actually invalid per spec, but for testing)
        second_sni = bytearray()
        second_sni.extend(b"\x00\x00")  # Extension Type: SNI

        hostname = "second.example.com"
        hostname_bytes = hostname.encode("utf-8")
        sni_data = bytearray()
        sni_list_length = 1 + 2 + len(hostname_bytes)
        sni_data.extend(struct.pack("!H", sni_list_length))
        sni_data.extend(b"\x00")  # Server Name Type
        sni_data.extend(struct.pack("!H", len(hostname_bytes)))
        sni_data.extend(hostname_bytes)

        second_sni.extend(struct.pack("!H", len(sni_data)))
        second_sni.extend(sni_data)

        # Append to packet (simplified)
        packet_data = bytearray(packet)
        packet_data.extend(second_sni)

        return bytes(packet_data)

    def _create_client_hello_with_empty_sni(self) -> bytes:
        """Create a TLS Client Hello with empty SNI extension."""
        # Similar to normal SNI but with empty hostname
        return self._create_client_hello_with_sni("")

    def _create_malformed_sni_packet(self) -> bytes:
        """Create a packet with malformed SNI extension."""
        # Start with valid structure
        record = bytearray()
        record.extend(b"\x16\x03\x03\x00\x50")  # TLS record header
        record.extend(b"\x01\x00\x00\x4c")  # Handshake header
        record.extend(b"\x03\x03")  # Client Hello version
        record.extend(b"\x00" * 32)  # Random
        record.extend(b"\x00")  # Session ID length
        record.extend(b"\x00\x02\x00\x35")  # Cipher suites
        record.extend(b"\x01\x00")  # Compression methods

        # Add malformed extensions
        record.extend(b"\x00\x10")  # Extensions length
        record.extend(b"\x00\x00")  # SNI extension type
        record.extend(b"\x00\x0c")  # Extension length
        record.extend(b"\xff\xff")  # Malformed SNI list length
        record.extend(b"\x00" * 10)  # Malformed data

        return bytes(record)


@pytest.fixture
def sni_detector():
    """Fixture providing an SNIDetector instance."""
    return SNIDetector()


@pytest.fixture
def sample_client_hello():
    """Fixture providing a sample TLS Client Hello packet."""
    detector = SNIDetector()
    return detector._create_client_hello_with_sni("test.example.com")


class TestSNIDetectorIntegration:
    """Integration tests for SNIDetector with real-world scenarios."""

    def test_youtube_client_hello(self, sni_detector):
        """Test SNI detection with YouTube-like Client Hello."""
        packet = self._create_youtube_client_hello()

        assert sni_detector.is_client_hello(packet) is True

        sni_position = sni_detector.find_sni_position(packet)
        assert sni_position is not None

        sni_value = sni_detector.extract_sni_value(packet)
        assert sni_value == "www.youtube.com"

    def test_google_client_hello(self, sni_detector):
        """Test SNI detection with Google-like Client Hello."""
        packet = self._create_google_client_hello()

        info = sni_detector.get_sni_info(packet)

        assert info["is_client_hello"] is True
        assert info["has_sni"] is True
        assert info["sni_value"] == "www.google.com"

    def test_cloudflare_client_hello(self, sni_detector):
        """Test SNI detection with Cloudflare-protected site."""
        packet = self._create_cloudflare_client_hello()

        extensions = sni_detector.parse_tls_extensions(packet)

        assert 0x0000 in extensions  # SNI extension present

        sni_value = sni_detector.extract_sni_value(packet)
        assert sni_value == "example.cloudflare.com"

    def test_performance_large_packet(self, sni_detector):
        """Test performance with large TLS packet."""
        # Create a large packet with many extensions
        packet = self._create_large_client_hello()

        import time

        start_time = time.time()

        result = sni_detector.find_sni_position(packet)

        end_time = time.time()
        processing_time = end_time - start_time

        # Should complete within reasonable time (< 100ms)
        assert processing_time < 0.1
        assert result is not None

    def _create_youtube_client_hello(self) -> bytes:
        """Create a realistic YouTube Client Hello packet."""
        detector = SNIDetector()
        return detector._create_client_hello_with_sni("www.youtube.com")

    def _create_google_client_hello(self) -> bytes:
        """Create a realistic Google Client Hello packet."""
        detector = SNIDetector()
        return detector._create_client_hello_with_sni("www.google.com")

    def _create_cloudflare_client_hello(self) -> bytes:
        """Create a Cloudflare-protected site Client Hello."""
        detector = SNIDetector()
        return detector._create_client_hello_with_sni("example.cloudflare.com")

    def _create_large_client_hello(self) -> bytes:
        """Create a large Client Hello packet with many extensions."""
        # Start with basic SNI packet
        detector = SNIDetector()
        base_packet = bytearray(
            detector._create_client_hello_with_sni("large.example.com")
        )

        # Add many dummy extensions to make it large
        for i in range(10):
            ext_type = 0x1000 + i  # Use private extension types
            ext_data = b"\x00" * 100  # 100 bytes of dummy data

            extension = bytearray()
            extension.extend(struct.pack("!H", ext_type))
            extension.extend(struct.pack("!H", len(ext_data)))
            extension.extend(ext_data)

            base_packet.extend(extension)

        return bytes(base_packet)

    def _create_client_hello_with_multiple_extensions(self) -> bytes:
        """Create a Client Hello packet with multiple extensions."""
        # TLS Record Header
        record = bytearray()
        record.extend(b"\x16")  # Content Type: Handshake
        record.extend(b"\x03\x03")  # Version: TLS 1.2

        # We'll set the record length later
        record_length_pos = len(record)
        record.extend(b"\x00\x00")  # Placeholder for record length

        # Handshake Header
        handshake_start = len(record)
        record.extend(b"\x01")  # Handshake Type: Client Hello

        # We'll set the handshake length later
        handshake_length_pos = len(record)
        record.extend(b"\x00\x00\x00")  # Placeholder for handshake length (3 bytes)

        # Client Hello Message
        record.extend(b"\x03\x03")  # Client Version: TLS 1.2
        record.extend(b"\x00" * 32)  # Random (32 bytes)
        record.extend(b"\x00")  # Session ID Length (0)

        # Cipher Suites
        record.extend(b"\x00\x02")  # Cipher Suites Length (2 bytes)
        record.extend(b"\x00\x35")  # TLS_RSA_WITH_AES_256_CBC_SHA

        # Compression Methods
        record.extend(b"\x01")  # Compression Methods Length (1 byte)
        record.extend(b"\x00")  # Compression Method: null

        # Extensions
        extensions_length_pos = len(record)
        record.extend(b"\x00\x00")  # Extensions length placeholder

        # SNI Extension (type 0x0000)
        record.extend(struct.pack(">H", 0x0000))  # Extension Type: SNI
        hostname = "example.com"
        hostname_bytes = hostname.encode("utf-8")
        sni_list_length = 1 + 2 + len(hostname_bytes)
        sni_extension_length = 2 + sni_list_length
        record.extend(struct.pack(">H", sni_extension_length))  # Extension Length
        record.extend(struct.pack(">H", sni_list_length))  # Server Name List Length
        record.extend(b"\x00")  # Server Name Type: host_name
        record.extend(struct.pack(">H", len(hostname_bytes)))  # Server Name Length
        record.extend(hostname_bytes)  # Server Name

        # Supported Groups Extension (type 0x000a)
        record.extend(struct.pack(">H", 0x000A))  # Extension Type: Supported Groups
        groups_data = b"\x00\x04\x00\x17\x00\x18"  # secp256r1, secp384r1
        record.extend(struct.pack(">H", len(groups_data)))  # Extension Length
        record.extend(groups_data)

        # EC Point Formats Extension (type 0x000b)
        record.extend(struct.pack(">H", 0x000B))  # Extension Type: EC Point Formats
        formats_data = b"\x01\x00"  # uncompressed
        record.extend(struct.pack(">H", len(formats_data)))  # Extension Length
        record.extend(formats_data)

        # Calculate and set lengths
        total_extensions_length = len(record) - extensions_length_pos - 2
        struct.pack_into(">H", record, extensions_length_pos, total_extensions_length)

        handshake_length = len(record) - handshake_start - 4
        struct.pack_into(">I", record, handshake_length_pos, handshake_length)
        record[handshake_length_pos] = (
            0  # Clear the first byte (should be 0 for 3-byte length)
        )

        record_length = len(record) - 5  # Exclude TLS record header
        struct.pack_into(">H", record, record_length_pos, record_length)

        return bytes(record)
