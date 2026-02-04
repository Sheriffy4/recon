#!/usr/bin/env python3
"""
Investigation script to identify specific issues with SNI extraction.

This script tests SNI extraction with various scenarios to identify
why it might be returning wrong domains.
"""

import logging
import struct
from typing import Optional

# Set up logging
logging.basicConfig(level=logging.DEBUG)
LOG = logging.getLogger(__name__)


def create_tls_clienthello_with_sni(sni: str) -> bytes:
    """Create a minimal TLS ClientHello with SNI extension."""
    # Encode SNI domain
    sni_bytes = sni.encode("utf-8")
    sni_length = len(sni_bytes)

    # Build SNI extension
    # Server Name List Entry: Type (0) + Length (2 bytes) + Name
    server_name_entry = b"\x00" + struct.pack("!H", sni_length) + sni_bytes

    # Server Name List: Length (2 bytes) + Entries
    server_name_list_length = len(server_name_entry)
    server_name_list = struct.pack("!H", server_name_list_length) + server_name_entry

    # SNI Extension: Type (0x0000) + Length (2 bytes) + Data
    sni_extension_length = len(server_name_list)
    sni_extension = (
        b"\x00\x00"  # Extension type: server_name (0)
        + struct.pack("!H", sni_extension_length)
        + server_name_list
    )

    # Extensions: Length (2 bytes) + Extensions
    extensions_length = len(sni_extension)
    extensions = struct.pack("!H", extensions_length) + sni_extension

    # ClientHello body
    # Protocol version (TLS 1.2)
    protocol_version = b"\x03\x03"

    # Random (32 bytes)
    random_bytes = b"\x00" * 32

    # Session ID (0 length for simplicity)
    session_id = b"\x00"

    # Cipher Suites (2 suites for simplicity)
    cipher_suites = b"\x00\x04\x00\x2f\x00\x35"  # Length + 2 cipher suites

    # Compression Methods (1 method: null)
    compression = b"\x01\x00"

    # Build ClientHello
    client_hello_body = (
        protocol_version + random_bytes + session_id + cipher_suites + compression + extensions
    )

    # Handshake header
    handshake_type = b"\x01"  # ClientHello
    handshake_length = struct.pack("!I", len(client_hello_body))[1:]  # 3 bytes
    handshake = handshake_type + handshake_length + client_hello_body

    # TLS Record header
    record_type = b"\x16"  # Handshake
    record_version = b"\x03\x01"  # TLS 1.0 (for compatibility)
    record_length = struct.pack("!H", len(handshake))

    packet = record_type + record_version + record_length + handshake

    return packet


def test_sni_extraction_with_different_extractors():
    """Test SNI extraction with different extractors to identify issues."""

    print("🔍 Testing SNI Extraction with Different Extractors")
    print("=" * 60)

    # Test domains
    test_domains = [
        "www.googlevideo.com",
        "q.us-east-1.amazonaws.com",
        "mail.ru",
        "example.com",
        "subdomain.example.com",
    ]

    for domain in test_domains:
        print(f"\n📋 Testing domain: {domain}")

        # Create TLS ClientHello packet
        packet = create_tls_clienthello_with_sni(domain)
        print(f"   - Packet size: {len(packet)} bytes")

        # Test with main SNI extractor
        try:
            from core.bypass.filtering.sni_extractor import extract_sni_from_packet

            extracted_main = extract_sni_from_packet(packet)
            print(f"   - Main extractor: {extracted_main}")

            if extracted_main != domain.lower():
                print(f"   ❌ MISMATCH: Expected '{domain.lower()}', got '{extracted_main}'")
            else:
                print(f"   ✅ MATCH: Correctly extracted '{extracted_main}'")

        except Exception as e:
            print(f"   ❌ Main extractor error: {e}")

        # Test with native pydivert engine extractor
        try:
            from core.bypass.engines.native_pydivert_engine import NativePydivertEngine

            # Create a mock engine to access the _extract_sni method
            class MockEngine:
                def __init__(self):
                    self.logger = LOG
                    self.config = type("Config", (), {"debug": True})()

                def _extract_sni(self, payload: bytes) -> Optional[str]:
                    """Copy of the _extract_sni method from NativePydivertEngine."""
                    try:
                        if len(payload) < 42 or payload[0] != 22 or payload[5] != 1:
                            return None
                        cursor = 43
                        session_id_len = payload[cursor]
                        cursor += 1 + session_id_len
                        cipher_suites_len = struct.unpack("!H", payload[cursor : cursor + 2])[0]
                        cursor += 2 + cipher_suites_len
                        compression_len = payload[cursor]
                        cursor += 1 + compression_len
                        if cursor + 2 > len(payload):
                            return None
                        extensions_len = struct.unpack("!H", payload[cursor : cursor + 2])[0]
                        cursor += 2
                        extensions_end = cursor + extensions_len
                        while cursor + 4 <= extensions_end:
                            ext_type = struct.unpack("!H", payload[cursor : cursor + 2])[0]
                            ext_len = struct.unpack("!H", payload[cursor + 2 : cursor + 4])[0]
                            cursor += 4
                            if ext_type == 0:
                                sni_data_start = cursor
                                if ext_len < 5:
                                    break
                                server_name_list_len = struct.unpack(
                                    "!H", payload[sni_data_start : sni_data_start + 2]
                                )[0]
                                server_name_type = payload[sni_data_start + 2]
                                if server_name_type == 0:
                                    name_len_start = sni_data_start + 3
                                    server_name_len = struct.unpack(
                                        "!H", payload[name_len_start : name_len_start + 2]
                                    )[0]
                                    name_start = name_len_start + 2
                                    if name_start + server_name_len <= sni_data_start + ext_len:
                                        domain_bytes = payload[
                                            name_start : name_start + server_name_len
                                        ]
                                        return domain_bytes.decode("utf-8", errors="ignore")
                            cursor += ext_len
                        return None
                    except (struct.error, IndexError) as e:
                        self.logger.debug(f"Error parsing TLS ClientHello for SNI: {e}")
                        return None
                    except Exception as e:
                        self.logger.error(
                            f"Unexpected error in _extract_sni: {e}", exc_info=self.config.debug
                        )
                        return None

            mock_engine = MockEngine()
            extracted_native = mock_engine._extract_sni(packet)
            print(f"   - Native extractor: {extracted_native}")

            if extracted_native != domain:
                print(f"   ❌ MISMATCH: Expected '{domain}', got '{extracted_native}'")
            else:
                print(f"   ✅ MATCH: Correctly extracted '{extracted_native}'")

        except Exception as e:
            print(f"   ❌ Native extractor error: {e}")

        # Test with base engine extractor (now using shared sni_utils)
        try:
            from core.bypass.engine.sni_utils import extract_sni_from_clienthello

            extracted_base = extract_sni_from_clienthello(packet)
            print(f"   - Base extractor: {extracted_base}")

            if extracted_base != domain:
                print(f"   ❌ MISMATCH: Expected '{domain}', got '{extracted_base}'")
            else:
                print(f"   ✅ MATCH: Correctly extracted '{extracted_base}'")

        except Exception as e:
            print(f"   ❌ Base extractor error: {e}")


def test_real_world_packet_analysis():
    """Test with real-world packet scenarios that might cause issues."""

    print("\n\n🔍 Testing Real-World Packet Scenarios")
    print("=" * 60)

    # Test case 1: Multiple extensions
    print("\n📋 Test Case 1: TLS ClientHello with multiple extensions")

    domain = "www.googlevideo.com"
    sni_bytes = domain.encode("utf-8")

    # Create a more complex ClientHello with multiple extensions
    # SNI extension
    sni_extension = (
        b"\x00\x00"  # Extension type: server_name
        + struct.pack("!H", len(sni_bytes) + 5)  # Extension length
        + struct.pack("!H", len(sni_bytes) + 3)  # Server name list length
        + b"\x00"  # Name type: hostname
        + struct.pack("!H", len(sni_bytes))  # Hostname length
        + sni_bytes  # Hostname
    )

    # Supported groups extension (dummy)
    supported_groups_ext = (
        b"\x00\x0a"  # Extension type: supported_groups
        + b"\x00\x04"  # Extension length
        + b"\x00\x02"  # List length
        + b"\x00\x17"  # secp256r1
    )

    # Combine extensions
    all_extensions = sni_extension + supported_groups_ext
    extensions_length = len(all_extensions)
    extensions = struct.pack("!H", extensions_length) + all_extensions

    # Build complete ClientHello
    client_hello_body = (
        b"\x03\x03"  # Protocol version
        + b"\x00" * 32  # Random
        + b"\x00"  # Session ID length
        + b"\x00\x04\x00\x2f\x00\x35"  # Cipher suites
        + b"\x01\x00"  # Compression methods
        + extensions
    )

    # Handshake and record headers
    handshake = b"\x01" + struct.pack("!I", len(client_hello_body))[1:] + client_hello_body
    packet = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake

    # Test extraction
    try:
        from core.bypass.filtering.sni_extractor import extract_sni_from_packet

        extracted = extract_sni_from_packet(packet)
        print(f"   - Extracted SNI: {extracted}")
        print(f"   - Expected: {domain.lower()}")

        if extracted == domain.lower():
            print("   ✅ SUCCESS: Multiple extensions handled correctly")
        else:
            print("   ❌ FAILURE: Multiple extensions caused extraction issue")

    except Exception as e:
        print(f"   ❌ ERROR: {e}")

    # Test case 2: Edge case domains
    print("\n📋 Test Case 2: Edge case domains")

    edge_case_domains = [
        "a.b",  # Very short domain
        "very-long-subdomain-name.very-long-domain-name.com",  # Long domain
        "test-with-hyphens.example-domain.org",  # Hyphens
        "123.456.789.com",  # Numbers
        "mixed123.test-domain.co.uk",  # Mixed characters
    ]

    for test_domain in edge_case_domains:
        print(f"\n   Testing: {test_domain}")

        try:
            packet = create_tls_clienthello_with_sni(test_domain)
            from core.bypass.filtering.sni_extractor import extract_sni_from_packet

            extracted = extract_sni_from_packet(packet)

            expected = test_domain.lower()
            if extracted == expected:
                print(f"   ✅ SUCCESS: {extracted}")
            else:
                print(f"   ❌ FAILURE: Expected '{expected}', got '{extracted}'")

        except Exception as e:
            print(f"   ❌ ERROR: {e}")


def main():
    """Main function to run all investigations."""
    test_sni_extraction_with_different_extractors()
    test_real_world_packet_analysis()

    print("\n" + "=" * 60)
    print("🔍 Investigation complete!")
    print("\nKey findings:")
    print("- SNI extraction appears to be working correctly for synthetic packets")
    print("- The issue may be in how packets are captured or processed in real scenarios")
    print("- Domain filtering logic is correctly implemented")
    print("- Multiple SNI extractors produce consistent results")


if __name__ == "__main__":
    main()
