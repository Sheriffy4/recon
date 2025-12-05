"""
Property-based tests for PCAPValidator.

Feature: attack-application-parity
Tests correctness properties for PCAP analysis and ClientHello parsing.
"""

import struct
import pytest
from hypothesis import given, strategies as st, settings, assume, HealthCheck

from core.validation.pcap_validator import (
    PCAPValidator,
    ClientHelloInfo,
    DetectedAttacks,
    TCPStream
)


# ============================================================================
# Strategies for generating test data
# ============================================================================

@st.composite
def valid_sni(draw):
    """Generate valid SNI (domain name)."""
    # Generate domain parts
    num_parts = draw(st.integers(min_value=1, max_value=4))
    parts = []
    for _ in range(num_parts):
        part_len = draw(st.integers(min_value=1, max_value=20))
        part = draw(st.text(
            alphabet=st.sampled_from('abcdefghijklmnopqrstuvwxyz0123456789-'),
            min_size=part_len,
            max_size=part_len
        ))
        # Ensure part doesn't start or end with hyphen
        if part.startswith('-') or part.endswith('-'):
            part = 'a' + part[1:-1] + 'a' if len(part) > 2 else 'aa'
        parts.append(part)
    
    return '.'.join(parts)


@st.composite
def tls_version(draw):
    """Generate valid TLS version."""
    return draw(st.sampled_from([(3, 1), (3, 3), (3, 4)]))  # TLS 1.0, 1.2, 1.3


@st.composite
def cipher_suites_list(draw):
    """Generate valid cipher suites list."""
    # Common cipher suites
    common_ciphers = [
        0x1301, 0x1302, 0x1303,  # TLS 1.3
        0xc02c, 0xc02b, 0xc030, 0xc02f,  # ECDHE
        0x009e, 0x009f, 0x006b, 0x0067,  # DHE
    ]
    num_ciphers = draw(st.integers(min_value=1, max_value=10))
    return draw(st.lists(
        st.sampled_from(common_ciphers),
        min_size=num_ciphers,
        max_size=num_ciphers
    ))


@st.composite
def extensions_list(draw):
    """Generate valid extensions list."""
    # Common extension types
    common_extensions = [
        0x0000,  # SNI
        0x000a,  # supported_groups
        0x000b,  # ec_point_formats
        0x000d,  # signature_algorithms
        0x0017,  # extended_master_secret
        0x002b,  # supported_versions
        0x002d,  # psk_key_exchange_modes
        0x0033,  # key_share
    ]
    num_extensions = draw(st.integers(min_value=1, max_value=8))
    return draw(st.lists(
        st.sampled_from(common_extensions),
        min_size=num_extensions,
        max_size=num_extensions,
        unique=True
    ))


def build_clienthello(
    sni: str,
    version: tuple = (3, 3),
    cipher_suites: list = None,
    extensions: list = None
) -> bytes:
    """Build a valid TLS ClientHello message."""
    if cipher_suites is None:
        cipher_suites = [0x1301, 0xc02c]
    if extensions is None:
        extensions = [0x0000]  # SNI only
    
    # Build extensions
    ext_data = b""
    
    # SNI extension (type 0x0000)
    # Format: SNI list length (2) + name type (1) + name length (2) + name
    sni_bytes = sni.encode('ascii')
    sni_entry = struct.pack("B", 0x00)  # host_name type
    sni_entry += struct.pack(">H", len(sni_bytes))  # name length
    sni_entry += sni_bytes
    sni_ext = struct.pack(">H", len(sni_entry))  # SNI list length
    sni_ext += sni_entry
    ext_data += struct.pack(">HH", 0x0000, len(sni_ext)) + sni_ext
    
    # supported_groups extension (type 0x000a)
    if 0x000a in extensions:
        groups = [0x001d, 0x0017, 0x0018]  # x25519, secp256r1, secp384r1
        groups_data = struct.pack(">H", len(groups) * 2)
        for g in groups:
            groups_data += struct.pack(">H", g)
        ext_data += struct.pack(">HH", 0x000a, len(groups_data)) + groups_data
    
    # ec_point_formats extension (type 0x000b)
    if 0x000b in extensions:
        formats = [0x00]  # uncompressed
        formats_data = struct.pack("B", len(formats)) + bytes(formats)
        ext_data += struct.pack(">HH", 0x000b, len(formats_data)) + formats_data
    
    # Build cipher suites
    cipher_data = struct.pack(">H", len(cipher_suites) * 2)
    for cs in cipher_suites:
        cipher_data += struct.pack(">H", cs)
    
    # Build ClientHello body
    client_hello = b""
    client_hello += struct.pack("BB", version[0], version[1])  # Client version
    client_hello += b"\x00" * 32  # Random
    client_hello += struct.pack("B", 0)  # Session ID length
    client_hello += cipher_data  # Cipher suites
    client_hello += struct.pack("B", 1) + b"\x00"  # Compression methods
    client_hello += struct.pack(">H", len(ext_data)) + ext_data  # Extensions
    
    # Build handshake message
    hs_msg = struct.pack("B", 0x01)  # ClientHello type
    hs_msg += struct.pack(">I", len(client_hello))[1:]  # 3-byte length
    hs_msg += client_hello
    
    # Build TLS record
    record = struct.pack("B", 0x16)  # Handshake
    record += struct.pack("BB", 3, 1)  # Record version (TLS 1.0)
    record += struct.pack(">H", len(hs_msg))  # Record length
    record += hs_msg
    
    return record


def fragment_data(data: bytes, num_fragments: int) -> list:
    """Fragment data into specified number of pieces."""
    if num_fragments <= 1:
        return [data]
    
    # Calculate fragment sizes
    total_len = len(data)
    base_size = total_len // num_fragments
    remainder = total_len % num_fragments
    
    fragments = []
    offset = 0
    for i in range(num_fragments):
        size = base_size + (1 if i < remainder else 0)
        if size > 0:
            fragments.append(data[offset:offset + size])
            offset += size
    
    return fragments


# ============================================================================
# Property Tests for SNI Extraction (Property 8)
# ============================================================================

class TestSNIExtractionFromFragmentedPackets:
    """
    **Feature: attack-application-parity, Property 8: SNI Extraction from Fragmented Packets**
    **Validates: Requirements 3.1**
    
    Property: For any PCAP file with fragmented ClientHello, the Validator
    should correctly extract the SNI after reassembly.
    """
    
    @given(
        sni=valid_sni(),
        num_fragments=st.integers(min_value=1, max_value=5)
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_sni_extraction_after_reassembly(self, sni, num_fragments):
        """
        Test that SNI is correctly extracted after reassembling fragments.
        
        For any valid SNI and any number of fragments, reassembling and
        parsing should recover the original SNI.
        """
        # Build ClientHello with SNI
        clienthello = build_clienthello(sni)
        
        # Fragment the ClientHello
        fragments = fragment_data(clienthello, num_fragments)
        
        # Reassemble (simulate what reassemble_clienthello does)
        reassembled = b"".join(fragments)
        
        # Parse the reassembled ClientHello
        validator = PCAPValidator()
        info = validator.parse_clienthello(reassembled)
        
        # Assert: SNI should match original
        assert info.error is None, f"Parsing should succeed, got error: {info.error}"
        assert info.sni == sni, f"SNI should be '{sni}', got '{info.sni}'"
    
    @given(sni=valid_sni())
    @settings(max_examples=100)
    def test_sni_offset_is_correct(self, sni):
        """
        Test that SNI offset is correctly calculated.
        
        For any valid SNI, the offset should point to the actual SNI
        location in the ClientHello.
        """
        # Build ClientHello with SNI
        clienthello = build_clienthello(sni)
        
        # Parse
        validator = PCAPValidator()
        info = validator.parse_clienthello(clienthello)
        
        # Assert: SNI offset should be valid
        assert info.error is None, f"Parsing should succeed, got error: {info.error}"
        assert info.sni_offset is not None, "SNI offset should be set"
        
        # Verify offset points to SNI
        sni_bytes = sni.encode('ascii')
        extracted = clienthello[info.sni_offset:info.sni_offset + len(sni_bytes)]
        assert extracted == sni_bytes, \
            f"Data at offset should be SNI bytes, got {extracted!r}"
    
    @given(
        sni=valid_sni(),
        num_fragments=st.integers(min_value=2, max_value=8)
    )
    @settings(max_examples=100)
    def test_fragmentation_preserves_sni(self, sni, num_fragments):
        """
        Test that fragmenting and reassembling preserves SNI.
        
        For any valid SNI and fragmentation, the round-trip should
        preserve the SNI exactly.
        """
        # Build ClientHello
        clienthello = build_clienthello(sni)
        
        # Fragment
        fragments = fragment_data(clienthello, num_fragments)
        
        # Verify fragments cover entire data
        total_fragment_len = sum(len(f) for f in fragments)
        assert total_fragment_len == len(clienthello), \
            "Fragments should cover entire ClientHello"
        
        # Reassemble
        reassembled = b"".join(fragments)
        
        # Assert: reassembled should equal original
        assert reassembled == clienthello, \
            "Reassembled data should equal original"
        
        # Parse and verify SNI
        validator = PCAPValidator()
        info = validator.parse_clienthello(reassembled)
        assert info.sni == sni, f"SNI should be preserved: expected '{sni}', got '{info.sni}'"


# ============================================================================
# Property Tests for ClientHello Parsing Completeness (Property 15)
# ============================================================================

class TestClientHelloParsingCompleteness:
    """
    **Feature: attack-application-parity, Property 15: ClientHello Parsing Completeness**
    **Validates: Requirements 8.1**
    
    Property: For any ClientHello, the Validator should extract TLS version,
    cipher suites, extensions, curves, and ec_point_formats.
    """
    
    @given(
        sni=valid_sni(),
        version=tls_version(),
        cipher_suites=cipher_suites_list()
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_extracts_tls_version(self, sni, version, cipher_suites):
        """
        Test that TLS version is correctly extracted.
        
        For any valid ClientHello with a specific version, parsing should
        extract that version.
        """
        # Build ClientHello with specific version
        clienthello = build_clienthello(sni, version=version, cipher_suites=cipher_suites)
        
        # Parse
        validator = PCAPValidator()
        info = validator.parse_clienthello(clienthello)
        
        # Assert: version should be extracted
        assert info.error is None, f"Parsing should succeed, got error: {info.error}"
        expected_version = f"{version[0]}.{version[1]}"
        assert info.client_version == expected_version, \
            f"Client version should be '{expected_version}', got '{info.client_version}'"
    
    @given(
        sni=valid_sni(),
        cipher_suites=cipher_suites_list()
    )
    @settings(max_examples=100)
    def test_extracts_cipher_suites(self, sni, cipher_suites):
        """
        Test that cipher suites are correctly extracted.
        
        For any valid ClientHello with specific cipher suites, parsing
        should extract all of them.
        """
        # Build ClientHello with specific cipher suites
        clienthello = build_clienthello(sni, cipher_suites=cipher_suites)
        
        # Parse
        validator = PCAPValidator()
        info = validator.parse_clienthello(clienthello)
        
        # Assert: cipher suites should be extracted
        assert info.error is None, f"Parsing should succeed, got error: {info.error}"
        assert info.cipher_suites == cipher_suites, \
            f"Cipher suites should be {cipher_suites}, got {info.cipher_suites}"
    
    @given(sni=valid_sni())
    @settings(max_examples=100)
    def test_extracts_extensions(self, sni):
        """
        Test that extensions list is correctly extracted.
        
        For any valid ClientHello, parsing should extract the extensions list.
        """
        # Build ClientHello with multiple extensions
        extensions = [0x0000, 0x000a, 0x000b]  # SNI, supported_groups, ec_point_formats
        clienthello = build_clienthello(sni, extensions=extensions)
        
        # Parse
        validator = PCAPValidator()
        info = validator.parse_clienthello(clienthello)
        
        # Assert: extensions should be extracted
        assert info.error is None, f"Parsing should succeed, got error: {info.error}"
        assert 0x0000 in info.extensions, "SNI extension should be in list"
        assert 0x000a in info.extensions, "supported_groups extension should be in list"
        assert 0x000b in info.extensions, "ec_point_formats extension should be in list"
    
    @given(sni=valid_sni())
    @settings(max_examples=100)
    def test_extracts_supported_groups(self, sni):
        """
        Test that supported_groups (curves) are correctly extracted.
        
        For any valid ClientHello with supported_groups extension, parsing
        should extract the groups list.
        """
        # Build ClientHello with supported_groups extension
        extensions = [0x0000, 0x000a]
        clienthello = build_clienthello(sni, extensions=extensions)
        
        # Parse
        validator = PCAPValidator()
        info = validator.parse_clienthello(clienthello)
        
        # Assert: supported_groups should be extracted
        assert info.error is None, f"Parsing should succeed, got error: {info.error}"
        assert len(info.supported_groups) > 0, "supported_groups should be extracted"
        # Verify expected groups are present
        expected_groups = [0x001d, 0x0017, 0x0018]  # x25519, secp256r1, secp384r1
        for g in expected_groups:
            assert g in info.supported_groups, f"Group {g:#06x} should be in supported_groups"
    
    @given(sni=valid_sni())
    @settings(max_examples=100)
    def test_extracts_ec_point_formats(self, sni):
        """
        Test that ec_point_formats are correctly extracted.
        
        For any valid ClientHello with ec_point_formats extension, parsing
        should extract the formats list.
        """
        # Build ClientHello with ec_point_formats extension
        extensions = [0x0000, 0x000b]
        clienthello = build_clienthello(sni, extensions=extensions)
        
        # Parse
        validator = PCAPValidator()
        info = validator.parse_clienthello(clienthello)
        
        # Assert: ec_point_formats should be extracted
        assert info.error is None, f"Parsing should succeed, got error: {info.error}"
        assert len(info.ec_point_formats) > 0, "ec_point_formats should be extracted"
        assert 0x00 in info.ec_point_formats, "Uncompressed format (0x00) should be present"
    
    @given(sni=valid_sni())
    @settings(max_examples=100)
    def test_calculates_ja3_fingerprint(self, sni):
        """
        Test that JA3 fingerprint is calculated.
        
        For any valid ClientHello, parsing should calculate a JA3 fingerprint.
        """
        # Build ClientHello
        clienthello = build_clienthello(sni)
        
        # Parse
        validator = PCAPValidator()
        info = validator.parse_clienthello(clienthello)
        
        # Assert: JA3 should be calculated
        assert info.error is None, f"Parsing should succeed, got error: {info.error}"
        assert info.ja3 is not None, "JA3 should be calculated"
        assert len(info.ja3) == 32, "JA3 should be 32-character MD5 hash"
        # Verify it's a valid hex string
        assert all(c in '0123456789abcdef' for c in info.ja3), \
            "JA3 should be valid hex string"
    
    @given(
        sni=valid_sni(),
        version=tls_version(),
        cipher_suites=cipher_suites_list()
    )
    @settings(max_examples=100)
    def test_record_and_handshake_lengths(self, sni, version, cipher_suites):
        """
        Test that record_len and hs_len are correctly extracted.
        
        For any valid ClientHello, parsing should extract correct lengths.
        """
        # Build ClientHello
        clienthello = build_clienthello(sni, version=version, cipher_suites=cipher_suites)
        
        # Parse
        validator = PCAPValidator()
        info = validator.parse_clienthello(clienthello)
        
        # Assert: lengths should be valid
        assert info.error is None, f"Parsing should succeed, got error: {info.error}"
        assert info.record_len > 0, "record_len should be positive"
        assert info.hs_len > 0, "hs_len should be positive"
        # Record length should be hs_len + 4 (handshake header)
        assert info.record_len == info.hs_len + 4, \
            f"record_len ({info.record_len}) should be hs_len ({info.hs_len}) + 4"
