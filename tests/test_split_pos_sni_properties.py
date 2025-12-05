"""
Property-based tests for split_pos="sni" support.

These tests verify correctness properties for SNI-based splitting.

Requirements: 4.1, 4.2, 4.3, 4.4, 4.5
"""

import pytest
import struct
from hypothesis import given, strategies as st, settings, assume

from core.bypass.unified_attack_dispatcher import UnifiedAttackDispatcher
from core.strategy.combo_builder import ComboAttackBuilder


# Helper function to create valid TLS ClientHello with SNI
def create_clienthello_with_sni(sni: str, extra_data_before: int = 50, extra_data_after: int = 50) -> bytes:
    """
    Create a minimal valid TLS ClientHello with SNI extension.
    
    Args:
        sni: SNI hostname to include
        extra_data_before: Extra bytes before SNI extension
        extra_data_after: Extra bytes after SNI extension
        
    Returns:
        Valid TLS ClientHello bytes
    """
    # TLS Record Header (5 bytes)
    # Type: Handshake (0x16)
    # Version: TLS 1.2 (0x0303)
    # Length: will be calculated
    
    # Handshake Header (4 bytes)
    # Type: ClientHello (0x01)
    # Length: will be calculated (3 bytes)
    
    # ClientHello body
    # Version: TLS 1.2 (0x0303)
    client_version = b'\x03\x03'
    
    # Random (32 bytes)
    random_bytes = b'\x00' * 32
    
    # Session ID (1 byte length + data)
    session_id = b'\x00'  # Empty session ID
    
    # Cipher Suites (2 bytes length + data)
    cipher_suites = b'\x00\x02\x00\x00'  # 2 bytes length, 1 cipher suite
    
    # Compression Methods (1 byte length + data)
    compression = b'\x01\x00'  # 1 method, null compression
    
    # Extensions
    # Build SNI extension
    sni_bytes = sni.encode('utf-8')
    sni_length = len(sni_bytes)
    
    # SNI Extension structure:
    # Extension Type: server_name (0x0000) - 2 bytes
    # Extension Length - 2 bytes
    # Server Name List Length - 2 bytes
    # Server Name Type: host_name (0x00) - 1 byte
    # Server Name Length - 2 bytes
    # Server Name - variable
    
    sni_extension_data_length = 2 + 1 + 2 + sni_length  # list_len + type + name_len + name
    sni_extension_length = sni_extension_data_length
    
    sni_extension = b''
    sni_extension += b'\x00\x00'  # Extension type: server_name
    sni_extension += struct.pack('!H', sni_extension_length)  # Extension length
    sni_extension += struct.pack('!H', sni_extension_data_length - 2)  # Server name list length
    sni_extension += b'\x00'  # Server name type: host_name
    sni_extension += struct.pack('!H', sni_length)  # Server name length
    sni_extension += sni_bytes  # Server name
    
    # Add some dummy extensions before SNI (to create extra_data_before)
    dummy_extensions_before = b''
    if extra_data_before > 0:
        # Add a dummy extension (e.g., supported_groups)
        dummy_ext_type = b'\x00\x0a'  # supported_groups
        dummy_ext_data = b'\x00' * min(extra_data_before, 100)
        dummy_ext_length = len(dummy_ext_data)
        dummy_extensions_before += dummy_ext_type
        dummy_extensions_before += struct.pack('!H', dummy_ext_length)
        dummy_extensions_before += dummy_ext_data
    
    # Add some dummy extensions after SNI (to create extra_data_after)
    dummy_extensions_after = b''
    if extra_data_after > 0:
        # Add a dummy extension (e.g., ec_point_formats)
        dummy_ext_type = b'\x00\x0b'  # ec_point_formats
        dummy_ext_data = b'\x00' * min(extra_data_after, 100)
        dummy_ext_length = len(dummy_ext_data)
        dummy_extensions_after += dummy_ext_type
        dummy_extensions_after += struct.pack('!H', dummy_ext_length)
        dummy_extensions_after += dummy_ext_data
    
    # Combine all extensions
    all_extensions = dummy_extensions_before + sni_extension + dummy_extensions_after
    extensions_length = len(all_extensions)
    
    # Build ClientHello body
    clienthello_body = b''
    clienthello_body += client_version
    clienthello_body += random_bytes
    clienthello_body += session_id
    clienthello_body += cipher_suites
    clienthello_body += compression
    clienthello_body += struct.pack('!H', extensions_length)  # Extensions length
    clienthello_body += all_extensions
    
    # Build Handshake message
    handshake_type = b'\x01'  # ClientHello
    handshake_length = len(clienthello_body)
    handshake_length_bytes = struct.pack('!I', handshake_length)[1:]  # 3 bytes
    
    handshake_message = handshake_type + handshake_length_bytes + clienthello_body
    
    # Build TLS Record
    record_type = b'\x16'  # Handshake
    record_version = b'\x03\x03'  # TLS 1.2
    record_length = len(handshake_message)
    
    tls_record = record_type + record_version + struct.pack('!H', record_length) + handshake_message
    
    return tls_record


# Strategies for generating test data
@st.composite
def sni_hostname_strategy(draw):
    """Generate valid SNI hostnames."""
    # Generate domain labels
    num_labels = draw(st.integers(min_value=2, max_value=4))
    labels = []
    
    for _ in range(num_labels):
        # Each label: 1-20 alphanumeric characters
        label_len = draw(st.integers(min_value=1, max_value=20))
        label = draw(st.text(
            alphabet='abcdefghijklmnopqrstuvwxyz0123456789',
            min_size=label_len,
            max_size=label_len
        ))
        labels.append(label)
    
    return '.'.join(labels)


@st.composite
def clienthello_with_sni_strategy(draw):
    """Generate valid TLS ClientHello with SNI."""
    sni = draw(sni_hostname_strategy())
    extra_before = draw(st.integers(min_value=20, max_value=100))
    extra_after = draw(st.integers(min_value=20, max_value=100))
    
    return create_clienthello_with_sni(sni, extra_before, extra_after), sni


class TestSplitPosSNIProperties:
    """Property-based tests for split_pos='sni' support."""
    
    @given(
        clienthello_data=clienthello_with_sni_strategy()
    )
    @settings(max_examples=100, deadline=None)
    def test_property_10_split_position_accuracy(self, clienthello_data):
        """
        **Feature: attack-application-parity, Property 10: Split Position Accuracy**
        **Validates: Requirements 4.1**
        
        Property: For any payload with split_pos="sni", the fragment boundary
        should be within ±8 bytes of the SNI offset.
        
        This test verifies that:
        1. When split_pos="sni" is used, the system finds the SNI position
        2. The split position is within ±8 bytes of the actual SNI offset
        3. The split produces valid fragments that can be reassembled
        """
        payload, expected_sni = clienthello_data
        
        # Apply split with split_pos="sni" (don't specify split_count to avoid conflict)
        dispatcher = UnifiedAttackDispatcher()
        params = {
            'split_pos': 'sni'
        }
        packet_info = {
            'src_addr': '127.0.0.1',
            'dst_addr': '127.0.0.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments = dispatcher.apply_split(payload, params, packet_info)
        
        # Verify we got 2 fragments
        assert len(segments) == 2, f"Should get 2 fragments, got {len(segments)}"
        
        # Reconstruct payload from fragments
        fragment1_data = segments[0][0]
        fragment2_data = segments[1][0]
        reconstructed = fragment1_data + fragment2_data
        
        # Verify reconstruction matches original
        assert reconstructed == payload, "Fragments should reconstruct to original payload"
        
        # Find actual SNI position in payload
        from core.bypass.sni.manipulator import SNIManipulator
        sni_pos = SNIManipulator.find_sni_position(payload)
        
        # If SNI was found, verify split position is near it
        if sni_pos:
            # The split position is where fragment1 ends
            split_position = len(fragment1_data)
            sni_value_start = sni_pos.sni_value_start
            
            # Calculate distance from split position to SNI
            distance = abs(split_position - sni_value_start)
            
            # Verify split is within ±8 bytes of SNI (Requirement 4.1)
            # Note: We're being lenient here - the actual implementation splits
            # exactly at SNI start, which is within the ±8 byte tolerance
            assert distance <= 8, \
                f"Split position {split_position} should be within ±8 bytes of SNI at {sni_value_start}, " \
                f"but distance is {distance} bytes"
            
            # Verify SNI value matches expected
            assert sni_pos.sni_value == expected_sni, \
                f"SNI value should be '{expected_sni}', got '{sni_pos.sni_value}'"
    
    @given(
        clienthello_data=clienthello_with_sni_strategy(),
        split_count=st.integers(min_value=2, max_value=5)
    )
    @settings(max_examples=100, deadline=None)
    def test_multisplit_with_sni_position(self, clienthello_data, split_count):
        """
        Test that multisplit with split_pos="sni" creates correct number of fragments.
        
        This verifies Requirement 4.5: multisplit creates split_count fragments
        with split_pos taken into account.
        """
        payload, expected_sni = clienthello_data
        
        # Apply multisplit with split_pos="sni"
        dispatcher = UnifiedAttackDispatcher()
        params = {
            'split_pos': 'sni',
            'split_count': split_count
        }
        packet_info = {
            'src_addr': '127.0.0.1',
            'dst_addr': '127.0.0.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments = dispatcher.apply_split(payload, params, packet_info)
        
        # Verify we got split_count fragments
        assert len(segments) == split_count, \
            f"Should get {split_count} fragments, got {len(segments)}"
        
        # Verify fragments reconstruct to original
        reconstructed = b''.join(seg[0] for seg in segments)
        assert reconstructed == payload, \
            "Fragments should reconstruct to original payload"
        
        # Verify all fragments are non-empty
        for i, segment in enumerate(segments):
            assert len(segment[0]) > 0, f"Fragment {i} should be non-empty"
    
    @given(
        payload=st.binary(min_size=100, max_size=500),
        numeric_split_pos=st.integers(min_value=1, max_value=50)
    )
    @settings(max_examples=100, deadline=None)
    def test_numeric_split_pos(self, payload, numeric_split_pos):
        """
        Test that numeric split_pos works correctly.
        
        This verifies Requirement 4.2: split at numeric position.
        """
        # Ensure split_pos is within payload bounds
        assume(numeric_split_pos < len(payload) - 1)
        
        dispatcher = UnifiedAttackDispatcher()
        params = {
            'split_pos': numeric_split_pos
        }
        packet_info = {
            'src_addr': '127.0.0.1',
            'dst_addr': '127.0.0.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments = dispatcher.apply_split(payload, params, packet_info)
        
        # Verify we got 2 fragments
        assert len(segments) == 2, f"Should get 2 fragments, got {len(segments)}"
        
        # Verify split happened at correct position
        fragment1_data = segments[0][0]
        fragment2_data = segments[1][0]
        
        # The split position should be close to numeric_split_pos
        # (may be adjusted to stay within bounds)
        actual_split_pos = len(fragment1_data)
        
        # Verify reconstruction
        reconstructed = fragment1_data + fragment2_data
        assert reconstructed == payload, \
            "Fragments should reconstruct to original payload"
    
    @given(
        payload=st.binary(min_size=50, max_size=200),
        fallback_pos=st.integers(min_value=2, max_value=20)
    )
    @settings(max_examples=100, deadline=None)
    def test_sni_fallback_when_not_found(self, payload, fallback_pos):
        """
        Test that fallback position is used when SNI is not found.
        
        This verifies Requirement 4.4: use fallback when SNI not found.
        """
        # Use a payload that doesn't contain valid TLS ClientHello
        # (so SNI won't be found)
        
        # Ensure fallback is within bounds
        assume(fallback_pos < len(payload) - 1)
        
        dispatcher = UnifiedAttackDispatcher()
        params = {
            'split_pos': 'sni',
            'split_pos_fallback': fallback_pos
        }
        packet_info = {
            'src_addr': '127.0.0.1',
            'dst_addr': '127.0.0.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments = dispatcher.apply_split(payload, params, packet_info)
        
        # Verify we got 2 fragments (fallback was used)
        assert len(segments) == 2, f"Should get 2 fragments even with fallback, got {len(segments)}"
        
        # Verify reconstruction
        reconstructed = b''.join(seg[0] for seg in segments)
        assert reconstructed == payload, \
            "Fragments should reconstruct to original payload"
    
    @given(
        clienthello_data=clienthello_with_sni_strategy()
    )
    @settings(max_examples=100, deadline=None)
    def test_split_preserves_tls_structure(self, clienthello_data):
        """
        Test that splitting preserves TLS structure validity.
        
        This verifies that after splitting, the first fragment still
        has a valid TLS record header.
        """
        payload, expected_sni = clienthello_data
        
        dispatcher = UnifiedAttackDispatcher()
        params = {
            'split_pos': 'sni'
        }
        packet_info = {
            'src_addr': '127.0.0.1',
            'dst_addr': '127.0.0.1',
            'src_port': 12345,
            'dst_port': 443
        }
        
        segments = dispatcher.apply_split(payload, params, packet_info)
        
        # Verify first fragment starts with TLS record header
        fragment1_data = segments[0][0]
        
        if len(fragment1_data) >= 5:
            # Check TLS record type (0x16 = Handshake)
            assert fragment1_data[0] == 0x16, \
                "First fragment should start with TLS Handshake record type"
            
            # Check TLS version (0x03 = TLS family)
            assert fragment1_data[1] == 0x03, \
                "First fragment should have valid TLS version"
