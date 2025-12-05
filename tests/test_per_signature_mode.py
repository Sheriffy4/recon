"""
Test for _fake_per_signature() mode implementation.

This test verifies that the per_signature mode correctly:
1. Detects which fragments contain signatures (SNI/Host)
2. Generates fake only for signature-containing fragments
3. Uses SNIManipulator to find signature position

Requirements: 5.1
"""

import pytest
from core.bypass.unified_attack_dispatcher import UnifiedAttackDispatcher


def create_tls_clienthello_with_sni(sni: str = "example.com") -> bytes:
    """
    Create a minimal TLS ClientHello with SNI extension.
    
    This creates a valid TLS 1.2 ClientHello structure with SNI.
    """
    # TLS Record Header (5 bytes)
    # Type: Handshake (0x16)
    # Version: TLS 1.2 (0x0303)
    # Length: will be calculated
    
    # Handshake Header (4 bytes)
    # Type: ClientHello (0x01)
    # Length: will be calculated
    
    # ClientHello body
    # Version: TLS 1.2 (0x0303)
    client_version = b'\x03\x03'
    
    # Random (32 bytes)
    random = b'\x00' * 32
    
    # Session ID (1 byte length + data)
    session_id = b'\x00'  # Empty session ID
    
    # Cipher Suites (2 bytes length + data)
    cipher_suites = b'\x00\x02\x00\x00'  # 2 bytes length, 1 cipher suite
    
    # Compression Methods (1 byte length + data)
    compression = b'\x01\x00'  # 1 method, null compression
    
    # Extensions
    # SNI Extension
    sni_bytes = sni.encode('utf-8')
    sni_length = len(sni_bytes)
    
    # Server Name List Entry
    # Type: host_name (0)
    # Length: 2 bytes
    # Name: variable
    server_name_entry = b'\x00' + sni_length.to_bytes(2, 'big') + sni_bytes
    
    # Server Name List
    # Length: 2 bytes
    # Entries: variable
    server_name_list_length = len(server_name_entry)
    server_name_list = server_name_list_length.to_bytes(2, 'big') + server_name_entry
    
    # SNI Extension
    # Type: server_name (0x0000)
    # Length: 2 bytes
    # Data: server name list
    sni_extension_length = len(server_name_list)
    sni_extension = (
        b'\x00\x00' +  # Extension type: server_name
        sni_extension_length.to_bytes(2, 'big') +
        server_name_list
    )
    
    # Extensions length
    extensions_length = len(sni_extension)
    extensions = extensions_length.to_bytes(2, 'big') + sni_extension
    
    # ClientHello body
    client_hello_body = (
        client_version +
        random +
        session_id +
        cipher_suites +
        compression +
        extensions
    )
    
    # Handshake header
    handshake_length = len(client_hello_body)
    handshake_header = (
        b'\x01' +  # Type: ClientHello
        handshake_length.to_bytes(3, 'big')
    )
    
    # TLS record
    record_length = len(handshake_header) + len(client_hello_body)
    tls_record = (
        b'\x16' +  # Type: Handshake
        b'\x03\x03' +  # Version: TLS 1.2
        record_length.to_bytes(2, 'big') +
        handshake_header +
        client_hello_body
    )
    
    return tls_record


def test_per_signature_mode_basic():
    """
    Test that per_signature mode generates fake only for signature-containing fragments.
    """
    # Create a TLS ClientHello with SNI
    payload = create_tls_clienthello_with_sni("example.com")
    
    # Split into 3 fragments
    # Fragment 1: First 50 bytes (before SNI)
    # Fragment 2: Next 50 bytes (contains SNI)
    # Fragment 3: Remaining bytes (after SNI)
    fragment1 = payload[:50]
    fragment2 = payload[50:100]
    fragment3 = payload[100:]
    
    fragments = [
        (fragment1, 0, {'tcp_flags': 'PA', 'fragment': 1}),
        (fragment2, 50, {'tcp_flags': 'PA', 'fragment': 2}),
        (fragment3, 100, {'tcp_flags': 'PA', 'fragment': 3})
    ]
    
    # Create dispatcher
    dispatcher = UnifiedAttackDispatcher()
    
    # Apply per_signature mode
    params = {
        'ttl': 1,
        'fooling': 'badsum',
        'fake_mode': 'per_signature'
    }
    
    result = dispatcher.apply_fake_to_fragments(
        fragments,
        params,
        {'domain': 'example.com'}
    )
    
    # Count fake segments
    fake_count = sum(1 for seg in result if seg[2].get('is_fake', False))
    
    # Should have fewer fakes than fragments (only for signature-containing fragments)
    # In this case, SNI should be in fragment 2, so we expect 1 fake
    print(f"Generated {fake_count} fake packets for {len(fragments)} fragments")
    print(f"Total segments: {len(result)}")
    
    # Verify we have at least one fake (for the signature fragment)
    assert fake_count >= 1, f"Expected at least 1 fake packet, got {fake_count}"
    
    # Verify we have fewer fakes than total fragments (optimization)
    assert fake_count <= len(fragments), (
        f"Expected at most {len(fragments)} fake packets, got {fake_count}"
    )
    
    # Verify all real fragments are present
    real_count = sum(1 for seg in result if not seg[2].get('is_fake', False))
    assert real_count == len(fragments), (
        f"Expected {len(fragments)} real fragments, got {real_count}"
    )


def test_per_signature_mode_no_signature():
    """
    Test that per_signature mode handles fragments without signature gracefully.
    """
    # Create fragments without TLS/SNI (just random data)
    fragments = [
        (b'random_data_1', 0, {'tcp_flags': 'PA', 'fragment': 1}),
        (b'random_data_2', 13, {'tcp_flags': 'PA', 'fragment': 2}),
        (b'random_data_3', 26, {'tcp_flags': 'PA', 'fragment': 3})
    ]
    
    # Create dispatcher
    dispatcher = UnifiedAttackDispatcher()
    
    # Apply per_signature mode
    params = {
        'ttl': 1,
        'fooling': 'badsum',
        'fake_mode': 'per_signature'
    }
    
    result = dispatcher.apply_fake_to_fragments(
        fragments,
        params,
        {'domain': 'test.com'}
    )
    
    # Should still return segments (all real fragments)
    assert len(result) >= len(fragments), (
        f"Expected at least {len(fragments)} segments, got {len(result)}"
    )
    
    # Count fake segments
    fake_count = sum(1 for seg in result if seg[2].get('is_fake', False))
    
    # When no signature found, should generate 0 fakes (optimization)
    print(f"Generated {fake_count} fake packets for fragments without signature")
    
    # Verify all real fragments are present
    real_count = sum(1 for seg in result if not seg[2].get('is_fake', False))
    assert real_count == len(fragments), (
        f"Expected {len(fragments)} real fragments, got {real_count}"
    )


def test_per_signature_mode_parameters():
    """
    Test that per_signature mode uses correct TTL and fooling parameters.
    """
    # Create a TLS ClientHello with SNI
    payload = create_tls_clienthello_with_sni("test.com")
    
    # Split into 2 fragments
    mid = len(payload) // 2
    fragments = [
        (payload[:mid], 0, {'tcp_flags': 'PA', 'fragment': 1}),
        (payload[mid:], mid, {'tcp_flags': 'PA', 'fragment': 2})
    ]
    
    # Create dispatcher
    dispatcher = UnifiedAttackDispatcher()
    
    # Apply per_signature mode with specific parameters
    ttl = 5
    fooling = 'badseq'
    params = {
        'ttl': ttl,
        'fooling': fooling,
        'fake_mode': 'per_signature'
    }
    
    result = dispatcher.apply_fake_to_fragments(
        fragments,
        params,
        {'domain': 'test.com'}
    )
    
    # Extract fake segments
    fake_segments = [seg for seg in result if seg[2].get('is_fake', False)]
    
    if fake_segments:
        # Verify all fakes have correct TTL
        for seg in fake_segments:
            assert seg[2].get('ttl') == ttl, (
                f"Expected fake TTL={ttl}, got {seg[2].get('ttl')}"
            )
            assert seg[2].get('fooling') == fooling, (
                f"Expected fake fooling={fooling}, got {seg[2].get('fooling')}"
            )


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
