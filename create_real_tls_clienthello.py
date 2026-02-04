#!/usr/bin/env python3
"""
Create a real TLS ClientHello packet for testing
"""

import sys
import os
import struct

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.bypass.filtering.sni_extractor import SNIExtractor
from core.bypass.engine.attack_dispatcher import AttackDispatcher
from core.bypass.techniques.primitives import BypassTechniques

def create_real_tls_clienthello(hostname: str) -> bytes:
    """
    Create a more realistic TLS ClientHello packet.
    
    Based on actual TLS 1.2 ClientHello structure.
    """
    # Encode hostname
    hostname_bytes = hostname.encode('utf-8')
    hostname_len = len(hostname_bytes)
    
    # SNI Extension (Extension Type 0x0000)
    sni_name_list = (
        b'\x00' +  # Name Type: hostname (0)
        struct.pack('>H', hostname_len) +  # Name Length
        hostname_bytes  # Name Data
    )
    
    sni_extension = (
        struct.pack('>H', 0x0000) +  # Extension Type: SNI
        struct.pack('>H', len(sni_name_list) + 2) +  # Extension Length
        struct.pack('>H', len(sni_name_list)) +  # Server Name List Length
        sni_name_list
    )
    
    # Other common extensions
    supported_groups_ext = (
        struct.pack('>H', 0x000a) +  # Extension Type: supported_groups
        struct.pack('>H', 8) +  # Extension Length
        struct.pack('>H', 6) +  # List Length
        struct.pack('>H', 0x001d) +  # x25519
        struct.pack('>H', 0x0017) +  # secp256r1
        struct.pack('>H', 0x0018)   # secp384r1
    )
    
    signature_algorithms_ext = (
        struct.pack('>H', 0x000d) +  # Extension Type: signature_algorithms
        struct.pack('>H', 6) +  # Extension Length
        struct.pack('>H', 4) +  # List Length
        struct.pack('>H', 0x0804) +  # rsa_pss_rsae_sha256
        struct.pack('>H', 0x0401)   # rsa_pkcs1_sha256
    )
    
    # Combine extensions
    extensions_data = sni_extension + supported_groups_ext + signature_algorithms_ext
    extensions = struct.pack('>H', len(extensions_data)) + extensions_data
    
    # ClientHello content
    version = struct.pack('>H', 0x0303)  # TLS 1.2
    random = b'\x01\x02\x03\x04' * 8  # 32 bytes of "random" data
    session_id_len = 0
    session_id = b''
    
    # Cipher suites (more realistic)
    cipher_suites = (
        struct.pack('>H', 6) +  # Length
        struct.pack('>H', 0x1301) +  # TLS_AES_128_GCM_SHA256
        struct.pack('>H', 0x1302) +  # TLS_AES_256_GCM_SHA384
        struct.pack('>H', 0x1303)   # TLS_CHACHA20_POLY1305_SHA256
    )
    
    # Compression methods
    compression_methods = b'\x01\x00'  # Length=1, no compression
    
    # Build ClientHello
    clienthello_data = (
        version +
        random +
        struct.pack('B', session_id_len) + session_id +
        cipher_suites +
        compression_methods +
        extensions
    )
    
    # Handshake message
    handshake_type = 0x01  # ClientHello
    handshake_length = len(clienthello_data)
    handshake = (
        struct.pack('B', handshake_type) +
        struct.pack('>I', handshake_length)[1:] +  # 3 bytes length
        clienthello_data
    )
    
    # TLS record
    record_type = 0x16  # Handshake
    record_version = struct.pack('>H', 0x0301)  # TLS 1.0 (for record layer)
    record_length = len(handshake)
    record = (
        struct.pack('B', record_type) +
        record_version +
        struct.pack('>H', record_length) +
        handshake
    )
    
    return record

def test_real_clienthello():
    """Test with a more realistic ClientHello."""
    print("=== Testing Real TLS ClientHello ===")
    
    hostname = "www.googlevideo.com"
    packet = create_real_tls_clienthello(hostname)
    
    print(f"Created packet for hostname: {hostname}")
    print(f"Packet length: {len(packet)} bytes")
    print(f"Packet hex (first 100 bytes): {packet[:100].hex()}")
    
    # Test with SNIExtractor
    extractor = SNIExtractor()
    is_clienthello = extractor.is_tls_clienthello(packet)
    print(f"Is TLS ClientHello: {is_clienthello}")
    
    if is_clienthello:
        extracted_sni = extractor.extract_sni(packet)
        print(f"Extracted SNI: {extracted_sni}")
        
        if extracted_sni == hostname:
            print("✅ SUCCESS: SNIExtractor works correctly")
        else:
            print(f"❌ FAILED: Expected '{hostname}', got '{extracted_sni}'")
    else:
        print("❌ FAILED: Packet not recognized as TLS ClientHello")
    
    # Test with AttackDispatcher
    print("\n--- Testing with AttackDispatcher ---")
    techniques = BypassTechniques()
    dispatcher = AttackDispatcher(techniques)
    
    result = dispatcher._parse_sni_extension(packet)
    if result:
        offset, extracted_hostname = result
        print(f"AttackDispatcher extracted: '{extracted_hostname}' at offset {offset}")
        
        if extracted_hostname == hostname:
            print("✅ SUCCESS: AttackDispatcher works correctly")
        else:
            print(f"❌ FAILED: Expected '{hostname}', got '{extracted_hostname}'")
    else:
        print("❌ FAILED: AttackDispatcher could not extract SNI")

def main():
    """Run the test."""
    test_real_clienthello()

if __name__ == "__main__":
    main()