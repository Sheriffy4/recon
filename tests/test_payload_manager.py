"""
Property-based tests for PayloadManager.

Tests the correctness properties defined in the design document for
the fake-payload-generation feature.

**Feature: fake-payload-generation, Property 3: File Loading Consistency**
"""

import pytest
import tempfile
import shutil
from contextlib import contextmanager
from pathlib import Path
from hypothesis import given, strategies as st, settings, assume

from core.payload.manager import PayloadManager
from core.payload.types import PayloadType, PayloadInfo


def create_valid_tls_clienthello(random_bytes: bytes) -> bytes:
    """
    Create a valid TLS ClientHello structure with random content.
    
    Structure:
    - Byte 0: 0x16 (Handshake)
    - Bytes 1-2: 0x03 0x01 (TLS 1.0 version)
    - Bytes 3-4: Length (big-endian)
    - Byte 5: 0x01 (ClientHello handshake type)
    - Rest: random content
    """
    # Minimum content after header
    content = random_bytes if len(random_bytes) >= 38 else random_bytes + bytes(38 - len(random_bytes))
    
    # Build TLS record
    # Handshake content: type (1) + length (3) + content
    handshake_length = len(content)
    handshake = bytes([0x01]) + handshake_length.to_bytes(3, 'big') + content
    
    # TLS record: type (1) + version (2) + length (2) + handshake
    record_length = len(handshake)
    tls_record = bytes([0x16, 0x03, 0x01]) + record_length.to_bytes(2, 'big') + handshake
    
    return tls_record


@contextmanager
def temp_payload_dirs():
    """Context manager for temporary payload directories."""
    temp_dir = tempfile.mkdtemp()
    payload_dir = Path(temp_dir) / "captured"
    bundled_dir = Path(temp_dir) / "bundled"
    payload_dir.mkdir(parents=True)
    bundled_dir.mkdir(parents=True)
    
    try:
        yield payload_dir, bundled_dir
    finally:
        shutil.rmtree(temp_dir)


class TestFileLoadingConsistency:
    """
    Property-based tests for file loading consistency.
    
    **Feature: fake-payload-generation, Property 3: File Loading Consistency**
    **Validates: Requirements 1.1, 4.1**
    
    Property: For any payload file loaded from disk, the loaded bytes MUST 
    match the file content exactly (no corruption during load).
    """
    
    @given(random_content=st.binary(min_size=38, max_size=500))
    @settings(max_examples=100)
    def test_file_loading_preserves_bytes(self, random_content):
        """
        **Feature: fake-payload-generation, Property 3: File Loading Consistency**
        **Validates: Requirements 1.1, 4.1**
        
        Property: For any payload file loaded from disk, the loaded bytes MUST 
        match the file content exactly.
        """
        with temp_payload_dirs() as (payload_dir, bundled_dir):
            # Create valid TLS ClientHello with random content
            payload_bytes = create_valid_tls_clienthello(random_content)
            
            # Write to file
            test_file = bundled_dir / "tls_clienthello_test_domain_com.bin"
            test_file.write_bytes(payload_bytes)
            
            # Create manager and load
            manager = PayloadManager(payload_dir=payload_dir, bundled_dir=bundled_dir)
            loaded_count = manager.load_all()
            
            # Should have loaded at least one payload
            assert loaded_count >= 1, "Should load at least one payload"
            
            # Get the loaded payload
            loaded_payload = manager.get_payload(PayloadType.TLS, "test.domain.com")
            
            # Loaded bytes must match exactly
            assert loaded_payload == payload_bytes, (
                f"Loaded payload differs from file content. "
                f"Original: {len(payload_bytes)} bytes, Loaded: {len(loaded_payload) if loaded_payload else 0} bytes"
            )

    @given(random_content=st.binary(min_size=38, max_size=500))
    @settings(max_examples=100)
    def test_add_payload_roundtrip(self, random_content):
        """
        **Feature: fake-payload-generation, Property 3: File Loading Consistency**
        **Validates: Requirements 1.1, 4.1**
        
        Property: Adding a payload and then loading it back MUST preserve
        the exact bytes.
        """
        with temp_payload_dirs() as (payload_dir, bundled_dir):
            # Create valid TLS ClientHello
            payload_bytes = create_valid_tls_clienthello(random_content)
            
            # Create manager
            manager = PayloadManager(payload_dir=payload_dir, bundled_dir=bundled_dir)
            
            # Add payload
            info = manager.add_payload(
                data=payload_bytes,
                payload_type=PayloadType.TLS,
                domain="roundtrip.test.com",
                source="captured"
            )
            
            # Verify file was created
            assert info.file_path is not None
            assert info.file_path.exists()
            
            # Read file directly and compare
            file_content = info.file_path.read_bytes()
            assert file_content == payload_bytes, "File content must match original payload"
            
            # Create new manager and load
            manager2 = PayloadManager(payload_dir=payload_dir, bundled_dir=bundled_dir)
            manager2.load_all()
            
            # Get payload back
            loaded = manager2.get_payload(PayloadType.TLS, "roundtrip.test.com")
            assert loaded == payload_bytes, "Loaded payload must match original"
    
    @given(
        content1=st.binary(min_size=38, max_size=200),
        content2=st.binary(min_size=38, max_size=200)
    )
    @settings(max_examples=50)
    def test_multiple_files_loaded_correctly(self, content1, content2):
        """
        **Feature: fake-payload-generation, Property 3: File Loading Consistency**
        **Validates: Requirements 1.1, 4.1**
        
        Property: Multiple payload files loaded from disk MUST each match
        their respective file contents exactly.
        """
        # Ensure different content
        assume(content1 != content2)
        
        with temp_payload_dirs() as (payload_dir, bundled_dir):
            # Create two different payloads
            payload1 = create_valid_tls_clienthello(content1)
            payload2 = create_valid_tls_clienthello(content2)
            
            # Write to files with different domains
            file1 = bundled_dir / "tls_clienthello_domain1_com.bin"
            file2 = bundled_dir / "tls_clienthello_domain2_com.bin"
            file1.write_bytes(payload1)
            file2.write_bytes(payload2)
            
            # Load all
            manager = PayloadManager(payload_dir=payload_dir, bundled_dir=bundled_dir)
            loaded_count = manager.load_all()
            
            assert loaded_count >= 2, "Should load at least 2 payloads"
            
            # Each loaded payload must match its file
            loaded1 = manager.get_payload(PayloadType.TLS, "domain1.com")
            loaded2 = manager.get_payload(PayloadType.TLS, "domain2.com")
            
            assert loaded1 == payload1, "First payload must match"
            assert loaded2 == payload2, "Second payload must match"


class TestPayloadManagerBasicOperations:
    """Unit tests for basic PayloadManager operations."""
    
    def test_empty_directories_returns_zero(self):
        """Test that empty directories return zero payloads."""
        with temp_payload_dirs() as (payload_dir, bundled_dir):
            manager = PayloadManager(payload_dir=payload_dir, bundled_dir=bundled_dir)
            count = manager.load_all()
            
            assert count == 0
            assert len(manager) == 0
    
    def test_get_default_payload_returns_zeros(self):
        """Test that default payload is zeros of correct size."""
        with temp_payload_dirs() as (payload_dir, bundled_dir):
            manager = PayloadManager(payload_dir=payload_dir, bundled_dir=bundled_dir)
            default = manager.get_default_payload(PayloadType.TLS)
            
            assert len(default) == 1400  # DEFAULT_PAYLOAD_SIZE
            assert default == bytes(1400)
    
    def test_get_payload_returns_none_when_empty(self):
        """Test that get_payload returns None when no payloads loaded."""
        with temp_payload_dirs() as (payload_dir, bundled_dir):
            manager = PayloadManager(payload_dir=payload_dir, bundled_dir=bundled_dir)
            manager.load_all()
            
            result = manager.get_payload(PayloadType.TLS, "nonexistent.com")
            assert result is None
    
    def test_cdn_mapping_googlevideo(self):
        """Test CDN domain mapping for googlevideo.com."""
        with temp_payload_dirs() as (payload_dir, bundled_dir):
            # Create google.com payload
            google_payload = create_valid_tls_clienthello(b"google content here")
            google_file = bundled_dir / "tls_clienthello_www_google_com.bin"
            google_file.write_bytes(google_payload)
            
            manager = PayloadManager(payload_dir=payload_dir, bundled_dir=bundled_dir)
            manager.load_all()
            
            # Request for googlevideo.com should return google.com payload
            result = manager.get_payload_for_cdn("googlevideo.com")
            assert result == google_payload
    
    def test_list_payloads_filters_by_type(self):
        """Test that list_payloads filters by type correctly."""
        with temp_payload_dirs() as (payload_dir, bundled_dir):
            # Create TLS payload
            tls_payload = create_valid_tls_clienthello(b"tls content")
            tls_file = bundled_dir / "tls_clienthello_example_com.bin"
            tls_file.write_bytes(tls_payload)
            
            manager = PayloadManager(payload_dir=payload_dir, bundled_dir=bundled_dir)
            manager.load_all()
            
            # List TLS payloads
            tls_list = manager.list_payloads(PayloadType.TLS)
            assert len(tls_list) >= 1
            assert all(p.payload_type == PayloadType.TLS for p in tls_list)
            
            # List HTTP payloads (should be empty)
            http_list = manager.list_payloads(PayloadType.HTTP)
            assert len(http_list) == 0
    
    def test_resolve_placeholder_tls(self):
        """Test placeholder resolution for PAYLOADTLS."""
        with temp_payload_dirs() as (payload_dir, bundled_dir):
            # Create TLS payload
            tls_payload = create_valid_tls_clienthello(b"placeholder test")
            tls_file = bundled_dir / "tls_clienthello_test_com.bin"
            tls_file.write_bytes(tls_payload)
            
            manager = PayloadManager(payload_dir=payload_dir, bundled_dir=bundled_dir)
            manager.load_all()
            
            # Resolve placeholder
            result = manager.resolve_placeholder("PAYLOADTLS")
            assert result == tls_payload
    
    def test_resolve_placeholder_returns_default_when_empty(self):
        """Test placeholder resolution returns default when no payloads."""
        with temp_payload_dirs() as (payload_dir, bundled_dir):
            manager = PayloadManager(payload_dir=payload_dir, bundled_dir=bundled_dir)
            manager.load_all()
            
            # Resolve placeholder should return default
            result = manager.resolve_placeholder("PAYLOADTLS")
            assert result == bytes(1400)  # Default payload
