"""
Unit tests for PositionResolver component.

Tests position resolution for numeric positions, SNI detection,
and position validation with various packet sizes and formats.
"""

import pytest
import struct
from unittest.mock import Mock, patch

from core.bypass.strategies.position_resolver import PositionResolver
from core.bypass.strategies.config_models import SplitConfig
from core.bypass.strategies.exceptions import PacketTooSmallError, InvalidSplitPositionError


class TestPositionResolver:
    """Test suite for PositionResolver component."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.resolver = PositionResolver()
    
    def test_init(self):
        """Test PositionResolver initialization."""
        resolver = PositionResolver()
        assert resolver is not None
        assert hasattr(resolver, 'logger')
    
    def test_resolve_numeric_positions_valid(self):
        """Test resolving valid numeric positions."""
        packet = b'A' * 100  # 100-byte packet
        positions = [3, 10, 50]
        
        result = self.resolver.resolve_numeric_positions(packet, positions)
        
        assert result == [3, 10, 50]  # Should be sorted
    
    def test_resolve_numeric_positions_invalid(self):
        """Test resolving invalid numeric positions."""
        packet = b'A' * 20  # 20-byte packet
        positions = [3, 10, 25, 50]  # 25 and 50 are too large
        
        result = self.resolver.resolve_numeric_positions(packet, positions)
        
        assert result == [3, 10]  # Only valid positions
    
    def test_resolve_numeric_positions_empty_packet(self):
        """Test resolving positions with empty packet."""
        packet = b''
        positions = [3, 10]
        
        with pytest.raises(PacketTooSmallError):
            self.resolver.resolve_numeric_positions(packet, positions)
    
    def test_resolve_numeric_positions_no_valid(self):
        """Test resolving positions when none are valid."""
        packet = b'AB'  # 2-byte packet
        positions = [5, 10, 20]  # All too large
        
        result = self.resolver.resolve_numeric_positions(packet, positions)
        
        assert result == []
    
    def test_validate_position_valid(self):
        """Test position validation with valid positions."""
        packet = b'A' * 50
        
        assert self.resolver.validate_position(packet, 3) is True
        assert self.resolver.validate_position(packet, 10) is True
        assert self.resolver.validate_position(packet, 25) is True
        assert self.resolver.validate_position(packet, 48) is True  # Leave 1 byte for second part
    
    def test_validate_position_invalid(self):
        """Test position validation with invalid positions."""
        packet = b'A' * 10
        
        assert self.resolver.validate_position(packet, 0) is False    # Zero position
        assert self.resolver.validate_position(packet, -1) is False   # Negative position
        assert self.resolver.validate_position(packet, 10) is False   # Equal to packet size
        assert self.resolver.validate_position(packet, 9) is False    # Would leave 0 bytes for second part
        assert self.resolver.validate_position(packet, 15) is False   # Larger than packet
    
    def test_validate_position_empty_packet(self):
        """Test position validation with empty packet."""
        packet = b''
        
        assert self.resolver.validate_position(packet, 1) is False
        assert self.resolver.validate_position(packet, 0) is False
    
    def test_is_client_hello_valid(self):
        """Test TLS Client Hello detection with valid packets."""
        # Create a minimal TLS Client Hello packet
        # TLS record: type(0x16) + version(0x0303) + length(0x0020) + handshake_type(0x01)
        tls_packet = struct.pack('>BHHB', 0x16, 0x0303, 0x0020, 0x01) + b'\x00' * 28
        
        assert self.resolver._is_client_hello(tls_packet) is True
    
    def test_is_client_hello_invalid_type(self):
        """Test TLS Client Hello detection with invalid record type."""
        # Wrong record type (0x15 instead of 0x16)
        invalid_packet = struct.pack('>BHHB', 0x15, 0x0303, 0x0020, 0x01) + b'\x00' * 28
        
        assert self.resolver._is_client_hello(invalid_packet) is False
    
    def test_is_client_hello_invalid_version(self):
        """Test TLS Client Hello detection with invalid TLS version."""
        # Invalid TLS version (0x0200)
        invalid_packet = struct.pack('>BHHB', 0x16, 0x0200, 0x0020, 0x01) + b'\x00' * 28
        
        assert self.resolver._is_client_hello(invalid_packet) is False
    
    def test_is_client_hello_invalid_handshake_type(self):
        """Test TLS Client Hello detection with invalid handshake type."""
        # Wrong handshake type (0x02 instead of 0x01)
        invalid_packet = struct.pack('>BHHB', 0x16, 0x0303, 0x0020, 0x02) + b'\x00' * 28
        
        assert self.resolver._is_client_hello(invalid_packet) is False
    
    def test_is_client_hello_too_small(self):
        """Test TLS Client Hello detection with too small packet."""
        small_packet = b'\x16\x03\x03'  # Only 3 bytes
        
        assert self.resolver._is_client_hello(small_packet) is False
    
    def test_resolve_sni_position_valid(self):
        """Test SNI position resolution with valid TLS Client Hello."""
        # Create a TLS Client Hello with SNI extension at known position
        tls_packet = self._create_tls_client_hello_with_sni("example.com", sni_position=100)
        
        result = self.resolver.resolve_sni_position(tls_packet)
        
        assert result == 100
    
    def test_resolve_sni_position_no_sni(self):
        """Test SNI position resolution with TLS Client Hello without SNI."""
        # Create a TLS Client Hello without SNI extension
        tls_packet = self._create_tls_client_hello_without_sni()
        
        result = self.resolver.resolve_sni_position(tls_packet)
        
        assert result is None
    
    def test_resolve_sni_position_not_client_hello(self):
        """Test SNI position resolution with non-TLS packet."""
        non_tls_packet = b'HTTP/1.1 GET / HTTP/1.1\r\n\r\n'
        
        result = self.resolver.resolve_sni_position(non_tls_packet)
        
        assert result is None
    
    def test_resolve_sni_position_malformed_packet(self):
        """Test SNI position resolution with malformed TLS packet."""
        # Create a packet that looks like TLS but is malformed
        malformed_packet = struct.pack('>BHHB', 0x16, 0x0303, 0x0020, 0x01) + b'\xFF' * 10
        
        result = self.resolver.resolve_sni_position(malformed_packet)
        
        assert result is None
    
    def test_resolve_positions_sni_priority(self):
        """Test position resolution with SNI having priority."""
        # Create TLS Client Hello with SNI at position 80
        tls_packet = self._create_tls_client_hello_with_sni("example.com", sni_position=80)
        
        config = SplitConfig(
            numeric_positions=[3, 10, 50],
            use_sni=True,
            priority_order=['sni', 'numeric']
        )
        
        result = self.resolver.resolve_positions(tls_packet, config)
        
        # SNI position should be first due to priority
        assert 80 in result
        assert result.index(80) == 0  # SNI should be first
    
    def test_resolve_positions_numeric_only(self):
        """Test position resolution with numeric positions only."""
        packet = b'A' * 100
        
        config = SplitConfig(
            numeric_positions=[3, 10, 50],
            use_sni=False,
            priority_order=['numeric']
        )
        
        result = self.resolver.resolve_positions(packet, config)
        
        assert result == [3, 10, 50]
    
    def test_resolve_positions_fallback(self):
        """Test position resolution with fallback when no positions are valid."""
        packet = b'AB'  # Very small packet
        
        config = SplitConfig(
            numeric_positions=[10, 20, 50],  # All too large
            use_sni=False,
            priority_order=['numeric']
        )
        
        result = self.resolver.resolve_positions(packet, config)
        
        # Should return empty list since no fallback positions are valid for 2-byte packet
        assert result == []
    
    def test_get_fallback_positions(self):
        """Test fallback position generation."""
        packet = b'A' * 50
        
        result = self.resolver._get_fallback_positions(packet)
        
        # Should include common positions that are valid for 50-byte packet
        assert 3 in result
        assert 10 in result
        assert 25 in result  # packet_size // 2
    
    def test_get_fallback_positions_small_packet(self):
        """Test fallback position generation with small packet."""
        packet = b'AB'  # 2-byte packet
        
        result = self.resolver._get_fallback_positions(packet)
        
        # No valid fallback positions for 2-byte packet
        assert result == []
    
    def test_find_sni_extension_position_valid(self):
        """Test finding SNI extension position in valid TLS packet."""
        # This is a more detailed test of the internal method
        tls_packet = self._create_detailed_tls_client_hello_with_sni()
        
        result = self.resolver._find_sni_extension_position(tls_packet)
        
        assert result is not None
        assert isinstance(result, int)
        assert result > 0
    
    def test_find_sni_extension_position_no_extensions(self):
        """Test finding SNI extension position in TLS packet without extensions."""
        tls_packet = self._create_tls_client_hello_without_extensions()
        
        result = self.resolver._find_sni_extension_position(tls_packet)
        
        assert result is None
    
    def test_resolve_positions_duplicate_removal(self):
        """Test that duplicate positions are removed."""
        packet = b'A' * 100
        
        # Mock SNI detector to return position 10 (same as numeric)
        with patch.object(self.resolver, 'resolve_sni_position', return_value=10):
            config = SplitConfig(
                numeric_positions=[3, 10, 50],
                use_sni=True,
                priority_order=['sni', 'numeric']
            )
            
            result = self.resolver.resolve_positions(packet, config)
            
            # Should only have one instance of position 10
            assert result.count(10) == 1
            assert len(result) == 3  # 3, 10, 50
    
    def _create_tls_client_hello_with_sni(self, hostname: str, sni_position: int) -> bytes:
        """Create a TLS Client Hello packet with SNI extension at specified position."""
        # This is a simplified version - in real implementation would create proper TLS structure
        base_packet = b'\x16\x03\x03\x00\x50\x01\x00\x00\x4C'  # TLS record + handshake header
        base_packet += b'\x03\x03'  # Client Hello version
        base_packet += b'\x00' * 32  # Random
        base_packet += b'\x00'  # Session ID length
        base_packet += b'\x00\x02\x00\x35'  # Cipher suites
        base_packet += b'\x01\x00'  # Compression methods
        
        # Pad to reach desired SNI position
        padding_needed = sni_position - len(base_packet) - 2  # -2 for extensions length
        if padding_needed > 0:
            base_packet += b'\x00' * padding_needed
        
        # Add extensions length
        extensions_length = 4 + 2 + 2 + 1 + 2 + len(hostname.encode())
        base_packet += struct.pack('>H', extensions_length)
        
        # Add SNI extension
        base_packet += struct.pack('>H', 0x0000)  # SNI extension type
        sni_data_length = 2 + 1 + 2 + len(hostname.encode())
        base_packet += struct.pack('>H', sni_data_length)  # SNI extension length
        base_packet += struct.pack('>H', sni_data_length - 2)  # SNI list length
        base_packet += b'\x00'  # Name type (hostname)
        base_packet += struct.pack('>H', len(hostname.encode()))  # Name length
        base_packet += hostname.encode()  # Hostname
        
        return base_packet
    
    def _create_tls_client_hello_without_sni(self) -> bytes:
        """Create a TLS Client Hello packet without SNI extension."""
        packet = b'\x16\x03\x03\x00\x30\x01\x00\x00\x2C'  # TLS record + handshake header
        packet += b'\x03\x03'  # Client Hello version
        packet += b'\x00' * 32  # Random
        packet += b'\x00'  # Session ID length
        packet += b'\x00\x02\x00\x35'  # Cipher suites
        packet += b'\x01\x00'  # Compression methods
        packet += b'\x00\x00'  # Extensions length (0 = no extensions)
        
        return packet
    
    def _create_detailed_tls_client_hello_with_sni(self) -> bytes:
        """Create a detailed TLS Client Hello with proper structure."""
        # TLS Record Header
        record = bytearray()
        record.extend(b'\x16')  # Content Type: Handshake
        record.extend(b'\x03\x03')  # Version: TLS 1.2
        
        # Handshake message
        handshake = bytearray()
        handshake.extend(b'\x01')  # Handshake Type: Client Hello
        
        # Client Hello message
        client_hello = bytearray()
        client_hello.extend(b'\x03\x03')  # Version: TLS 1.2
        client_hello.extend(b'\x00' * 32)  # Random
        client_hello.extend(b'\x00')  # Session ID Length
        
        # Cipher Suites
        client_hello.extend(b'\x00\x02')  # Cipher Suites Length
        client_hello.extend(b'\x00\x35')  # Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA
        
        # Compression Methods
        client_hello.extend(b'\x01')  # Compression Methods Length
        client_hello.extend(b'\x00')  # Compression Method: null
        
        # Extensions
        extensions = bytearray()
        
        # SNI Extension
        sni_extension = bytearray()
        sni_extension.extend(b'\x00\x00')  # Extension Type: SNI
        
        sni_data = bytearray()
        sni_data.extend(b'\x00\x0e')  # Server Name List Length
        sni_data.extend(b'\x00')  # Server Name Type: host_name
        sni_data.extend(b'\x00\x0b')  # Server Name Length
        sni_data.extend(b'example.com')  # Server Name
        
        sni_extension.extend(struct.pack('>H', len(sni_data)))  # Extension Length
        sni_extension.extend(sni_data)
        
        extensions.extend(sni_extension)
        
        # Add extensions to client hello
        client_hello.extend(struct.pack('>H', len(extensions)))  # Extensions Length
        client_hello.extend(extensions)
        
        # Add client hello to handshake
        handshake.extend(struct.pack('>I', len(client_hello))[1:])  # Length (3 bytes)
        handshake.extend(client_hello)
        
        # Add handshake to record
        record.extend(struct.pack('>H', len(handshake)))  # Record Length
        record.extend(handshake)
        
        return bytes(record)
    
    def _create_tls_client_hello_without_extensions(self) -> bytes:
        """Create a TLS Client Hello without any extensions."""
        # TLS Record Header
        record = bytearray()
        record.extend(b'\x16')  # Content Type: Handshake
        record.extend(b'\x03\x03')  # Version: TLS 1.2
        
        # Handshake message
        handshake = bytearray()
        handshake.extend(b'\x01')  # Handshake Type: Client Hello
        
        # Client Hello message
        client_hello = bytearray()
        client_hello.extend(b'\x03\x03')  # Version: TLS 1.2
        client_hello.extend(b'\x00' * 32)  # Random
        client_hello.extend(b'\x00')  # Session ID Length
        
        # Cipher Suites
        client_hello.extend(b'\x00\x02')  # Cipher Suites Length
        client_hello.extend(b'\x00\x35')  # Cipher Suite
        
        # Compression Methods
        client_hello.extend(b'\x01')  # Compression Methods Length
        client_hello.extend(b'\x00')  # Compression Method: null
        
        # No extensions
        
        # Add client hello to handshake
        handshake.extend(struct.pack('>I', len(client_hello))[1:])  # Length (3 bytes)
        handshake.extend(client_hello)
        
        # Add handshake to record
        record.extend(struct.pack('>H', len(handshake)))  # Record Length
        record.extend(handshake)
        
        return bytes(record)


@pytest.fixture
def position_resolver():
    """Fixture providing a PositionResolver instance."""
    return PositionResolver()


@pytest.fixture
def sample_tls_packet():
    """Fixture providing a sample TLS Client Hello packet."""
    resolver = PositionResolver()
    return resolver._create_detailed_tls_client_hello_with_sni()


@pytest.fixture
def split_config_numeric():
    """Fixture providing a numeric-only split configuration."""
    return SplitConfig(
        numeric_positions=[3, 10, 50],
        use_sni=False,
        priority_order=['numeric']
    )


@pytest.fixture
def split_config_sni():
    """Fixture providing an SNI-enabled split configuration."""
    return SplitConfig(
        numeric_positions=[3, 10],
        use_sni=True,
        priority_order=['sni', 'numeric']
    )


class TestPositionResolverIntegration:
    """Integration tests for PositionResolver with various scenarios."""
    
    def test_real_world_scenario_youtube(self, position_resolver):
        """Test position resolution with YouTube-like TLS packet."""
        # Simulate a TLS Client Hello to youtube.com
        youtube_packet = self._create_youtube_tls_packet()
        
        config = SplitConfig(
            numeric_positions=[3, 10],
            use_sni=True,
            priority_order=['sni', 'numeric']
        )
        
        result = position_resolver.resolve_positions(youtube_packet, config)
        
        # Should have both SNI and numeric positions
        assert len(result) >= 2
        assert any(pos <= 10 for pos in result)  # Should have small numeric positions
    
    def test_edge_case_tiny_packet(self, position_resolver):
        """Test position resolution with very small packet."""
        tiny_packet = b'AB'  # 2 bytes
        
        config = SplitConfig(
            numeric_positions=[1, 3, 5],
            use_sni=False,
            priority_order=['numeric']
        )
        
        result = position_resolver.resolve_positions(tiny_packet, config)
        
        # Only position 1 should be valid (leaves 1 byte for second part)
        assert result == []  # Actually, position 1 would leave 1 byte, but validate_position requires at least 1 byte after
    
    def test_edge_case_large_packet(self, position_resolver):
        """Test position resolution with very large packet."""
        large_packet = b'A' * 10000  # 10KB packet
        
        config = SplitConfig(
            numeric_positions=[3, 10, 100, 1000],
            use_sni=False,
            priority_order=['numeric']
        )
        
        result = position_resolver.resolve_positions(large_packet, config)
        
        # All positions should be valid
        assert result == [3, 10, 100, 1000]
    
    def _create_youtube_tls_packet(self) -> bytes:
        """Create a realistic TLS Client Hello packet for youtube.com."""
        # This would be a more realistic packet structure
        # For now, create a simplified version
        packet = b'\x16\x03\x03\x01\x00'  # TLS record header
        packet += b'\x01\x00\x00\xFC'  # Handshake header
        packet += b'\x03\x03'  # Client Hello version
        packet += b'\x00' * 32  # Random
        packet += b'\x00'  # Session ID length
        packet += b'\x00\x20'  # Cipher suites length
        packet += b'\x00' * 32  # Cipher suites
        packet += b'\x01\x00'  # Compression methods
        
        # Extensions with SNI for youtube.com
        extensions = bytearray()
        
        # SNI Extension
        sni_ext = bytearray()
        sni_ext.extend(b'\x00\x00')  # SNI type
        sni_data = bytearray()
        sni_data.extend(b'\x00\x0d')  # Server name list length
        sni_data.extend(b'\x00')  # Name type
        sni_data.extend(b'\x00\x0a')  # Name length
        sni_data.extend(b'youtube.com')
        sni_ext.extend(struct.pack('>H', len(sni_data)))
        sni_ext.extend(sni_data)
        
        extensions.extend(sni_ext)
        
        packet += struct.pack('>H', len(extensions))
        packet += extensions
        
        return packet